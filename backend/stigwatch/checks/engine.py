"""Declarative STIG check engine over collector facts.

The engine is collector-agnostic. A collector module (``stigwatch.facts.linux``,
``stigwatch.facts.windows``) turns raw collector JSON into facts:
``{fact_id: {"status": "ok"|"unavailable", "value": <normalised>, "reason", "command"}}``.
A checks file (``checks/<collector>.yml``) maps STIG IDs to conditions over those facts.

Conditions are tri-state: True, False or None (unknown). A leaf names a ``path`` whose
first segment is a fact id (``"login_defs.PASS_MIN_DAYS"``, or a list of segments when a
key contains dots: ``[sysctl_runtime, kernel.dmesg_restrict]``); ``name[]`` iterates a
list and requires every element (``quant: any`` needs one). A fact that was not read, or
a path the fact does not report, is unknown. An explicit ``null`` means "not configured":
it never satisfies a requirement (only the ``unset`` operator tests for it). ``all`` and
``any`` combine conditions. Unknown never decides a rule.

Per check, in order:
  ``na_if``  true    -> Not_Applicable (a gathered fact proves the rule does not apply);
             unknown -> Not_Reviewed (applicability cannot be established)
  ``logic``  true    -> ``result_if_true`` (NotAFinding, or Not_Reviewed when the facts
                        are supporting evidence only)
  ``logic``  false   -> with ``unmet_if``: true -> ``result_if_false``, otherwise
                        Not_Reviewed; without ``unmet_if``: ``result_if_false`` (Open)
  ``logic``  unknown -> Not_Reviewed, naming the facts that could not be read
Rules of the benchmark without a check are Not_Reviewed ("Manual review").

Ported from CMMC Ready's evidence engine: met_if / unmet_if / fail_result / met_result
became logic / unmet_if / result_if_false / result_if_true.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Any

import yaml

from ..benchmarks import Benchmark, load_benchmark
from ..facts import Operator
from ..facts import linux as linux_facts
from ..facts import windows as windows_facts

OPEN = "Open"
NOT_A_FINDING = "NotAFinding"
NOT_APPLICABLE = "Not_Applicable"
NOT_REVIEWED = "Not_Reviewed"
STATUSES = (OPEN, NOT_A_FINDING, NOT_APPLICABLE, NOT_REVIEWED)

CHECKS_DIR = Path(__file__).resolve().parent
# Benchmark id -> checks file. The file names its collector.
CHECK_FILES: dict[str, Path] = {
    "ubuntu-22.04": CHECKS_DIR / "linux.yml",
    "windows-server-2022": CHECKS_DIR / "windows.yml",
}
COLLECTORS: dict[str, Any] = {linux_facts.COLLECTOR: linux_facts,
                              windows_facts.COLLECTOR: windows_facts}

_BUILTIN_OPS = {
    "eq", "ne", "ge", "le", "gt", "lt", "in", "not_in", "subset", "contains",
    "nonempty", "empty", "unset", "matches", "perm_le",
}
_SYMBOL = {
    "eq": "=", "ne": "!=", "ge": ">=", "le": "<=", "gt": ">", "lt": "<", "in": "in",
    "not_in": "not in", "subset": "only contains values from", "contains": "contains",
    "matches": "matches", "perm_le": "mode no more permissive than",
}
_CHECK_KEYS = {
    "stig_id", "facts", "logic", "result_if_true", "result_if_false", "unmet_if", "na_if",
    "rationale", "observe",
}


@dataclass(frozen=True)
class Check:
    stig_id: str
    facts: tuple[str, ...]
    logic: dict
    rationale: str
    result_if_true: str = NOT_A_FINDING
    result_if_false: str = OPEN
    unmet_if: dict | None = None
    na_if: dict | None = None
    observe: tuple[tuple[str, ...], ...] = ()

    @property
    def outcomes(self) -> frozenset[str]:
        """Statuses this check can produce besides Not_Reviewed."""
        out = {self.result_if_true, self.result_if_false}
        if self.na_if is not None:
            out.add(NOT_APPLICABLE)
        return frozenset(out - {NOT_REVIEWED})


@dataclass(frozen=True)
class CheckSet:
    benchmark_id: str
    collector: str
    checks: dict[str, Check]


@dataclass(frozen=True)
class RuleResult:
    stig_id: str
    status: str
    evidence: tuple[dict, ...]
    reason: str
    rationale: str = ""
    automated: bool = False

    def as_dict(self) -> dict:
        return {
            "stig_id": self.stig_id, "status": self.status, "reason": self.reason,
            "rationale": self.rationale, "automated": self.automated,
            "evidence": [dict(e) for e in self.evidence],
        }


# --------------------------------------------------------------------------- paths

def _parse_path(raw: Any, where: str = "path") -> tuple[str, ...]:
    if isinstance(raw, str):
        tokens = tuple(raw.split("."))
    elif isinstance(raw, list) and raw and all(isinstance(t, (str, int)) for t in raw):
        tokens = tuple(str(t) for t in raw)
    else:
        raise ValueError(f"{where}: path must be a dotted string or a list of keys")
    if any(not t or t == "[]" for t in tokens):
        raise ValueError(f"{where}: empty path segment in {raw!r}")
    return tokens


def show_path(path: tuple[str, ...]) -> str:
    out = path[0]
    for t in path[1:]:
        out += f"[{t}]" if any(c in t for c in "./\\ ") else f".{t}"
    return out


def _resolve(value: Any, path: tuple[str, ...]) -> tuple[bool, Any, bool]:
    """Return (found, value-or-list, iterated)."""
    nodes = [value]
    iterated = False
    for token in path:
        each = token.endswith("[]")
        key = token[:-2] if each else token
        nxt: list[Any] = []
        for node in nodes:
            if not isinstance(node, dict) or key not in node:
                return False, None, False
            child = node[key]
            if each:
                if not isinstance(child, list) or not child:
                    return False, None, False
                nxt.extend(child)
                iterated = True
            else:
                nxt.append(child)
        nodes = nxt
    return True, (nodes if iterated else nodes[0]), iterated


# --------------------------------------------------------------------------- validation

def _is_num(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _ops_of(cond: dict) -> list[str]:
    return sorted(set(cond) - {"path", "quant"})


def _check_condition(cond: Any, where: str, facts: tuple[str, ...],
                     ops: dict[str, Operator]) -> None:
    if not isinstance(cond, dict):
        raise ValueError(f"{where}: condition must be a mapping")
    if "all" in cond or "any" in cond:
        key = "all" if "all" in cond else "any"
        if set(cond) != {key} or not isinstance(cond[key], list) or not cond[key]:
            raise ValueError(f"{where}: '{key}' takes a non-empty list")
        for sub in cond[key]:
            _check_condition(sub, where, facts, ops)
        return
    if "path" not in cond:
        raise ValueError(f"{where}: leaf condition needs a path")
    path = _parse_path(cond["path"], where)
    if path[0] not in facts:
        raise ValueError(f"{where}: path {cond['path']!r} uses fact {path[0]!r} "
                         "that is not listed in facts")
    if cond.get("quant", "all") not in ("all", "any"):
        raise ValueError(f"{where}: quant must be 'all' or 'any'")
    names = _ops_of(cond)
    if not names:
        raise ValueError(f"{where}: leaf condition needs an operator")
    for op in names:
        arg = cond[op]
        if op in ops:
            ops[op].validate(arg)
        elif op not in _BUILTIN_OPS:
            raise ValueError(f"{where}: unknown operator {op!r}")
        elif op in ("in", "not_in", "subset") and not isinstance(arg, list):
            raise ValueError(f"{where}: {op} takes a list")
        elif op in ("nonempty", "empty", "unset") and not isinstance(arg, bool):
            raise ValueError(f"{where}: {op} takes true or false")
        elif op == "matches":
            if not isinstance(arg, str):
                raise ValueError(f"{where}: matches takes a regular expression")
            re.compile(arg)
        elif op == "perm_le" and not (isinstance(arg, str) and re.fullmatch(r"[0-7]{3,4}", arg)):
            raise ValueError(f"{where}: perm_le takes an octal mode string such as '640'")
        elif op in ("ge", "le", "gt", "lt") and not _is_num(arg):
            raise ValueError(f"{where}: {op} takes a number")


def build_checks(raw: Any, benchmark: Benchmark | None = None) -> CheckSet:
    """Validate a parsed checks file. Raises ValueError on any problem."""
    if not isinstance(raw, dict):
        raise ValueError("checks file must be a mapping")
    module = COLLECTORS.get(raw.get("collector"))
    if module is None:
        raise ValueError(f"unknown collector {raw.get('collector')!r}")
    bid = raw.get("benchmark")
    if not isinstance(bid, str):
        raise ValueError("checks file needs a benchmark id")
    if benchmark is not None and benchmark.benchmark_id != bid:
        raise ValueError(f"checks are for {bid!r}, not {benchmark.benchmark_id!r}")
    items = raw.get("checks")
    if not isinstance(items, list) or not items:
        raise ValueError("checks file needs a non-empty 'checks' list")
    ops: dict[str, Operator] = getattr(module, "OPERATORS", {})
    out: dict[str, Check] = {}
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("each check must be a mapping")
        sid = item.get("stig_id")
        where = f"check {sid!r}"
        if not isinstance(sid, str) or not sid:
            raise ValueError("check without a stig_id")
        if sid in out:
            raise ValueError(f"{where}: duplicate stig_id")
        unknown = set(item) - _CHECK_KEYS
        if unknown:
            raise ValueError(f"{where}: unknown keys {sorted(unknown)}")
        if benchmark is not None and benchmark.rule(sid) is None:
            raise ValueError(f"{where}: not a rule of {benchmark.benchmark_id}")
        facts = item.get("facts")
        if not isinstance(facts, list) or not facts or not all(isinstance(f, str) for f in facts):
            raise ValueError(f"{where}: facts must be a non-empty list of fact ids")
        for f in facts:
            if f not in module.FACTS:
                raise ValueError(f"{where}: unknown fact {f!r}")
        facts_t = tuple(facts)
        rationale = str(item.get("rationale") or "").strip()
        if not rationale:
            raise ValueError(f"{where}: rationale is required")
        _check_condition(item.get("logic"), where, facts_t, ops)
        for key in ("unmet_if", "na_if"):
            if item.get(key) is not None:
                _check_condition(item[key], f"{where} {key}", facts_t, ops)
        rtrue = item.get("result_if_true", NOT_A_FINDING)
        if rtrue not in (NOT_A_FINDING, NOT_REVIEWED):
            raise ValueError(f"{where}: result_if_true must be NotAFinding or Not_Reviewed")
        rfalse = item.get("result_if_false", OPEN)
        if rfalse not in (OPEN, NOT_REVIEWED):
            raise ValueError(f"{where}: result_if_false must be Open or Not_Reviewed")
        observe = tuple(_parse_path(p, where) for p in item.get("observe") or [])
        for p in observe:
            if p[0] not in facts_t:
                raise ValueError(f"{where}: observe path uses fact {p[0]!r} not listed in facts")
        out[sid] = Check(sid, facts_t, item["logic"], rationale, rtrue, rfalse,
                         item.get("unmet_if"), item.get("na_if"), observe)
    return CheckSet(bid, module.COLLECTOR, out)


@cache
def load_checks(benchmark_id: str) -> CheckSet:
    path = CHECK_FILES.get(benchmark_id)
    if path is None:
        raise ValueError(f"no checks for benchmark {benchmark_id!r}")
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    return build_checks(raw, load_benchmark(benchmark_id))


# --------------------------------------------------------------------------- evaluation

def _same_kind(a: Any, b: Any) -> bool:
    return ((isinstance(a, bool) and isinstance(b, bool))
            or (_is_num(a) and _is_num(b))
            or (isinstance(a, str) and isinstance(b, str)))


def _test(op: str, actual: Any, expected: Any, ops: dict[str, Operator]) -> bool | None:
    if op == "unset":
        return (actual is None) == expected
    if actual is None:  # explicitly "not configured"
        return False
    if op in ops:
        return ops[op].test(actual, expected)
    if op in ("nonempty", "empty"):
        if isinstance(actual, str):
            filled = bool(actual.strip())
        elif isinstance(actual, (list, dict)):
            filled = bool(actual)
        else:
            return None
        return filled if (op == "nonempty") == expected else not filled
    if op in ("ge", "le", "gt", "lt"):
        if not (_is_num(actual) and _is_num(expected)):
            return None
        return {"ge": actual >= expected, "le": actual <= expected,
                "gt": actual > expected, "lt": actual < expected}[op]
    if op in ("eq", "ne"):
        if not _same_kind(actual, expected):
            return None
        return (actual == expected) if op == "eq" else (actual != expected)
    if op in ("in", "not_in"):
        if not any(_same_kind(actual, e) for e in expected):
            return None
        return (actual in expected) if op == "in" else (actual not in expected)
    if op == "subset":
        if not isinstance(actual, list):
            return None
        return all(a in expected for a in actual)
    if op == "contains":
        if isinstance(actual, list):
            return expected in actual
        if isinstance(actual, str) and isinstance(expected, str):
            return expected in actual
        return None
    if op == "matches":
        return re.search(expected, actual) is not None if isinstance(actual, str) else None
    if op == "perm_le":
        if not (isinstance(actual, str) and re.fullmatch(r"[0-7]{1,5}", actual)):
            return None
        return (int(actual, 8) & ~int(expected, 8) & 0o7777) == 0
    return None


def _tri_all(items: list[bool | None]) -> bool | None:
    if any(i is False for i in items):
        return False
    return None if any(i is None for i in items) else True


def _tri_any(items: list[bool | None]) -> bool | None:
    if any(i is True for i in items):
        return True
    return None if any(i is None for i in items) else False


def _eval(cond: dict, values: dict, ops: dict[str, Operator]) -> bool | None:
    if "all" in cond:
        return _tri_all([_eval(c, values, ops) for c in cond["all"]])
    if "any" in cond:
        return _tri_any([_eval(c, values, ops) for c in cond["any"]])
    found, got, iterated = _resolve(values, _parse_path(cond["path"]))
    if not found:
        return None
    elements = got if iterated else [got]
    per_element = [_tri_all([_test(op, el, cond[op], ops) for op in _ops_of(cond)])
                   for el in elements]
    return _tri_any(per_element) if cond.get("quant") == "any" else _tri_all(per_element)


def _leaves(cond: dict | None) -> list[dict]:
    if cond is None:
        return []
    if "all" in cond or "any" in cond:
        out: list[dict] = []
        for sub in cond.get("all", cond.get("any")):
            out.extend(_leaves(sub))
        return out
    return [cond]


def _fmt(v: Any) -> str:
    return repr(v) if isinstance(v, str) else str(v)


def _describe_leaf(cond: dict, ops: dict[str, Operator]) -> str:
    path = show_path(_parse_path(cond["path"]))
    if cond.get("quant") == "any":
        path = f"any of {path}"
    parts = []
    for op in _ops_of(cond):
        arg = cond[op]
        if op in ops:
            parts.append(f"{path} has {ops[op].describe(arg)}")
        elif op == "unset":
            parts.append(f"{path} is {'not set' if arg else 'set'}")
        elif op in ("nonempty", "empty"):
            empty = (op == "empty") == arg
            parts.append(f"{path} is {'empty' if empty else 'non-empty'}")
        else:
            parts.append(f"{path} {_SYMBOL[op]} {_fmt(arg)}")
    return " and ".join(parts)


def describe(cond: dict, ops: dict[str, Operator] | None = None) -> str:
    ops = ops or {}
    if "all" in cond or "any" in cond:
        key, glue = ("all", " and ") if "all" in cond else ("any", " or ")
        parts = [describe(c, ops) for c in cond[key]]
        return parts[0] if len(parts) == 1 else "(" + glue.join(parts) + ")"
    return _describe_leaf(cond, ops)


def _partial_reason(fact: dict, path: tuple[str, ...]) -> str | None:
    """The reason a part of a readable fact could not be read, if the fact records one.

    A fact may carry ``partial``: a nested mapping, following the value's keys, whose
    string leaves explain why that part of the value is missing."""
    node: Any = fact.get("partial")
    for token in path[1:]:
        if isinstance(node, str):
            return node
        if not isinstance(node, dict) or token not in node:
            return None
        node = node[token]
    return node if isinstance(node, str) else None


def _observed(facts: dict, values: dict, path: tuple[str, ...], leaves: list[dict],
              ops: dict[str, Operator]) -> Any:
    fact = facts.get(path[0])
    if fact is None:
        return "not collected"
    if fact.get("status") != "ok":
        return f"unavailable: {fact.get('reason') or 'no reason given'}"
    found, got, _ = _resolve(values, path)
    if not found:
        reason = _partial_reason(fact, path)
        return f"unavailable: {reason}" if reason else "not reported"
    for leaf in leaves:
        for op in _ops_of(leaf):
            if op in ops and ops[op].observe is not None:
                return ops[op].observe(got, leaf[op])
    return got


def _evidence(check: Check, facts: dict, values: dict, conds: list[dict | None],
              ops: dict[str, Operator], context: bool = True) -> tuple[dict, ...]:
    by_path: dict[tuple[str, ...], list[dict]] = {}
    for cond in conds:
        for leaf in _leaves(cond):
            by_path.setdefault(_parse_path(leaf["path"]), []).append(leaf)
    for p in check.observe if context else ():
        by_path.setdefault(p, [])
    out = []
    for path, leaves in by_path.items():
        fact = facts.get(path[0]) or {}
        expected = " and ".join(_describe_leaf(leaf, ops) for leaf in leaves) or "(context)"
        out.append({
            "fact": path[0],
            "path": show_path(path),
            "observed": _observed(facts, values, path, leaves, ops),
            "expected": expected,
            "command": fact.get("command") or "",
        })
    return tuple(out)


def _show(evidence: tuple[dict, ...]) -> str:
    parts = []
    for e in evidence:
        text = _fmt(e["observed"])
        if len(text) > 160:
            text = text[:157] + "..."
        parts.append(f"{e['path']}={text}")
    return "; ".join(parts)


def _unreadable(check: Check, facts: dict) -> list[str]:
    out = []
    for f in check.facts:
        fact = facts.get(f)
        if fact is None:
            out.append(f"{f} was not collected")
        elif fact.get("status") != "ok":
            cmd = fact.get("command")
            suffix = f" (command: {cmd})" if cmd else ""
            out.append(f"{f} could not be read: {fact.get('reason') or 'no reason given'}{suffix}")
    return out


def evaluate_check(check: Check, facts: dict, ops: dict[str, Operator] | None = None) -> RuleResult:
    ops = ops or {}
    values = {k: v.get("value") for k, v in facts.items() if v.get("status") == "ok"}

    def done(status: str, reason: str, conds: list[dict | None]) -> RuleResult:
        return RuleResult(check.stig_id, status, _evidence(check, facts, values, conds, ops),
                          reason, check.rationale, True)

    expected = describe(check.logic, ops)
    conds = [check.na_if, check.logic, check.unmet_if]
    not_applicable = False if check.na_if is None else _eval(check.na_if, values, ops)
    if not_applicable is True:
        # Only the facts that prove non-applicability (not the context paths) are named.
        ev = _evidence(check, facts, values, [check.na_if], ops, context=False)
        return RuleResult(check.stig_id, NOT_APPLICABLE, ev,
                          f"Not applicable: {describe(check.na_if, ops)} "
                          f"(fact: {', '.join(sorted({e['fact'] for e in ev}))}; "
                          f"observed {_show(ev)}).", check.rationale, True)
    ev = _evidence(check, facts, values, conds, ops)
    seen = _show(ev)
    missing = _unreadable(check, facts)
    if not_applicable is None:
        # Whether the rule applies is unknown: neither a finding nor a pass can be claimed.
        extra = (" " + "; ".join(missing) + ".") if missing else ""
        return done(NOT_REVIEWED, f"Not reviewed: whether the rule applies could not be "
                                  f"determined ({describe(check.na_if, ops)} is unknown; observed "
                                  f"{seen}).{extra}", conds)
    met = _eval(check.logic, values, ops)
    if met is None:
        if missing:
            return done(NOT_REVIEWED, "Not reviewed: " + "; ".join(missing)
                        + f". Expected {expected}.", conds)
        return done(NOT_REVIEWED, f"Not reviewed: the collected facts are inconclusive "
                                  f"(observed {seen}); expected {expected}.", conds)
    if met:
        if check.result_if_true == NOT_REVIEWED:
            return done(NOT_REVIEWED, f"Not reviewed: supporting evidence only (observed "
                                      f"{seen}). {check.rationale}", conds)
        return done(NOT_A_FINDING, f"Not a finding: {expected} (observed {seen}).", conds)
    if check.unmet_if is not None and _eval(check.unmet_if, values, ops) is not True:
        extra = (" " + "; ".join(missing) + ".") if missing else ""
        return done(NOT_REVIEWED, f"Not reviewed: observed {seen} does not prove a finding; "
                                  f"expected {expected}.{extra}", conds)
    if check.result_if_false == NOT_REVIEWED:
        return done(NOT_REVIEWED, f"Not reviewed: {expected} is not shown (observed {seen}). "
                                  f"{check.rationale}", conds)
    return done(OPEN, f"Open: expected {expected}; observed {seen}.", conds)


def collector_module(collector_json: Any) -> Any:
    module = (COLLECTORS.get(collector_json.get("collector"))
              if isinstance(collector_json, dict) else None)
    if module is None:
        raise ValueError("not a recognised collector file")
    return module


def evaluate(collector_json: dict, benchmark: Benchmark | None = None) -> list[RuleResult]:
    """One RuleResult per benchmark rule, in benchmark order.

    Raises ValueError for unknown collectors, unsupported versions, or collector output
    that does not belong to the benchmark.
    """
    module = collector_module(collector_json)
    module.validate(collector_json)
    if benchmark is None:
        benchmark = load_benchmark(module.BENCHMARK)
    checkset = load_checks(benchmark.benchmark_id)
    if checkset.collector != module.COLLECTOR:
        raise ValueError(f"{module.COLLECTOR} collector output cannot be scanned against "
                         f"{benchmark.benchmark_id}")
    facts = module.facts(collector_json)
    ops: dict[str, Operator] = getattr(module, "OPERATORS", {})
    results: list[RuleResult] = []
    for rule in benchmark.rules:
        check = checkset.checks.get(rule.stig_id)
        if check is None:
            results.append(RuleResult(
                rule.stig_id, NOT_REVIEWED, (),
                "Manual review: STIGWatch has no automated check for this rule.", "", False))
            continue
        try:
            results.append(evaluate_check(check, facts, ops))
        except Exception as exc:  # a malformed value must never decide a rule
            results.append(RuleResult(
                rule.stig_id, NOT_REVIEWED, (),
                f"Not reviewed: the check could not be evaluated ({type(exc).__name__}).",
                check.rationale, True))
    return results


def status_counts(results: list[RuleResult]) -> dict[str, int]:
    counts = {s: 0 for s in STATUSES}
    for r in results:
        counts[r.status] += 1
    return counts


# --------------------------------------------------------------------------- coverage

@dataclass
class Coverage:
    benchmark_id: str
    label: str
    by_cat: dict[str, dict[str, int]] = field(default_factory=dict)
    automated: list[tuple[str, str, str]] = field(default_factory=list)  # (stig_id, cat, kind)
    manual: list[tuple[str, str]] = field(default_factory=list)


def check_kind(check: Check) -> str:
    """full: can return Open and NotAFinding; partial: one of them; evidence: neither."""
    decisive = check.outcomes & {OPEN, NOT_A_FINDING}
    return "full" if len(decisive) == 2 else "partial" if decisive else "evidence"


def coverage(benchmark_id: str) -> Coverage:
    bench = load_benchmark(benchmark_id)
    checkset = load_checks(benchmark_id)
    cov = Coverage(bench.benchmark_id, bench.label)
    for cat in ("CAT I", "CAT II", "CAT III"):
        cov.by_cat[cat] = {"total": 0, "automated": 0, "full": 0, "partial": 0,
                           "evidence": 0, "manual": 0}
    for rule in bench.rules:
        row = cov.by_cat[rule.cat]
        row["total"] += 1
        check = checkset.checks.get(rule.stig_id)
        if check is None:
            row["manual"] += 1
            cov.manual.append((rule.stig_id, rule.cat))
        else:
            kind = check_kind(check)
            row["automated"] += 1
            row[kind] += 1
            cov.automated.append((rule.stig_id, rule.cat, kind))
    return cov


def coverage_lines(benchmark_id: str) -> list[str]:
    cov = coverage(benchmark_id)
    total = sum(r["total"] for r in cov.by_cat.values())
    decisive = sum(1 for _, _, kind in cov.automated if kind != "evidence")
    lines = [
        f"{cov.benchmark_id} {cov.label}: {len(cov.automated)} of {total} rules automated "
        f"({decisive} can decide a result, {len(cov.automated) - decisive} evidence or "
        f"applicability only), {len(cov.manual)} manual review",
        f"{'':9}{'rules':>6}{'automated':>11}{'full':>6}{'partial':>9}{'evidence':>10}{'manual':>8}",
    ]
    for cat, row in cov.by_cat.items():
        lines.append(f"{cat:9}{row['total']:>6}{row['automated']:>11}{row['full']:>6}"
                     f"{row['partial']:>9}{row['evidence']:>10}{row['manual']:>8}")
    lines.append("full = can return Open and NotAFinding; partial = one of them "
                 "(the other outcome is Not_Reviewed); evidence = neither (Not_Applicable "
                 "when a fact proves it, otherwise Not_Reviewed with the facts shown)")
    cat1 = [f"{s} ({k})" for s, c, k in cov.automated if c == "CAT I"]
    lines.append("CAT I automated: " + ", ".join(cat1))
    cat1_manual = [s for s, c in cov.manual if c == "CAT I"]
    lines.append("CAT I manual: " + (", ".join(cat1_manual) or "none"))
    return lines
