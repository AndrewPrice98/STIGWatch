"""Generated remediation (Ansible playbook, PowerShell script) for review only.

STIGWatch never connects to a host and never applies anything. This module turns the open
findings of one host into text a person reviews and runs themselves.

A fix is generated only when it is safe, mechanical and derivable from the rule's own check
definition (``checks/linux.yml``, ``checks/windows.yml``): the generator reads the check's
conditions, and each condition that is not already met (the evidence says so) must map onto
a known idempotent change. The target value comes from the check (``eq`` gives that value,
``le`` / ``ge`` give the bound, ``subset`` gives the allowed list). One condition without a
safe mapping makes the whole rule manual: it is listed in a comment block with the rule's
fix text and never half-fixed.

Linux (Ansible, ``ansible.builtin`` modules plus ``ansible.posix.sysctl``): sshd_config
directives, sysctl, packages present or absent, systemd units enabled/started/stopped/masked,
login.defs, useradd defaults, pwquality, auditd.conf and limits.conf keys, file mode and
owner, audit rules, TMOUT, the usb-storage modprobe file and APT settings.

Windows (PowerShell): HKLM registry values with their exact type, local account policy and
user rights through a generated INF for ``secedit /configure``, ``auditpol /set`` by
subcategory GUID, and Windows Server features removed. Every change sits behind
``ShouldProcess``; the script is a dry run unless ``-Apply`` is given.

Output is deterministic (no timestamps) and ASCII only.
"""

from __future__ import annotations

import re
import textwrap
import unicodedata
from dataclasses import dataclass, field
from typing import Any

import yaml

from .benchmarks import Benchmark, Rule
from .checks import engine
from .facts import windows as windows_facts

REVIEW_HEADER = "Review before applying; test on a non-production host."
DISCLAIMER = ("STIGWatch is an independent tool. It is not a DISA product and does not "
              "replace the SCAP Compliance Checker, Evaluate-STIG or an assessor's review.")
_CATS = ("CAT I", "CAT II", "CAT III")
_TAG_CAT = {"CAT I": "cat1", "CAT II": "cat2", "CAT III": "cat3"}
_ID_RE = re.compile(r"^[A-Z0-9][A-Z0-9-]{2,40}$")


class Unsupported(Exception):
    """The rule (or one of its conditions) has no safe automatic fix; the text says why."""


# --------------------------------------------------------------------------- shared helpers

def _get(item: Any, key: str, default: Any = None) -> Any:
    if isinstance(item, dict):
        return item.get(key, default)
    return getattr(item, key, default)


def _one_line(text: Any, limit: int = 160) -> str:
    """Text safe inside a one-line comment: ASCII, no control or line-separator characters."""
    out = []
    for ch in str(text):
        cat = unicodedata.category(ch)
        if ch in " \t\r\n" or cat in ("Zs", "Zl", "Zp", "Cc"):
            out.append(" ")
        elif cat[0] == "C":
            continue
        elif ord(ch) > 126:
            out.append("?")
        else:
            out.append(ch)
    s = re.sub(r" +", " ", "".join(out)).strip()
    return s if len(s) <= limit else s[: limit - 3].rstrip() + "..."


def _summary(rule: Rule | None) -> str:
    if rule is None:
        return "(rule is not in this benchmark release)"
    return _one_line(rule.fix_text, 300) or "(no fix text)"


def _title(rule: Rule | None, stig_id: str) -> str:
    return _one_line(rule.title, 140) if rule else stig_id


def _item_ids(open_results: Any, benchmark: Benchmark) -> list[tuple[str, Any]]:
    """Open items, one per STIG ID, ordered CAT I, II, III then by STIG ID."""
    items: dict[str, Any] = {}
    for it in open_results or []:
        sid = _get(it, "stig_id")
        if not isinstance(sid, str) or not _ID_RE.match(sid):
            continue
        if _get(it, "status", "Open") != "Open":
            continue
        items[sid] = it

    def key(sid: str) -> tuple[int, str]:
        rule = benchmark.rule(sid)
        return (_CATS.index(rule.cat) if rule else len(_CATS), sid)

    return [(sid, items[sid]) for sid in sorted(items, key=key)]


def _host_name(host: Any) -> str:
    # "<#" and "#>" would open or close a PowerShell block comment, so they never survive.
    # Host names are untrusted. They only ever appear in comments, and the characters that
    # open a Jinja expression, a YAML/PowerShell comment form or a block comment are removed.
    name = _one_line(_get(host, "name", host if isinstance(host, str) else ""), 80)
    name = re.sub(r"[{}%#<>$`]", "_", name)
    return name or "(unnamed)"


def _block_safe(text: str) -> str:
    return text.replace("<#", "< #").replace("#>", "# >")


def _collector_name(benchmark_id: str) -> str:
    return "windows" if benchmark_id.startswith("windows") else "linux"


# --------------------------------------------------------------------------- check conditions

@dataclass(frozen=True)
class Leaf:
    path: tuple[str, ...]
    op: str
    arg: Any


def _leaf_ops(cond: dict) -> list[Leaf]:
    path = engine._parse_path(cond["path"])
    if cond.get("quant") not in (None, "all"):
        raise Unsupported(f"{engine.show_path(path)} uses a quantifier")
    ops = [k for k in cond if k not in ("path", "quant")]
    if not ops:
        raise Unsupported("empty condition")
    return [Leaf(path, op, cond[op]) for op in ops]


def _registry_any(children: list[dict]) -> list[Leaf]:
    """``any`` over one registry value: unset, eq, or a one-value ``in``. The rule is met by
    setting the value, so that is what the fix does."""
    wanted: list[Any] = []
    path = None
    for c in children:
        if not isinstance(c, dict) or "path" not in c:
            raise Unsupported("alternative conditions without a single target")
        for lf in _leaf_ops(c):
            if lf.path[0] != "registry":
                raise Unsupported("alternative conditions outside the registry")
            if path not in (None, lf.path):
                raise Unsupported("alternatives on different values")
            path = lf.path
            if lf.op == "unset":
                continue
            if lf.op == "eq":
                wanted.append(lf.arg)
            elif lf.op == "in" and isinstance(lf.arg, list) and len(lf.arg) == 1:
                wanted.append(lf.arg[0])
            else:
                raise Unsupported("several acceptable values; the choice is the assessor's")
    if path is None or len({repr(w) for w in wanted}) != 1:
        raise Unsupported("alternatives without one definite value")
    return [Leaf(path, "eq", wanted[0])]


def _conjunction(logic: dict) -> list[Leaf]:
    if "all" in logic:
        out: list[Leaf] = []
        for child in logic["all"]:
            out.extend(_conjunction(child))
        return out
    if "any" in logic:
        return _registry_any(logic["any"])
    return _leaf_ops(logic)


def _observed(item: Any) -> dict[str, Any]:
    return {e.get("path"): e.get("observed") for e in (_get(item, "evidence") or [])
            if isinstance(e, dict)}


def _satisfied(leaf: Leaf, obs: dict[str, Any], ops: dict) -> bool:
    key = engine.show_path(leaf.path)
    if key not in obs or any(t.endswith("[]") for t in leaf.path) or leaf.op in ops:
        return False
    try:
        return engine._test(leaf.op, obs[key], leaf.arg, ops) is True
    except Exception:  # an operator that cannot compare these values decides nothing
        return False


class Cons:
    """Constraints collected for one target."""

    def __init__(self) -> None:
        self.entries: list[tuple[str, str, Any]] = []   # (field, op, arg)

    def add(self, fld: str, op: str, arg: Any) -> None:
        self.entries.append((fld, op, arg))

    def fields(self, name: str) -> list[tuple[str, Any]]:
        return [(op, arg) for f, op, arg in self.entries if f == name]

    def value(self, name: str = "v") -> Any:
        eq: list[Any] = []
        ge: list[Any] = []
        le: list[Any] = []
        sub: list[list] = []
        for op, arg in self.fields(name):
            if op == "eq":
                eq.append(arg)
            elif op == "in" and isinstance(arg, list) and len(arg) == 1:
                eq.append(arg[0])
            elif op == "ge":
                ge.append(arg)
            elif op == "le":
                le.append(arg)
            elif op == "subset":
                sub.append(arg)
            elif op in ("nonempty", "unset"):
                continue
            else:
                raise Unsupported(f"no single target value for operator '{op}'")
        for lst in (ge, le):
            if any(isinstance(x, bool) or not isinstance(x, (int, float)) for x in lst):
                raise Unsupported("non-numeric bound")
        if eq:
            if len({repr(e) for e in eq}) > 1:
                raise Unsupported("contradicting values")
            v = eq[0]
            if (ge or le) and (isinstance(v, bool) or not isinstance(v, (int, float))
                               or any(v < g for g in ge) or any(v > h for h in le)):
                raise Unsupported("value outside the bounds")
            return v
        if sub:
            return [x for x in sub[0] if all(x in s for s in sub[1:])]
        hi = min(le) if le else None
        lo = max(ge) if ge else None
        if hi is not None:
            if lo is not None and lo > hi:
                raise Unsupported("empty range")
            return hi
        if lo is not None:
            return lo
        raise Unsupported("no value can be derived from the check")


def _safe_text(value: Any, pattern: str = r"[A-Za-z0-9_.,@:+/=<>!%~ -]{1,400}") -> str:
    s = str(value)
    if not re.fullmatch(pattern, s) or "{" in s or "}" in s:
        raise Unsupported("value is not a plain token")
    return s


def _plan_leaves(check: engine.Check | None, item: Any | None, ops: dict) -> list[Leaf]:
    """The conditions a fix must establish: those the evidence does not show as met. With
    no evidence, or when every condition is met, all of them."""
    if check is None:
        raise Unsupported("the rule has no automated check, so there is no target value")
    leaves = _conjunction(check.logic)
    if item is None:
        return leaves
    obs = _observed(item)
    pending = [lf for lf in leaves if not _satisfied(lf, obs, ops)]
    return pending or leaves


def _ops(benchmark: Benchmark) -> dict:
    collector = engine.COLLECTORS[_collector_name(benchmark.benchmark_id)]
    return dict(getattr(collector, "OPERATORS", {}) or {})


def domain_role_of(raw: Any) -> str | None:
    """``dc``, ``member``, ``standalone`` or ``workstation`` from a stored Windows collector
    scan (the Win32_ComputerSystem.DomainRole fact), else None."""
    try:
        value = raw["facts"]["domain_role"]["value"]
        code = value["domain_role"]
    except (KeyError, TypeError):
        return None
    return {0: "workstation", 1: "member-workstation", 2: "standalone", 3: "member",
            4: "dc", 5: "dc"}.get(code) if isinstance(code, int) else None


# =========================================================================== Linux / Ansible

_SSHD_NAMES = {
    "permitemptypasswords": "PermitEmptyPasswords", "permituserenvironment": "PermitUserEnvironment",
    "x11forwarding": "X11Forwarding", "x11uselocalhost": "X11UseLocalhost",
    "clientalivecountmax": "ClientAliveCountMax", "clientaliveinterval": "ClientAliveInterval",
    "ciphers": "Ciphers", "macs": "MACs", "kexalgorithms": "KexAlgorithms",
    "pubkeyauthentication": "PubkeyAuthentication", "permitrootlogin": "PermitRootLogin",
    "passwordauthentication": "PasswordAuthentication", "hostbasedauthentication": "HostbasedAuthentication",
    "ignorerhosts": "IgnoreRhosts", "usepam": "UsePAM",
}
_KV_FILES = {
    "login_defs": ("/etc/login.defs", "space", {"PASS_MIN_DAYS", "PASS_MAX_DAYS", "UMASK", "ENCRYPT_METHOD"}),
    "useradd_defaults": ("/etc/default/useradd", "equals", {"INACTIVE"}),
    "pwquality_conf": ("/etc/security/pwquality.conf", "spaced_equals",
                       {"ucredit", "lcredit", "dcredit", "ocredit", "dictcheck", "minlen", "difok",
                        "enforcing", "minclass", "maxrepeat", "maxclassrepeat"}),
    "auditd_conf": ("/etc/audit/auditd.conf", "spaced_equals",
                    {"space_left_percent", "space_left_action", "log_group", "disk_full_action",
                     "admin_space_left_action"}),
}
_SYSCTL_DENY = {"crypto.fips_enabled"}
_FILE_PATHS = {"var_log": "/var/log", "syslog": "/var/log/syslog", "journalctl": "/usr/bin/journalctl"}
_AUDIT_TOOLS = ("auditctl", "aureport", "ausearch", "autrace", "auditd", "augenrules")
_SSHD_DROPIN = "/etc/ssh/sshd_config.d/00-stigwatch.conf"
_SSHD_FILES = ("{{ ['/etc/ssh/sshd_config'] + (stigwatch_sshd_dropins.files | map(attribute='path') "
               "| list) }}")
_PRIO = {"pkg": 0, "apt": 1, "sshd": 1, "sysctl": 1, "kv": 1, "file": 1, "tmout": 1, "usb": 1,
         "limits": 1, "audit": 2, "unit": 3}


def _linux_target(leaf: Leaf) -> tuple[tuple, str]:
    p = leaf.path
    head, n = p[0], len(p)
    if head == "sshd_config" and n == 3 and p[1] in _SSHD_NAMES and p[2] in ("value", "list"):
        return ("sshd", _SSHD_NAMES[p[1]]), "v"
    if head == "sysctl_runtime" and n == 2 and p[1] not in _SYSCTL_DENY:
        return ("sysctl", p[1]), "v"
    if head == "sysctl_saved" and n == 3 and p[2] in ("value", "values") and p[1] not in _SYSCTL_DENY:
        return ("sysctl", p[1]), "v"
    if head == "packages" and n == 3 and p[2] == "installed":
        return ("pkg", p[1]), "installed"
    if head == "units" and n == 3 and p[2] in ("file", "active", "load"):
        return ("unit", p[1]), p[2]
    if head in _KV_FILES and n == 2 and p[1] in _KV_FILES[head][2]:
        return ("kv", head, p[1]), "v"
    if head == "limits" and n == 2 and p[1] in ("all_users_limit", "max_value"):
        return ("limits",), "v"
    if head == "shell_tmout" and n == 2 and p[1] in ("count", "min", "max"):
        return ("tmout",), p[1]
    if head == "modprobe_usb" and n == 2 and p[1] in ("install_false", "blacklist") and leaf.arg is True:
        return ("usb",), p[1]
    if head == "apt_conf" and n == 3 and p[2] == "value" and p[1] in (
            "allow_unauthenticated", "remove_unused_kernel_packages", "remove_unused_dependencies"):
        return ("apt", p[1]), "v"
    if head == "path_stats" and n == 3 and p[2] in ("mode", "user", "group") and p[1] in _FILE_PATHS:
        return ("file", _FILE_PATHS[p[1]]), p[2]
    if head == "path_stats" and n == 3 and p[1] == "audit_tools[]" and p[2] in ("mode", "user", "group"):
        return ("file", "audit_tools"), p[2]
    if head == "audit_rules" and n == 1 and leaf.op == "audit":
        return ("audit", repr(sorted(leaf.arg.items(), key=repr))), "rule"
    raise Unsupported(f"{engine.show_path(p)} {leaf.op} has no safe automatic change")


def _symbolic_mode(max_mode: str) -> str:
    """chmod-style removal of the bits above ``max_mode``: never widens a file."""
    if not re.fullmatch(r"[0-7]{3,4}", max_mode):
        raise Unsupported("mode is not octal")
    m = int(max_mode, 8)
    parts = []
    for who, shift in (("u", 6), ("g", 3), ("o", 0)):
        extra = 7 & ~((m >> shift) & 7)
        if extra:
            parts.append(f"{who}-" + "".join(c for c, b in (("r", 4), ("w", 2), ("x", 1)) if extra & b))
    for who, bit, letter in (("u", 0o4000, "s"), ("g", 0o2000, "s"), ("o", 0o1000, "t")):
        if not m & bit:
            parts.append(f"{who}-{letter}")
    return ",".join(parts)


def _audit_lines(arg: dict) -> list[str]:
    key = "-k stigwatch"
    if "watch" in arg:
        path = _safe_text(arg["watch"], r"/[A-Za-z0-9_./-]{1,200}")
        return [f"-w {path} -p {_safe_text(arg['perm'], r'[rwxa]{1,4}')} {key}"]
    if "exec" in arg:
        path = _safe_text(arg["exec"], r"/[A-Za-z0-9_./-]{1,200}")
        return [f"-a always,exit -F path={path} -F perm=x -F auid>=1000 -F auid!=-1 {key}"]
    calls = ",".join(_safe_text(s, r"[a-z0-9_]{1,40}") for s in arg["syscalls"])
    variants = arg.get("filters", [["auid>=1000", "auid!=-1"]])
    lines = []
    for arch in arg.get("arches", ["b32", "b64"]):
        for variant in variants:
            filters = " ".join(
                ("-C " + _safe_text(f[2:], r"[A-Za-z0-9_<>=!&-]{1,40}")) if f.startswith("C:")
                else "-F " + _safe_text(f, r"[A-Za-z0-9_<>=!&-]{1,40}") for f in variant)
            lines.append(f"-a always,exit -F arch={_safe_text(arch, r'b(32|64)')} -S {calls} {filters} {key}")
    return lines


def _task(name: str, module: str, args: dict, sid: str, cat: str, **extra: Any) -> dict:
    t: dict[str, Any] = {"name": name, module: args}
    t.update(extra)
    t["tags"] = [sid, _TAG_CAT[cat], "stigwatch"]
    return t


def _scalar(v: Any) -> Any:
    if isinstance(v, (list, bool)) or v is None:
        raise Unsupported("no single scalar value")
    return v


def _linux_tasks(sid: str, rule: Rule, leaves: list[Leaf]) -> list[dict]:
    targets: dict[tuple, Cons] = {}
    for lf in leaves:
        key, fld = _linux_target(lf)
        targets.setdefault(key, Cons()).add(fld, lf.op, lf.arg)
    cat = rule.cat
    label = f"{sid} ({cat}): {_one_line(rule.title, 90).replace('{', '(').replace('}', ')')}"
    out: list[tuple[int, str, dict]] = []
    blocks = 0

    for key, cons in targets.items():
        kind = key[0]
        task: dict
        if kind == "pkg":
            name = _safe_text(key[1], r"[a-z0-9][a-z0-9.+-]{0,60}")
            vals = {repr(arg) for op, arg in cons.fields("installed") if op == "eq"}
            if vals == {"True"}:
                task = _task(label, "ansible.builtin.apt", {
                    "name": name, "state": "present", "update_cache": True,
                    "cache_valid_time": 3600}, sid, cat)
            elif vals == {"False"}:
                task = _task(label, "ansible.builtin.apt", {"name": name, "state": "absent"}, sid, cat)
            else:
                raise Unsupported("package state is not a single yes/no")
        elif kind == "unit":
            unit = _safe_text(key[1], r"[A-Za-z0-9@_.-]{1,80}\.(service|target|socket|timer)")
            args: dict[str, Any] = {"name": unit}
            for fld, op, arg in cons.entries:
                if fld == "file" and op == "eq" and arg in ("enabled", "disabled"):
                    args["enabled"] = arg == "enabled"
                elif fld == "active" and op == "eq" and arg == "active":
                    args["state"] = "started"
                elif fld == "active" and op == "ne" and arg == "active":
                    args["state"] = "stopped"
                    args["masked"] = True   # stopping alone would not survive a reboot
                elif fld == "load" and op == "eq" and arg == "masked":
                    args["masked"] = True
                else:
                    raise Unsupported(f"unit condition {fld} {op} {arg!r} has no safe change")
            task = _task(label, "ansible.builtin.systemd", args, sid, cat)
        elif kind == "sshd":
            v = cons.value()
            val = ",".join(map(str, v)) if isinstance(v, list) else v
            if val in ("", None) or isinstance(val, bool):
                raise Unsupported("no sshd value")
            val = _safe_text(val, r"[A-Za-z0-9_.,@:+/=-]{1,400}")
            # sshd keeps the first value it reads and Ubuntu's stock sshd_config includes
            # sshd_config.d at the top, so the value goes into a drop-in that sorts first.
            # The check also counts a second, different value as a finding, so active
            # copies of the directive in the main file and other drop-ins are commented out.
            out.append((_PRIO[kind], repr(key) + "0", _task(label, "ansible.builtin.lineinfile", {
                "path": _SSHD_DROPIN, "regexp": rf"(?i)^\s*{key[1]}\s", "line": f"{key[1]} {val}",
                "create": True, "owner": "root", "group": "root", "mode": "0644",
                "validate": "/usr/sbin/sshd -t -f %s"}, sid, cat, notify="Reload sshd")))
            task = _task(label, "ansible.builtin.replace", {
                "path": "{{ item }}", "regexp": rf"(?i)^{key[1]}\s.*$",
                "replace": r"# STIGWatch disabled: \g<0>", "validate": "/usr/sbin/sshd -t -f %s"},
                sid, cat, loop=_SSHD_FILES, notify="Reload sshd")
        elif kind == "sysctl":
            v = cons.value()
            if isinstance(v, list):
                if len(v) != 1:
                    raise Unsupported("several allowed sysctl values")
                v = v[0]
            if isinstance(v, bool) or not isinstance(v, (int, str)):
                raise Unsupported("sysctl value")
            task = _task(label, "ansible.posix.sysctl", {
                "name": _safe_text(key[1], r"[a-z0-9_.]{1,80}"), "value": str(v),
                "sysctl_file": "/etc/sysctl.d/99-zz-stigwatch.conf",
                "sysctl_set": True, "state": "present", "reload": True}, sid, cat)
        elif kind == "kv":
            path, style, _ = _KV_FILES[key[1]]
            k = key[2]
            v = _scalar(cons.value())
            if k == "space_left_percent":
                k, v = "space_left", f"{v}%"
            v = _safe_text(v, r"[A-Za-z0-9_.%+-]{1,60}")
            sep = {"space": " ", "equals": "=", "spaced_equals": " = "}[style]
            regexp = rf"^\s*#?\s*{k}\s*=" if style != "space" else rf"^\s*#?\s*{k}\b"
            task = _task(label, "ansible.builtin.lineinfile", {
                "path": path, "regexp": regexp, "line": f"{k}{sep}{v}"}, sid, cat,
                **({"notify": "Reload auditd configuration"} if key[1] == "auditd_conf" else {}))
        elif kind == "limits":
            n = cons.value()
            if not isinstance(n, int) or isinstance(n, bool) or n < 1:
                raise Unsupported("maxlogins value")
            task = _task(label, "ansible.builtin.lineinfile", {
                "path": "/etc/security/limits.conf",
                "regexp": r"^\s*#?\s*\*\s+hard\s+maxlogins\b", "line": f"* hard maxlogins {n}"},
                sid, cat)
        elif kind == "tmout":
            cap = Cons()
            for f, op, arg in cons.entries:
                if f == "max" and op == "le":
                    cap.add("v", op, arg)
            n = cap.value("v")
            if not isinstance(n, int) or isinstance(n, bool) or not 1 <= n <= 86400:
                raise Unsupported("TMOUT value")
            task = _task(label, "ansible.builtin.copy", {
                "dest": "/etc/profile.d/99-terminal_tmout.sh",
                "content": f"TMOUT={n}\nreadonly TMOUT\nexport TMOUT\n",
                "owner": "root", "group": "root", "mode": "0644"}, sid, cat)
        elif kind == "usb":
            task = _task(label, "ansible.builtin.copy", {
                "dest": "/etc/modprobe.d/stigwatch-usb-storage.conf",
                "content": "install usb-storage /bin/false\nblacklist usb-storage\n",
                "owner": "root", "group": "root", "mode": "0644"}, sid, cat)
        elif kind == "apt":
            fld = key[1]
            if fld == "allow_unauthenticated":
                path, k, extra = "/etc/apt/apt.conf.d/99-stigwatch", "APT::Get::AllowUnauthenticated", \
                    {"create": True, "mode": "0644"}
                expect = "false"
            else:
                path = "/etc/apt/apt.conf.d/50unattended-upgrades"
                k = "Unattended-Upgrade::" + ("Remove-Unused-Kernel-Packages" if "kernel" in fld
                                              else "Remove-Unused-Dependencies")
                extra, expect = {"create": True, "mode": "0644"}, "true"
            if cons.value() != expect:
                raise Unsupported("apt value")
            task = _task(label, "ansible.builtin.lineinfile", {
                "path": path, "regexp": rf"^\s*(//)?\s*{re.escape(k)}\b", "line": f'{k} "{expect}";',
                **extra}, sid, cat)
        elif kind == "file":
            args = {}
            for fld, op, arg in cons.entries:
                if fld == "mode" and op == "perm_le":
                    args["mode"] = _symbolic_mode(str(arg))
                elif fld == "mode" and op == "eq":
                    args["mode"] = "0" + _safe_text(arg, r"[0-7]{3,4}")
                elif fld == "user" and op == "eq":
                    args["owner"] = _safe_text(arg, r"[a-z_][a-z0-9_-]{0,31}")
                elif fld == "group" and op == "eq":
                    args["group"] = _safe_text(arg, r"[a-z_][a-z0-9_-]{0,31}")
                else:
                    raise Unsupported(f"file condition {fld} {op}")
            if key[1] == "audit_tools":
                task = _task(label, "ansible.builtin.file", {"path": "{{ item }}", **args}, sid, cat,
                             loop=[f"/sbin/{t}" for t in _AUDIT_TOOLS], register="stigwatch_file",
                             failed_when="stigwatch_file.failed and 'is absent' not in "
                                         "(stigwatch_file.msg | default(''))")
            else:
                task = _task(label, "ansible.builtin.file", {"path": key[1], **args}, sid, cat)
        elif kind == "audit":
            rule_arg = dict(next(a for _, op, a in cons.entries if op == "audit"))
            blocks += 1
            task = _task(label, "ansible.builtin.blockinfile", {
                "path": "/etc/audit/rules.d/99-stigwatch.rules",
                "marker": f"# {{mark}} STIGWatch {sid} #{blocks}",
                "block": "\n".join(_audit_lines(rule_arg)) + "\n", "create": True, "owner": "root",
                "group": "root", "mode": "0640"}, sid, cat, notify="Load audit rules")
        else:  # pragma: no cover - every target kind is handled above
            raise Unsupported("unknown target")
        out.append((_PRIO[kind], repr(key) + "1", task))
    out.sort(key=lambda t: (t[0], t[1]))
    return [t for _, _, t in out]


class _Dumper(yaml.SafeDumper):
    def increase_indent(self, flow: bool = False, indentless: bool = False) -> Any:
        return super().increase_indent(flow, False)   # indent sequences (ansible-lint wants it)


def _str_repr(dumper: yaml.SafeDumper, data: str) -> Any:
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


_Dumper.add_representer(str, _str_repr)


def _dump(data: Any) -> str:
    return yaml.dump(data, Dumper=_Dumper, sort_keys=False, default_flow_style=False,
                     width=100000, allow_unicode=False, indent=2)


@dataclass
class Plan:
    """What the generator decided for the open findings of one host."""
    automated: list[tuple[str, Rule, Any]] = field(default_factory=list)   # (id, rule, payload)
    manual: list[tuple[str, Rule | None, str]] = field(default_factory=list)  # (id, rule, why)


def _check_for(benchmark: Benchmark, sid: str) -> engine.Check | None:
    try:
        return engine.load_checks(benchmark.benchmark_id).checks.get(sid)
    except ValueError:
        return None


def plan(open_results: Any, benchmark: Benchmark, domain_role: str | None = None) -> Plan:
    """Split the open findings into generated fixes and manual ones. ``domain_role`` is the
    host's role from the scan (``dc``, ``member``, ``standalone``) when known."""
    build = _linux_build if _collector_name(benchmark.benchmark_id) == "linux" else _windows_build
    ops = _ops(benchmark)
    result = Plan()
    for sid, item in _item_ids(open_results, benchmark):
        rule = benchmark.rule(sid)
        try:
            if rule is None:
                raise Unsupported("the rule is not in this benchmark release")
            leaves = _plan_leaves(_check_for(benchmark, sid), item, ops)
            result.automated.append((sid, rule, build(sid, rule, leaves, _observed(item), domain_role)))
        except Unsupported as exc:
            result.manual.append((sid, rule, str(exc)))
    return result


def _manual_block(p: Plan, prefix: str = "# ") -> list[str]:
    bar = prefix + "=" * 74
    lines = [bar,
             prefix + "MANUAL: no safe automatic fix was derived for these findings. Each needs a",
             prefix + "decision or a change STIGWatch does not make for you. Fix text summary follows.",
             bar]
    if not p.manual:
        lines.append(prefix + "(none)")
    for sid, rule, why in p.manual:
        head = f"{sid} ({rule.cat if rule else 'CAT ?'}): {_title(rule, sid)}"
        for n, chunk in enumerate(textwrap.wrap(head, 110) or [head]):
            lines.append(prefix + ("  " if n else "") + chunk)
        lines.append(f"{prefix}  not automated: {_one_line(why, 100)}")
        for n, chunk in enumerate(textwrap.wrap("fix: " + _summary(rule), 105)):
            lines.append(prefix + "  " + ("  " if n else "") + chunk)
    return lines


def _linux_build(sid: str, rule: Rule, leaves: list[Leaf], obs: dict | None = None,
                 role: str | None = None) -> list[dict]:
    tasks = _linux_tasks(sid, rule, leaves)
    if not tasks:
        raise Unsupported("nothing to change")
    return tasks


def ansible_playbook(host: Any, open_results: Any, benchmark: Benchmark) -> str:
    p = plan(open_results, benchmark)
    tasks = [t for _, _, ts in p.automated for t in ts]
    # auditd refuses a manual stop (RefuseManualStop), so it is never restarted: rules are
    # loaded with augenrules and auditd.conf is re-read with SIGHUP.
    handlers = [
        {"name": "Reload sshd", "ansible.builtin.systemd": {"name": "ssh", "state": "reloaded"}},
        # With immutable rules (-e 2) the kernel refuses the load until a reboot. That is
        # reported, not treated as a failure of the whole run.
        {"name": "Load audit rules", "ansible.builtin.command": "augenrules --load",
         "register": "stigwatch_augenrules", "changed_when": True, "failed_when": False},
        {"name": "Report audit rules that need a reboot",
         "ansible.builtin.debug": {"msg": "augenrules could not load the rules (the audit "
                                          "configuration is immutable, -e 2, or the load failed). "
                                          "Reboot the host to activate them and check the output "
                                          "of augenrules --check."},
         "listen": "Load audit rules",
         "when": "stigwatch_augenrules is defined and stigwatch_augenrules.rc | default(0) != 0"},
        {"name": "Reload auditd configuration",
         "ansible.builtin.command": "systemctl kill -s SIGHUP auditd", "changed_when": True},
    ]
    # The play name and the hosts pattern are constants: nothing taken from a scan (a host
    # name, a comment) ever reaches a value Ansible templates. The host name is in a comment.
    play: dict[str, Any] = {
        "name": "STIGWatch remediation",
        "hosts": "{{ stigwatch_target }}", "become": True, "gather_facts": False,
    }
    if any("ansible.builtin.replace" in t for t in tasks):
        play["pre_tasks"] = [{
            "name": "Look for an Include of sshd_config.d/*.conf in sshd_config",
            "ansible.builtin.command": {
                "argv": ["grep", "-Eqi", r"^[[:space:]]*Include[[:space:]].*sshd_config\.d/\*\.conf",
                         "/etc/ssh/sshd_config"]},
            "register": "stigwatch_sshd_include", "changed_when": False, "failed_when": False,
            "check_mode": False, "tags": ["always"],
        }, {
            "name": "Require that sshd_config includes sshd_config.d/*.conf",
            "ansible.builtin.assert": {
                "that": ["stigwatch_sshd_include.rc == 0"],
                "fail_msg": "/etc/ssh/sshd_config has no Include of /etc/ssh/sshd_config.d/*.conf, "
                            "so the sshd settings this play writes to sshd_config.d/00-stigwatch.conf "
                            "would not take effect. Add that Include line (Ubuntu 22.04 ships it) "
                            "and run the play again.",
                "quiet": True},
            "tags": ["always"],
        }, {
            "name": "Find sshd drop-in files",
            "ansible.builtin.find": {"paths": "/etc/ssh/sshd_config.d", "patterns": "*.conf",
                                     "excludes": "00-stigwatch.conf"},
            "register": "stigwatch_sshd_dropins", "tags": ["always"],
        }]
    play["tasks"] = tasks or [{"name": "Nothing to change automatically",
                               "ansible.builtin.meta": "noop", "tags": ["stigwatch"]}]
    play["handlers"] = handlers
    head = [
        f"# {REVIEW_HEADER}",
        "# Generated by STIGWatch from open findings. STIGWatch never applies changes.",
        f"# Host: {_host_name(host)}    Benchmark: {_one_line(benchmark.title, 80)} {benchmark.label}",
        f"# {DISCLAIMER}",
        "# Run first with: ansible-playbook -i <inventory> -e stigwatch_target=<host-or-group> \\",
        "#   --check --diff this-file.yml   (stigwatch_target is required; the play fails if unset)",
        "# Needs the ansible.posix collection (sysctl): ansible-galaxy collection install ansible.posix",
        "# Select findings with --tags <STIG-ID>. sshd values go in sshd_config.d/00-stigwatch.conf",
        "# and active copies elsewhere are commented out. Audit rules: if the rules are",
        "# immutable (-e 2) a reboot is needed.",
        f"# Automated: {len(p.automated)}    Manual: {len(p.manual)}",
        "---",
    ]
    return "\n".join(head) + "\n" + _dump([play]) + "\n" + "\n".join(_manual_block(p)) + "\n"


def automated_ids(benchmark: Benchmark) -> list[str]:
    """STIG IDs of the benchmark whose fix can be generated when none of its conditions
    is known to be met (the case for a host that fails the rule completely)."""
    build = _linux_build if _collector_name(benchmark.benchmark_id) == "linux" else _windows_build
    ops = _ops(benchmark)
    out = []
    for r in benchmark.rules:
        try:
            build(r.stig_id, r, _plan_leaves(_check_for(benchmark, r.stig_id), None, ops), None, None)
        except Unsupported:
            continue
        out.append(r.stig_id)
    return out


# =========================================================================== Windows / PowerShell

_AUDIT_SUFFIX = "-69AE-11D9-BED3-505054503030}"
_SECEDIT_ACCESS = {
    "LockoutBadCount", "ResetLockoutCount", "LockoutDuration", "PasswordHistorySize",
    "MaximumPasswordAge", "MinimumPasswordAge", "MinimumPasswordLength", "PasswordComplexity",
    "ClearTextPassword", "EnableGuestAccount", "LSAAnonymousNameLookup",
}
# Rights whose change can lock administrators out of the host: left to a person.
_RIGHTS_LOCKOUT = {"SeNetworkLogonRight", "SeInteractiveLogonRight", "SeRemoteInteractiveLogonRight",
                   "SeDenyNetworkLogonRight", "SeDenyInteractiveLogonRight",
                   "SeDenyRemoteInteractiveLogonRight", "SeBatchLogonRight", "SeServiceLogonRight"}
# Registry values that decide who or what may connect or authenticate. A wrong value can lock
# an administrator, a service or a domain trust out, so these run only with -IncludeAccessChanges.
_ACCESS_VALUES = {
    "LocalAccountTokenFilterPolicy", "FilterAdministratorToken", "LDAPServerIntegrity",
    "LDAPClientIntegrity", "RequireSecuritySignature", "EnableSecuritySignature",
    "RequireSignOrSeal", "SealSecureChannel", "SignSecureChannel", "RequireStrongKey",
    "LmCompatibilityLevel", "NTLMMinClientSec", "NTLMMinServerSec", "RestrictAnonymous",
    "RestrictAnonymousSAM", "RestrictNullSessAccess", "RestrictRemoteSAM", "RestrictRemoteClients",
    "allownullsessionfallback", "AllowBasic", "AllowUnencryptedTraffic", "AllowDigest",
    "DisableRunAs", "SupportedEncryptionTypes", "EnableLUA", "ConsentPromptBehaviorAdmin",
    "ConsentPromptBehaviorUser", "EnableInstallerDetection", "EnableSecureUIAPaths",
    "EnableVirtualization", "LimitBlankPasswordUse", "UseMachineId", "AllowOnlineID",
    "EveryoneIncludesAnonymous", "NoLMHash", "MinEncryptionLevel", "fEncryptRPCTraffic",
    "SMB1", "Start", "RefusePasswordChange", "DisablePasswordChange", "MaximumPasswordAge",
    "AllowInsecureGuestAuth", "EnableUIADesktopToggle", "InactivityTimeoutSecs",
    "DisableAutomaticRestartSignOn", "CachedLogonsCount", "scremoveoption",
}
_REG_TYPE_WORDS = {"DWord": "REG_DWORD", "String": "REG_SZ"}


def _audit_guids() -> dict[str, str]:
    """Audit subcategory name -> GUID. The collector keeps the GUID prefix of each
    subcategory it reads (``{0CCE923F``); the rest of the GUID is the same for all of them."""
    table = next((v for v in vars(windows_facts).values()
                  if isinstance(v, dict) and "{0CCE923F" in v), {})
    return {name: prefix + _AUDIT_SUFFIX for prefix, name in table.items()}


def _ps_quote(value: Any) -> str:
    """A PowerShell single-quoted string. PowerShell also treats the typographic single
    quotes as quotes, so only printable ASCII is accepted and ``'`` is doubled."""
    s = str(value)
    if not re.fullmatch(r"[\x20-\x7e]*", s):
        raise Unsupported("value is not printable ASCII")
    return "'" + s.replace("'", "''") + "'"


def _win_target(leaf: Leaf) -> tuple[tuple, str]:
    p = leaf.path
    head, n = p[0], len(p)
    if head == "registry" and n == 4 and p[3] in ("value", "number"):
        key = p[1]
        if not key.startswith("HKLM\\") or re.search(r"[\[\]*?]", key) or re.search(r"[\[\]*?]", p[2]):
            raise Unsupported("registry value is outside HKLM or has wildcard characters")
        return ("reg", key, p[2], p[3]), "v"
    if head == "security_policy" and n == 3 and p[1] == "system_access" and p[2] in _SECEDIT_ACCESS:
        return ("sec", p[2]), "v"
    if head == "user_rights" and n == 2 and re.fullmatch(r"Se[A-Za-z]+", p[1]):
        if p[1] in _RIGHTS_LOCKOUT:
            raise Unsupported(f"{p[1]} can lock administrators out; change it by hand")
        if leaf.op not in ("empty", "subset"):
            raise Unsupported(f"{p[1]} {leaf.op}: the principals to add are the assessor's choice")
        return ("right", p[1]), "v"
    if head == "audit_policy" and n == 3 and p[2] in ("success", "failure") and leaf.op == "eq" \
            and leaf.arg is True and p[1] in _audit_guids():
        return ("audit", p[1]), p[2]
    if head == "features" and n == 2 and leaf.op == "in" and isinstance(leaf.arg, list) \
            and set(leaf.arg) <= {"Available", "Removed"}:
        return ("feature", p[1]), "v"
    raise Unsupported(f"{engine.show_path(p)} {leaf.op} has no safe automatic change")


_SID_RE = re.compile(r"S-1-[0-9]+(-[0-9]+)+")
_ORG_SID_RE = re.compile(r"S-1-5-(21|80|82)-")


def _windows_steps(sid: str, rule: Rule, leaves: list[Leaf], obs: dict | None = None,
                   role: str | None = None) -> list[str]:
    targets: dict[tuple, Cons] = {}
    for lf in leaves:
        key, fld = _win_target(lf)
        targets.setdefault(key, Cons()).add(fld, lf.op, lf.arg)
    steps: list[tuple[int, str, str]] = []
    sec_access: list[str] = []
    rights: list[str] = []
    audits: dict[str, set[str]] = {}
    for key, cons in targets.items():
        kind = key[0]
        if kind == "reg":
            _, regkey, name, fld = key
            v = cons.value()
            if fld == "number":
                if isinstance(v, bool) or not isinstance(v, int):
                    raise Unsupported("registry number")
                v, rtype = str(v), "String"
            elif isinstance(v, (bool, list)):
                raise Unsupported("registry value type")
            elif isinstance(v, int):
                if not 0 <= v <= 0xFFFFFFFF:
                    raise Unsupported("DWord out of range")
                rtype = "DWord"
            else:
                rtype = "String"
            seen = set(re.findall(r"REG_[A-Z_]+", rule.fix_text))
            if seen and _REG_TYPE_WORDS[rtype] not in seen:
                raise Unsupported(f"the fix text names {', '.join(sorted(seen))}, not {_REG_TYPE_WORDS[rtype]}")
            ps_path = "HKLM:" + regkey[len("HKLM"):]
            val = str(v) if rtype == "DWord" else _ps_quote(v)
            line = (f"    Set-StigRegistryValue -StigId {_ps_quote(sid)} "
                    f"-Path {_ps_quote(ps_path)} -Name {_ps_quote(name)} -Value {val} -Type {rtype}")
            if name in _ACCESS_VALUES:
                line = ("    # WARNING: this can change who or what may connect or sign in; it runs only "
                        "with -IncludeAccessChanges.\n" + line + " -AccessChange")
            steps.append((1, regkey + "\\" + name, line))
        elif kind == "sec":
            v = cons.value()
            if isinstance(v, bool) or not isinstance(v, int):
                raise Unsupported("account policy value")
            sec_access.append(f"{key[1]} = {v}")
        elif kind == "right":
            # Never replace a list wholesale: keep the principals that are both present and
            # allowed, so the change can only remove access, never add any.
            if role == "dc":
                raise Unsupported("domain controller: user rights are managed by Group Policy, by hand")
            fields = cons.fields("v")
            if any(op == "empty" and arg is not True for op, arg in fields):
                raise Unsupported("user right with a negated condition")
            allowed = cons.value() if any(op == "subset" for op, _ in fields) else []
            keep: list[str] = []
            if obs is None:
                raise Unsupported("the current principals of this right are not known")
            if obs is not None:
                current = obs.get(engine.show_path(("user_rights", key[1])))
                if not isinstance(current, list) or not all(
                        isinstance(x, str) and _SID_RE.fullmatch(x) for x in current):
                    raise Unsupported("the current principals of this right are not known")
                excess = [x for x in current if x not in allowed]
                if any(_ORG_SID_RE.match(x) for x in excess):
                    raise Unsupported("the excess includes domain, service or virtual-account SIDs; "
                                      "review who holds the right first")
                keep = [x for x in current if x in allowed]
            rights.append(f"{key[1]} = {','.join('*' + x for x in keep)}")
        elif kind == "audit":
            audits.setdefault(key[1], set()).update(f for f, _, _ in cons.entries)
        elif kind == "feature":
            name = _safe_text(key[1], r"[A-Za-z0-9._-]{1,60}")
            steps.append((3, name, f"    Remove-StigWindowsFeature -StigId {_ps_quote(sid)} -Name {_ps_quote(name)}"))
        else:  # pragma: no cover
            raise Unsupported("unknown target")
    guids = _audit_guids()
    for sub in sorted(audits):
        s = "$true" if "success" in audits[sub] else "$false"
        f = "$true" if "failure" in audits[sub] else "$false"
        steps.append((2, sub, f"    Set-StigAuditPolicy -StigId {_ps_quote(sid)} -Subcategory {_ps_quote(sub)} "
                      f"-Guid {_ps_quote(guids[sub])} -Success {s} -Failure {f}"))
    if sec_access:
        body = ", ".join(_ps_quote(line) for line in sorted(sec_access))
        steps.append((0, "sec", f"    Invoke-StigSecedit -StigId {_ps_quote(sid)} -Area 'SECURITYPOLICY' "
                      f"-Section 'System Access' -Lines @({body})"))
    if rights:
        body = ", ".join(_ps_quote(line) for line in sorted(rights))
        steps.append((0, "right", f"    Invoke-StigSecedit -StigId {_ps_quote(sid)} -Area 'USER_RIGHTS' "
                      f"-Section 'Privilege Rights' -Lines @({body}) -AccessChange"))
    steps.sort(key=lambda t: (t[0], t[1]))
    return [s for _, _, s in steps]


def _fn_name(sid: str) -> str:
    return "Repair-" + sid


def _windows_build(sid: str, rule: Rule, leaves: list[Leaf], obs: dict | None = None,
                   role: str | None = None) -> str:
    steps = _windows_steps(sid, rule, leaves, obs, role)
    if not steps:
        raise Unsupported("nothing to change")
    return "\n".join([
        f"# {sid} ({rule.cat}): {_title(rule, sid)}",
        f"function {_fn_name(sid)} {{",
        "    [CmdletBinding(SupportsShouldProcess = $true)]",
        "    param()",
        *steps,
        "}",
    ])


_PS_HELPERS = r'''
function Set-StigRegistryValue {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$StigId,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][ValidateSet('DWord', 'String')][string]$Type,
        [switch]$AccessChange
    )
    $target = "$Path\$Name"
    if ($AccessChange -and -not $IncludeAccessChanges) {
        Write-Warning "$StigId skipped: $target changes who or what may connect. Review it, then re-run with -IncludeAccessChanges."
        return
    }
    if ($PSCmdlet.ShouldProcess($target, "$StigId set $Type value to $Value")) {
        if (-not (Test-Path -LiteralPath $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        $data = $Value
        if ($Type -eq 'DWord' -and ([uint64]$Value) -gt 2147483647) {
            $data = [BitConverter]::ToInt32([BitConverter]::GetBytes([uint32]$Value), 0)
        }
        Set-ItemProperty -LiteralPath $Path -Name $Name -Value $data -Type $Type
        Write-Output "CHANGED $StigId $target = $Value ($Type)"
    }
}

function Invoke-StigSecedit {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$StigId,
        [Parameter(Mandatory = $true)][ValidateSet('SECURITYPOLICY', 'USER_RIGHTS')][string]$Area,
        [Parameter(Mandatory = $true)][string]$Section,
        [Parameter(Mandatory = $true)][string[]]$Lines,
        [switch]$AccessChange
    )
    if ($AccessChange -and -not $IncludeAccessChanges) {
        Write-Warning "$StigId skipped: $Section changes who may connect or sign in. Review it, then re-run with -IncludeAccessChanges."
        return
    }
    $inf = @('[Unicode]', 'Unicode=yes', '[Version]', 'signature="$CHICAGO$"', 'Revision=1', "[$Section]") + $Lines
    if ($PSCmdlet.ShouldProcess("local security policy ($Area)", "$StigId secedit /configure: $($Lines -join '; ')")) {
        $work = Join-Path ([System.IO.Path]::GetTempPath()) ('stigwatch-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $work | Out-Null
        try {
            $infPath = Join-Path $work 'stigwatch.inf'
            $dbPath = Join-Path $work 'stigwatch.sdb'
            Set-Content -LiteralPath $infPath -Value ($inf -join "`r`n") -Encoding Unicode
            & secedit.exe /configure /db $dbPath /cfg $infPath /areas $Area /quiet
            if ($LASTEXITCODE -ne 0) { throw "secedit.exe exited with code $LASTEXITCODE" }
            Write-Output "CHANGED $StigId secedit $Area : $($Lines -join '; ')"
        }
        finally {
            Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Set-StigAuditPolicy {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$StigId,
        [Parameter(Mandatory = $true)][string]$Subcategory,
        [Parameter(Mandatory = $true)][string]$Guid,
        [bool]$Success = $false,
        [bool]$Failure = $false
    )
    $arguments = @('/set', "/subcategory:$Guid")
    if ($Success) { $arguments += '/success:enable' }
    if ($Failure) { $arguments += '/failure:enable' }
    if ($PSCmdlet.ShouldProcess("audit subcategory $Subcategory $Guid", "$StigId auditpol $($arguments -join ' ')")) {
        & auditpol.exe @arguments | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "auditpol.exe exited with code $LASTEXITCODE" }
        Write-Output "CHANGED $StigId auditpol $($arguments -join ' ')"
    }
}

function Remove-StigWindowsFeature {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$StigId,
        [Parameter(Mandatory = $true)][string]$Name
    )
    if ($PSCmdlet.ShouldProcess($Name, "$StigId Uninstall-WindowsFeature (a restart may be needed)")) {
        if (-not (Get-Command -Name Uninstall-WindowsFeature -ErrorAction SilentlyContinue)) {
            throw 'Uninstall-WindowsFeature is not available on this host.'
        }
        Uninstall-WindowsFeature -Name $Name | Out-Null
        Write-Output "CHANGED $StigId feature $Name removed"
    }
}
'''.strip("\n")


def powershell_script(host: Any, open_results: Any, benchmark: Benchmark,
                      domain_role: str | None = None) -> str:
    role = domain_role or (None if isinstance(host, str) else _get(host, "domain_role"))
    p = plan(open_results, benchmark, role)
    names = [_fn_name(sid) for sid, _, _ in p.automated]
    head = [
        "<#",
        ".SYNOPSIS",
        "    STIGWatch remediation for " + _host_name(host) + ".",
        ".DESCRIPTION",
        "    " + REVIEW_HEADER,
        "    Generated by STIGWatch from open findings. STIGWatch never applies changes.",
        f"    Benchmark: {_block_safe(_one_line(benchmark.title, 80))} {_block_safe(benchmark.label)}",
        "    " + DISCLAIMER,
        "    Dry run by default: nothing changes unless -Apply is given. Run as Administrator.",
        f"    Automated: {len(p.automated)}    Manual: {len(p.manual)}",
        ".PARAMETER IncludeAccessChanges",
        "    Also apply changes that can alter who or what may connect or sign in (SMB/LDAP signing,",
        "    NTLM level, UAC remote filtering, WinRM, user rights). Off by default; review first.",
        ".PARAMETER Apply",
        "    Make the changes. Without it every change is only reported (-WhatIf behaviour).",
        "#>",
        "[CmdletBinding(SupportsShouldProcess = $true)]",
        "param(",
        "    [switch]$Apply,",
        "    [switch]$IncludeAccessChanges",
        ")",
        "",
        "Set-StrictMode -Version Latest",
        "$ErrorActionPreference = 'Stop'",
        "",
        "if (-not $Apply) {",
        "    $WhatIfPreference = $true",
        "    Write-Output 'DRY RUN: no change will be made. Re-run with -Apply after review.'",
        "}",
        "else {",
        "    $principal = New-Object System.Security.Principal.WindowsPrincipal("
        "[System.Security.Principal.WindowsIdentity]::GetCurrent())",
        "    if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {",
        "        throw 'Run this script from an elevated PowerShell session to use -Apply.'",
        "    }",
        "}",
        "",
        "$transcript = Join-Path ([System.IO.Path]::GetTempPath()) "
        "('stigwatch-remediation-{0:yyyyMMdd-HHmmss}.log' -f (Get-Date))",
        "Start-Transcript -Path $transcript -WhatIf:$false | Out-Null",
        "",
        _PS_HELPERS,
        "",
    ]
    body: list[str] = []
    for _, _, fn in p.automated:
        body.extend([fn, ""])
    tail = [
        "$failed = 0",
        "try {",
        "    $steps = @(" + ", ".join(_ps_quote(n) for n in names) + ")",
        "    foreach ($step in $steps) {",
        "        try {",
        "            & $step",
        "        }",
        "        catch {",
        "            $failed++",
        "            Write-Warning \"$step failed: $($_.Exception.Message)\"",
        "        }",
        "    }",
        "}",
        "finally {",
        "    Stop-Transcript | Out-Null",
        "}",
        "if ($failed -gt 0) { exit 1 }",
        "",
    ]
    return "\n".join(head + body + tail + _manual_block(p)) + "\n"
