"""DISA benchmark catalog: XCCDF parsing, JSON catalog loading and integrity checks.

XCCDF input is untrusted: it is parsed with defusedxml (DTDs and entities refused), read
straight from the zip (nothing is extracted to disk) and size-limited.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from defusedxml import ElementTree as SafeET

SCHEMA_VERSION = 1
SEVERITIES = ("high", "medium", "low")
CAT_LABELS = {"high": "CAT I", "medium": "CAT II", "low": "CAT III"}
CCI_SYSTEM = "http://cyber.mil/cci"
MAX_XCCDF_BYTES = 64 * 1024 * 1024
MAX_ZIP_BYTES = 256 * 1024 * 1024

BUNDLED_DIR = Path(__file__).resolve().parent.parent / "data" / "benchmarks"

# Stable benchmark keys used across the app, keyed by the DISA XCCDF Benchmark@id.
KNOWN_BENCHMARK_IDS = {
    "CAN_Ubuntu_22-04_LTS_STIG": "ubuntu-22.04",
    "MS_Windows_Server_2022_STIG": "windows-server-2022",
}

RULE_FIELDS = (
    "group_id", "rule_id", "stig_id", "severity", "title", "discussion",
    "check_text", "fix_text", "ccis",
)
TOP_FIELDS = (
    "benchmark_id", "title", "version", "release", "date", "source_url", "rules",
)
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


class BenchmarkError(Exception):
    """Raised for unreadable, malformed or inconsistent benchmark data."""


@dataclass(frozen=True)
class Rule:
    group_id: str
    rule_id: str
    stig_id: str
    severity: str
    title: str
    discussion: str
    check_text: str
    fix_text: str
    ccis: tuple[str, ...] = ()
    ia_controls: str = ""

    @property
    def cat(self) -> str:
        return CAT_LABELS[self.severity]


@dataclass
class Benchmark:
    benchmark_id: str
    title: str
    version: str
    release: str
    date: str
    source_url: str
    rules: list[Rule]
    metadata_only: bool = False
    data: dict[str, Any] = field(default_factory=dict, repr=False)

    def rule(self, stig_id: str) -> Rule | None:
        return self._index().get(stig_id)

    def _index(self) -> dict[str, Rule]:
        idx = getattr(self, "_idx", None)
        if idx is None:
            idx = {r.stig_id: r for r in self.rules}
            self._idx = idx
        return idx

    def counts(self) -> dict[str, int]:
        c = {s: 0 for s in SEVERITIES}
        for r in self.rules:
            c[r.severity] += 1
        return c

    @property
    def label(self) -> str:
        return f"V{self.version}R{self.release}"


# --------------------------------------------------------------------------- XCCDF parsing

def _local(tag: Any) -> str:
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def _children(el: Any, name: str) -> list[Any]:
    return [c for c in el if _local(c.tag) == name]


def _child(el: Any, name: str) -> Any | None:
    for c in el:
        if _local(c.tag) == name:
            return c
    return None


def _text(el: Any | None) -> str:
    """All text of an element (including nested markup text), normalised."""
    if el is None:
        return ""
    return _clean("".join(el.itertext()))


def _clean(s: str) -> str:
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    return "\n".join(line.rstrip() for line in s.split("\n")).strip()


def _embedded(description: Any | None) -> dict[str, str]:
    """Unescape the DISA description (escaped <VulnDiscussion>...</IAControls> markup)."""
    raw = description.text if description is not None and description.text else ""
    if not raw.strip():
        return {}
    try:
        root = SafeET.fromstring(f"<d>{raw}</d>", forbid_dtd=True)
    except Exception as exc:  # defusedxml raises several types for refused constructs
        raise BenchmarkError(f"rule description is not well-formed embedded XML: {exc}") from exc
    return {_local(c.tag): _text(c) for c in root}


def parse_release_info(text: str) -> tuple[str, str]:
    """'Release: 10 Benchmark Date: 30 Sep 2026' -> ('10', '2026-09-30')."""
    m = re.search(r"Release:\s*(\d+)\s+Benchmark Date:\s*(\d{1,2} [A-Za-z]{3} \d{4})", text or "")
    if not m:
        raise BenchmarkError(f"unrecognised release-info: {text!r}")
    try:
        date = datetime.strptime(m.group(2), "%d %b %Y").date().isoformat()
    except ValueError as exc:
        raise BenchmarkError(f"bad benchmark date in release-info: {text!r}") from exc
    return m.group(1), date


def slugify_benchmark_id(xccdf_id: str) -> str:
    known = KNOWN_BENCHMARK_IDS.get(xccdf_id)
    if known:
        return known
    slug = re.sub(r"[^a-z0-9._-]+", "-", xccdf_id.lower()).strip("-.")[:64]
    if not _ID_RE.match(slug):
        raise BenchmarkError(f"cannot derive a benchmark id from {xccdf_id!r}")
    return slug


def parse_xccdf(xml_bytes: bytes, source_url: str = "") -> dict[str, Any]:
    """Parse DISA XCCDF bytes into the catalog dict."""
    try:
        root = SafeET.fromstring(xml_bytes, forbid_dtd=True)
    except Exception as exc:
        raise BenchmarkError(f"XCCDF is not safe, well-formed XML: {exc}") from exc
    if _local(root.tag) != "Benchmark":
        raise BenchmarkError("root element is not an XCCDF Benchmark")
    xccdf_id = root.get("id") or ""
    title = _text(_child(root, "title"))
    version = _text(_child(root, "version"))
    release = date = ""
    for pt in _children(root, "plain-text"):
        if pt.get("id") == "release-info":
            release, date = parse_release_info(_text(pt))
    if not (xccdf_id and title and version and release):
        raise BenchmarkError("Benchmark is missing id, title, version or release-info")
    status = _child(root, "status")
    rules: list[dict[str, Any]] = []
    for group in _children(root, "Group"):
        for rule in _children(group, "Rule"):
            sev = rule.get("severity") or ""
            if sev not in SEVERITIES:
                raise BenchmarkError(f"rule {rule.get('id')!r} has unsupported severity {sev!r}")
            emb = _embedded(_child(rule, "description"))
            check = _child(rule, "check")
            ccis = [
                _text(i) for i in _children(rule, "ident") if i.get("system") == CCI_SYSTEM
            ]
            entry: dict[str, Any] = {
                "group_id": group.get("id") or "",
                "rule_id": rule.get("id") or "",
                "stig_id": _text(_child(rule, "version")),
                "severity": sev,
                "title": _text(_child(rule, "title")),
                "discussion": emb.get("VulnDiscussion", ""),
                "check_text": _text(_child(check, "check-content")) if check is not None else "",
                "fix_text": _text(_child(rule, "fixtext")),
                "ccis": ccis,
            }
            if emb.get("IAControls"):
                entry["ia_controls"] = emb["IAControls"]
            rules.append(entry)
    return {
        "schema": SCHEMA_VERSION,
        "benchmark_id": slugify_benchmark_id(xccdf_id),
        "xccdf_id": xccdf_id,
        "title": title,
        "version": version,
        "release": release,
        "date": date,
        "status_date": status.get("date", "") if status is not None else "",
        "source_url": source_url,
        "metadata_only": False,
        "counts": {s: sum(1 for r in rules if r["severity"] == s) for s in SEVERITIES},
        "rules": rules,
    }


def read_xccdf_from_zip(zip_path: Path) -> tuple[bytes, str]:
    """Return (xccdf bytes, sha256 of the zip). Never extracts to disk."""
    zip_path = Path(zip_path)
    if not zip_path.is_file():
        raise BenchmarkError(f"not a file: {zip_path}")
    if zip_path.stat().st_size > MAX_ZIP_BYTES:
        raise BenchmarkError("zip is too large")
    digest = hashlib.sha256(zip_path.read_bytes()).hexdigest()
    try:
        with zipfile.ZipFile(zip_path) as zf:
            members = [
                i for i in zf.infolist()
                if not i.is_dir() and i.filename.lower().endswith("xccdf.xml")
            ]
            if len(members) != 1:
                raise BenchmarkError(
                    f"expected exactly one *xccdf.xml in the zip, found {len(members)}"
                )
            info = members[0]
            if info.file_size > MAX_XCCDF_BYTES:
                raise BenchmarkError("XCCDF member is too large")
            with zf.open(info) as fh:
                blob = fh.read(MAX_XCCDF_BYTES + 1)
            if len(blob) > MAX_XCCDF_BYTES:
                raise BenchmarkError("XCCDF member is too large")
    except zipfile.BadZipFile as exc:
        raise BenchmarkError(f"not a valid zip file: {zip_path}") from exc
    return blob, digest


def build_from_zip(zip_path: Path, source_url: str = "") -> dict[str, Any]:
    blob, digest = read_xccdf_from_zip(zip_path)
    data = parse_xccdf(blob, source_url=source_url)
    data["source_sha256"] = digest
    errors = validate_data(data)
    if errors:
        raise BenchmarkError("; ".join(errors[:5]))
    return data


def dumps(data: dict[str, Any]) -> str:
    """Deterministic serialisation used for committed catalog files."""
    return json.dumps(data, indent=1, ensure_ascii=False) + "\n"


# --------------------------------------------------------------------------- validation

def validate_data(data: Any) -> list[str]:
    """Integrity checks; returns a list of problems (empty = ok)."""
    if not isinstance(data, dict):
        return ["catalog is not a JSON object"]
    errs: list[str] = []
    for f in TOP_FIELDS:
        if f not in data:
            errs.append(f"missing field {f!r}")
    if errs:
        return errs
    if not isinstance(data["benchmark_id"], str) or not _ID_RE.match(data["benchmark_id"]):
        errs.append("invalid benchmark_id")
    for f in ("title", "version", "release", "date"):
        if not isinstance(data[f], str) or not data[f]:
            errs.append(f"empty {f}")
    rules = data["rules"]
    if not isinstance(rules, list) or not rules:
        return errs + ["rules must be a non-empty list"]
    metadata_only = bool(data.get("metadata_only", False))
    seen: dict[str, set[str]] = {"group_id": set(), "rule_id": set(), "stig_id": set()}
    counts = {s: 0 for s in SEVERITIES}
    for i, r in enumerate(rules):
        where = f"rule[{i}]"
        if not isinstance(r, dict):
            errs.append(f"{where} is not an object")
            continue
        missing = [f for f in RULE_FIELDS if f not in r]
        if missing:
            errs.append(f"{where} missing {missing}")
            continue
        where = f"rule {r['stig_id'] or i}"
        for f in ("group_id", "rule_id", "stig_id", "title"):
            if not isinstance(r[f], str) or not r[f]:
                errs.append(f"{where}: empty {f}")
            elif f in seen:
                if r[f] in seen[f]:
                    errs.append(f"duplicate {f} {r[f]!r}")
                seen[f].add(r[f])
        if r["severity"] in counts:
            counts[r["severity"]] += 1
        else:
            errs.append(f"{where}: bad severity {r['severity']!r}")
        if not metadata_only:
            for f in ("check_text", "fix_text"):
                if not isinstance(r[f], str) or not r[f].strip():
                    errs.append(f"{where}: empty {f}")
        if not isinstance(r["ccis"], list) or not all(
            isinstance(c, str) and re.fullmatch(r"CCI-\d{6}", c) for c in r["ccis"]
        ):
            errs.append(f"{where}: malformed ccis")
    recorded = data.get("counts")
    if not isinstance(recorded, dict) or any(recorded.get(s) != counts[s] for s in SEVERITIES):
        errs.append(f"recorded counts {recorded!r} do not match rules {counts!r}")
    return errs


def _to_benchmark(data: dict[str, Any]) -> Benchmark:
    rules = [
        Rule(
            group_id=r["group_id"], rule_id=r["rule_id"], stig_id=r["stig_id"],
            severity=r["severity"], title=r["title"], discussion=r["discussion"],
            check_text=r["check_text"], fix_text=r["fix_text"], ccis=tuple(r["ccis"]),
            ia_controls=r.get("ia_controls", ""),
        )
        for r in data["rules"]
    ]
    return Benchmark(
        benchmark_id=data["benchmark_id"], title=data["title"], version=data["version"],
        release=data["release"], date=data["date"], source_url=data["source_url"],
        rules=rules, metadata_only=bool(data.get("metadata_only", False)), data=data,
    )


# --------------------------------------------------------------------------- catalog access

def user_dir() -> Path:
    """Directory for locally imported benchmarks (STIGWATCH_DATA_DIR, else ~/.stigwatch)."""
    base = os.environ.get("STIGWATCH_DATA_DIR")
    root = Path(base) if base else Path.home() / ".stigwatch"
    return root / "benchmarks"


def _search_dirs() -> list[Path]:
    return [user_dir(), BUNDLED_DIR]


def list_benchmarks() -> list[str]:
    """Benchmark ids available (imported ones override bundled ones with the same id)."""
    ids: set[str] = set()
    for d in _search_dirs():
        if d.is_dir():
            ids.update(p.stem for p in d.glob("*.json") if _ID_RE.match(p.stem))
    return sorted(ids)


def load_benchmark(benchmark_id: str) -> Benchmark:
    if not isinstance(benchmark_id, str) or not _ID_RE.match(benchmark_id):
        raise BenchmarkError(f"invalid benchmark id {benchmark_id!r}")
    for d in _search_dirs():
        path = d / f"{benchmark_id}.json"
        if path.is_file():
            return load_benchmark_file(path)
    raise BenchmarkError(f"unknown benchmark {benchmark_id!r}")


def load_benchmark_file(path: Path) -> Benchmark:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise BenchmarkError(f"cannot read {path}: {exc}") from exc
    errs = validate_data(data)
    if errs:
        raise BenchmarkError(f"{path}: " + "; ".join(errs[:5]))
    return _to_benchmark(data)


def summary_line(b: Benchmark) -> str:
    c = b.counts()
    return (
        f"{b.benchmark_id} {b.label}: {len(b.rules)} rules "
        f"(CAT I {c['high']}, CAT II {c['medium']}, CAT III {c['low']})"
    )


def check_directory(directory: Path = BUNDLED_DIR) -> tuple[list[str], list[str]]:
    """Validate every catalog file in a directory -> (summary lines, problems)."""
    lines: list[str] = []
    problems: list[str] = []
    files = sorted(Path(directory).glob("*.json"))
    if not files:
        problems.append(f"no benchmark files in {directory}")
    for p in files:
        try:
            b = load_benchmark_file(p)
        except BenchmarkError as exc:
            problems.append(str(exc))
            continue
        if p.stem != b.benchmark_id:
            problems.append(f"{p.name}: file name does not match benchmark_id {b.benchmark_id!r}")
        lines.append(summary_line(b))
    return lines, problems


def import_zip(zip_path: Path, out_dir: Path | None = None, source_url: str = "") -> Path:
    """Parse a DISA STIG zip and write <benchmark_id>.json into out_dir (default: user dir)."""
    data = build_from_zip(Path(zip_path), source_url=source_url)
    out = Path(out_dir) if out_dir else user_dir()
    out.mkdir(parents=True, exist_ok=True)
    target = out / f"{data['benchmark_id']}.json"
    target.write_text(dumps(data), encoding="utf-8", newline="\n")
    return target
