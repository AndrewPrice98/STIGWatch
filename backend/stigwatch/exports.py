"""Checklist (.ckl, .cklb) and fleet report exports.

``ckl`` writes a STIG Viewer 2 checklist (XML) and ``cklb`` a STIG Viewer 3 checklist (JSON),
each with every rule of the benchmark. Their layouts follow the published samples recorded in
DECISIONS.md (section 3 and 4). ``fleet_csv`` and ``fleet_report_html`` summarise the fleet;
the report is one self-contained, printable HTML file with no scripts.

Everything exported from a host or a comment is untrusted: XML is built with ElementTree (so
it is escaped) after characters XML 1.0 forbids are removed; the HTML escapes every value; CSV
cells that a spreadsheet would read as a formula are neutralised. Output is deterministic:
identifiers are UUIDv5 over host, benchmark and rule, and timestamps are the scan's own.

Statuses are STIGWatch's own (Open, NotAFinding, Not_Applicable, Not_Reviewed), which are the
``.ckl`` vocabulary; ``.cklb`` uses the lower-case spelling.
"""

from __future__ import annotations

import csv
import html
import io
import json
import re
import sqlite3
import uuid
import xml.etree.ElementTree as ET
from typing import Any, Callable

from . import benchmarks, db, remediation
from .benchmarks import Benchmark

DISCLAIMER = ("STIGWatch is an independent tool. It is not a DISA product and does not "
              "replace the SCAP Compliance Checker, Evaluate-STIG or an assessor's review.")

CKL_STATUSES = ("Open", "NotAFinding", "Not_Applicable", "Not_Reviewed")
CKLB_STATUS = {"Open": "open", "NotAFinding": "not_a_finding",
               "Not_Applicable": "not_applicable", "Not_Reviewed": "not_reviewed"}
SEVERITY_WEIGHT = "10.0"
NAMESPACE = uuid.UUID("5d3c2c1e-6b0a-4a52-9a43-0c1d6a7e5a10")   # fixed: ids must be stable
MAX_HOST_NAME = 255
MAX_DETAIL = 6000
MAX_VALUE = 400
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_XML_BAD = re.compile("[^\u0009\u000a\u000d -퟿-�\U00010000-\U0010ffff]")
_FORMULA = ("=", "+", "-", "@", "\t", "\r")
CATS = ("CAT I", "CAT II", "CAT III")


# --------------------------------------------------------------------------- text helpers

def clean_text(value: Any, limit: int | None = None) -> str:
    """Text that XML 1.0 can carry: forbidden control characters and lone surrogates are
    dropped, line endings are normalised, and the length is capped."""
    s = "" if value is None else str(value)
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    s = _XML_BAD.sub("", s)
    if limit is not None and len(s) > limit:
        s = s[: limit - 3] + "..."
    return s


def safe_filename(name: Any, ext: str, *, stamp: str = "") -> str:
    """A file name for a download: letters, digits, dot, dash and underscore only."""
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", str(name or "host")).strip("._-")[:60] or "host"
    tail = re.sub(r"[^0-9A-Za-z-]+", "", stamp)[:20]
    return f"{base}{'-' + tail if tail else ''}.{ext.lstrip('.')}"


def _u(*parts: str) -> str:
    return str(uuid.uuid5(NAMESPACE, "|".join(parts)))


def _benchmark_date(iso: str) -> str:
    m = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})", str(iso))
    if not m or not 1 <= int(m[2]) <= 12:
        return str(iso)
    return f"{int(m[3]):02d} {_MONTHS[int(m[2]) - 1]} {m[1]}"


def _release_info(b: Benchmark) -> str:
    return f"Release: {b.release} Benchmark Date: {_benchmark_date(b.date)}"


def _stig_ref(b: Benchmark) -> str:
    return f"{b.title} :: Version {b.version}, {_release_info(b)}"


def _stig_name(b: Benchmark) -> str:
    return str(b.data.get("xccdf_id") or b.benchmark_id)


def _iso_ms(collected_at: str) -> str:
    m = re.fullmatch(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})Z?", str(collected_at))
    return f"{m[1]}.000Z" if m else "1970-01-01T00:00:00.000Z"


def host_name_of(host: Any) -> str:
    name = host.get("name") if isinstance(host, dict) else host
    return clean_text(name, MAX_HOST_NAME).replace("\n", " ").strip() or "unnamed"


# --------------------------------------------------------------------------- scan view

def load_scan(conn: sqlite3.Connection, scan_id: int) -> dict | None:
    """A stored scan with its results (and the raw collector JSON) for the checklist exports."""
    scan = db.get_scan(conn, scan_id)
    if scan is None:
        return None
    scan["results"] = db.scan_results(conn, scan_id)
    scan["raw"] = db.get_raw(conn, scan_id)
    return scan


def _results_by_id(scan: dict) -> dict[str, dict]:
    results = scan.get("results") or []
    if isinstance(results, dict):
        return {sid: dict(v, stig_id=sid) for sid, v in results.items()}
    return {r["stig_id"]: r for r in results}


def _fmt_value(v: Any) -> str:
    if isinstance(v, (list, tuple)):
        shown = ", ".join(_fmt_value(x) for x in v[:10]) + (f", ... ({len(v)} items)" if len(v) > 10 else "")
        return "[" + shown + "]"
    if isinstance(v, dict):
        return clean_text(json.dumps(v, ensure_ascii=False, sort_keys=True), MAX_VALUE)
    if v is None:
        return "not set"
    return clean_text(v, MAX_VALUE).replace("\n", " | ")


def finding_details(result: dict | None, scan: dict, b: Benchmark) -> str:
    """Evidence summary for FINDING_DETAILS: what was observed against what the rule needs,
    and the collector command it came from."""
    head = (f"STIGWatch scan collected {clean_text(scan.get('collected_at'))} against "
            f"{b.title} {b.label}.")
    if result is None:
        return head + "\nNo result was recorded for this rule in this scan."
    lines = [head, f"Status: {result.get('status')}."]
    reason = clean_text(result.get("reason"), 1500)
    if reason:
        lines.append(reason)
    evidence = result.get("evidence") or []
    if not isinstance(evidence, list):
        evidence = []
    shown = [e for e in evidence if isinstance(e, dict) and e.get("expected") != "(context)"]
    shown += [e for e in evidence if isinstance(e, dict) and e.get("expected") == "(context)"]
    for e in shown[:12]:
        lines.append(f"- {clean_text(e.get('path'), 160)}: observed {_fmt_value(e.get('observed'))}; "
                     f"expected {clean_text(e.get('expected'), 300)}")
    commands: list[str] = []
    for e in shown:
        cmd = clean_text(e.get("command"), 300)
        if cmd and cmd not in commands:
            commands.append(cmd)
    for cmd in commands[:3]:
        lines.append(f"Collector command: {cmd}")
    return clean_text("\n".join(lines), MAX_DETAIL)


def _comment(result: dict | None) -> str:
    if not result:
        return ""
    return clean_text(result.get("comment") or result.get("comment_at_scan") or "", 8000)


def _status(result: dict | None) -> str:
    s = (result or {}).get("status")
    return s if s in CKL_STATUSES else "Not_Reviewed"


def _role(scan: dict) -> str:
    """STIG Viewer's asset role, from the stored domain-role fact of a Windows scan."""
    return {"dc": "Domain Controller", "member": "Member Server",
            "standalone": "Member Server"}.get(remediation.domain_role_of(scan.get("raw")), "None")


# --------------------------------------------------------------------------- .ckl (XML)

def _sub(parent: ET.Element, tag: str, text: str | None = None) -> ET.Element:
    el = ET.SubElement(parent, tag)
    if text:
        el.text = clean_text(text)
    return el


def _stig_data(vuln: ET.Element, name: str, value: str | None) -> None:
    sd = ET.SubElement(vuln, "STIG_DATA")
    _sub(sd, "VULN_ATTRIBUTE", name)
    _sub(sd, "ATTRIBUTE_DATA", value or "")


def ckl(host: dict, scan: dict, benchmark: Benchmark) -> bytes:
    """STIG Viewer 2 checklist: every rule of the benchmark, UTF-8 XML."""
    name = host_name_of(host)
    results = _results_by_id(scan)
    root = ET.Element("CHECKLIST")
    asset = ET.SubElement(root, "ASSET")
    for tag, text in (
            ("ROLE", _role(scan)), ("ASSET_TYPE", "Computing"), ("MARKING", "NONE"),
            ("HOST_NAME", name), ("HOST_IP", ""), ("HOST_MAC", ""), ("HOST_GUID", ""),
            ("HOST_FQDN", ""), ("TECH_AREA", ""), ("TARGET_KEY", ""), ("WEB_OR_DATABASE", "false"),
            ("WEB_DB_SITE", ""), ("WEB_DB_INSTANCE", "")):
        _sub(asset, tag, text)
    stigs = ET.SubElement(root, "STIGS")
    istig = ET.SubElement(stigs, "iSTIG")
    info = ET.SubElement(istig, "STIG_INFO")
    for sid_name, data in (
            ("version", benchmark.version), ("classification", ""), ("customname", ""),
            ("stigid", _stig_name(benchmark)),
            ("description", f"Checklist generated by STIGWatch from {benchmark.title}. {DISCLAIMER}"),
            ("filename", str(benchmark.source_url).rsplit("/", 1)[-1]),
            ("releaseinfo", _release_info(benchmark)), ("title", benchmark.title),
            ("uuid", _u(name, benchmark.benchmark_id, "stig")), ("notice", "terms-of-use"),
            ("source", "")):
        si = ET.SubElement(info, "SI_DATA")
        _sub(si, "SID_NAME", sid_name)
        if data:
            _sub(si, "SID_DATA", data)
    ref = _stig_ref(benchmark)
    for rule in benchmark.rules:
        result = results.get(rule.stig_id)
        v = ET.SubElement(istig, "VULN")
        _stig_data(v, "Vuln_Num", rule.group_id)
        _stig_data(v, "Severity", rule.severity)
        _stig_data(v, "Weight", SEVERITY_WEIGHT)
        _stig_data(v, "Group_Title", rule.title)
        _stig_data(v, "Rule_ID", rule.rule_id)
        _stig_data(v, "Rule_Ver", rule.stig_id)
        _stig_data(v, "Rule_Title", rule.title)
        _stig_data(v, "Vuln_Discuss", rule.discussion)
        _stig_data(v, "IA_Controls", rule.ia_controls)
        _stig_data(v, "Check_Content", rule.check_text)
        _stig_data(v, "Fix_Text", rule.fix_text)
        for attr in ("False_Positives", "False_Negatives"):
            _stig_data(v, attr, "")
        _stig_data(v, "Documentable", "false")
        for attr in ("Mitigations", "Potential_Impact", "Third_Party_Tools", "Mitigation_Control",
                     "Responsibility", "Security_Override_Guidance"):
            _stig_data(v, attr, "")
        _stig_data(v, "STIGRef", ref)
        for cci in rule.ccis:
            _stig_data(v, "CCI_REF", cci)
        _sub(v, "STATUS", _status(result))
        _sub(v, "FINDING_DETAILS", finding_details(result, scan, benchmark))
        _sub(v, "COMMENTS", _comment(result))
        _sub(v, "SEVERITY_OVERRIDE", "")
        _sub(v, "SEVERITY_JUSTIFICATION", "")
    ET.indent(root, space="  ")
    # The disclaimer comment sits before the root element (ElementTree cannot place it there).
    body = ET.tostring(root, encoding="unicode")
    return (f'<?xml version="1.0" encoding="UTF-8"?>\n<!-- {DISCLAIMER} -->\n'
            + body + "\n").encode("utf-8")


# --------------------------------------------------------------------------- .cklb (JSON)

def cklb(host: dict, scan: dict, benchmark: Benchmark) -> bytes:
    """STIG Viewer 3 checklist: every rule of the benchmark, UTF-8 JSON."""
    name = host_name_of(host)
    results = _results_by_id(scan)
    stig_uuid = _u(name, benchmark.benchmark_id, "stig")
    stamp = _iso_ms(scan.get("collected_at", ""))
    rules = []
    for rule in benchmark.rules:
        result = results.get(rule.stig_id)
        rules.append({
            "uuid": _u(name, benchmark.benchmark_id, rule.stig_id),
            "stig_uuid": stig_uuid,
            "target_key": None, "stig_ref": None,
            "group_id": rule.group_id,
            "rule_id": rule.rule_id.removesuffix("_rule"),
            "rule_id_src": rule.rule_id,
            "weight": SEVERITY_WEIGHT, "classification": "NONE",
            "severity": rule.severity,
            "rule_version": rule.stig_id,
            "group_title": clean_text(rule.title),
            "rule_title": clean_text(rule.title),
            "fix_text": clean_text(rule.fix_text),
            "false_positives": None, "false_negatives": None,
            "discussion": clean_text(rule.discussion),
            "check_content": clean_text(rule.check_text),
            "documentable": "false",
            "mitigations": None, "potential_impacts": None, "third_party_tools": None,
            "mitigation_control": None, "responsibility": None, "security_override_guidance": None,
            "ia_controls": rule.ia_controls or None,
            "check_content_ref": {"href": "", "name": "M"},
            "legacy_ids": [],
            "group_tree": [{"id": rule.group_id, "title": clean_text(rule.title),
                            "description": "<GroupDescription></GroupDescription>"}],
            "createdAt": stamp, "updatedAt": stamp,
            "STIGUuid": stig_uuid,
            "status": CKLB_STATUS[_status(result)],
            "overrides": {},
            "comments": _comment(result),
            "finding_details": finding_details(result, scan, benchmark),
            "ccis": list(rule.ccis),
        })
    version = int(benchmark.version) if str(benchmark.version).isdigit() else 0
    doc = {
        "title": f"{name}-{_stig_name(benchmark)}-V{benchmark.version}R{benchmark.release}",
        "id": _u(name, benchmark.benchmark_id, "checklist"),
        "active": False, "mode": 1, "has_path": True,
        "target_data": {
            "target_type": "Computing", "host_name": name, "ip_address": "", "mac_address": "",
            "fqdn": "", "comments": DISCLAIMER, "role": _role(scan),
            "is_web_database": False, "technology_area": "", "web_db_site": "", "web_db_instance": "",
        },
        "stigs": [{
            "stig_name": benchmark.title, "display_name": benchmark.title,
            "stig_id": _stig_name(benchmark), "version": version,
            "release_info": _release_info(benchmark), "uuid": stig_uuid,
            "reference_identifier": "0000", "size": len(rules), "rules": rules,
        }],
    }
    return json.dumps(doc, ensure_ascii=False, indent=2).encode("utf-8")


# --------------------------------------------------------------------------- fleet summary

def _bench_loader() -> Callable[[str], Benchmark | None]:
    cache: dict[str, Benchmark | None] = {}

    def load(bid: str) -> Benchmark | None:
        if bid not in cache:
            try:
                cache[bid] = benchmarks.load_benchmark(bid)
            except Exception:
                cache[bid] = None
        return cache[bid]
    return load


def fleet_rows(conn: sqlite3.Connection,
               loader: Callable[[str], Benchmark | None] | None = None) -> dict:
    """Numbers behind the CSV and the report, computed from the database."""
    load = loader or _bench_loader()
    rows = []
    regressions = []
    for host in db.list_hosts(conn):
        scans = db.list_scans(conn, host["id"])
        row: dict[str, Any] = {"host": host["name"], "os": host["os"], "environment": host["environment"],
                               "owner": host["owner"], "benchmark_id": host["benchmark_id"],
                               "scans": len(scans), "release": "", "collected_at": "",
                               "open": {c: 0 for c in CATS}, "status": {s: 0 for s in CKL_STATUSES},
                               "compliance": None, "series": [], "regressed": 0}
        if scans:
            last = scans[-1]
            row.update(release=last["benchmark_release"], collected_at=last["collected_at"])
            for r in conn.execute("SELECT status, cat, COUNT(*) AS n FROM results WHERE scan_id = ? "
                                  "GROUP BY status, cat", (last["id"],)):
                row["status"][r["status"]] += r["n"]
                if r["status"] == "Open":
                    row["open"][r["cat"]] += r["n"]
            decided = row["status"]["Open"] + row["status"]["NotAFinding"]
            if decided:
                row["compliance"] = round(100.0 * row["status"]["NotAFinding"] / decided, 1)
            row["series"] = [sum(p["open"].values()) for p in db.host_trend(conn, host["id"])]
            drift = db.drift_for_scan(conn, last["id"])
            if drift:
                row["regressed"] = len(drift["regressed"])
                b = load(host["benchmark_id"])
                for item in drift["regressed"]:
                    rule = b.rule(item["stig_id"]) if b else None
                    regressions.append({"host": host["name"], "stig_id": item["stig_id"],
                                        "cat": item["cat"], "from": item["from"],
                                        "title": rule.title if rule else "", "when": last["collected_at"]})
        rows.append(row)
    rows.sort(key=lambda r: (-r["open"]["CAT I"], -r["open"]["CAT II"], -r["open"]["CAT III"], r["host"]))
    regressions.sort(key=lambda r: (CATS.index(r["cat"]) if r["cat"] in CATS else 9, r["host"], r["stig_id"]))
    return {"hosts": rows, "regressions": regressions, "trend": db.fleet_trend(conn)}


def _csv_cell(v: Any) -> str:
    s = clean_text("" if v is None else v).replace("\n", " ")
    return "'" + s if s.startswith(_FORMULA) else s


def fleet_csv(conn: sqlite3.Connection, data: dict | None = None) -> str:
    """One row per host, last line the disclaimer. Cells that start like a formula get a
    leading apostrophe, so a hostile host name cannot run in a spreadsheet."""
    data = data or fleet_rows(conn)
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\r\n")
    w.writerow(["host", "os", "environment", "owner", "benchmark", "release", "last_scan",
                "open_cat1", "open_cat2", "open_cat3", "open_total", "not_a_finding",
                "not_applicable", "not_reviewed", "compliance_percent", "newly_regressed",
                "first_scan_open", "scans"])
    for r in data["hosts"]:
        o, s = r["open"], r["status"]
        w.writerow([_csv_cell(x) for x in (
            r["host"], r["os"], r["environment"], r["owner"], r["benchmark_id"], r["release"],
            r["collected_at"], o["CAT I"], o["CAT II"], o["CAT III"], sum(o.values()),
            s["NotAFinding"], s["Not_Applicable"], s["Not_Reviewed"],
            "" if r["compliance"] is None else r["compliance"], r["regressed"],
            r["series"][0] if r["series"] else "", r["scans"])])
    w.writerow(["# compliance_percent = NotAFinding / (Open + NotAFinding) in the latest scan; "
                "Not_Reviewed and Not_Applicable rules are not counted. newly_regressed = rules "
                "that went from NotAFinding or Not_Applicable to Open since the previous scan. "
                "first_scan_open = open findings in the host's first scan."])
    w.writerow(["# " + DISCLAIMER])
    return out.getvalue()


# --------------------------------------------------------------------------- HTML report

def sparkline(values: list[int], width: int = 120, height: int = 28, label: str = "") -> str:
    """Inline SVG of a series, scaled server-side. A single point is a dot."""
    pad = 3
    esc = html.escape(clean_text(label) or "trend", quote=True)
    if not values:
        return f'<svg class="spark" width="{width}" height="{height}" role="img" aria-label="{esc}: no data"></svg>'
    lo, hi = min(values), max(values)
    n = len(values)

    def xy(i: int, v: int) -> tuple[float, float]:
        x = pad + (width - 2 * pad) * (i / (n - 1) if n > 1 else 0.5)
        y = height - pad - (height - 2 * pad) * ((v - lo) / (hi - lo) if hi != lo else 0.5)
        return round(x, 1), round(y, 1)

    pts = [xy(i, v) for i, v in enumerate(values)]
    line = " ".join(f"{x},{y}" for x, y in pts)
    lx, ly = pts[-1]
    shape = f'<polyline points="{line}" fill="none" stroke-width="1.5"/>' if n > 1 else ""
    return (f'<svg class="spark" width="{width}" height="{height}" viewBox="0 0 {width} {height}" '
            f'role="img" aria-label="{esc}: {values[0]} then {values[-1]}">'
            f'<title>{esc}: {" ".join(map(str, values))}</title>{shape}'
            f'<circle cx="{lx}" cy="{ly}" r="2.5"/></svg>')


_CSS = """
:root{--bg:#fff;--fg:#111827;--muted:#4b5563;--line:#cbd5e1;--head:#e2e8f0;--c1:#b91c1c;--c2:#b45309;--c3:#854d0e}
*{box-sizing:border-box}
body{font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:var(--fg);background:var(--bg);margin:0 auto;padding:24px;max-width:1100px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:26px 0 8px}
.muted{color:var(--muted)}
.cards{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0}
.card{border:1px solid var(--line);border-radius:6px;padding:8px 14px;min-width:120px}
.card b{display:block;font-size:22px}
table{border-collapse:collapse;width:100%}
th,td{border:1px solid var(--line);padding:5px 8px;text-align:left;vertical-align:middle}
th{background:var(--head)}td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}
.c1{color:var(--c1);font-weight:700}.c2{color:var(--c2);font-weight:700}.c3{color:var(--c3);font-weight:700}
.spark{vertical-align:middle}.spark polyline{stroke:#0f766e}.spark circle{fill:#0f766e}
.disclaimer{margin-top:28px;padding-top:10px;border-top:1px solid var(--line);color:var(--muted)}
@media print{body{padding:0;max-width:none;font-size:11px}.card{break-inside:avoid}tr{break-inside:avoid}h2{break-after:avoid}}
"""


def _e(v: Any) -> str:
    return html.escape(clean_text(v), quote=True)


def _num(n: int, cls: str) -> str:
    return f'<td class="n {cls}">{n}</td>' if n else f'<td class="n">{n}</td>'


def fleet_report_html(conn: sqlite3.Connection, data: dict | None = None) -> str:
    """Self-contained, printable fleet report: no scripts, inline CSS, every value escaped."""
    data = data or fleet_rows(conn)
    hosts, regs = data["hosts"], data["regressions"]
    totals = {c: sum(h["open"][c] for h in hosts) for c in CATS}
    as_of = max((h["collected_at"] for h in hosts if h["collected_at"]), default="")
    parts = [
        "<!doctype html>", '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">",
        "<title>STIGWatch fleet report</title>", f"<style>{_CSS}</style></head><body>",
        "<h1>STIGWatch fleet report</h1>",
        f'<p class="muted">{len(hosts)} hosts. Latest scan collected {_e(as_of) or "n/a"}. '
        "Open findings are counted from each host's latest scan.</p>",
        '<div class="cards">',
    ]
    for cat, cls in zip(CATS, ("c1", "c2", "c3")):
        parts.append(f'<div class="card"><span class="{cls}">{cat} open</span><b>{totals[cat]}</b></div>')
    series = [sum(p["open"].values()) for p in data["trend"]]
    parts.append('<div class="card"><span>Open findings over time</span><b>'
                 f'{series[0] if series else 0} to {series[-1] if series else 0}</b>'
                 f'{sparkline(series, 160, 32, "Fleet open findings per week")}</div></div>')
    parts.append("<h2>Hosts</h2><table><thead><tr><th>Host</th><th>OS</th><th>Environment</th>"
                 "<th>Benchmark</th><th>Last scan</th>"
                 '<th class="n">CAT I</th><th class="n">CAT II</th><th class="n">CAT III</th>'
                 '<th class="n">Compliance</th><th>Open over time</th></tr></thead><tbody>')
    for h in hosts:
        o = h["open"]
        comp = "n/a" if h["compliance"] is None else f'{h["compliance"]:.1f}%'
        s = h["series"]
        parts.append(
            f'<tr><td>{_e(h["host"])}</td><td>{_e(h["os"])}</td><td>{_e(h["environment"])}</td>'
            f'<td>{_e(h["benchmark_id"])} {_e(h["release"])}</td><td>{_e(h["collected_at"]) or "never"}</td>'
            f'{_num(o["CAT I"], "c1")}{_num(o["CAT II"], "c2")}{_num(o["CAT III"], "c3")}'
            f'<td class="n">{comp}</td><td>{sparkline(s, 110, 24, "Open findings of " + h["host"])} '
            f'<span class="muted">{(str(s[0]) + " to " + str(s[-1])) if s else "no scans"}</span></td></tr>')
    if not hosts:
        parts.append('<tr><td colspan="10">No hosts yet.</td></tr>')
    parts.append("</tbody></table>")
    parts.append("<h2>Top regressions</h2>")
    if regs:
        parts.append('<p class="muted">Rules that were NotAFinding or Not_Applicable in a host\'s previous '
                     "scan and are Open in its latest.</p><table><thead><tr><th>CAT</th><th>Host</th>"
                     "<th>STIG ID</th><th>Rule</th><th>Was</th><th>Latest scan</th></tr></thead><tbody>")
        for r in regs[:15]:
            cls = {"CAT I": "c1", "CAT II": "c2", "CAT III": "c3"}.get(r["cat"], "")
            parts.append(f'<tr><td class="{cls}">{_e(r["cat"])}</td><td>{_e(r["host"])}</td>'
                         f'<td>{_e(r["stig_id"])}</td><td>{_e(r["title"])}</td><td>{_e(r["from"])}</td>'
                         f'<td>{_e(r["when"])}</td></tr>')
        parts.append("</tbody></table>")
        if len(regs) > 15:
            parts.append(f'<p class="muted">{len(regs) - 15} more not shown.</p>')
    else:
        parts.append('<p class="muted">No regressions between the latest two scans of any host.</p>')
    parts.append('<h2>How to read this</h2><p class="muted">Compliance is NotAFinding divided by '
                 "Open plus NotAFinding in the latest scan; Not_Reviewed and Not_Applicable rules are "
                 "not counted. A high percentage with many Not_Reviewed rules means little was "
                 "checked, so read it with the scan coverage.</p>")
    parts.append(f'<p class="disclaimer">{html.escape(DISCLAIMER, quote=False)}</p></body></html>')
    return "\n".join(parts) + "\n"
