"""Drift between two scans of one host, compared by STIG ID.

Rule identity is the DISA STIG ID (``UBTU-22-255025``), never the position in a benchmark
or a Group/Rule ID, so a host scanned first against release N and later against release
N+1 compares correctly. A rule that exists in only one of the two scans (renamed,
removed or added by the new release) is listed under ``removed_rules`` / ``new_rules``
and is never reported as fixed or regressed: STIGWatch cannot tell a renamed rule from a
removed one, so it does not guess.

For rules in both scans every rule lands in exactly one bucket:

  regressed        NotAFinding or Not_Applicable -> Open
  fixed            Open -> NotAFinding or Not_Applicable
  newly_open       Not_Reviewed -> Open (the finding may be old; it was not visible before)
  lost_visibility  Open -> Not_Reviewed (for example the collector ran without privileges;
                   the finding is not known to be fixed)
  other_changes    any other status change (for example NotAFinding -> Not_Reviewed)
  unchanged_counts same status in both scans, counted per status

A scan view is a dict ``{"id", "benchmark_release", "results"}`` where ``results`` maps
STIG ID to ``{"status", "cat"}`` (or is a list of dicts with ``stig_id``, ``status``, ``cat``).
"""

from __future__ import annotations

from typing import Any

from .constants import CATS, NOT_A_FINDING, NOT_APPLICABLE, NOT_REVIEWED, OPEN, STATUSES  # noqa: F401
_CLOSED = {NOT_A_FINDING, NOT_APPLICABLE}


def _index(results: Any) -> dict[str, dict]:
    if isinstance(results, dict):
        return {sid: dict(v) for sid, v in results.items()}
    return {r["stig_id"]: dict(r) for r in results}


def _sort_key(item: dict) -> tuple[int, str]:
    cat = item["cat"]
    return (CATS.index(cat) if cat in CATS else len(CATS), item["stig_id"])


def classify(before: str, after: str) -> str:
    """Bucket name for one rule's status change."""
    if before == after:
        return "unchanged"
    if after == OPEN:
        return "regressed" if before in _CLOSED else "newly_open"
    if before == OPEN:
        return "fixed" if after in _CLOSED else "lost_visibility"
    return "other_changes"


def drift(prev_scan: dict, scan: dict) -> dict:
    prev, cur = _index(prev_scan["results"]), _index(scan["results"])
    out: dict[str, Any] = {
        "prev_scan_id": prev_scan.get("id"),
        "scan_id": scan.get("id"),
        "prev_release": prev_scan.get("benchmark_release"),
        "release": scan.get("benchmark_release"),
        "regressed": [], "fixed": [], "newly_open": [], "lost_visibility": [],
        "other_changes": [], "new_rules": [], "removed_rules": [],
    }
    out["benchmark_changed"] = out["prev_release"] != out["release"]
    unchanged = {s: 0 for s in STATUSES}
    for sid, now in cur.items():
        before = prev.get(sid)
        if before is None:
            out["new_rules"].append({"stig_id": sid, "cat": now["cat"], "status": now["status"]})
            continue
        bucket = classify(before["status"], now["status"])
        if bucket == "unchanged":
            unchanged[now["status"]] += 1
        else:
            out[bucket].append({"stig_id": sid, "cat": now["cat"],
                                "from": before["status"], "to": now["status"]})
    for sid, before in prev.items():
        if sid not in cur:
            out["removed_rules"].append({"stig_id": sid, "cat": before["cat"],
                                         "status": before["status"]})
    for key in ("regressed", "fixed", "newly_open", "lost_visibility", "other_changes",
                "new_rules", "removed_rules"):
        out[key].sort(key=_sort_key)
    out["unchanged_counts"] = unchanged
    return out


def cat1_regressions(result: dict) -> list[dict]:
    """The regressions that raise an alert."""
    return [r for r in result["regressed"] if r["cat"] == "CAT I"]
