"""Drift between scans (compared by STIG ID) and the storage around it: results, comments,
CAT I alerts and trends."""

import copy
import json
from pathlib import Path

import pytest

from stigwatch import benchmarks, db, drift
from stigwatch.checks import engine

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def fixture(name: str, collected_at: str | None = None, host: str | None = None) -> dict:
    raw = json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))
    if collected_at:
        raw["collected_at"] = collected_at
    if host:
        raw["host"]["name"] = host
    return raw


def view(results: dict, scan_id=1, release="V2R10") -> dict:
    return {"id": scan_id, "benchmark_release": release,
            "results": {sid: {"status": s, "cat": c} for sid, (s, c) in results.items()}}


def release_n_plus_1() -> benchmarks.Benchmark:
    """A synthetic next release of the Ubuntu STIG: one rule renamed, one removed, one added."""
    data = copy.deepcopy(benchmarks.load_benchmark("ubuntu-22.04").data)
    data["release"] = "11"
    rules = []
    for rule in data["rules"]:
        if rule["stig_id"] == "UBTU-22-255040":      # X11 forwarding, CAT I: renamed
            rule = {**rule, "stig_id": "UBTU-22-255041"}
        elif rule["stig_id"] == "UBTU-22-215035":    # telnet package, CAT I: removed
            continue
        rules.append(rule)
    rules.append({**data["rules"][0], "stig_id": "UBTU-22-999001", "group_id": "V-999001",
                  "rule_id": "SV-999001r1_rule", "severity": "medium"})
    data["rules"] = rules
    return benchmarks._to_benchmark(data)


# -- the pure function ----------------------------------------------------------------------

def test_every_common_rule_lands_in_exactly_one_bucket():
    prev = view({"A": ("NotAFinding", "CAT I"), "B": ("Open", "CAT II"), "C": ("Not_Reviewed", "CAT II"),
                 "D": ("Open", "CAT III"), "E": ("NotAFinding", "CAT II"), "F": ("Open", "CAT II"),
                 "G": ("Not_Applicable", "CAT II")})
    cur = view({"A": ("Open", "CAT I"), "B": ("NotAFinding", "CAT II"), "C": ("Open", "CAT II"),
                "D": ("Not_Reviewed", "CAT III"), "E": ("Not_Reviewed", "CAT II"), "F": ("Open", "CAT II"),
                "G": ("Open", "CAT II")}, scan_id=2)
    d = drift.drift(prev, cur)
    assert [r["stig_id"] for r in d["regressed"]] == ["A", "G"]
    assert [r["stig_id"] for r in d["fixed"]] == ["B"]
    assert [r["stig_id"] for r in d["newly_open"]] == ["C"]
    assert [r["stig_id"] for r in d["lost_visibility"]] == ["D"]
    assert [r["stig_id"] for r in d["other_changes"]] == ["E"]
    assert d["unchanged_counts"] == {"Open": 1, "NotAFinding": 0, "Not_Applicable": 0, "Not_Reviewed": 0}
    assert d["new_rules"] == [] and d["removed_rules"] == []
    total = sum(len(d[k]) for k in ("regressed", "fixed", "newly_open", "lost_visibility", "other_changes"))
    assert total + sum(d["unchanged_counts"].values()) == 7
    assert (d["prev_scan_id"], d["scan_id"]) == (1, 2)


def test_buckets_are_sorted_by_cat_then_id():
    prev = view({"Z": ("NotAFinding", "CAT I"), "B": ("NotAFinding", "CAT III"), "A": ("NotAFinding", "CAT II")})
    cur = view({k: ("Open", c) for k, c in (("Z", "CAT I"), ("B", "CAT III"), ("A", "CAT II"))}, scan_id=2)
    assert [r["stig_id"] for r in drift.drift(prev, cur)["regressed"]] == ["Z", "A", "B"]


def test_accepts_result_lists():
    prev = {"id": 1, "results": [{"stig_id": "A", "status": "Open", "cat": "CAT I"}]}
    cur = {"id": 2, "results": [{"stig_id": "A", "status": "NotAFinding", "cat": "CAT I"}]}
    assert drift.drift(prev, cur)["fixed"] == [{"stig_id": "A", "cat": "CAT I", "from": "Open", "to": "NotAFinding"}]


def test_losing_visibility_is_not_a_fix():
    d = drift.drift(view({"A": ("Open", "CAT I")}), view({"A": ("Not_Reviewed", "CAT I")}, scan_id=2))
    assert d["fixed"] == [] and len(d["lost_visibility"]) == 1


# -- drift across benchmark releases (Review Focus 3) ----------------------------------------------

def test_drift_across_releases(conn):
    """A host first scanned against release N and later against N+1: renamed, removed and
    added rules are listed separately and are never reported as fixed or regressed."""
    old = benchmarks.load_benchmark("ubuntu-22.04")
    new = release_n_plus_1()
    assert old.label != new.label
    host = db.add_host(conn, "legacy-01", "linux", "ubuntu-22.04", environment="prod")

    db.add_scan(conn, host, fixture("linux-noncompliant", "2026-11-02T10:00:00Z"), old)
    # Same facts, newer release: nothing about the host changed.
    second = db.add_scan(conn, host, fixture("linux-noncompliant", "2026-11-09T10:00:00Z"), new)

    d = db.drift_for_scan(conn, second)
    assert d["benchmark_changed"] and (d["prev_release"], d["release"]) == (old.label, new.label)
    assert [r["stig_id"] for r in d["removed_rules"]] == ["UBTU-22-215035", "UBTU-22-255040"]
    assert [r["stig_id"] for r in d["new_rules"]] == ["UBTU-22-255041", "UBTU-22-999001"]
    # Both removed rules were Open CAT I findings; neither is "fixed".
    assert {r["status"] for r in d["removed_rules"]} == {"Open"}
    assert d["fixed"] == [] and d["regressed"] == []
    assert d["newly_open"] == [] and d["lost_visibility"] == [] and d["other_changes"] == []
    assert sum(d["unchanged_counts"].values()) == len(old.rules) - 2
    assert db.list_alerts(conn, host) == []

    # Then the host is hardened: real fixes show up, the renamed and removed rules do not.
    third = db.add_scan(conn, host, fixture("linux-compliant", "2026-11-16T10:00:00Z", "legacy-01"), new)
    d2 = db.drift_for_scan(conn, third)
    assert not d2["benchmark_changed"]
    fixed = {r["stig_id"] for r in d2["fixed"]}
    assert fixed and not fixed & {"UBTU-22-215035", "UBTU-22-255040", "UBTU-22-255041", "UBTU-22-999001"}
    assert d2["regressed"] == []
    renamed = {r["stig_id"]: r["status"] for r in db.scan_results(conn, third)}["UBTU-22-255041"]
    assert renamed == "Not_Reviewed"  # no check exists under the new ID; it is not guessed from the old one
    assert d2["unchanged_counts"]["Not_Reviewed"] >= 1


def test_removed_rule_that_was_compliant_is_not_a_regression_either():
    prev = view({"OLD": ("NotAFinding", "CAT I"), "KEEP": ("Open", "CAT II")}, release="V1R1")
    cur = view({"NEW": ("Open", "CAT I"), "KEEP": ("Open", "CAT II")}, scan_id=2, release="V1R2")
    d = drift.drift(prev, cur)
    assert d["regressed"] == [] and d["fixed"] == []
    assert [r["stig_id"] for r in d["removed_rules"]] == ["OLD"]
    assert [r["stig_id"] for r in d["new_rules"]] == ["NEW"]
    assert drift.cat1_regressions(d) == []


def test_severity_change_between_releases_uses_the_new_category():
    prev = view({"A": ("NotAFinding", "CAT II")}, release="V1R1")
    cur = view({"A": ("Open", "CAT I")}, scan_id=2, release="V1R2")
    assert [r["cat"] for r in drift.drift(prev, cur)["regressed"]] == ["CAT I"]


# -- storage ----------------------------------------------------------------------------------

def test_scan_is_stored_with_raw_json_and_results(conn):
    host = db.add_host(conn, "web-01", "linux", "ubuntu-22.04", environment="prod", owner="Web", tags=["a"])
    raw = fixture("linux-noncompliant", "2026-11-02T10:00:00Z")
    scan = db.add_scan(conn, host, raw)
    assert db.get_raw(conn, scan) == raw
    stored = db.scan_results(conn, scan)
    live = engine.evaluate(raw)
    assert [(r["stig_id"], r["status"], r["reason"]) for r in stored] == [(r.stig_id, r.status, r.reason) for r in live]
    assert {r["cat"] for r in stored} == {"CAT I", "CAT II", "CAT III"}
    assert db.get_host(conn, host)["tags"] == ["a"]
    # Re-evaluation from the stored raw JSON gives the same results again.
    before = db.scan_results(conn, scan)
    db.reevaluate_scan(conn, scan)
    assert db.scan_results(conn, scan) == before


def test_invalid_collector_output_is_rejected_and_nothing_stored(conn):
    host = db.add_host(conn, "x", "linux", "ubuntu-22.04")
    with pytest.raises(ValueError):
        db.add_scan(conn, host, {"collector": "nonsense"})
    assert conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 0


def test_cat1_regression_creates_an_alert(conn):
    host = db.add_host(conn, "web-01", "linux", "ubuntu-22.04")
    good = fixture("linux-compliant", "2026-11-02T10:00:00Z", "web-01")
    bad = copy.deepcopy(good)
    bad["collected_at"] = "2026-11-09T10:00:00Z"
    bad["facts"]["sshd_config"]["value"]["text"] = bad["facts"]["sshd_config"]["value"]["text"].replace(
        "PermitEmptyPasswords no", "PermitEmptyPasswords yes")
    first = db.add_scan(conn, host, good)
    assert db.list_alerts(conn) == []
    second = db.add_scan(conn, host, bad)
    alerts = db.list_alerts(conn)
    assert [(a["stig_id"], a["cat"], a["scan_id"], a["prev_scan_id"], a["host_name"]) for a in alerts] == [
        ("UBTU-22-255025", "CAT I", second, first, "web-01")]
    assert "NotAFinding to Open" in alerts[0]["message"]
    # Fixing it again raises nothing new.
    db.add_scan(conn, host, {**good, "collected_at": "2026-11-16T10:00:00Z"})
    assert len(db.list_alerts(conn)) == 1


def test_only_cat1_regressions_alert(conn):
    host = db.add_host(conn, "web-01", "linux", "ubuntu-22.04")
    db.add_scan(conn, host, fixture("linux-compliant", "2026-11-02T10:00:00Z", "web-01"))
    worse = fixture("linux-noncompliant", "2026-11-09T10:00:00Z", "web-01")
    # Take the non-compliant fixture but keep the sshd facts compliant: CAT II/III regress too.
    worse["facts"]["sshd_config"] = fixture("linux-compliant")["facts"]["sshd_config"]
    scan = db.add_scan(conn, host, worse)
    d = db.drift_for_scan(conn, scan)
    assert {r["cat"] for r in d["regressed"]} >= {"CAT I", "CAT II"}
    assert {a["stig_id"] for a in db.list_alerts(conn)} == {r["stig_id"] for r in d["regressed"] if r["cat"] == "CAT I"}
    assert all(a["cat"] == "CAT I" for a in db.list_alerts(conn))


def test_unprivileged_rescan_is_not_a_fix_and_not_an_alert(conn):
    host = db.add_host(conn, "web-01", "linux", "ubuntu-22.04")
    db.add_scan(conn, host, fixture("linux-noncompliant", "2026-11-02T10:00:00Z", "web-01"))
    scan = db.add_scan(conn, host, fixture("linux-unprivileged", "2026-11-09T10:00:00Z", "web-01"))
    d = db.drift_for_scan(conn, scan)
    assert d["lost_visibility"]  # findings that can no longer be seen
    assert not {r["stig_id"] for r in d["fixed"]} & {r["stig_id"] for r in d["lost_visibility"]}
    assert db.list_alerts(conn) == []


def test_first_scan_has_no_drift(conn):
    host = db.add_host(conn, "web-01", "linux", "ubuntu-22.04")
    scan = db.add_scan(conn, host, fixture("linux-compliant", "2026-11-02T10:00:00Z", "web-01"))
    assert db.drift_for_scan(conn, scan) is None and db.previous_scan_id(conn, scan) is None


def test_previous_scan_follows_collection_time_not_upload_order(conn):
    host = db.add_host(conn, "web-01", "linux", "ubuntu-22.04")
    late = db.add_scan(conn, host, fixture("linux-compliant", "2026-11-09T10:00:00Z", "web-01"))
    early = db.add_scan(conn, host, fixture("linux-compliant", "2026-11-02T10:00:00Z", "web-01"))
    assert db.previous_scan_id(conn, late) == early
    assert db.previous_scan_id(conn, early) is None


def test_comments_persist_across_scans(conn):
    host = db.add_host(conn, "web-01", "linux", "ubuntu-22.04")
    first = db.add_scan(conn, host, fixture("linux-noncompliant", "2026-11-02T10:00:00Z", "web-01"))
    db.set_comment(conn, host, "UBTU-22-255040", "Needed for the vendor GUI; see RA-9.")
    second = db.add_scan(conn, host, fixture("linux-noncompliant", "2026-11-09T10:00:00Z", "web-01"))
    one = {r["stig_id"]: r for r in db.scan_results(conn, first)}["UBTU-22-255040"]
    two = {r["stig_id"]: r for r in db.scan_results(conn, second)}["UBTU-22-255040"]
    assert one["comment"] == two["comment"] == "Needed for the vendor GUI; see RA-9."  # live comment, both scans
    assert one["comment_at_scan"] == "" and two["comment_at_scan"] == "Needed for the vendor GUI; see RA-9."
    db.set_comment(conn, host, "UBTU-22-255040", "Updated text.")
    assert db.get_comments(conn, host)["UBTU-22-255040"]["text"] == "Updated text."
    db.set_comment(conn, host, "UBTU-22-255040", "  ")  # empty removes it
    assert db.get_comments(conn, host) == {}


def test_comments_are_per_host(conn):
    a = db.add_host(conn, "a", "linux", "ubuntu-22.04")
    b = db.add_host(conn, "b", "linux", "ubuntu-22.04")
    db.set_comment(conn, a, "UBTU-22-255040", "only on a")
    assert db.get_comments(conn, b) == {}


def test_hostile_text_is_stored_as_data(conn):
    nasty = "x'); DROP TABLE hosts;--"
    with pytest.raises(ValueError):          # the name itself is validated ...
        db.add_host(conn, nasty, "linux", "ubuntu-22.04")
    host = db.add_host(conn, "web-01", "linux", "ubuntu-22.04", owner=nasty)   # ... other text is data
    db.set_comment(conn, host, nasty, nasty)
    assert db.get_host_by_name(conn, "web-01")["owner"] == nasty
    assert db.get_comments(conn, host)[nasty]["text"] == nasty
    assert conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0] == 1


def test_trends(conn):
    web = db.add_host(conn, "web-01", "linux", "ubuntu-22.04")
    win = db.add_host(conn, "app-01", "windows", "windows-server-2022")
    db.add_scan(conn, web, fixture("linux-noncompliant", "2026-11-02T10:00:00Z", "web-01"))
    db.add_scan(conn, web, fixture("linux-compliant", "2026-11-09T10:00:00Z", "web-01"))
    db.add_scan(conn, win, fixture("windows-noncompliant", "2026-11-09T11:00:00Z", "app-01"))
    trend = db.host_trend(conn, web)
    assert [t["open"]["CAT I"] for t in trend] == [10, 0]
    assert trend[0]["open"]["CAT II"] > 0 and trend[1]["open"] == {"CAT I": 0, "CAT II": 0, "CAT III": 0}
    fleet = db.fleet_trend(conn)
    assert [(p["week"], p["hosts"]) for p in fleet] == [("2026-11-02", 1), ("2026-11-09", 2)]
    assert fleet[0]["open"]["CAT I"] == 10
    assert fleet[1]["open"]["CAT I"] == 0 + 14  # web-01 now compliant, app-01 non-compliant
