"""The fictional demo fleet: story numbers, determinism, seeding and its time budget."""

import importlib.util
import json
import sqlite3
import time
from pathlib import Path

import pytest

from stigwatch import config, db, demo
from stigwatch.checks import engine

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "build_demo.py"
WEEK6 = "2026-10-26"   # collected_at date of the week-6 scans (week 1 = 2026-09-21)


def load_build_demo():
    spec = importlib.util.spec_from_file_location("build_demo", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def seeded(tmp_path_factory):
    path = tmp_path_factory.mktemp("demo") / "demo.db"
    conn = db.connect(path)
    assert demo.seed(conn)
    yield conn
    conn.close()


def scans(conn, name):
    return db.list_scans(conn, db.get_host_by_name(conn, name)["id"])


def week_drift(conn, name, week):
    """Drift into the given week (2 to 8) for a host."""
    return db.drift_for_scan(conn, scans(conn, name)[week - 1]["id"])


# -- the fixture ------------------------------------------------------------------------------

@pytest.fixture(scope="module")
def fresh_build():
    build = load_build_demo()
    return build, build.build()


def test_fixture_equals_fresh_build(fresh_build):
    build, fixture = fresh_build
    assert build.OUT == config.DEMO_FIXTURE
    assert build.render(fixture) == config.DEMO_FIXTURE.read_text(encoding="utf-8")
    assert fixture == demo.load_fixture()


def test_check_flag_detects_a_stale_fixture(fresh_build, tmp_path, monkeypatch):
    build, fixture = fresh_build
    monkeypatch.setattr(build, "build", lambda: fixture)
    monkeypatch.setattr(build, "OUT", tmp_path / "demo_fixture.json")
    assert build.main(["--check"]) == 1                      # missing file
    build.OUT.write_text(build.render(fixture), encoding="utf-8")
    assert build.main(["--check"]) == 0
    build.OUT.write_text(build.render(fixture).replace("web-01", "web-99", 1), encoding="utf-8")
    assert build.main(["--check"]) == 1                      # edited by hand


def test_build_is_deterministic(fresh_build):
    build, fixture = fresh_build
    again = build.build()
    assert build.render(again) == build.render(fixture)


def test_fixture_is_reasonably_small_and_complete():
    assert config.DEMO_FIXTURE.stat().st_size < 2 * 1024 * 1024
    fixture = demo.load_fixture()
    assert fixture["format"] == demo.FIXTURE_FORMAT and fixture["weeks"] == 8
    assert len(fixture["hosts"]) == 14
    assert all(len(h["states"]) == 8 for h in fixture["hosts"])


def test_stored_results_are_what_the_engine_produces(seeded):
    """Every seeded scan, re-evaluated from its stored raw JSON, gives the stored results."""
    benches = {}
    for host in db.list_hosts(seeded):
        bench = benches.setdefault(host["benchmark_id"], demo.bundled_benchmark(host["benchmark_id"]))
        for scan in db.list_scans(seeded, host["id"]):
            live = engine.evaluate(db.get_raw(seeded, scan["id"]), bench)
            stored = db.scan_results(seeded, scan["id"])
            assert [(r["stig_id"], r["status"], r["reason"], r["evidence"]) for r in stored] == [
                (r.stig_id, r.status, r.reason, [dict(e) for e in r.evidence]) for r in live], (host["name"], scan["id"])


# -- the fleet ---------------------------------------------------------------------------------

def test_fleet_shape(seeded):
    hosts = {h["name"]: h for h in db.list_hosts(seeded)}
    assert len(hosts) == 14
    assert sum(h["os"] == "linux" for h in hosts.values()) == 8
    assert sum(h["os"] == "windows" for h in hosts.values()) == 6
    assert {h["environment"] for h in hosts.values()} == {"prod", "staging", "dev"}
    assert all(h["owner"] for h in hosts.values())
    assert {"web-01", "web-02", "api-01", "db-01", "db-02", "dc-01", "file-01"} <= set(hosts)
    for h in hosts.values():
        found = db.list_scans(seeded, h["id"])
        assert len(found) == 8
        assert [s["collected_at"][:10] for s in found][0] == "2026-09-21"
        assert [s["collected_at"][:10] for s in found][-1] == "2026-11-09"
        assert {s["benchmark_id"] for s in found} == {h["benchmark_id"]}


def test_dc_01_is_a_domain_controller(seeded):
    raw = db.get_raw(seeded, scans(seeded, "dc-01")[-1]["id"])
    assert raw["facts"]["domain_role"]["value"]["domain_role"] in (4, 5)   # backup or primary DC


def test_expected_counts_in_fixture_match_stored_results(seeded):
    expected = demo.load_fixture()["expected"]
    for host in db.list_hosts(seeded):
        got = [[t["open"]["CAT I"], t["open"]["CAT II"], t["open"]["CAT III"]]
               for t in db.host_trend(seeded, host["id"])]
        assert got == expected[host["name"]], host["name"]


def test_fleet_trend_story(seeded):
    trend = db.fleet_trend(seeded)
    assert len(trend) == 8 and all(p["hosts"] == 14 for p in trend)
    cat1 = [p["open"]["CAT I"] for p in trend]
    # Overall improvement: far fewer open CAT I findings in week 8 than in week 1 ...
    assert cat1[7] < cat1[0] and cat1[7] <= cat1[0] // 5
    assert [p["open"]["CAT II"] for p in trend][7] < [p["open"]["CAT II"] for p in trend][0]
    # ... but the week-6 change pushes the line back up before week 8 brings it down.
    assert cat1[5] > cat1[4]
    assert cat1[7] < cat1[5]


def test_week_6_regression_on_two_prod_hosts(seeded):
    hosts = {h["name"]: h for h in db.list_hosts(seeded)}
    assert hosts["web-01"]["environment"] == hosts["file-01"]["environment"] == "prod"
    for name, rules in (("web-01", {"UBTU-22-255025", "UBTU-22-255040"}),
                        ("file-01", {"WN22-AC-000090", "WN22-SO-000210"})):
        d = week_drift(seeded, name, 6)
        assert {r["stig_id"] for r in d["regressed"] if r["cat"] == "CAT I"} == rules
        before = db.host_trend(seeded, hosts[name]["id"])
        assert before[4]["open"]["CAT I"] == 0 and before[5]["open"]["CAT I"] == 2
    # No other host regresses a CAT I rule in week 6 (or any other week).
    alerts = db.list_alerts(seeded)
    assert {a["host_name"] for a in alerts} == {"web-01", "file-01"}
    assert len(alerts) == 4 and {a["created_at"][:10] for a in alerts} == {WEEK6}
    assert all(a["cat"] == "CAT I" and a["kind"] == "cat1_regression" for a in alerts)


def test_week_8_fixes_part_of_the_regression(seeded):
    for name, fixed, still_open in (("web-01", "UBTU-22-255040", "UBTU-22-255025"),
                                    ("file-01", "WN22-SO-000210", "WN22-AC-000090")):
        d = week_drift(seeded, name, 8)
        assert fixed in {r["stig_id"] for r in d["fixed"] if r["cat"] == "CAT I"}
        results = {r["stig_id"]: r["status"] for r in db.scan_results(seeded, scans(seeded, name)[7]["id"])}
        assert results[still_open] == "Open"
        assert results[fixed] == "NotAFinding"


def test_most_hosts_improve_week_over_week(seeded):
    improving = 0
    for host in db.list_hosts(seeded):
        totals = [sum(t["open"].values()) for t in db.host_trend(seeded, host["id"])]
        assert totals[-1] <= totals[0], host["name"]
        improving += totals[-1] < totals[0]
    assert improving >= 12


def test_one_host_is_unprivileged_throughout(seeded):
    host = db.get_host_by_name(seeded, "ci-01")
    for scan in db.list_scans(seeded, host["id"]):
        assert db.get_raw(seeded, scan["id"])["privileged"] is False
        statuses = [r["status"] for r in db.scan_results(seeded, scan["id"])]
        assert statuses.count("Not_Reviewed") > len(statuses) // 3
    # The other hosts are scanned with privileges.
    assert all(db.get_raw(seeded, scans(seeded, h)[0]["id"])["privileged"] is True
               for h in ("web-01", "dc-01", "file-01"))
    reasons = [r for r in db.scan_results(seeded, scans(seeded, "ci-01")[0]["id"])
               if r["stig_id"] == "UBTU-22-611065"]
    assert reasons[0]["status"] == "Not_Reviewed" and "Not reviewed" in reasons[0]["reason"]


def test_assessor_comments_persist_across_scans(seeded):
    host = db.get_host_by_name(seeded, "ci-01")
    first, last = scans(seeded, "ci-01")[0], scans(seeded, "ci-01")[-1]
    one = {r["stig_id"]: r for r in db.scan_results(seeded, first["id"])}["UBTU-22-611065"]
    eight = {r["stig_id"]: r for r in db.scan_results(seeded, last["id"])}["UBTU-22-611065"]
    assert one["comment"] == eight["comment"] and "sudo" in eight["comment"]
    assert one["comment_at_scan"] == eight["comment_at_scan"] == one["comment"]   # written before week 1
    assert host["id"] in {c["host_id"] for c in seeded.execute("SELECT host_id FROM comments")}
    # web-01: no comment before week 6, the week-6 text for weeks 6 and 7, then it is replaced.
    web = [{r["stig_id"]: r for r in db.scan_results(seeded, s["id"])}["UBTU-22-255025"]
           for s in scans(seeded, "web-01")]
    assert [bool(r["comment_at_scan"]) for r in web] == [False] * 5 + [True] * 3
    assert "INC-5530" in web[5]["comment_at_scan"] and "INC-5530" in web[6]["comment_at_scan"]
    assert "X11Forwarding is fixed" in web[7]["comment_at_scan"]
    assert all("X11Forwarding is fixed" in r["comment"] for r in web)   # live comment: the latest one


def test_comment_rules_exist_in_the_benchmarks():
    fixture = demo.load_fixture()
    ids = {h["os"]: {r.stig_id for r in demo.bundled_benchmark(h["benchmark_id"]).rules} for h in fixture["hosts"]}
    host_os = {h["name"]: h["os"] for h in fixture["hosts"]}
    for c in fixture["comments"]:
        assert c["stig_id"] in ids[host_os[c["host"]]]


def test_demo_fleet_names():
    hosts = {h["name"] for h in demo.load_fixture()["hosts"]}
    assert hosts == {"web-01", "web-02", "api-01", "db-01", "db-02", "jump-01", "ci-01", "log-01",
                     "dc-01", "app-01", "file-01", "rds-01", "mgmt-01", "bkp-01"}


# -- seeding -----------------------------------------------------------------------------------

def counts(conn):
    return [conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            for t in ("hosts", "scans", "results", "comments", "alerts")]


def test_seed_is_idempotent(db_file):
    conn = db.connect(db_file)
    assert demo.seed(conn) is True
    before = counts(conn)
    assert before[:2] == [14, 112] and before[3] == 4 and before[4] == 4
    assert demo.seed(conn) is False
    assert counts(conn) == before
    conn.close()


def test_seed_time_budget(db_file):
    """Cold start on a serverless host must stay fast: seeding the whole fleet, including
    opening the database, well under the 3 second budget."""
    start = time.perf_counter()
    conn = db.connect(db_file)
    assert demo.seed(conn)
    elapsed = time.perf_counter() - start
    conn.close()
    assert elapsed < 3.0, f"seeding took {elapsed:.2f}s"


def test_ensure_seeded_creates_the_database(db_file):
    demo.ensure_seeded()
    demo.ensure_seeded()   # second call changes nothing
    conn = db.connect(db_file)
    assert counts(conn)[:2] == [14, 112]
    conn.close()


def test_seed_is_all_or_nothing(db_file, monkeypatch):
    """A failure halfway through leaves an empty database, and a later seed still works."""
    conn = db.connect(db_file)
    real = db.add_scan
    calls = []

    def flaky(*args, **kwargs):
        calls.append(1)
        if len(calls) == 60:
            raise sqlite3.OperationalError("disk I/O error")
        return real(*args, **kwargs)

    monkeypatch.setattr(db, "add_scan", flaky)
    with pytest.raises(sqlite3.OperationalError):
        demo.seed(conn)
    assert counts(conn) == [0, 0, 0, 0, 0]
    assert not conn.in_transaction
    monkeypatch.setattr(db, "add_scan", real)
    assert demo.seed(conn) is True
    assert counts(conn)[:2] == [14, 112]
    conn.close()


def test_seed_rechecks_under_the_write_lock(db_file, monkeypatch):
    """Another process seeds between the first check and the write lock: this one backs off
    without writing anything."""
    first, other = db.connect(db_file), db.connect(db_file)
    real = demo.prepared_states

    def seed_elsewhere(fixture):
        monkeypatch.setattr(demo, "prepared_states", real)
        assert demo.seed(other) is True
        return real(fixture)

    monkeypatch.setattr(demo, "prepared_states", seed_elsewhere)
    assert demo.seed(first) is False
    assert counts(first)[:2] == [14, 112]   # one fleet, not two
    first.close()
    other.close()


def test_defect_that_does_not_fit_fails_loudly():
    fixture = demo.load_fixture()
    raw = fixture["templates"]["linux-compliant"]
    with pytest.raises(ValueError):
        demo.apply_defect(raw, {"op": "text", "fact": "sshd_config", "find": "NoSuchDirective", "replace": "x"}, {})
    with pytest.raises(ValueError):
        demo.apply_defect(raw, {"op": "bogus", "fact": "sshd_config"}, {})
    unreadable = fixture["templates"]["linux-unprivileged"]
    shadow = next(f for f, v in unreadable["facts"].items() if v["status"] != "ok")
    with pytest.raises(ValueError):
        demo.apply_defect(unreadable, {"op": "swap", "fact": shadow}, {shadow: {}})


def test_fixture_json_is_valid_utf8():
    json.loads(config.DEMO_FIXTURE.read_bytes().decode("utf-8"))
