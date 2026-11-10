"""A newer benchmark release is imported while older scans exist: uploads keep working, old
checklists keep the release they were evaluated against, and the mismatch is stated."""

import json
from pathlib import Path

import pytest
from defusedxml import ElementTree as SafeET
from fastapi.testclient import TestClient

from stigwatch import api, benchmarks, demo, exports
from stigwatch import db as dbm
from stigwatch.checks import engine
from conftest import TEST_PASSWORD, TEST_USER

FIX = Path(__file__).parent / "fixtures"
DROPPED = "UBTU-22-255040"   # a rule STIGWatch has a check for


@pytest.fixture
def newer_release(tmp_path, monkeypatch):
    """Import 'ubuntu-22.04 V2R11' = the bundled V2R10 with one checked rule removed."""
    data = json.loads((benchmarks.BUNDLED_DIR / "ubuntu-22.04.json").read_text(encoding="utf-8"))
    assert any(r["stig_id"] == DROPPED for r in data["rules"])
    assert DROPPED in engine.load_checks("ubuntu-22.04").checks
    data["release"] = "11"
    data["date"] = "2026-12-31"
    data["rules"] = [r for r in data["rules"] if r["stig_id"] != DROPPED]
    data["counts"] = {s: sum(1 for r in data["rules"] if r["severity"] == s) for s in benchmarks.SEVERITIES}
    out = tmp_path / "userdata" / "benchmarks"
    out.mkdir(parents=True)
    (out / "ubuntu-22.04.json").write_text(benchmarks.dumps(data), encoding="utf-8")
    monkeypatch.setenv("STIGWATCH_DATA_DIR", str(tmp_path / "userdata"))
    engine.load_checks.cache_clear()
    yield data
    engine.load_checks.cache_clear()


@pytest.fixture
def seeded_client(db_file):
    """The demo fleet (V2R10 Ubuntu scans), seeded before any newer release exists."""
    conn = dbm.connect(db_file)
    demo.seed(conn)
    conn.close()
    with TestClient(api.app) as c:
        assert c.post("/api/auth/login", json={"username": TEST_USER, "password": TEST_PASSWORD}).status_code == 200
        yield c


def test_checks_for_removed_rules_are_skipped_not_fatal(newer_release):
    checkset = engine.load_checks("ubuntu-22.04")
    assert checkset.skipped == (DROPPED,) and DROPPED not in checkset.checks


def test_bundled_checks_all_exist_in_the_bundled_releases():
    for bid in benchmarks.list_benchmarks():
        assert engine.load_checks(bid).skipped == (), bid


def test_ubuntu_upload_still_works_on_a_newer_release(seeded_client, newer_release):
    raw = json.loads((FIX / "linux-compliant.json").read_text(encoding="utf-8"))
    raw["host"]["name"] = "fresh-01"
    r = seeded_client.post("/api/scans", content=json.dumps(raw).encode(),
                           headers={"content-type": "application/json"})
    assert r.status_code == 201, r.text
    scan_id = r.json()["scan_id"]
    ckl = seeded_client.get(f"/api/scans/{scan_id}/export.ckl")
    assert ckl.status_code == 200 and "x-stigwatch-notice" not in ckl.headers
    root = SafeET.fromstring(ckl.content)
    info = {s.find("SID_NAME").text: (s.find("SID_DATA").text if s.find("SID_DATA") is not None else "")
            for s in root.iter("SI_DATA")}
    assert info["releaseinfo"].startswith("Release: 11 Benchmark Date: 31 Dec 2026")
    ids = {v.findall("STIG_DATA")[4].find("ATTRIBUTE_DATA").text for v in root.iter("VULN")}
    assert DROPPED not in ids


def test_old_scans_keep_their_release_and_say_so(seeded_client, newer_release):
    host = next(h for h in seeded_client.get("/api/hosts").json() if h["name"] == "web-01")
    scans = seeded_client.get(f"/api/hosts/{host['id']}/scans").json()
    old = scans[-1]
    assert old["benchmark_release"] == "V2R10"
    ckl = seeded_client.get(f"/api/scans/{old['id']}/export.ckl")
    assert ckl.status_code == 200
    assert "V2R10" in ckl.headers["x-stigwatch-notice"] and "V2R11" in ckl.headers["x-stigwatch-notice"]
    root = SafeET.fromstring(ckl.content)
    info = {s.find("SID_NAME").text: (s.findtext("SID_DATA") or "") for s in root.iter("SI_DATA")}
    assert info["version"] == "2"
    assert info["releaseinfo"] == "Release: 10"          # no date: the V2R10 date is not known here
    assert "RELEASE MISMATCH" in root.find("ASSET/TARGET_COMMENT").text
    stigrefs = {s.find("ATTRIBUTE_DATA").text for v in root.iter("VULN") for s in v.findall("STIG_DATA")
                if s.find("VULN_ATTRIBUTE").text == "STIGRef"}
    assert all("Release: 10" in ref and "Release: 11" not in ref for ref in stigrefs)
    details = next(v.find("FINDING_DETAILS").text for v in root.iter("VULN"))
    assert "V2R10" in details and "V2R11" not in details
    assert "1 result(s) for rules that V2R11 no longer contains" in info["description"]
    cklb = json.loads(seeded_client.get(f"/api/scans/{old['id']}/export.cklb").content)
    assert cklb["stigs"][0]["release_info"] == "Release: 10"
    assert cklb["title"].endswith("-V2R10")
    assert "RELEASE MISMATCH" in cklb["target_data"]["comments"]


def test_exports_without_a_mismatch_have_no_notice(conn):
    demo.seed(conn)
    host = dbm.get_host_by_name(conn, "web-01")
    scan = exports.load_scan(conn, dbm.list_scans(conn, host["id"])[-1]["id"])
    assert exports.for_scan(scan, demo.bundled_benchmark("ubuntu-22.04"))[1] == ""
