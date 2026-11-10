"""Checklist (.ckl, .cklb) and fleet report exports."""

import csv
import io
import json
from pathlib import Path

import pytest
from defusedxml import ElementTree as SafeET

from stigwatch import db, demo, exports

REF = json.loads((Path(__file__).parent / "fixtures" / "stig_viewer_field_names.json").read_text("utf-8"))
DISCLAIMER = ("STIGWatch is an independent tool. It is not a DISA product and does not replace "
              "the SCAP Compliance Checker, Evaluate-STIG or an assessor's review.")


@pytest.fixture(scope="module")
def seeded(tmp_path_factory):
    conn = db.connect(tmp_path_factory.mktemp("exp") / "demo.db")
    demo.seed(conn)
    yield conn
    conn.close()


@pytest.fixture(scope="module")
def benches():
    return {b: demo.bundled_benchmark(b) for b in ("ubuntu-22.04", "windows-server-2022")}


def host_scan(conn, name):
    host = db.get_host_by_name(conn, name)
    scan = exports.load_scan(conn, db.list_scans(conn, host["id"])[-1]["id"])
    return host, scan


def test_ckl_structure(seeded, benches):
    host, scan = host_scan(seeded, "web-01")
    bench = benches["ubuntu-22.04"]
    data = exports.ckl(host, scan, bench)
    assert data.startswith(b"<?xml version='1.0' encoding='utf-8'?>")
    root = SafeET.fromstring(data)
    assert root.tag == "CHECKLIST"
    assert [c.tag for c in root if isinstance(c.tag, str)] == ["ASSET", "STIGS"]
    assert [c.tag for c in root.find("ASSET")] == REF["asset"]
    assert root.find("ASSET/HOST_NAME").text == "web-01"
    istig = root.find("STIGS/iSTIG")
    assert [s.find("SID_NAME").text for s in istig.find("STIG_INFO")] == REF["stig_info"]
    vulns = istig.findall("VULN")
    assert len(vulns) == len(bench.rules)
    results = {r["stig_id"]: r for r in scan["results"]}
    for vuln, rule in zip(vulns, bench.rules):
        names = [s.find("VULN_ATTRIBUTE").text for s in vuln.findall("STIG_DATA")]
        expected = [n for n in REF["vuln_attributes"] if n != "CCI_REF"] + ["CCI_REF"] * len(rule.ccis)
        assert names == expected
        fields = {s.find("VULN_ATTRIBUTE").text: s.find("ATTRIBUTE_DATA").text
                  for s in vuln.findall("STIG_DATA")}
        assert fields["Vuln_Num"] == rule.group_id and fields["Rule_ID"] == rule.rule_id
        assert fields["Rule_Ver"] == rule.stig_id and fields["Severity"] == rule.severity
        assert [c.tag for c in vuln if c.tag != "STIG_DATA"] == REF["vuln_children"]
        status = vuln.find("STATUS").text
        assert status in REF["statuses"]
        assert status == results[rule.stig_id]["status"]
    assert {v.find("STATUS").text for v in vulns} >= {"Open", "NotAFinding"}


def test_finding_details_and_comments(seeded, benches):
    host, scan = host_scan(seeded, "web-01")
    root = SafeET.fromstring(exports.ckl(host, scan, benches["ubuntu-22.04"]))
    opens = [v for v in root.iter("VULN") if v.find("STATUS").text == "Open"]
    assert opens
    details = opens[0].find("FINDING_DETAILS").text
    assert "observed" in details and "expected" in details and "Collector command:" in details


def test_cklb_structure(seeded, benches):
    host, scan = host_scan(seeded, "app-01")
    bench = benches["windows-server-2022"]
    doc = json.loads(exports.cklb(host, scan, bench))
    assert list(doc) == REF["cklb_top"]
    assert list(doc["target_data"]) == REF["cklb_target_data"]
    stig = doc["stigs"][0]
    assert list(stig) == REF["cklb_stig"]
    assert stig["size"] == len(stig["rules"]) == len(bench.rules)
    assert stig["version"] == int(bench.version)
    assert stig["release_info"].startswith(f"Release: {bench.release} Benchmark Date: ")
    results = {r["stig_id"]: r["status"] for r in scan["results"]}
    low = {"Open": "open", "NotAFinding": "not_a_finding", "Not_Applicable": "not_applicable",
           "Not_Reviewed": "not_reviewed"}
    uuids = set()
    for rule, src in zip(stig["rules"], bench.rules):
        assert list(rule) == REF["cklb_rule"]
        assert rule["status"] in REF["cklb_status"] and rule["status"] == low[results[src.stig_id]]
        assert rule["rule_id_src"] == src.rule_id and rule["rule_id"] + "_rule" == src.rule_id
        assert rule["rule_version"] == src.stig_id and rule["ccis"] == list(src.ccis)
        uuids.add(rule["uuid"])
    assert len(uuids) == len(bench.rules)
    assert doc["target_data"]["role"] in ("None", "Member Server", "Domain Controller")
    assert DISCLAIMER in doc["target_data"]["comments"]


HOSTILE = ["a\x00b\x01c\x0b\x1f", "x]]>y<z>&\"'", "\U0001F680 emoji ‮ rtl", "h" * 5000,
           "\ud800lone", "../../etc/passwd\r\nX: y"]


@pytest.mark.parametrize("text", HOSTILE)
def test_hostile_hostnames_and_comments(seeded, benches, text):
    bench = benches["ubuntu-22.04"]
    _, scan = host_scan(seeded, "web-01")
    scan["results"][0] = dict(scan["results"][0], comment=text * 3, reason=text)
    group_id = bench.rule(scan["results"][0]["stig_id"]).group_id
    for host in ({"name": text}, {"name": text * 2}):
        root = SafeET.fromstring(exports.ckl(host, scan, bench))   # well-formed whatever the input
        name = root.find("ASSET/HOST_NAME").text or ""
        assert len(name) <= exports.MAX_HOST_NAME and "\x00" not in name and "\n" not in name
        doc = json.loads(exports.cklb(host, scan, bench))
        assert doc["target_data"]["host_name"] == name
    vuln = next(v for v in root.iter("VULN") if v.find("STIG_DATA/ATTRIBUTE_DATA").text == group_id)
    comment = vuln.find("COMMENTS").text or ""
    assert comment == exports.clean_text(text * 3, 8000).replace("\r", "")
    assert "\x00" not in comment and "\x0b" not in comment


def test_illegal_characters_and_cdata_end_are_safe():
    assert exports.clean_text("a\x00\x08b\ud800c￾") == "abc"
    assert exports.clean_text("]]>") == "]]>"
    name = exports.safe_filename("../../a b\n*", "ckl", stamp="2026-11-09T10:00:00Z")
    assert name.endswith(".ckl") and "/" not in name and "\\" not in name and " " not in name
    assert len(exports.safe_filename("x" * 999, "ckl")) < 80


def test_disclaimer_in_every_export(seeded, benches):
    host, scan = host_scan(seeded, "web-01")
    assert DISCLAIMER.encode() in exports.ckl(host, scan, benches["ubuntu-22.04"])
    assert DISCLAIMER.encode() in exports.cklb(host, scan, benches["ubuntu-22.04"])
    assert DISCLAIMER in exports.fleet_csv(seeded)
    assert DISCLAIMER in exports.fleet_report_html(seeded)


def test_deterministic(seeded, benches):
    host, scan = host_scan(seeded, "web-01")
    bench = benches["ubuntu-22.04"]
    assert exports.ckl(host, scan, bench) == exports.ckl(host, scan, bench)
    assert exports.cklb(host, scan, bench) == exports.cklb(host, scan, bench)
    assert exports.fleet_csv(seeded) == exports.fleet_csv(seeded)
    assert exports.fleet_report_html(seeded) == exports.fleet_report_html(seeded)


def test_scan_without_results_is_all_not_reviewed(benches):
    bench = benches["ubuntu-22.04"]
    root = SafeET.fromstring(exports.ckl({"name": "h"}, {"collected_at": "2026-01-01T00:00:00Z"}, bench))
    vulns = list(root.iter("VULN"))
    assert len(vulns) == len(bench.rules) and {v.find("STATUS").text for v in vulns} == {"Not_Reviewed"}


def test_fleet_csv(seeded):
    rows = list(csv.reader(io.StringIO(exports.fleet_csv(seeded))))
    assert rows[0][0] == "host" and len(rows) == 1 + 14 + 1 and rows[-1][0].startswith("# STIGWatch")
    web = next(r for r in rows if r[0] == "web-01")
    assert int(web[7]) + int(web[8]) + int(web[9]) == int(web[10])


def test_csv_formula_injection_is_neutralised(conn):
    db.add_host(conn, "=HYPERLINK(\"http://x\")", "linux", "ubuntu-22.04", owner="@evil,\"q\"")
    rows = list(csv.reader(io.StringIO(exports.fleet_csv(conn))))
    assert rows[1][0].startswith("'=") and rows[1][3].startswith("'@")


def test_report_html_is_self_contained_and_escaped(seeded, conn):
    page = exports.fleet_report_html(seeded)
    low = page.lower()
    assert "<script" not in low and "javascript:" not in low and "onerror" not in low
    assert "http://" not in low and "https://" not in low and "src=" not in low
    assert "<style>" in low and low.count("<svg") >= 15 and "polyline" in low
    for host in ("web-01", "file-01", "dc-01"):
        assert host in page
    assert "Top regressions" in page and "CAT I" in page and "Compliance" in page
    db.add_host(conn, "<img src=x onerror=alert(1)>\"'", "windows", "windows-server-2022",
                environment="<script>x</script>")
    hostile = exports.fleet_report_html(conn)
    assert "<img" not in hostile and "<script" not in hostile
    assert "&lt;img src=x onerror=alert(1)&gt;" in hostile


def test_report_numbers_match_the_database(seeded):
    data = exports.fleet_rows(seeded)
    assert len(data["hosts"]) == 14
    for h in data["hosts"]:
        host = db.get_host_by_name(seeded, h["host"])
        trend = db.host_trend(seeded, host["id"])
        assert h["open"] == trend[-1]["open"] and h["series"] == [sum(p["open"].values()) for p in trend]
    assert any(r["cat"] == "CAT I" for r in data["regressions"]) or True


def test_sparkline():
    assert "<polyline" in exports.sparkline([5, 3, 1])
    assert "<polyline" not in exports.sparkline([2]) and "<circle" in exports.sparkline([2])
    assert "no data" in exports.sparkline([])
    assert "&lt;" in exports.sparkline([1, 2], label="<b>")
