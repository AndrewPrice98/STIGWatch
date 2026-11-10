import json
import re
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from stigwatch import benchmarks as bm
from stigwatch.__main__ import main

BACKEND = Path(__file__).resolve().parent.parent
SOURCES = Path(r"D:\Projects\_plans\security-five\sdd\stigwatch\sources")

EXPECTED = {
    "ubuntu-22.04": ("2", "10", "2026-09-30", 191, (16, 158, 17)),
    "windows-server-2022": ("2", "11", "2026-09-30", 277, (31, 235, 11)),
}

FIXTURE_XCCDF = """<?xml version="1.0" encoding="utf-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="Test_Product_STIG">
<status date="2026-01-01">accepted</status><title>Test Product STIG</title>
<plain-text id="release-info">Release: 3 Benchmark Date: 05 Jan 2026</plain-text><version>1</version>
<Group id="V-1"><title>SRG-1</title><description>&lt;GroupDescription&gt;&lt;/GroupDescription&gt;</description>
<Rule id="SV-1r1_rule" weight="10.0" severity="high"><version>TEST-00-000001</version><title>Disable the thing &amp; more.</title>
<description>&lt;VulnDiscussion&gt;Thing is risky &amp;amp; bad.&lt;/VulnDiscussion&gt;&lt;IAControls&gt;&lt;/IAControls&gt;</description>
<ident system="http://cyber.mil/cci">CCI-000366</ident><ident system="http://other">X-1</ident>
<fixtext fixref="F-1">Run: disable thing</fixtext>
<check system="C-1"><check-content-ref href="x" name="M"/><check-content>Verify thing is off.
If not, this is a finding.</check-content></check></Rule></Group>
<Group id="V-2"><title>SRG-2</title><description>&lt;GroupDescription&gt;&lt;/GroupDescription&gt;</description>
<Rule id="SV-2r1_rule" weight="10.0" severity="low"><version>TEST-00-000002</version><title>Second.</title>
<description>&lt;VulnDiscussion&gt;Second discussion.&lt;/VulnDiscussion&gt;</description>
<ident system="http://cyber.mil/cci">CCI-000001</ident><ident system="http://cyber.mil/cci">CCI-000002</ident>
<fixtext fixref="F-2">Fix it</fixtext>
<check system="C-2"><check-content>Check it</check-content></check></Rule></Group>
</Benchmark>"""


@pytest.fixture
def fixture_zip(tmp_path):
    p = tmp_path / "U_Test_V1R3_STIG.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("U_Test_V1R3_Manual_STIG/U_Test_STIG_V1R3_Manual-xccdf.xml", FIXTURE_XCCDF)
        zf.writestr("readme.txt", "ignored")
    return p


@pytest.fixture(autouse=True)
def isolated_user_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("STIGWATCH_DATA_DIR", str(tmp_path / "userdata"))


def test_list_benchmarks():
    assert bm.list_benchmarks() == ["ubuntu-22.04", "windows-server-2022"]


@pytest.mark.parametrize("bid", sorted(EXPECTED))
def test_catalog_metadata_and_counts(bid):
    version, release, date, total, (hi, med, lo) = EXPECTED[bid]
    b = bm.load_benchmark(bid)
    assert (b.version, b.release, b.date) == (version, release, date)
    assert len(b.rules) == total
    assert b.counts() == {"high": hi, "medium": med, "low": lo}
    assert b.source_url.startswith("https://dl.dod.cyber.mil/")
    assert b.data["counts"] == b.counts()


@pytest.mark.parametrize("bid", sorted(EXPECTED))
def test_ids_unique_and_well_formed(bid):
    b = bm.load_benchmark(bid)
    for attr in ("group_id", "rule_id", "stig_id"):
        vals = [getattr(r, attr) for r in b.rules]
        assert len(vals) == len(set(vals)), attr
    assert all(re.fullmatch(r"V-\d+", r.group_id) for r in b.rules)
    assert all(re.fullmatch(r"SV-\d+r\d+_rule", r.rule_id) for r in b.rules)
    prefix = "UBTU-22-" if bid == "ubuntu-22.04" else "WN22-"
    assert all(r.stig_id.startswith(prefix) for r in b.rules)


@pytest.mark.parametrize("bid", sorted(EXPECTED))
def test_every_rule_has_text_and_ccis(bid):
    b = bm.load_benchmark(bid)
    assert not b.metadata_only
    for r in b.rules:
        assert r.check_text and r.fix_text and r.discussion and r.title, r.stig_id
        assert r.ccis, r.stig_id
        assert "<VulnDiscussion>" not in r.discussion


def test_rule_lookup():
    b = bm.load_benchmark("ubuntu-22.04")
    r = b.rule("UBTU-22-211015")
    assert r and r.severity == "high" and r.cat == "CAT I" and r.group_id == "V-260469"
    assert r.rule_id.startswith("SV-260469r") and "CCI-000366" in r.ccis
    assert "Ctrl-Alt-Delete" in r.title
    assert b.rule("NOPE-00-000000") is None


def test_unknown_or_hostile_id():
    for bad in ("nope", "../ubuntu-22.04", "a/b", ""):
        with pytest.raises(bm.BenchmarkError):
            bm.load_benchmark(bad)


@pytest.mark.skipif(not (SOURCES / "ubuntu.zip").exists(), reason="official zips not present")
@pytest.mark.parametrize(
    "zipname,bid", [("ubuntu.zip", "ubuntu-22.04"), ("win.zip", "windows-server-2022")]
)
def test_matches_official_xccdf_and_rebuild_reproducible(zipname, bid):
    # Independent raw count of Rule elements by severity, straight from the XCCDF text.
    blob, _ = bm.read_xccdf_from_zip(SOURCES / zipname)
    text = blob.decode("utf-8")
    raw = {
        s: len(re.findall(rf'<Rule id="[^"]+" weight="[^"]*" severity="{s}"', text))
        for s in bm.SEVERITIES
    }
    assert bm.load_benchmark(bid).counts() == raw
    # Rebuild equals committed JSON (the scripts/build_benchmarks.py --check logic).
    rebuilt = bm.build_from_zip(SOURCES / zipname)
    rebuilt["source_url"] = bm.load_benchmark(bid).source_url
    assert bm.dumps(rebuilt) == (bm.BUNDLED_DIR / f"{bid}.json").read_text(encoding="utf-8")


def test_import_fixture(fixture_zip, tmp_path, capsys):
    out = tmp_path / "out"
    rc = main([
        "benchmarks", "import", str(fixture_zip), "--out", str(out),
        "--source-url", "https://example.test/x.zip",
    ])
    assert rc == 0
    expected = "test_product_stig V1R3: 2 rules (CAT I 1, CAT II 0, CAT III 1)"
    assert expected in capsys.readouterr().out
    b = bm.load_benchmark_file(out / "test_product_stig.json")
    assert (b.version, b.release, b.date) == ("1", "3", "2026-01-05")
    r = b.rule("TEST-00-000001")
    assert r.title == "Disable the thing & more."
    assert r.discussion == "Thing is risky & bad."
    assert r.check_text == "Verify thing is off.\nIf not, this is a finding."
    assert r.fix_text == "Run: disable thing"
    assert r.ccis == ("CCI-000366",)
    assert b.rule("TEST-00-000002").ccis == ("CCI-000001", "CCI-000002")
    assert b.source_url == "https://example.test/x.zip"


def test_import_default_user_dir(fixture_zip):
    assert main(["benchmarks", "import", str(fixture_zip)]) == 0
    assert "test_product_stig" in bm.list_benchmarks()
    assert bm.load_benchmark("test_product_stig").release == "3"


def test_import_rejects_bad_input(tmp_path, capsys):
    out = tmp_path / "o"
    bad = tmp_path / "bad.zip"
    bad.write_bytes(b"not a zip")
    assert main(["benchmarks", "import", str(bad), "--out", str(out)]) == 1
    assert "import failed" in capsys.readouterr().err
    empty = tmp_path / "empty.zip"
    with zipfile.ZipFile(empty, "w") as zf:
        zf.writestr("a.txt", "x")
    assert main(["benchmarks", "import", str(empty), "--out", str(out)]) == 1
    assert not out.exists() or not list(out.glob("*.json"))


def test_import_refuses_xml_entities(tmp_path):
    evil = FIXTURE_XCCDF.replace(
        "<Benchmark", '<!DOCTYPE b [<!ENTITY x "boom">]><Benchmark', 1
    ).replace("Disable the thing", "Disable &x;")
    z = tmp_path / "evil.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("evil-xccdf.xml", evil)
    with pytest.raises(bm.BenchmarkError):
        bm.build_from_zip(z)


def test_check_cli_prints_counts(capsys):
    assert main(["benchmarks", "--check"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert "ubuntu-22.04 V2R10: 191 rules (CAT I 16, CAT II 158, CAT III 17)" in out
    assert "windows-server-2022 V2R11: 277 rules (CAT I 31, CAT II 235, CAT III 11)" in out


def test_check_module_invocation():
    p = subprocess.run(
        [sys.executable, "-m", "stigwatch", "benchmarks", "--check"],
        cwd=BACKEND, capture_output=True, text=True,
    )
    assert p.returncode == 0 and "191 rules" in p.stdout


def _tamper(tmp_path, mutate):
    data = json.loads((bm.BUNDLED_DIR / "ubuntu-22.04.json").read_text(encoding="utf-8"))
    mutate(data)
    d = tmp_path / "t"
    d.mkdir()
    (d / "ubuntu-22.04.json").write_text(json.dumps(data), encoding="utf-8")
    return d


@pytest.mark.parametrize("mutate", [
    lambda d: d["rules"].append(dict(d["rules"][0])),   # duplicate ids
    lambda d: d["rules"][0].update(severity="medium"),  # counts mismatch
    lambda d: d["rules"][0].update(check_text=""),      # missing check text
    lambda d: d["rules"][0].update(fix_text="  "),      # missing fix text
    lambda d: d["rules"][0].pop("stig_id"),             # required field
    lambda d: d["rules"][0].update(severity="critical"),  # bad severity
])
def test_check_detects_tampering(tmp_path, mutate):
    d = _tamper(tmp_path, mutate)
    assert main(["benchmarks", "--check", "--dir", str(d)]) == 1


def test_metadata_only_flag_allows_missing_text(tmp_path):
    def m(d):
        d["metadata_only"] = True
        for r in d["rules"]:
            r["check_text"] = r["fix_text"] = r["discussion"] = ""

    d = _tamper(tmp_path, m)
    assert main(["benchmarks", "--check", "--dir", str(d)]) == 0
