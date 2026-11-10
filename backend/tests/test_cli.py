"""serve, demo, and the generated coverage tables."""

import os
import re

import pytest

from stigwatch import coverage_doc, remediation
from stigwatch.__main__ import build_parser, main
from stigwatch import benchmarks


@pytest.fixture
def server_env(monkeypatch):
    for name in ("STIGWATCH_DB", "STIGWATCH_DEMO"):
        monkeypatch.setenv(name, "x")
        monkeypatch.delenv(name)
    calls = []
    monkeypatch.setattr("uvicorn.run", lambda app, **kw: calls.append((app, kw, dict(os.environ))))
    return calls


def test_parser_defaults():
    parser = build_parser()
    demo = parser.parse_args(["demo"])
    assert demo.db is None and not demo.serve and not demo.reset and not demo.check
    serve = parser.parse_args(["serve", "--port", "9000", "--host", "0.0.0.0", "--reload"])
    assert (serve.host, serve.port, serve.reload) == ("0.0.0.0", 9000, True)
    with pytest.raises(SystemExit):
        parser.parse_args(["serve", "--port", "nope"])


def test_serve_runs_uvicorn(server_env):
    assert main(["serve", "--port", "9001"]) == 0
    app, kw, _ = server_env[0]
    assert app == "stigwatch.api:app" and kw["port"] == 9001 and kw["host"] == "127.0.0.1"


def test_demo_seeds_its_own_database_and_serves_in_demo_mode(tmp_path, server_env, capsys):
    path = tmp_path / "demo.db"
    assert main(["demo", "--db", str(path)]) == 0
    assert "14 hosts (8 linux, 6 windows), 112 scans" in capsys.readouterr().out
    assert server_env == []
    assert main(["demo", "--db", str(path)]) == 0
    assert "already holds hosts" in capsys.readouterr().out
    assert main(["demo", "--db", str(path), "--reset", "--serve"]) == 0
    app, _, env = server_env[0]
    assert env["STIGWATCH_DEMO"] == "true" and env["STIGWATCH_DB"] == str(path.resolve())


def test_demo_check_passes_on_the_committed_fixture(capsys):
    assert main(["demo", "--check"]) == 0
    assert "open counts match the fixture" in capsys.readouterr().out


def test_coverage_tables_are_current(capsys):
    assert main(["coverage", "--check"]) == 0, capsys.readouterr().err


def test_coverage_check_detects_a_stale_doc(tmp_path, monkeypatch, capsys):
    stale = tmp_path / "COVERAGE.md"
    stale.write_text("old", encoding="utf-8")
    monkeypatch.setattr(coverage_doc, "COVERAGE_DOC", stale)
    assert main(["coverage", "--check"]) == 1
    assert "docs/COVERAGE.md" in capsys.readouterr().err


def test_coverage_numbers_come_from_the_generators():
    text = coverage_doc.full_markdown()
    for bid in coverage_doc.BENCHMARKS:
        bench = benchmarks.load_benchmark(bid)
        fixes = len(remediation.automated_ids(bench))
        assert f"**{fixes}** |" in text
    # The figures quoted in the README prose (checked against the generators, not typed twice).
    readme = coverage_doc.README.read_text(encoding="utf-8")
    win = len(remediation.automated_ids(benchmarks.load_benchmark("windows-server-2022")))
    assert f"{win} of 277" in readme
    from stigwatch.checks import engine
    assert f"{len(engine.coverage('ubuntu-22.04').automated)} of 191" in readme
    ubuntu_fixes = len(remediation.automated_ids(benchmarks.load_benchmark("ubuntu-22.04")))
    win_checks = len(engine.coverage("windows-server-2022").automated)
    # every figure in the "Coverage is not full benchmark coverage" paragraph
    assert f"Ubuntu: {len(engine.coverage('ubuntu-22.04').automated)} of 191 rules have an automated check" in readme
    assert f"Windows: {win_checks} of 277 have one" in readme
    assert f"remediation is generated for {win} of 277" in readme
    assert f"Ubuntu remediation is generated for {ubuntu_fixes} of 191" in readme
    assert re.search(r"coverage:start", readme)


def test_coverage_with_a_benchmark_and_md_is_refused(capsys):
    assert main(["coverage", "--check", "ubuntu-22.04"]) == 1
    assert main(["coverage"]) == 1
