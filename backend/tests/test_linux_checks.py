"""Ubuntu 22.04 collector facts, the check engine and the linux.yml checks."""

import copy
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from stigwatch import benchmarks as bm
from stigwatch.__main__ import main
from stigwatch.checks import engine
from stigwatch.facts import linux

BACKEND = Path(__file__).resolve().parent.parent
REPO = BACKEND.parent
FIXTURES = BACKEND / "tests" / "fixtures"
COLLECTOR = REPO / "collectors" / "collect-linux.sh"

OPEN, NAF, NA, NR = engine.OPEN, engine.NOT_A_FINDING, engine.NOT_APPLICABLE, engine.NOT_REVIEWED
GUI_RULES = {"UBTU-22-271010", "UBTU-22-271015", "UBTU-22-271020", "UBTU-22-271025", "UBTU-22-271030"}
CAT1 = {
    "UBTU-22-211015", "UBTU-22-212010", "UBTU-22-215030", "UBTU-22-215035", "UBTU-22-231010",
    "UBTU-22-255010", "UBTU-22-255015", "UBTU-22-255025", "UBTU-22-255040", "UBTU-22-271030",
    "UBTU-22-432015", "UBTU-22-611060", "UBTU-22-611065", "UBTU-22-612040", "UBTU-22-671010",
    "UBTU-22-211000",
}


def load(name: str) -> dict:
    return json.loads((FIXTURES / f"linux-{name}.json").read_text(encoding="utf-8"))


def results(data: dict) -> dict[str, engine.RuleResult]:
    return {r.stig_id: r for r in engine.evaluate(data)}


@pytest.fixture(scope="module")
def bench():
    return bm.load_benchmark("ubuntu-22.04")


@pytest.fixture(scope="module")
def checkset():
    return engine.load_checks("ubuntu-22.04")


# --------------------------------------------------------------------------- catalog and coverage

def test_every_stig_id_exists_in_benchmark(bench, checkset):
    raw = engine.yaml.safe_load((engine.CHECKS_DIR / "linux.yml").read_text(encoding="utf-8"))
    ids = [c["stig_id"] for c in raw["checks"]]
    assert len(ids) == len(set(ids))
    missing = [s for s in ids if bench.rule(s) is None]
    assert missing == []
    assert set(ids) == set(checkset.checks)


def test_coverage_at_least_50_and_every_cat1(bench, checkset):
    cov = engine.coverage("ubuntu-22.04")
    automated = {s for s, _, _ in cov.automated}
    assert len(automated) >= 50
    cat1 = {r.stig_id for r in bench.rules if r.severity == "high"}
    covered = sorted(cat1 & automated)
    print("CAT I covered:", ", ".join(covered))
    assert set(covered) == CAT1 == cat1
    assert cov.by_cat["CAT I"]["manual"] == 0
    total = sum(row["total"] for row in cov.by_cat.values())
    assert total == len(bench.rules) == 191
    assert sum(row["automated"] + row["manual"] for row in cov.by_cat.values()) == 191
    # partial CAT I checks are the ones needing an organisational judgement
    kinds = {s: k for s, c, k in cov.automated if c == "CAT I"}
    assert {s for s, k in kinds.items() if k != "full"} == {"UBTU-22-432015", "UBTU-22-211000"}


def test_coverage_cli(capsys):
    assert main(["coverage", "ubuntu-22.04"]) == 0
    out = capsys.readouterr().out
    assert "174 of 191 rules automated" in out
    assert "CAT I manual: none" in out
    assert main(["coverage", "no-such-benchmark"]) == 1


def test_every_rule_gets_exactly_one_result(bench):
    out = engine.evaluate(load("compliant"))
    assert [r.stig_id for r in out] == [r.stig_id for r in bench.rules]
    assert all(r.status in engine.STATUSES for r in out)
    manual = [r for r in out if not r.automated]
    assert manual and all(r.status == NR and r.reason.startswith("Manual review") for r in manual)


def test_every_check_has_rationale_and_known_facts(checkset):
    for check in checkset.checks.values():
        assert check.rationale
        assert all(f in linux.FACTS for f in check.facts)


# --------------------------------------------------------------------------- fixtures

def test_fixtures_are_current():
    proc = subprocess.run([sys.executable, str(BACKEND / "scripts" / "make_linux_fixtures.py"), "--check"],
                          capture_output=True, text=True, cwd=BACKEND)
    assert proc.returncode == 0, proc.stderr


def test_compliant_fixture():
    res = results(load("compliant"))
    assert [s for s, r in res.items() if r.status == OPEN] == []
    for sid in CAT1 - GUI_RULES - {"UBTU-22-432015"}:
        assert res[sid].status == NAF, (sid, res[sid].reason)
    # a sudo group member always needs an organisational decision
    assert res["UBTU-22-432015"].status == NR
    assert "account-1" in str(res["UBTU-22-432015"].evidence)
    # time servers and remote audit target need a human to confirm authority
    assert res["UBTU-22-252010"].status == NR
    assert res["UBTU-22-653020"].status == NR
    # the check text makes /var/log mode not applicable when rsyslog is active and enabled
    assert res["UBTU-22-232025"].status == NA
    counts = engine.status_counts(list(res.values()))
    assert counts[NAF] >= 150


def test_noncompliant_fixture():
    res = results(load("noncompliant"))
    opens = {s for s, r in res.items() if r.status == OPEN}
    assert CAT1 - opens - GUI_RULES == {"UBTU-22-215030", "UBTU-22-255010", "UBTU-22-255015",
                                        "UBTU-22-432015", "UBTU-22-211000"}
    expected_open = {
        "UBTU-22-213010",  # dmesg_restrict 0
        "UBTU-22-213015",  # kdump-tools active
        "UBTU-22-213020",  # a saved randomize_va_space of 0
        "UBTU-22-253010",  # conflicting saved tcp_syncookies
        "UBTU-22-255020",  # no Banner
        "UBTU-22-255035",  # ClientAliveInterval 900
        "UBTU-22-255050",  # chacha20 cipher
        "UBTU-22-291015",  # wireless interface
        "UBTU-22-411010",  # root not locked
        "UBTU-22-411015",  # duplicate interactive UID
        "UBTU-22-411035",  # INACTIVE missing
        "UBTU-22-412040",  # system account with a shell
        "UBTU-22-432010", "UBTU-22-432011", "UBTU-22-654224",
        "UBTU-22-611055",  # yescrypt, no rounds
        "UBTU-22-232027",  # journal file 644
        "UBTU-22-252020",  # not UTC
        "UBTU-22-251015", "UBTU-22-251020",  # ufw inactive
    }
    assert expected_open <= opens, expected_open - opens
    # conflicting PermitUserEnvironment values are a finding, as the check text says
    ev ={e["path"]: e for e in res["UBTU-22-255025"].evidence}
    assert ev["sshd_config.permituserenvironment.value"]["observed"] is None
    # PASS_MAX_DAYS 99999: the check text and title disagree, so no verdict
    assert res["UBTU-22-411030"].status == NR
    # no smart-card PAM module installed or configured proves 631015 does not apply
    assert res["UBTU-22-631015"].status == NA
    assert res["UBTU-22-651010"].status == NR  # another integrity tool might exist


def test_open_results_carry_evidence_and_command():
    res = results(load("noncompliant"))
    r = res["UBTU-22-215035"]
    assert r.status == OPEN
    assert r.evidence[0]["fact"] == "packages"
    assert r.evidence[0]["observed"] is True
    assert r.evidence[0]["command"].startswith("dpkg-query -W")
    assert "telnetd" in r.evidence[0]["expected"]


# --------------------------------------------------------------------------- Review Focus 1

def test_unreadable_facts_not_reviewed(checkset):
    """A fact the collector could not read never decides a rule."""
    # 1. the unprivileged fixture: nothing is Open and every rule that depends only on
    #    root-only facts is Not_Reviewed and names the unreadable fact and its reason.
    data = load("unprivileged")
    facts = linux.facts(data)
    unreadable = {f for f, v in facts.items() if v["status"] != "ok"}
    assert {"shadow", "audit_rules", "sudoers", "grub_cfg", "auditd_conf"} <= unreadable
    res = results(data)
    assert [s for s, r in res.items() if r.status == OPEN] == []
    for sid, check in checkset.checks.items():
        if set(check.facts) <= unreadable:
            r = res[sid]
            assert r.status == NR, (sid, r.status)
            assert "could not be read" in r.reason, sid
            for f in check.facts:
                assert facts[f]["reason"] in r.reason
    assert "awk: cannot open /etc/shadow (Permission denied)" in res["UBTU-22-611065"].reason
    assert "requires root" in res["UBTU-22-654150"].reason

    # 2. every check, with every one of its facts unreadable, is Not_Reviewed (never Open,
    #    NotAFinding or Not_Applicable).
    base = load("compliant")
    for sid, check in checkset.checks.items():
        d = copy.deepcopy(base)
        for f in check.facts:
            if f in linux.DERIVED:
                for src in linux.DERIVED[f]:
                    d["facts"][src] = {"status": "unavailable", "value": None,
                                       "reason": "permission denied", "command": "x"}
            else:
                d["facts"][f] = {"status": "unavailable", "value": None,
                                 "reason": "permission denied", "command": "x"}
        r = results(d)[sid]
        assert r.status == NR, (sid, r.status, r.reason)
        assert "permission denied" in r.reason, sid


def test_missing_commands_on_minimal_image():
    data = load("minimal")
    res = results(data)
    for sid in ("UBTU-22-654150", "UBTU-22-654155", "UBTU-22-654230", "UBTU-22-653045"):
        assert res[sid].status == NR
        assert "auditctl not found" in res[sid].reason or "auditd.conf not found" in res[sid].reason
    assert res["UBTU-22-231010"].status == NR and "lsblk not found" in res["UBTU-22-231010"].reason
    # A readable fact can still prove a finding: auditd is not installed.
    assert res["UBTU-22-653010"].status == OPEN
    assert res["UBTU-22-651025"].status == OPEN  # no AIDE cron script at all


def test_unparsable_fact_becomes_unavailable():
    data = load("compliant")
    data["facts"]["grub_cfg"]["value"] = {"exists": True, "pbkdf2_entries": "lots"}
    data["facts"]["login_defs"]["value"] = "not an object"
    facts = linux.facts(data)
    assert facts["grub_cfg"]["status"] == "unavailable"
    assert "could not be parsed" in facts["grub_cfg"]["reason"]
    res = results(data)
    assert res["UBTU-22-212010"].status == NR
    assert res["UBTU-22-411025"].status == NR


def test_incomplete_find_only_decides_on_violations():
    data = load("compliant")
    data["facts"]["cmd_files_writable"]["value"] = {"complete": False, "count": 0, "sample": "",
                                                    "error": "find: '/usr/local/bin/x': Permission denied"}
    assert results(data)["UBTU-22-232015"].status == NR
    data["facts"]["cmd_files_writable"]["value"] = {"complete": False, "count": 1,
                                                    "sample": "777\troot\troot\t/usr/bin/evil", "error": "x"}
    assert results(data)["UBTU-22-232015"].status == OPEN


# --------------------------------------------------------------------------- Review Focus 2

def test_not_applicable_requires_fact(checkset):
    # GUI rules on a server: Not_Applicable, naming the fact that proves it.
    server = results(load("server-nogui"))
    for sid in GUI_RULES:
        r = server[sid]
        assert r.status == NA, sid
        assert "fact: gui" in r.reason
        assert r.evidence and r.evidence[0]["fact"] == "gui"
        assert r.evidence[0]["observed"] is False
    # The same rules on a workstation are evaluated.
    ws = results(load("gui"))
    for sid in GUI_RULES:
        assert ws[sid].status == NAF, (sid, ws[sid].reason)
    # Without the package fact nothing proves non-applicability: Not_Reviewed.
    data = load("server-nogui")
    data["facts"]["packages"] = {"status": "unavailable", "value": None,
                                 "reason": "dpkg-query not found", "command": "dpkg-query -W"}
    blind = results(data)
    for sid in GUI_RULES:
        assert blind[sid].status == NR, sid
    # A half-installed GUI package leaves the GUI flag unknown: still not N/A.
    data = load("server-nogui")
    data["facts"]["packages"]["value"]["text"] += "\ngdm3\tiU \t42.0-1ubuntu7"
    assert all(results(data)[s].status == NR for s in GUI_RULES)
    # A GUI workstation with a bad setting is Open, not Not_Applicable.
    data = load("gui")
    data["facts"]["gsettings"]["value"]["org.gnome.desktop.session idle-delay"]["output"] = "uint32 900"
    assert results(data)["UBTU-22-271025"].status == OPEN
    # Every na_if names gathered facts only, and the engine refuses one that does not.
    for check in checkset.checks.values():
        if check.na_if is not None:
            paths = [engine._parse_path(leaf["path"]) for leaf in engine._leaves(check.na_if)]
            assert all(p[0] in check.facts for p in paths)
    bad = {"collector": "linux", "benchmark": "ubuntu-22.04", "checks": [{
        "stig_id": "UBTU-22-271010", "facts": ["gdm_greeter"], "rationale": "x",
        "na_if": {"path": "gui.installed", "eq": False},
        "logic": {"path": "gdm_greeter.banner_enable", "eq": True}}]}
    with pytest.raises(ValueError, match="not listed in facts"):
        engine.build_checks(bad)


def test_not_applicable_from_check_text_note():
    data = load("compliant")
    old = "Names=rsyslog.service syslog.service\nLoadState=loaded\nActiveState=active"
    assert old in data["facts"]["units"]["value"]["text"]
    data["facts"]["units"]["value"]["text"] = data["facts"]["units"]["value"]["text"].replace(
        old, old.replace("ActiveState=active", "ActiveState=inactive"))
    assert results(data)["UBTU-22-232025"].status == NAF


# --------------------------------------------------------------------------- individual checks

def _sshd(data: dict, lines: list[tuple[str, str]]) -> dict:
    data["facts"]["sshd_config"]["value"] = {
        "files": sorted({p for p, _ in lines}),
        "text": "\n".join(f"{p}\t{ln}" for p, ln in lines)}
    return data


def test_sshd_directive_missing_commented_or_conflicting_is_open():
    base = [("/etc/ssh/sshd_config", "PermitEmptyPasswords no"),
            ("/etc/ssh/sshd_config", "PermitUserEnvironment no")]
    assert results(_sshd(load("compliant"), base))["UBTU-22-255025"].status == NAF
    missing = base[:1]
    assert results(_sshd(load("compliant"), missing))["UBTU-22-255025"].status == OPEN
    commented = base[:1] + [("/etc/ssh/sshd_config", "#PermitUserEnvironment no")]
    assert results(_sshd(load("compliant"), commented))["UBTU-22-255025"].status == OPEN
    conflict = base + [("/etc/ssh/sshd_config.d/50-x.conf", "permitemptypasswords yes")]
    assert results(_sshd(load("compliant"), conflict))["UBTU-22-255025"].status == OPEN
    in_match = base + [("/etc/ssh/sshd_config", "Match User backup"),
                       ("/etc/ssh/sshd_config", "PermitEmptyPasswords yes")]
    assert results(_sshd(load("compliant"), in_match))["UBTU-22-255025"].status == OPEN
    same_twice = base + [("/etc/ssh/sshd_config.d/50-x.conf", "PermitEmptyPasswords=no")]
    assert results(_sshd(load("compliant"), same_twice))["UBTU-22-255025"].status == NAF


def test_ssh_crypto_lists():
    d = _sshd(load("compliant"), [("/etc/ssh/sshd_config", "Ciphers aes256-ctr,aes128-ctr")])
    assert results(d)["UBTU-22-255050"].status == NAF  # a subset is "only" approved ciphers
    d = _sshd(load("compliant"), [(
        "/etc/ssh/sshd_config",
        "MACs hmac-sha2-256,hmac-sha2-512,hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com")])
    assert results(d)["UBTU-22-255055"].status == OPEN  # wrong order


def test_client_alive_interval_zero_is_not_decided():
    d = _sshd(load("compliant"), [("/etc/ssh/sshd_config", "ClientAliveInterval 0")])
    assert results(d)["UBTU-22-255035"].status == NR
    d = _sshd(load("compliant"), [("/etc/ssh/sshd_config", "ClientAliveInterval 300")])
    assert results(d)["UBTU-22-255035"].status == NAF


def test_banner_must_match_exactly():
    data = load("compliant")
    data["facts"]["ssh_banner"]["value"]["text"] = "Authorized users only."
    assert results(data)["UBTU-22-255020"].status == OPEN
    data = load("compliant")
    data["facts"]["ssh_banner"]["value"]["text"] = " ".join(
        data["facts"]["ssh_banner"]["value"]["text"].split())  # rewrapped, same words
    assert results(data)["UBTU-22-255020"].status == NAF


def test_banner_constant_matches_benchmark_text(bench):
    for sid in ("UBTU-22-255020", "UBTU-22-271015"):
        text = bench.rule(sid).check_text.replace("\\n", " ")
        assert linux.norm_ws(linux.DOD_BANNER) in linux.norm_ws(text), sid


def test_fips_file_missing_is_open():
    data = load("compliant")
    data["facts"]["sysctl_runtime"]["value"] = data["facts"]["sysctl_runtime"]["value"].replace(
        "crypto.fips_enabled\tok\t1", "crypto.fips_enabled\tmissing\t")
    assert results(data)["UBTU-22-671010"].status == OPEN
    data["facts"]["sysctl_runtime"]["value"] = data["facts"]["sysctl_runtime"]["value"].replace(
        "crypto.fips_enabled\tmissing\t", "crypto.fips_enabled\tunreadable\t")
    assert results(data)["UBTU-22-671010"].status == NR


def test_disk_encryption():
    data = load("compliant")
    assert results(data)["UBTU-22-231010"].status == NAF
    data["facts"]["block_devices"]["value"] += ('\nNAME="/dev/sdb" TYPE="disk" FSTYPE="" MOUNTPOINT="" PKNAME=""'
                                                '\nNAME="/dev/sdb1" TYPE="part" FSTYPE="xfs" MOUNTPOINT="" '
                                                'PKNAME="/dev/sdb"')
    assert results(data)["UBTU-22-231010"].status == NR  # unmounted plain partition: unverified
    data["facts"]["block_devices"]["value"] = data["facts"]["block_devices"]["value"].replace(
        'FSTYPE="xfs" MOUNTPOINT=""', 'FSTYPE="xfs" MOUNTPOINT="/srv"')
    r = results(data)["UBTU-22-231010"]
    assert r.status == OPEN and "/srv" in r.reason


def test_vendor_support_window():
    data = load("compliant")
    assert results(data)["UBTU-22-211000"].status == NAF
    data["collected_at"] = "2027-06-15T00:00:00Z"
    assert results(data)["UBTU-22-211000"].status == NR


def test_aide_script_compared_with_packaged_original():
    data = load("compliant")
    assert results(data)["UBTU-22-651025"].status == NAF
    data["facts"]["aide_cron"]["value"]["cron"] = "/etc/cron.daily/aide\t" + "0" * 40
    assert results(data)["UBTU-22-651025"].status == OPEN
    data["facts"]["aide_cron"]["value"]["dpkg_md5"] = "f" * 32  # packaged copy modified
    assert results(data)["UBTU-22-651025"].status == NR


def test_space_left_action_exec_needs_review():
    data = load("compliant")
    data["facts"]["auditd_conf"]["value"]["text"] = data["facts"]["auditd_conf"]["value"]["text"].replace(
        "space_left_action = email", "space_left_action = exec")
    assert results(data)["UBTU-22-653040"].status == NR
    data["facts"]["auditd_conf"]["value"]["text"] = data["facts"]["auditd_conf"]["value"]["text"].replace(
        "space_left_action = exec", "space_left_action = SYSLOG")
    assert results(data)["UBTU-22-653040"].status == OPEN


# --------------------------------------------------------------------------- audit operator

def _audit(lines: str, arg: dict):
    return linux._audit_test(linux.p_audit_rules(lines), arg)


def test_audit_rule_matching():
    exe = {"exec": "/usr/bin/su"}
    good = "-a always,exit -S all -F path=/bin/su -F perm=x -F auid>=1000 -F auid!=unset -k x"
    assert _audit(good, exe) is True  # /bin == /usr/bin, unset == -1, key ignored
    assert _audit("-a always,exit -S all -F path=/usr/bin/su -F perm=x -F auid>=1000 "
                  "-F auid!=4294967295 -F key=y", exe) is True
    assert _audit("-w /usr/bin/su -p x -k su", exe) is None  # another form: not decided
    assert _audit("No rules", exe) is False
    assert _audit("-w /etc/passwd -p wa -k x", exe) is False  # nothing mentions su
    watch = {"watch": "/var/run/utmp", "perm": "wa"}
    assert _audit("-w /run/utmp -p wa -k logins", watch) is True
    assert _audit("-w /var/run/utmp -p w -k logins", watch) is None
    sys_rule = {"syscalls": ["chmod", "fchmod", "fchmodat"]}
    both = ("-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=k\n"
            "-a always,exit -F arch=b32 -S chmod -S fchmod -F auid>=1000 -F auid!=-1 -F key=k\n"
            "-a always,exit -F arch=b32 -S fchmodat -F auid>=1000 -F auid!=-1 -F key=k")
    assert _audit(both, sys_rule) is True
    assert _audit(both.split("\n")[0], sys_rule) is None  # b32 missing
    assert _audit("-a never,exit -F arch=b64 -S chmod", sys_rule) is None
    with pytest.raises(ValueError):
        linux._audit_validate({"exec": "/x", "watch": "/y", "perm": "w"})


def test_audit_rules_in_fixtures():
    res = results(load("compliant"))
    audit_ids = [s for s, c in engine.load_checks("ubuntu-22.04").checks.items() if "audit_rules" in c.facts]
    assert len(audit_ids) >= 45
    assert all(res[s].status == NAF for s in audit_ids), [s for s in audit_ids if res[s].status != NAF]
    data = load("compliant")
    data["facts"]["audit_rules"]["value"] = "No rules"
    empty = results(data)
    assert all(empty[s].status == OPEN for s in audit_ids if s != "UBTU-22-654240")


# --------------------------------------------------------------------------- engine

def test_engine_condition_semantics():
    ops = linux.OPERATORS
    vals = {"f": {"a": None, "n": 5, "mode": "2755", "lst": [2, 2], "empty": []}}
    assert engine._eval({"path": "f.a", "eq": "x"}, vals, ops) is False  # not configured
    assert engine._eval({"path": "f.a", "unset": True}, vals, ops) is True
    assert engine._eval({"path": "f.missing", "eq": 1}, vals, ops) is None  # unknown
    assert engine._eval({"path": "g.x", "eq": 1}, vals, ops) is None
    assert engine._eval({"path": "f.mode", "perm_le": "2750"}, vals, ops) is False
    assert engine._eval({"path": "f.mode", "perm_le": "2755"}, vals, ops) is True
    assert engine._eval({"path": "f.lst", "subset": [2]}, vals, ops) is True
    assert engine._eval({"path": "f.empty", "subset": [2]}, vals, ops) is True
    assert engine._eval({"path": "f.n", "eq": "5"}, vals, ops) is None  # type mismatch
    assert engine._eval({"all": [{"path": "f.n", "eq": 6}, {"path": "f.missing", "eq": 1}]}, vals, ops) is False
    assert engine._eval({"any": [{"path": "f.n", "eq": 5}, {"path": "f.missing", "eq": 1}]}, vals, ops) is True
    assert engine._eval({"any": [{"path": "f.n", "eq": 6}, {"path": "f.missing", "eq": 1}]}, vals, ops) is None


def test_engine_rejects_bad_checks():
    def raw(**check):
        base = {"stig_id": "UBTU-22-215035", "facts": ["packages"], "rationale": "r",
                "logic": {"path": ["packages", "telnetd", "installed"], "eq": False}}
        base.update(check)
        return {"collector": "linux", "benchmark": "ubuntu-22.04", "checks": [base]}

    bench = bm.load_benchmark("ubuntu-22.04")
    engine.build_checks(raw(), bench)
    for bad, msg in (
        (raw(stig_id="UBTU-22-999999"), "not a rule"),
        (raw(facts=["nope"]), "unknown fact"),
        (raw(rationale=""), "rationale"),
        (raw(logic={"path": "packages.x", "approx": 1}), "unknown operator"),
        (raw(result_if_true="Open"), "result_if_true"),
        (raw(result_if_false="NotAFinding"), "result_if_false"),
        (raw(extra=1), "unknown keys"),
        (raw(logic={"path": "packages.x", "perm_le": "999"}), "perm_le"),
    ):
        with pytest.raises(ValueError, match=msg):
            engine.build_checks(bad, bench)


def test_evaluation_error_is_not_reviewed(monkeypatch):
    def boom(actual, arg):
        raise RuntimeError("bad value")

    op = linux.OPERATORS["audit"]
    monkeypatch.setitem(linux.OPERATORS, "audit", engine.Operator(boom, op.validate, op.describe))
    r = results(load("compliant"))["UBTU-22-654150"]
    assert r.status == NR and "RuntimeError" in r.reason


# --------------------------------------------------------------------------- envelope and CLI

@pytest.mark.parametrize("mutate, msg", [
    (lambda d: d.update(collector="windows"), "not a Linux"),
    (lambda d: d.update(version=2), "version"),
    (lambda d: d.pop("host"), "host.name"),
    (lambda d: d.update(collected_at=5), "collected_at"),
    (lambda d: d["facts"].update({"x": {"status": "maybe"}}), "invalid status"),
    (lambda d: d["facts"].update({"../x": {"status": "ok"}}), "invalid fact id"),
    (lambda d: d["facts"]["shadow"].update(command=["rm"]), "must be a string"),
])
def test_validate_rejects_bad_envelopes(mutate, msg):
    d = load("compliant")
    mutate(d)
    with pytest.raises(ValueError, match=msg):
        linux.validate(d)


def test_collect_parse_cli(capsys, tmp_path):
    assert main(["collect-parse", "linux", str(FIXTURES / "linux-unprivileged.json")]) == 0
    out = capsys.readouterr().out
    assert "47 of 63 facts read" in out
    assert "unavailable  shadow: awk: cannot open /etc/shadow (Permission denied)" in out
    assert main(["collect-parse", "linux", str(FIXTURES / "linux-unprivileged.json"), "--min-ok", "60"]) == 1
    bad = tmp_path / "bad.json"
    bad.write_bytes(b"\xff\xfe{}")
    assert main(["collect-parse", "linux", str(bad)]) == 1
    assert "invalid collector file" in capsys.readouterr().err


def test_scan_cli(capsys):
    assert main(["scan", str(FIXTURES / "linux-noncompliant.json")]) == 0
    out = capsys.readouterr().out
    assert "jammy-legacy-07: ubuntu-22.04 V2R10, 191 rules" in out
    assert "Open CAT I (10):" in out
    assert "UBTU-22-215035" in out
    assert main(["scan", str(FIXTURES / "linux-compliant.json"), "--benchmark", "windows-server-2022"]) == 1


# --------------------------------------------------------------------------- collector script

def _code_tokens(text: str) -> str:
    """The script with comments removed and quoted strings replaced by markers.

    Double-quoted strings that start with $TMP, $FACTS or $OUT become SAFE (redirect
    targets the collector may write to); other quoted strings become Q.
    """
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "#" and (i == 0 or text[i - 1] in " \t\n;"):
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "\\" and i + 1 < n:
            out.append(text[i:i + 2])
            i += 2
            continue
        if c == "'":
            j = text.index("'", i + 1)
            out.append(" Q ")
            i = j + 1
            continue
        if c == '"':
            j = i + 1
            while text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            body = text[i + 1:j]
            out.append(" SAFE " if re.match(r"\$(TMP|FACTS|OUT)\b|\$\{?(TMP|FACTS|OUT)\b", body) else " Q ")
            i = j + 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def test_collector_contains_no_write_commands():
    text = COLLECTOR.read_text(encoding="utf-8")
    assert text.startswith("#!/bin/sh\n")
    code = _code_tokens(text)
    # 1. every redirect writes only to the private temp dir, the output file or /dev/null
    for m in re.finditer(r"(?<![<>=!-])(\d?>>?)\s*(&\d|[^\s;|)&]+)", code):
        target = m.group(2)
        assert target in ("SAFE", "/dev/null") or target.startswith("&"), m.group(0)
    # 2. no command that changes the system
    forbidden = re.compile(
        r"(?<![\w./-])(mv|cp|chmod|chown|chgrp|ln|touch|mkdir|rmdir|tee|dd|truncate|install|"
        r"useradd|usermod|userdel|groupadd|groupmod|chage|chpasswd|sysctl|modprobe|insmod|rmmod|"
        r"mount|umount|apt|apt-get|dpkg|update-grub|grub-mkconfig|kill|pkill|reboot|shutdown|"
        r"crontab|dconf|service|sed\s+-i|perl|curl|wget|nc)(?![\w.-])")
    assert forbidden.findall(code) == []
    # 3. commands that can change state appear only in their read-only forms
    for line in code.splitlines():
        # fact ids passed to the emit helpers are names, not commands (e.g. "timedatectl")
        line = re.sub(r"\b(unavail|ok|text_fact|needs_root|find_fact|file_fact) \S+", r"\1", line)
        words = line.split()
        line = " ".join(words)
        if re.search(r"for t in auditctl aureport ausearch autrace auditd augenrules; do stat_line audit_tool", line):
            continue  # file names to stat, not commands
        assert "augenrules" not in words, line
        for cmd, allowed in (
            ("rm", r"rm -rf SAFE"),
            ("passwd", r"(have passwd|run passwd -S root)"),
            ("systemctl", r"(have systemctl|run systemctl show -p Id -p Names -p LoadState "
                          r"-p ActiveState -p UnitFileState \$UNITS)"),
            ("auditctl", r"(have auditctl|run auditctl Q)"),
            ("ufw", r"(have ufw|run ufw status)"),
            ("gsettings", r"(have gsettings|gsettings get \$pair)"),
            ("sshd", r"(have sshd|run sshd -T)"),
            ("dmesg", r"(have dmesg|run dmesg)"),
            ("aa-status", r"(have aa-status|run aa-status)"),
            ("timedatectl", r"(have timedatectl|run timedatectl show)"),
            ("dpkg-query", r"(have dpkg-query|run dpkg-query -W -f= Q \$PKGS)"),
            ("lsblk", r"(have lsblk|run lsblk -P -p -o NAME,TYPE,FSTYPE,MOUNTPOINT,PKNAME)"),
        ):
            if cmd in words:
                assert re.search(allowed, line), line.strip()
    # auditctl only ever receives -l or -s
    assert re.search(r'for spec in "audit_rules:-l" "audit_status:-s"; do', text)
    assert len(re.findall(r'run auditctl "\$flag"', text)) == 1


def test_collector_never_outputs_hashes():
    text = COLLECTOR.read_text(encoding="utf-8")
    shadow_lines = [ln for ln in text.splitlines() if "/etc/shadow" in ln and not ln.lstrip().startswith("#")]
    assert shadow_lines, "collector reads /etc/shadow"
    for ln in shadow_lines:
        assert "cat /etc/shadow" not in ln
        if "awk" in ln:
            assert "print $2" not in ln and "print $0" not in ln
    grub = [ln for ln in text.splitlines() if "grub.cfg" in ln and "grep" in ln]
    assert all("-c" in ln for ln in grub if "password" in ln)


def _sh() -> str | None:
    return shutil.which("sh")


def _function(name: str) -> str:
    text = COLLECTOR.read_text(encoding="utf-8")
    m = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", text, re.S | re.M)
    assert m, name
    return m.group(0)


@pytest.mark.skipif(_sh() is None, reason="no POSIX sh available")
def test_collector_json_escaper(tmp_path):
    # The function is run from a file: passing it with "sh -c" would expose it to the
    # Windows command-line quoting rules on developer machines.
    # STIGWATCH_TEST_AWK=mawk (set in CI) runs the escaper under that awk implementation.
    awk = os.environ.get("STIGWATCH_TEST_AWK")
    if awk:
        assert shutil.which(awk), f"{awk} is not installed"
    prefix = f'awk() {{ {awk} "$@"; }}\n' if awk else ""
    script = tmp_path / "jstr.sh"
    script.write_text(prefix + "ESCAPER=awk\n" + _function("jstr") + "jstr\n", encoding="utf-8",
                      newline="\n")
    tricky = 'quote " back\\slash\ttab\rCR \x01ctl \x1f é ünï 中文 {"a": [1]}\n\nlast'
    proc = subprocess.run([_sh(), str(script)], input=tricky.encode("utf-8"),
                          capture_output=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout.decode("utf-8")) == tricky
    empty = subprocess.run([_sh(), str(script)], input=b"", capture_output=True, timeout=60)
    assert json.loads(empty.stdout) == ""


@pytest.mark.skipif(not sys.platform.startswith("linux") or _sh() is None
                    or os.environ.get("STIGWATCH_RUN_COLLECTOR") != "1",
                    reason="Linux only; set STIGWATCH_RUN_COLLECTOR=1 (the CI linux-collector job does)")
def test_collector_runs_on_linux(tmp_path):
    out = tmp_path / "out.json"
    proc = subprocess.run([_sh(), str(COLLECTOR), "-o", str(out), "-r"], capture_output=True, text=True,
                          timeout=900, cwd=tmp_path)
    assert proc.returncode == 0, proc.stderr
    data = json.loads(out.read_text(encoding="utf-8"))
    linux.validate(data)
    assert set(linux.PARSERS) <= set(data["facts"])
    assert list(tmp_path.iterdir()) == [out]
    results_ = engine.evaluate(data)
    assert len(results_) == 191
    if os.geteuid() != 0:
        assert data["facts"]["shadow"]["status"] == "unavailable"


@pytest.mark.skipif(not sys.platform.startswith("linux") or _sh() is None
                    or (hasattr(os, "geteuid") and os.geteuid() == 0), reason="Linux, non-root only")
def test_collector_path_state_tells_denied_from_absent(tmp_path):
    locked = tmp_path / "locked"
    locked.mkdir()
    (locked / "file").write_text("x")
    locked.chmod(0)
    try:
        script = _function("path_state") + 'path_state "$1"; path_state "$2"; path_state "$3"\n'
        proc = subprocess.run([_sh(), "-c", script, "sh", str(locked / "file"), str(tmp_path / "nope"),
                               str(tmp_path)], capture_output=True, text=True, timeout=60)
        assert proc.stdout.split() == ["denied", "absent", "present"]
    finally:
        locked.chmod(0o700)
