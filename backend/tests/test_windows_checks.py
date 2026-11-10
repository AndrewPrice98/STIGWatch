"""Windows Server 2022 collector facts, the windows.yml checks and the collector script."""

import copy
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from stigwatch import benchmarks as bm
from stigwatch.__main__ import main
from stigwatch.checks import engine
from stigwatch.facts import linux, windows

BACKEND = Path(__file__).resolve().parent.parent
REPO = BACKEND.parent
FIXTURES = BACKEND / "tests" / "fixtures"
COLLECTOR = REPO / "collectors" / "collect-windows.ps1"

OPEN, NAF, NA, NR = engine.OPEN, engine.NOT_A_FINDING, engine.NOT_APPLICABLE, engine.NOT_REVIEWED
BID = "windows-server-2022"

# CAT I rules the facts can decide (Open or NotAFinding).
CAT1_FULL = {
    "WN22-00-000130", "WN22-00-000250", "WN22-AC-000090", "WN22-CC-000210", "WN22-CC-000220",
    "WN22-CC-000230", "WN22-CC-000430", "WN22-CC-000470", "WN22-CC-000500", "WN22-DC-000070",
    "WN22-DC-000080", "WN22-MS-000140", "WN22-SO-000020", "WN22-SO-000210", "WN22-SO-000220",
    "WN22-SO-000230", "WN22-SO-000250", "WN22-SO-000300", "WN22-SO-000310", "WN22-UR-000020",
    "WN22-UR-000060", "WN22-UR-000100",
}
# CAT I rules that need a human: applicability (DC vs member) is still decided from facts.
CAT1_EVIDENCE = {
    "WN22-DC-000010", "WN22-DC-000090", "WN22-DC-000100", "WN22-DC-000110", "WN22-DC-000150",
    "WN22-DC-000290", "WN22-DC-000300",
}
# CAT I rules with one decisive outcome (Open); the other outcome needs a human.
CAT1_PARTIAL = {"WN22-MS-000010"}
CAT1_MANUAL = {"WN22-00-000030"}
DC_CAT1 = {s for s in CAT1_FULL | CAT1_EVIDENCE if s.startswith("WN22-DC-")}
ALL_CAT1 = CAT1_FULL | CAT1_PARTIAL | CAT1_EVIDENCE | CAT1_MANUAL


def load(name: str) -> dict:
    return json.loads((FIXTURES / f"windows-{name}.json").read_text(encoding="utf-8"))


def results(data: dict) -> dict[str, engine.RuleResult]:
    return {r.stig_id: r for r in engine.evaluate(data)}


def unavailable(reason: str = "permission denied") -> dict:
    return {"status": "unavailable", "value": None, "reason": reason, "command": "x"}


def reg_entry(data: dict, key: str, name: str) -> dict:
    for e in data["facts"]["registry"]["value"]["values"]:
        if e["key"] == key and e["name"] == name:
            return e
    raise KeyError((key, name))


@pytest.fixture(scope="module")
def bench():
    return bm.load_benchmark(BID)


@pytest.fixture(scope="module")
def checkset():
    return engine.load_checks(BID)


# --------------------------------------------------------------------------- catalog and coverage

def test_every_stig_id_exists_in_benchmark(bench, checkset):
    raw = engine.yaml.safe_load((engine.CHECKS_DIR / "windows.yml").read_text(encoding="utf-8"))
    ids = [c["stig_id"] for c in raw["checks"]]
    assert len(ids) == len(set(ids))
    assert [s for s in ids if bench.rule(s) is None] == []
    assert set(ids) == set(checkset.checks)
    assert raw["collector"] == "windows" and checkset.collector == "windows"


def test_coverage_at_least_50_and_every_host_checkable_cat1(bench):
    cov = engine.coverage(BID)
    kinds = {s: k for s, _, k in cov.automated}
    decisive = {s for s, k in kinds.items() if k != "evidence"}
    assert len(decisive) >= 50
    cat1 = {r.stig_id for r in bench.rules if r.severity == "high"}
    assert len(cat1) == 31 == len(ALL_CAT1)
    assert cat1 == ALL_CAT1
    print("CAT I decided from facts:", ", ".join(sorted(CAT1_FULL)))
    assert {s for s in cat1 if kinds.get(s) == "full"} == CAT1_FULL
    assert {s for s in cat1 if kinds.get(s) == "partial"} == CAT1_PARTIAL
    assert {s for s in cat1 if kinds.get(s) == "evidence"} == CAT1_EVIDENCE
    assert {s for s, c in cov.manual if c == "CAT I"} == CAT1_MANUAL
    assert sum(row["total"] for row in cov.by_cat.values()) == len(bench.rules) == 277


def test_coverage_cli(capsys):
    assert main(["coverage", BID]) == 0
    out = capsys.readouterr().out
    assert re.search(r"windows-server-2022 V2R11: \d+ of 277 rules automated \(\d+ can decide a result, "
                     r"\d+ evidence or applicability only\), \d+ manual review", out)
    assert "CAT I manual: WN22-00-000030" in out


def test_every_rule_gets_exactly_one_result(bench):
    out = engine.evaluate(load("member-compliant"))
    assert [r.stig_id for r in out] == [r.stig_id for r in bench.rules]
    assert all(r.status in engine.STATUSES for r in out)
    manual = [r for r in out if not r.automated]
    assert manual and all(r.status == NR and r.reason.startswith("Manual review") for r in manual)


def test_every_check_has_rationale_and_known_facts(checkset):
    for check in checkset.checks.values():
        assert check.rationale
        assert all(f in windows.FACTS for f in check.facts)


def _registry_paths(cond) -> set[tuple[str, str]]:
    out = set()
    for leaf in engine._leaves(cond):
        p = engine._parse_path(leaf["path"])
        if p[0] == "registry":
            out.add((p[1], p[2]))
    return out


def test_every_registry_value_checked_is_collected(checkset):
    collected = {(f"{h}\\{k}", n) for h, k, n in
                 re.findall(r"@\('(HKLM|HKCU)', '([^']+)', '([^']+)'\)", COLLECTOR.read_text(encoding="utf-8"))}
    used = set()
    for check in checkset.checks.values():
        for cond in (check.logic, check.na_if, check.unmet_if):
            if cond is not None:
                used |= _registry_paths(cond)
        used |= {(p[1], p[2]) for p in check.observe if p[0] == "registry"}
    assert used and used <= collected, sorted(used - collected)


# --------------------------------------------------------------------------- fixtures

def test_fixtures_are_current():
    proc = subprocess.run([sys.executable, str(BACKEND / "scripts" / "make_windows_fixtures.py"), "--check"],
                          capture_output=True, text=True, cwd=BACKEND)
    assert proc.returncode == 0, proc.stderr


def test_compliant_member_fixture():
    res = results(load("member-compliant"))
    assert [s for s, r in res.items() if r.status == OPEN] == []
    for sid in CAT1_FULL - DC_CAT1:
        assert res[sid].status == NAF, (sid, res[sid].reason)
    for sid in DC_CAT1:
        assert res[sid].status == NA, sid
    # human decisions: local Administrators members, DoD certificates, transcript folder
    for sid in ("WN22-MS-000010", "WN22-PK-000010", "WN22-CC-000530", "WN22-CC-000280", "WN22-UC-000010"):
        assert res[sid].status == NR, sid
    assert "Server Admins - APP" in str(res["WN22-MS-000010"].evidence)
    counts = engine.status_counts(list(res.values()))
    assert counts[NAF] >= 190


def test_noncompliant_fixture():
    res = results(load("noncompliant"))
    opens = {s for s, r in res.items() if r.status == OPEN}
    assert CAT1_FULL - DC_CAT1 - opens == {"WN22-CC-000470", "WN22-SO-000020", "WN22-SO-000220",
                                            "WN22-SO-000230", "WN22-SO-000250", "WN22-UR-000060"}
    expected = {
        "WN22-AC-000020", "WN22-AC-000050", "WN22-AC-000060", "WN22-AC-000070", "WN22-AC-000090",
        "WN22-SO-000010", "WN22-SO-000030", "WN22-SO-000210", "WN22-SO-000130", "WN22-SO-000120",
        "WN22-UR-000020", "WN22-UR-000100", "WN22-MS-000070", "WN22-MS-000080", "WN22-MS-000050",
        "WN22-AU-000070", "WN22-AU-000080", "WN22-AU-000200", "WN22-AU-000040", "WN22-AU-000060",
        "WN22-00-000130", "WN22-00-000250", "WN22-00-000090", "WN22-00-000470", "WN22-00-000360",
        "WN22-00-000380", "WN22-00-000390", "WN22-00-000410", "WN22-00-000200", "WN22-00-000020",
        "WN22-00-000440", "WN22-CC-000130", "WN22-CC-000310", "WN22-CC-000280", "WN22-UC-000010",
        "WN22-CC-000110", "WN22-MS-000140",
    }
    assert expected <= opens, sorted(expected - opens)
    # Only the check text's finding values are Open; anything else needs review.
    assert res["WN22-00-000370"].status == NR      # TFTP-Client InstallPending
    assert res["WN22-SO-000320"].status == NR      # LDAP client signing 2 (stricter)
    assert res["WN22-AC-000010"].status == NR      # lockout duration not exported (no threshold)
    assert res["WN22-AC-000030"].status == NR
    assert res["WN22-00-000190"].status == NR      # an inactive account may be an application account
    assert res["WN22-00-000210"].status == NR
    assert res["WN22-AU-000240"].status == NR      # removable storage: VM / NAS exception
    assert res["WN22-00-000280"].status == NR      # a disabled profile: a third-party firewall may exist


def test_open_results_carry_evidence_and_command():
    r = results(load("noncompliant"))["WN22-SO-000300"]
    assert r.status == OPEN
    ev = r.evidence[0]
    assert ev["fact"] == "registry"
    assert ev["observed"] is None
    assert ev["path"] == r"registry[HKLM\SYSTEM\CurrentControlSet\Control\Lsa].NoLMHash.value"
    assert ev["command"].startswith("registry (read-only")
    r = results(load("noncompliant"))["WN22-UR-000020"]
    assert r.evidence[0]["command"].startswith("secedit /export /cfg")


# --------------------------------------------------------------------------- Review Focus 1

def test_unreadable_facts_not_reviewed(checkset):
    """A fact the collector could not read never decides a rule."""
    data = load("unprivileged")
    facts = windows.facts(data)
    unreadable = {f for f, v in facts.items() if v["status"] != "ok"}
    assert {"security_policy", "user_rights", "audit_policy", "features", "bitlocker", "tpm",
            "secure_boot"} == unreadable
    res = results(data)
    assert [s for s, r in res.items() if r.status == OPEN] == []
    for sid, check in checkset.checks.items():
        if set(check.facts) <= unreadable:
            r = res[sid]
            assert r.status == NR, (sid, r.status)
            assert "could not be read" in r.reason, sid
            for f in check.facts:
                assert facts[f]["reason"] in r.reason
    assert "requires elevation" in res["WN22-AC-000090"].reason
    assert "A required privilege is not held" in res["WN22-AU-000070"].reason
    # one registry value denied: that rule is unknown and says why; the others are decided
    r = res["WN22-SO-000250"]
    assert r.status == NR and "Requested registry access is not allowed" in r.reason
    assert res["WN22-SO-000220"].status == NAF
    # event log files whose permissions could not be read
    assert res["WN22-AU-000030"].status == NR and "unauthorized operation" in r.reason + res["WN22-AU-000030"].reason
    # the SMBv1 registry rules: applicability rests on the feature list, which is unreadable
    assert res["WN22-00-000390"].status == NR

    # Every check, with every one of its facts unreadable, is Not_Reviewed (never Open,
    # NotAFinding or Not_Applicable).
    base = load("member-compliant")
    for sid, check in checkset.checks.items():
        d = copy.deepcopy(base)
        for f in check.facts:
            for src in windows.DERIVED.get(f, (f,)):
                d["facts"][src] = unavailable()
        r = results(d)[sid]
        assert r.status == NR, (sid, r.status, r.reason)
        assert "permission denied" in r.reason, sid


def test_non_english_auditpol_is_unavailable(checkset):
    data = load("non-english")
    fact = windows.facts(data)["audit_policy"]
    assert fact["status"] == "unavailable" and "not English" in fact["reason"]
    res = results(data)
    audit_rules = [s for s, c in checkset.checks.items() if c.facts == ("audit_policy",)]
    assert len(audit_rules) >= 35
    for sid in audit_rules:
        assert res[sid].status == NR and "not English" in res[sid].reason
    # The numeric setting from 'auditpol /backup' needs no translation.
    data["facts"]["audit_policy"]["value"]["source"] = "backup"
    for row in data["facts"]["audit_policy"]["value"]["subcategories"]:
        row["setting_value"] = "3"
    assert results(data)["WN22-AU-000070"].status == NAF
    # A setting outside 0-3 is not guessed at.
    data["facts"]["audit_policy"]["value"]["subcategories"][0]["setting_value"] = "9"
    assert windows.facts(data)["audit_policy"]["status"] == "unavailable"


def test_user_right_granted_to_a_name_is_unknown():
    data = load("noncompliant")
    data["facts"]["user_rights"]["value"]["SeDebugPrivilege"] = "*S-1-5-32-544,svc-tools"
    data["facts"]["user_rights"]["value"]["SeTcbPrivilege"] = "account-3"
    res = results(data)
    for sid in ("WN22-UR-000100", "WN22-UR-000020"):
        assert res[sid].status == NR, sid
        assert "names rather than SIDs" in res[sid].reason
    # A right nobody holds is absent from the export; that is only trusted when the
    # section lists known rights at all.
    data["facts"]["user_rights"]["value"] = {"SeUnknownRight": "*S-1-5-18"}
    assert windows.facts(data)["user_rights"]["status"] == "unavailable"


def test_unparsable_fact_becomes_unavailable():
    data = load("member-compliant")
    data["facts"]["security_policy"]["value"]["System Access"]["MinimumPasswordLength"] = "fourteen"
    data["facts"]["domain_role"]["value"]["domain_role"] = 9
    facts = windows.facts(data)
    assert facts["security_policy"]["status"] == "unavailable"
    assert "could not be parsed" in facts["security_policy"]["reason"]
    assert facts["domain_role"]["status"] == "unavailable"
    res = results(data)
    assert res["WN22-AC-000070"].status == NR
    assert res["WN22-DC-000070"].status == NR  # applicability unknown


def test_registry_types_and_states():
    data = load("member-compliant")
    e = reg_entry(data, r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", "NoLMHash")
    # A REG_SZ "1" where the check text asks for REG_DWORD 1 is not treated as compliant.
    e.update(type="String", data="1")
    assert results(data)["WN22-SO-000300"].status == NR
    # .NET reports large DWORDs as negative numbers.
    e.update(type="DWord", data=-1)
    value = windows.facts(data)["registry"]["value"][r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa"]["NoLMHash"]
    assert value["value"] == 0xFFFFFFFF
    assert results(data)["WN22-SO-000300"].status == OPEN
    # absent (not configured) is a finding when the check text says so
    e.clear()
    e.update(key=r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", name="NoLMHash", state="absent")
    assert results(data)["WN22-SO-000300"].status == OPEN
    # ... and not when it says a missing value is not a finding
    e = reg_entry(data, r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer", "NoDataExecutionPrevention")
    assert e["state"] == "absent"
    assert results(data)["WN22-CC-000310"].status == NAF
    e.update(state="set", type="DWord", data=1)
    assert results(data)["WN22-CC-000310"].status == OPEN
    e.update(data=5)
    assert results(data)["WN22-CC-000310"].status == NR
    # an unknown registry state makes the whole fact unavailable rather than guessing
    e.update(state="weird")
    assert windows.facts(data)["registry"]["status"] == "unavailable"


def test_banner_must_match(bench):
    text = bench.rule("WN22-SO-000130").check_text
    assert linux.norm_ws(linux.DOD_BANNER) in linux.norm_ws(text)
    data = load("member-compliant")
    e = reg_entry(data, r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "LegalNoticeText")
    e["data"] = e["data"].replace("\r\n", "\n\n  ") + "\x00"
    assert results(data)["WN22-SO-000130"].status == NAF
    e["data"] = e["data"].replace("USG-authorized", "authorized")
    assert results(data)["WN22-SO-000130"].status == OPEN


# --------------------------------------------------------------------------- Review Focus 2

def test_not_applicable_requires_fact(checkset):
    dc_rules = {s for s, c in checkset.checks.items()
                if c.na_if == {"path": "domain_role.role", "ne": "dc"}}
    member_rules = {s for s, c in checkset.checks.items()
                    if c.na_if is not None and "domain_role" in json.dumps(c.na_if)
                    and s.startswith("WN22-MS-")}
    assert len(dc_rules) >= 40 and len(member_rules) >= 12
    member, dc = results(load("member-compliant")), results(load("dc"))
    for sid in dc_rules:
        r = member[sid]
        assert r.status == NA, sid
        assert "fact: domain_role" in r.reason
        assert r.evidence[0]["fact"] == "domain_role" and r.evidence[0]["observed"] == "member"
        assert dc[sid].status in (NAF, NR), (sid, dc[sid].status)
    for sid in member_rules:
        assert dc[sid].status == NA, sid
        assert "fact: domain_role" in dc[sid].reason
    for sid in DC_CAT1:
        assert member[sid].status == NA
    assert dc["WN22-DC-000070"].status == NAF and dc["WN22-DC-000080"].status == NAF
    assert dc["WN22-DC-000030"].status == NAF and dc["WN22-DC-000370"].status == NAF
    # Without the domain role nothing proves non-applicability: Not_Reviewed.
    data = load("member-compliant")
    data["facts"]["domain_role"] = unavailable("Get-CimInstance failed: RPC server unavailable")
    blind = results(data)
    for sid in dc_rules | member_rules:
        assert blind[sid].status == NR, sid
        assert "RPC server unavailable" in blind[sid].reason
    # A domain controller rule on a domain controller with a bad setting is Open, not N/A.
    data = load("dc")
    data["facts"]["user_rights"]["value"]["SeMachineAccountPrivilege"] = "*S-1-5-32-544,*S-1-5-11"
    assert results(data)["WN22-DC-000350"].status == OPEN
    # Every na_if names gathered facts only, and the engine refuses one that does not.
    for check in checkset.checks.values():
        if check.na_if is not None:
            paths = [engine._parse_path(leaf["path"]) for leaf in engine._leaves(check.na_if)]
            assert all(p[0] in check.facts for p in paths)
    bad = {"collector": "windows", "benchmark": BID, "checks": [{
        "stig_id": "WN22-DC-000320", "facts": ["registry"], "rationale": "x",
        "na_if": {"path": "domain_role.role", "ne": "dc"},
        "logic": {"path": ["registry", "HKLM\\X", "Y", "value"], "eq": 2}}]}
    with pytest.raises(ValueError, match="not listed in facts"):
        engine.build_checks(bad)


def test_standalone_and_exchange_applicability():
    res = results(load("standalone"))
    assert res["WN22-MS-000080"].status == NAF      # Guests only on a standalone system
    assert res["WN22-MS-000100"].status == NAF      # empty on a standalone system
    for sid in ("WN22-MS-000020", "WN22-MS-000030", "WN22-MS-000050", "WN22-MS-000140",
                "WN22-CC-000080", "WN22-CC-000110"):
        assert res[sid].status == NA, sid
    assert res["WN22-00-000020"].status == NAF      # standalone: no LAPS portion, password 69 days old
    data = load("member-compliant")
    data["facts"]["services"]["value"]["MSExchangeServiceHost"] = {"present": True, "status": "Running",
                                                                    "start_type": "Automatic"}
    data["facts"]["device_guard"]["value"]["security_services_running"] = [0]
    assert results(data)["WN22-MS-000140"].status == NA
    # Server Core: UAC rules and Eventvwr.exe are not applicable.
    data = load("member-compliant")
    data["facts"]["os"]["value"]["installation_type"] = "Server Core"
    res = results(data)
    assert res["WN22-SO-000440"].status == NA and res["WN22-AU-000060"].status == NA


# --------------------------------------------------------------------------- individual checks

def test_volumes():
    data = load("member-compliant")
    vols = data["facts"]["volumes"]["value"]
    assert results(data)["WN22-00-000130"].status == NAF
    # Without partition types an unlettered FAT32 system volume is still excluded...
    vols["partition_types_read"] = False
    for v in vols["volumes"]:
        v.pop("partition_type")
    assert results(data)["WN22-00-000130"].status == NAF
    # ... but another unlettered FAT volume cannot be classified.
    vols["volumes"].append({"drive_letter": "", "label": "", "file_system": "FAT32", "system_volume": False,
                            "boot_volume": False, "capacity": 1})
    assert results(data)["WN22-00-000130"].status == NR
    vols["volumes"].append({"drive_letter": "G:", "label": "", "file_system": "exFAT", "system_volume": False,
                            "boot_volume": False, "capacity": 1})
    assert results(data)["WN22-00-000130"].status == OPEN


def test_os_support_window():
    data = load("member-compliant")
    assert results(data)["WN22-00-000100"].status == NAF
    data["collected_at"] = "2031-10-16T00:00:00Z"
    assert results(data)["WN22-00-000100"].status == OPEN
    data["facts"]["os"]["value"].update(build_number="17763", caption="Microsoft Windows Server 2019 Standard")
    assert results(data)["WN22-00-000100"].status == NR


def test_acl_operator():
    op = windows.OPERATORS["acl"]
    entry = {"path": "x", "exists": True, "aces": [
        {"sid": "S-1-5-18", "type": "Allow", "rights": 0x1F01FF},
        {"sid": "S-1-5-11", "type": "Allow", "rights": 0x1200A9},
        {"sid": "S-1-5-32-545", "type": "Deny", "rights": 0x1F01FF},
    ]}
    assert op.test(entry, {"full": ["S-1-5-18"], "read": "any"}) is True
    assert op.test(entry, {"full": ["S-1-5-18"]}) is False
    entry["aces"].append({"sid": "S-1-5-21-1-2-3-1110", "type": "Allow", "rights": 0x1301BF})
    standard = {"full": ["S-1-5-18"], "read": "any", "standard": ["S-1-5-11", "S-1-5-21-*-513"]}
    assert op.test(entry, standard) is None  # an unknown principal with write access: review
    entry["aces"].append({"sid": "S-1-5-21-1-2-3-513", "type": "Allow", "rights": 0x1301BF})
    assert op.test(entry, standard) is False
    assert "exceeding: Domain Users" not in op.observe(entry, standard)  # not in SID_NAMES
    assert op.test({"path": "x", "error": "denied"}, standard) is None
    assert op.test({"path": "x", "exists": False}, standard) is None
    with pytest.raises(ValueError):
        op.validate({"read": "any"})


def test_has_sid_operator():
    op = windows.OPERATORS["has_sid"]
    rights = ["S-1-5-21-10-20-30-512", "S-1-5-32-546"]
    assert op.test(rights, "S-1-5-21-*-512") is True
    assert op.test(rights, "S-1-5-21-*-519") is False
    assert op.test("S-1-5-32-546", "S-1-5-32-546") is None
    with pytest.raises(ValueError):
        op.validate("Guests")


def test_kerberos_policy_on_dc():
    data = load("dc")
    kp = data["facts"]["security_policy"]["value"]["Kerberos Policy"]
    kp["MaxServiceAge"] = "0"
    kp.pop("MaxTicketAge")
    res = results(data)
    assert res["WN22-DC-000030"].status == OPEN
    assert res["WN22-DC-000040"].status == OPEN  # not in the export: not configured
    data["facts"]["security_policy"]["value"].pop("Kerberos Policy")
    assert results(data)["WN22-DC-000020"].status == NR  # section missing: not reported


# --------------------------------------------------------------------------- envelope and CLI

@pytest.mark.parametrize("mutate, msg", [
    (lambda d: d.update(collector="linux"), "not a Windows"),
    (lambda d: d.update(version=2), "version"),
    (lambda d: d.pop("host"), "host.name"),
    (lambda d: d.update(collected_at=5), "collected_at"),
    (lambda d: d.update(privileged="yes"), "privileged"),
    (lambda d: d["facts"].update({"x": {"status": "maybe"}}), "invalid status"),
    (lambda d: d["facts"].update({"..\\x": {"status": "ok"}}), "invalid fact id"),
    (lambda d: d["facts"]["registry"].update(command=["reg", "add"]), "must be a string"),
])
def test_validate_rejects_bad_envelopes(mutate, msg):
    d = load("member-compliant")
    mutate(d)
    with pytest.raises(ValueError, match=msg):
        windows.validate(d)


def test_collect_parse_cli(capsys):
    path = str(FIXTURES / "windows-unprivileged.json")
    assert main(["collect-parse", "windows", path]) == 0
    out = capsys.readouterr().out
    assert "host ws22-app-02 collected 2026-11-09T15:04:27Z: 13 of 20 facts read" in out
    assert "unavailable  user_rights: secedit /export failed (exit 740)" in out
    assert main(["collect-parse", "windows", path, "--min-ok", "15"]) == 1
    assert main(["collect-parse", "linux", path]) == 1
    assert "not 'linux'" in capsys.readouterr().err


def test_scan_cli_detects_the_collector(capsys):
    assert main(["scan", str(FIXTURES / "windows-noncompliant.json")]) == 0
    out = capsys.readouterr().out
    assert "ws22-legacy-04: windows-server-2022 V2R11, 277 rules" in out
    assert "Open CAT I (" in out and "WN22-UR-000020" in out
    assert main(["scan", str(FIXTURES / "windows-noncompliant.json"), "--benchmark", "ubuntu-22.04"]) == 1


# --------------------------------------------------------------------------- collector script

def _code(text: str) -> str:
    """The script without comments and the comment-based help block."""
    text = re.sub(r"<#.*?#>", "", text, flags=re.S)
    return "\n".join(re.sub(r"(^|\s)#.*$", "", ln) for ln in text.splitlines())


def test_collector_contains_no_write_commands():
    text = COLLECTOR.read_text(encoding="utf-8")
    code = _code(text)
    # cmdlet verbs that change state, other than the helpers the script defines
    verbs = re.findall(r"\b(Set|New|Remove|Add|Clear|Enable|Disable|Start|Stop|Restart|Install|Uninstall|"
                       r"Rename|Move|Copy|Register|Unregister|Suspend|Resume|Update|Write|Out|Export|Import|"
                       r"Grant|Revoke|Reset|Initialize|Format|Mount|Dismount|Lock|Unlock|Invoke)-(\w+)", code)
    allowed = {("Set", "StrictMode"), ("New", "Object"), ("Add", "Fact"), ("Remove", "Item"),
               ("Write", "Host"), ("Invoke", "Native")}
    assert {v for v in verbs if v not in allowed} == set()
    # Remove-Item only deletes the collector's own temporary exports
    for line in code.splitlines():
        if "Remove-Item" in line:
            assert re.search(r"Remove-Item -LiteralPath \$tmp -Force", line), line
    # registry: read-only opens, no writes
    assert re.findall(r"OpenSubKey\(([^)]*)\)", code) == ["$SubKey, $false"]
    assert not re.search(r"CreateSubKey|SetValue|DeleteValue|DeleteSubKey|SetAccessControl|Set-Acl", code)
    # native tools only in their read-only forms
    assert not re.search(r"\b(reg(\.exe)?\s+(add|delete|import|restore)|sc(\.exe)?\s+(config|stop|start|delete)|"
                         r"bcdedit|netsh|wmic|icacls|takeown|cacls|dism)\b", code, re.I)
    natives = re.findall(r"Invoke-Native '(\w+\.exe)' @\((.*)\)\s*$", code, re.M)
    assert sorted(natives) == sorted([
        ("auditpol.exe", "'/backup', ('/file:' + $tmp)"),
        ("auditpol.exe", "'/get', '/category:*', '/r'"),
        ("secedit.exe", "'/export', '/cfg', $tmp, '/areas', 'SECURITYPOLICY', 'USER_RIGHTS', '/quiet'"),
    ])
    assert "Invoke-Expression" not in code and "iex " not in code
    # the only file written is the output file
    assert len(re.findall(r"WriteAllText|Out-File|Set-Content|Add-Content", code)) == 1
    assert "[System.IO.File]::WriteAllText($target" in code
    # temporary exports are removed in a finally block
    assert code.count("finally {\n        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force }") == 2


def test_collector_never_reads_secrets():
    code = _code(COLLECTOR.read_text(encoding="utf-8"))
    assert not re.search(r"HKLM\\SECURITY|\\SAM\b|ntds\.dit'|Get-Content[^\n]*ntds|ConvertFrom-SecureString|"
                         r"Get-Credential|lsass|mimikatz|vssadmin|ntdsutil", code, re.I)
    # NTDS files are only listed and their ACLs read; their content is never opened
    assert re.search(r"Get-ChildItem -LiteralPath \$d -File", code)


@pytest.mark.skipif(sys.platform != "win32" or os.environ.get("STIGWATCH_RUN_COLLECTOR") != "1",
                    reason="runs the real collector on Windows only when STIGWATCH_RUN_COLLECTOR=1")
def test_collector_runs_on_windows(tmp_path):
    out = tmp_path / "out.json"
    shell = os.environ.get("STIGWATCH_TEST_POWERSHELL", "powershell")
    temp = tmp_path / "temp"
    temp.mkdir()
    env = dict(os.environ, TEMP=str(temp), TMP=str(temp))  # the collector's temp exports go here
    proc = subprocess.run([shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(COLLECTOR),
                           "-OutFile", str(out), "-RedactNames"], capture_output=True, text=True, timeout=600,
                          env=env)
    assert proc.returncode == 0, proc.stderr
    data = json.loads(out.read_text(encoding="utf-8"))
    windows.validate(data)
    assert set(data["facts"]) == set(windows.FACTS) - set(windows.DERIVED)
    info = windows.summary(data)
    assert info["ok"] >= 10
    assert list(temp.iterdir()) == []  # the secedit and auditpol exports were deleted
    assert len(engine.evaluate(data)) == 277


# --------------------------------------------------------------------------- domain, encryption and ACL regressions

def test_ms_000010_domain_admins_on_member_server():
    data = load("member-compliant")
    res = results(data)["WN22-MS-000010"]
    assert res.status == NR and "Server Admins - APP" in str(res.evidence)
    members = data["facts"]["local_admins"]["value"]["members"]
    members.append({"name": "EXAMPLE\\Domain Admins", "sid": "S-1-5-21-1004336348-1177238915-682003330-512",
                    "object_class": "Group", "principal_source": "ActiveDirectory"})
    r = results(data)["WN22-MS-000010"]
    assert r.status == OPEN
    assert "Domain Admins" in str(r.evidence)
    # standalone: no Domain Admins to replace, members need review; domain controller: N/A
    assert results(load("standalone"))["WN22-MS-000010"].status == NR
    assert results(load("dc"))["WN22-MS-000010"].status == NA
    # a member without a SID: whether Domain Admins is present is unknown
    members.append({"name": "orphan", "sid": "", "object_class": "User", "principal_source": "Unknown"})
    assert results(data)["WN22-MS-000010"].status == NR


def test_collect_parse_require(capsys):
    path = str(FIXTURES / "windows-unprivileged.json")
    assert main(["collect-parse", "windows", path, "--require", "registry,domain_role,acls"]) == 0
    capsys.readouterr()
    assert main(["collect-parse", "windows", path, "--require", "registry,security_policy, audit_policy"]) == 1
    assert "required facts not read: security_policy, audit_policy" in capsys.readouterr().err
    assert main(["collect-parse", "windows", path, "--require", "no_such_fact"]) == 1
    full = str(FIXTURES / "windows-member-compliant.json")
    assert main(["collect-parse", "windows", full, "--min-ok", "20", "--require",
                 "security_policy,user_rights,audit_policy,registry,features,domain_role,local_accounts,acls"]) == 0


def test_bitlocker_requires_full_encryption():
    data = load("member-compliant")
    vol = data["facts"]["bitlocker"]["value"]["volumes"][1]
    vol.update(volume_status="EncryptionInProgress", encryption_percentage=42)
    assert results(data)["WN22-00-000250"].status == NR
    vol.update(volume_status="FullyEncrypted", encryption_percentage=100)
    assert results(data)["WN22-00-000250"].status == NAF
    vol.update(volume_status="5", encryption_percentage=100)  # an unnamed status at 100%: encrypted
    assert results(data)["WN22-00-000250"].status == NAF
    vol.update(protection_status="Off", volume_status="FullyDecrypted", encryption_percentage=0)
    assert results(data)["WN22-00-000250"].status == OPEN


def test_fips_sharepoint_applicability_on_presence():
    data = load("member-compliant")
    data["facts"]["services"]["value"]["SPTimerV4"] = {"present": True, "status": "Stopped",
                                                       "start_type": "Disabled"}
    assert results(data)["WN22-SO-000360"].status == NA


def test_eventvwr_only_full_or_modify_is_open():
    data = load("member-compliant")
    aces = data["facts"]["acls"]["value"]["eventvwr"]["aces"]
    aces.append({"sid": "S-1-5-32-545", "type": "Allow", "rights": 0x116, "inherited": False,
                 "inheritance": 0, "propagation": 0})  # write data only
    r = results(data)["WN22-AU-000060"]
    assert r.status == NR and "to review" in str(r.evidence)
    aces.append({"sid": "S-1-5-11", "type": "Allow", "rights": 0x1301BF, "inherited": False,
                 "inheritance": 0, "propagation": 0})  # Modify
    assert results(data)["WN22-AU-000060"].status == OPEN
    aces[-1]["rights"] = 0x10000000  # GENERIC_ALL
    assert results(data)["WN22-AU-000060"].status == OPEN


def test_ntds_folder_error_keeps_other_acls():
    data = load("dc")
    acls = data["facts"]["acls"]["value"]
    acls["ntds_files"].append({"path": "D:\\NTDSLogs", "error": "Access to the path is denied."})
    res = results(data)
    assert res["WN22-DC-000070"].status == NR
    assert "Access to the path is denied" in str(res["WN22-DC-000070"].evidence)
    assert res["WN22-AU-000030"].status == NAF and res["WN22-DC-000080"].status == NAF
    code = _code(COLLECTOR.read_text(encoding="utf-8"))
    assert re.search(r"try \{\s*foreach \(\$f in @\(Get-ChildItem -LiteralPath \$d -File -ErrorAction Stop\)\)"
                     r".*?\} catch \{\s*\$files \+= \[ordered\]@\{ path = \$d; error =", code, re.S)


def test_symbolic_links_virtual_machines_only_with_hyper_v():
    data = load("member-compliant")
    data["facts"]["user_rights"]["value"]["SeCreateSymbolicLinkPrivilege"] = "*S-1-5-32-544,*S-1-5-83-0"
    assert results(data)["WN22-UR-000090"].status == OPEN  # Hyper-V available, not installed
    data["facts"]["features"]["value"]["states"]["Hyper-V"] = "Installed"
    assert results(data)["WN22-UR-000090"].status == NAF
    data["facts"]["features"] = unavailable("The requested operation requires elevation.")
    assert results(data)["WN22-UR-000090"].status == NR
    # Administrators only needs no feature fact
    data["facts"]["user_rights"]["value"]["SeCreateSymbolicLinkPrivilege"] = "*S-1-5-32-544"
    assert results(data)["WN22-UR-000090"].status == NAF
    assert "Win32_Tpm" in COLLECTOR.read_text(encoding="utf-8").split("#>")[0]


def test_collector_timestamps_never_use_the_host_culture():
    text = COLLECTOR.read_text(encoding="utf-8")
    calls = re.findall(r"\.ToString\('yyyy-MM-ddTHH:mm:ssZ'[^)]*\)", text)
    assert len(calls) == 2
    assert all("InvariantCulture" in c for c in calls)


@pytest.mark.parametrize("culture", ["fi-FI", "th-TH"])
def test_collector_timestamp_format_is_culture_independent(culture):
    """fi-FI writes '.' as the time separator and th-TH uses the Buddhist calendar (year 2569):
    the collector's own timestamp expression must still give the ISO form the server requires."""
    import shutil

    shell = os.environ.get("STIGWATCH_TEST_POWERSHELL", "powershell")
    if shutil.which(shell) is None:
        pytest.skip("PowerShell not available")
    expr = re.search(r"\(\[datetime\]\$Value\)\.ToUniversalTime\(\)\.ToString\('yyyy-MM-ddTHH:mm:ssZ'[^)]*\)",
                     COLLECTOR.read_text(encoding="utf-8")).group(0).replace("$Value", "$v")
    script = (f"$c = [Globalization.CultureInfo]::GetCultureInfo('{culture}'); "
              "[Threading.Thread]::CurrentThread.CurrentCulture = $c; "
              "$v = '2026-11-10T08:05:09Z'; "
              f"Write-Output ({expr})")
    out = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-Command", script],
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "2026-11-10T08:05:09Z"
    # Prove the culture really does change the format when no culture is passed.
    bare = expr.replace(", [System.Globalization.CultureInfo]::InvariantCulture", "")
    out = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-Command", script.replace(expr, bare)],
                         capture_output=True, text=True, timeout=60)
    assert out.stdout.strip() != "2026-11-10T08:05:09Z"
