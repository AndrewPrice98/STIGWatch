"""Regression tests for the Task 3 review (fix round 1)."""

import copy
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from stigwatch.checks import engine
from stigwatch.facts import linux

BACKEND = Path(__file__).resolve().parent.parent
FIXTURES = BACKEND / "tests" / "fixtures"
COLLECTOR = BACKEND.parent / "collectors" / "collect-linux.sh"
OPEN, NAF, NA, NR = engine.OPEN, engine.NOT_A_FINDING, engine.NOT_APPLICABLE, engine.NOT_REVIEWED


def load(name: str) -> dict:
    return json.loads((FIXTURES / f"linux-{name}.json").read_text(encoding="utf-8"))


def results(data: dict) -> dict[str, engine.RuleResult]:
    return {r.stig_id: r for r in engine.evaluate(data)}


def _function(name: str) -> str:
    text = COLLECTOR.read_text(encoding="utf-8")
    m = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", text, re.S | re.M)
    assert m, name
    return m.group(0)


def _run_sh(tmp_path: Path, body: str, stdin: bytes = b"") -> subprocess.CompletedProcess:
    script = tmp_path / "t.sh"
    script.write_text(body, encoding="utf-8", newline="\n")
    return subprocess.run([shutil.which("sh"), str(script)], input=stdin, capture_output=True, timeout=60)


needs_sh = pytest.mark.skipif(shutil.which("sh") is None, reason="no POSIX sh available")


# --------------------------------------------------------------------------- 1. systemd aliases

def test_unit_alias_is_reported_under_the_queried_name():
    # Real systemd output: an unmasked ctrl-alt-del.target is shown as reboot.target.
    data = load("noncompliant")
    text = data["facts"]["units"]["value"]["text"]
    assert "Id=reboot.target\nNames=reboot.target ctrl-alt-del.target" in text
    facts = linux.facts(data)
    assert facts["units"]["status"] == "ok"
    cad = facts["units"]["value"]["ctrl-alt-del.target"]
    assert cad["load"] == "loaded" and cad["id"] == "reboot.target"
    res = results(data)
    assert res["UBTU-22-211015"].status == OPEN  # not masked: a finding, not Not_Reviewed
    assert res["UBTU-22-255015"].status == NAF   # the rest of the units fact still decides
    assert res["UBTU-22-213015"].status == OPEN
    # masked on the compliant host
    assert results(load("compliant"))["UBTU-22-211015"].status == NAF


def test_unit_lookup_by_names_and_argument_order():
    v = {"queried": ["sshd.service", "x.target"],
         "text": "Id=ssh.service\nNames=ssh.service sshd.service\nLoadState=loaded\nActiveState=active\n"
                 "UnitFileState=enabled\n\nId=x.target\nNames=x.target\nLoadState=not-found\n"
                 "ActiveState=inactive\nUnitFileState="}
    out = linux.p_units(v)
    assert out["sshd.service"]["active"] == "active"
    assert out["x.target"]["load"] == "not-found"
    # output without Names (older systemd): argument order
    old = {"queried": ["ctrl-alt-del.target"],
           "text": "Id=reboot.target\nLoadState=loaded\nActiveState=inactive\nUnitFileState=static"}
    assert linux.p_units(old)["ctrl-alt-del.target"]["load"] == "loaded"
    with pytest.raises(ValueError):
        linux.p_units({"queried": ["a.service", "b.service"], "text": "Id=a.service\nNames=a.service"})


# --------------------------------------------------------------------------- 2. invalid UTF-8

@needs_sh
@pytest.mark.skipif(shutil.which("iconv") is None, reason="no iconv")
def test_collector_drops_invalid_utf8_and_records_it(tmp_path):
    work = tmp_path / "w"
    work.mkdir()
    body = ('{\n  "collector": "linux",\n  "utf8_bytes_dropped": UTF8_PLACEHOLDER,\n'
            '  "facts": {"x": "caf').encode() + b"\xe9\xff" + 'é"}\n}\n'.encode()
    (work / "result.json").write_bytes(body)
    script = ("have() { command -v \"$1\" >/dev/null 2>&1; }\n" + _function("write_output")
              + f'TMP="{work.as_posix()}"; OUT="{(tmp_path / "out.json").as_posix()}"\nwrite_output\n')
    proc = _run_sh(tmp_path, script)
    assert proc.returncode == 0, proc.stderr
    data = json.loads((tmp_path / "out.json").read_bytes().decode("utf-8"))  # strict decoding
    assert data["utf8_bytes_dropped"] is True
    assert data["facts"]["x"] == "café"
    # valid input: flag false, content unchanged
    (work / "result.json").write_bytes(body.replace(b"\xe9\xff", b""))
    assert _run_sh(tmp_path, script).returncode == 0
    data = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
    assert data["utf8_bytes_dropped"] is False


def test_envelope_flag_type_is_validated():
    d = load("compliant")
    d["utf8_bytes_dropped"] = "yes"
    with pytest.raises(ValueError, match="utf8_bytes_dropped"):
        linux.validate(d)
    d["utf8_bytes_dropped"] = None
    linux.validate(d)


# --------------------------------------------------------------------------- 3. idle-delay 0

def _idle(value: str) -> str:
    d = load("gui")
    d["facts"]["gsettings"]["value"]["org.gnome.desktop.session idle-delay"]["output"] = value
    return results(d)["UBTU-22-271025"].status


def test_idle_delay_zero_is_not_a_pass():
    assert _idle("uint32 600") == NAF
    assert _idle("uint32 0") == NR     # never idle: not "600 or less" in any useful sense
    assert _idle("uint32 900") == OPEN


# --------------------------------------------------------------------------- 4. sshd Include

def _sshd(lines):
    d = load("compliant")
    d["facts"]["sshd_config"]["value"] = {
        "files": sorted({p for p, _ in lines}), "text": "\n".join(f"{p}\t{ln}" for p, ln in lines)}
    return d


BASE_SSH = [("/etc/ssh/sshd_config", "PermitEmptyPasswords no"),
            ("/etc/ssh/sshd_config", "PermitUserEnvironment no")]


@pytest.mark.parametrize("include, status", [
    ("Include /etc/ssh/sshd_config.d/*.conf", NAF),
    ("Include sshd_config.d/*.conf", NAF),            # relative to /etc/ssh
    ("Include /etc/ssh/sshd_config.d/99-stig.conf", NAF),
    ("Include /etc/ssh/extra.conf", NR),
    ("Include /etc/ssh/sshd_config.d/*", NR),         # also matches non-.conf files
    ("Include local/*.conf", NR),
])
def test_sshd_include_of_uncollected_file_is_unknown(include, status):
    d = _sshd([("/etc/ssh/sshd_config", include)] + BASE_SSH)
    r = results(d)["UBTU-22-255025"]
    assert r.status == status, r.reason
    if status == NR:
        assert "does not read" in r.reason


# --------------------------------------------------------------------------- 5. maxlogins

def _limits(lines):
    d = load("compliant")
    d["facts"]["limits"]["value"] = {"files": ["/etc/security/limits.conf"],
                                     "text": "\n".join(f"/etc/security/limits.conf\t{ln}" for ln in lines)}
    return results(d)["UBTU-22-412020"].status


def test_maxlogins_every_entry_must_be_10_or_less():
    assert _limits(["* hard maxlogins 10"]) == NAF
    assert _limits(["* hard maxlogins 10", "@ops hard maxlogins 50"]) == OPEN
    assert _limits(["* hard maxlogins 10", "@ops hard maxlogins 5"]) == NAF
    assert _limits(["@ops hard maxlogins 5"]) == NR   # no limit for all accounts
    assert _limits([]) == OPEN


# --------------------------------------------------------------------------- minors

def _pam_auth(text):
    d = load("compliant")
    d["facts"]["pam_common_auth"]["value"]["text"] += "\n" + text
    return results(d)["UBTU-22-611060"].status


def test_nullok_counted_like_the_check_text_grep():
    assert _pam_auth("AUTH required pam_unix.so nullok") == OPEN
    assert _pam_auth("auth [success=1 default=ignore] pam_unix.so nullok_secure") == OPEN
    assert _pam_auth("# auth required pam_unix.so nullok") == NAF  # comment, not active


def test_every_fact_and_result_is_json_serialisable():
    for path in sorted(FIXTURES.glob("linux-*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        json.dumps(linux.facts(data))
        json.dumps([r.as_dict() for r in engine.evaluate(data)])
    rule = linux.parse_audit_rule("-a always,exit -F arch=b64 -S chmod -S fchmod -F auid>=1000 -F auid!=-1")
    assert rule["syscalls"] == ["chmod", "fchmod"] and isinstance(rule["filters"], list)


def test_banner_in_unreadable_location_is_not_reviewed():
    text = COLLECTOR.read_text(encoding="utf-8")
    assert 'elif [ "$(path_state "$banner")" = denied ]; then' in text
    d = load("compliant")
    d["facts"]["ssh_banner"] = {"status": "unavailable", "value": None,
                                "reason": "cannot read /etc/ssh/private/banner (permission denied)",
                                "command": "cat /etc/ssh/private/banner"}
    r = results(d)["UBTU-22-255020"]
    assert r.status == NR and "permission denied" in r.reason


def _sudoers(lines):
    d = load("compliant")
    d["facts"]["sudoers"]["value"] = {"files": ["/etc/sudoers"],
                                      "text": "\n".join(f"/etc/sudoers\t{ln}" for ln in lines)}
    return results(d)["UBTU-22-432011"]


def test_sudoers_include_of_uncollected_file_is_unknown():
    assert _sudoers(["@includedir /etc/sudoers.d", "#includedir /etc/sudoers.d"]).status == NAF
    assert _sudoers(["@include /etc/sudoers.d/ops"]).status == NAF
    r = _sudoers(["@include /etc/sudoers.local"])
    assert r.status == NR and "does not read" in r.reason
    assert _sudoers(["#include /etc/sudoers.%h"]).status == NR
    assert _sudoers(["@includedir /opt/sudo.d"]).status == NR


@needs_sh
def test_collector_keeps_sudoers_include_directives(tmp_path):
    script = _function("active") + "KEEP_INCLUDE=1\nactive\necho ---\nKEEP_INCLUDE=0\nactive < \"$0.in\"\n"
    (tmp_path / "t.sh.in").write_text("# comment\n#includedir /etc/sudoers.d\nroot ALL=(ALL) ALL\n\n",
                                      encoding="utf-8", newline="\n")
    proc = _run_sh(tmp_path, script, b"# comment\n#includedir /etc/sudoers.d\n@include x\nroot ALL\n")
    out = proc.stdout.decode().split("---\n")
    assert out[0].splitlines() == ["#includedir /etc/sudoers.d", "@include x", "root ALL"]
    assert out[1].splitlines() == ["root ALL=(ALL) ALL"]


def test_audit_never_rule_for_target_is_undecided():
    strict = "-a always,exit -S all -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=-1 -k su"
    assert linux._audit_test(linux.p_audit_rules(strict), {"exec": "/usr/bin/su"}) is True
    never = "-a never,exit -F path=/usr/bin/su -F perm=x\n" + strict
    assert linux._audit_test(linux.p_audit_rules(never), {"exec": "/usr/bin/su"}) is None
    d = load("compliant")
    d["facts"]["audit_rules"]["value"] = "-a never,exit -F arch=b64 -S chmod\n" + d["facts"]["audit_rules"]["value"]
    assert results(d)["UBTU-22-654155"].status == NR


def test_wording_does_not_claim_no_hashes_at_all():
    text = COLLECTOR.read_text(encoding="utf-8")
    assert "never outputs password hashes" in text
    readme = (BACKEND.parent / "README.md").read_text(encoding="utf-8")
    assert "never outputs password hashes" in readme
