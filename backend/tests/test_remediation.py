"""Generated remediation: the Ansible playbook and the PowerShell script."""

import dataclasses
import re
import shutil
import subprocess

import pytest
import yaml

from stigwatch import db, demo, remediation
from stigwatch.checks import engine

HEADER = "Review before applying; test on a non-production host."


@pytest.fixture(scope="module")
def seeded(tmp_path_factory):
    conn = db.connect(tmp_path_factory.mktemp("rem") / "demo.db")
    demo.seed(conn)
    yield conn
    conn.close()


@pytest.fixture(scope="module")
def benches():
    return {b: demo.bundled_benchmark(b) for b in ("ubuntu-22.04", "windows-server-2022")}


def latest_open(conn, host):
    scan = db.list_scans(conn, host["id"])[-1]
    return [r for r in db.scan_results(conn, scan["id"]) if r["status"] == "Open"]


def everything_open(bench):
    return [{"stig_id": r.stig_id, "status": "Open"} for r in bench.rules]


def parse(text):
    docs = yaml.safe_load(text)
    assert isinstance(docs, list) and len(docs) == 1
    return docs[0]


def tasks_of(text):
    return parse(text)["tasks"]


def fn_names(script):
    return re.findall(r"^function (Repair-[A-Z0-9-]+) \{", script, re.M)


# -- Ansible ---------------------------------------------------------------------------------

def test_playbook_parses_and_every_task_is_tagged_with_its_stig_id(benches):
    bench = benches["ubuntu-22.04"]
    text = remediation.ansible_playbook({"name": "h"}, everything_open(bench), bench)
    play = parse(text)
    assert play["become"] is True
    assert play["name"] == "STIGWatch remediation" and play["hosts"] == "{{ stigwatch_target }}"
    tasks = play["tasks"]
    assert len(tasks) > 100
    for t in tasks:
        sid = t["tags"][0]
        assert bench.rule(sid) is not None, sid
        assert sid in t["name"] and "stigwatch" in t["tags"]
        assert t["tags"][1] in ("cat1", "cat2", "cat3")
    handlers = {h["name"]: h for h in play["handlers"]}
    assert set(handlers) == {"Reload sshd", "Load audit rules", "Reload auditd configuration",
                             "Report audit rules that need a reboot"}
    # immutable audit rules (-e 2) must not fail the run: reported, with a reboot note
    assert handlers["Load audit rules"]["failed_when"] is False
    report = handlers["Report audit rules that need a reboot"]
    assert report["listen"] == "Load audit rules" and "Reboot" in report["ansible.builtin.debug"]["msg"]
    pre = play["pre_tasks"]
    assert pre[0]["ansible.builtin.command"]["argv"][-1] == "/etc/ssh/sshd_config"
    assert pre[0]["check_mode"] is False
    assert "sshd_config.d" in pre[1]["ansible.builtin.assert"]["fail_msg"]
    assert "stigwatch_sshd_include.rc == 0" in pre[1]["ansible.builtin.assert"]["that"]
    assert handlers["Load audit rules"]["ansible.builtin.command"] == "augenrules --load"
    assert handlers["Reload auditd configuration"]["ansible.builtin.command"] ==         "systemctl kill -s SIGHUP auditd"
    assert "restarted" not in str(play["handlers"])          # auditd refuses a manual stop
    notified = {t["notify"] for t in tasks if "notify" in t}
    assert notified <= {h["name"] for h in play["handlers"]}


def test_playbook_uses_only_idempotent_modules(benches):
    bench = benches["ubuntu-22.04"]
    tasks = tasks_of(remediation.ansible_playbook({"name": "h"}, everything_open(bench), bench))
    allowed = {"ansible.builtin.lineinfile", "ansible.builtin.blockinfile", "ansible.builtin.apt",
               "ansible.builtin.replace",
               "ansible.builtin.systemd", "ansible.builtin.file", "ansible.builtin.copy",
               "ansible.posix.sysctl"}
    modules = {k for t in tasks for k in t if "." in k}
    assert modules <= allowed, modules - allowed
    assert not {"command", "shell", "raw", "ansible.builtin.command", "ansible.builtin.shell"} & {
        k for t in tasks for k in t}
    for t in tasks:
        for module in ("ansible.builtin.lineinfile", "ansible.builtin.replace"):
            if module in t and "sshd_config" in t[module]["path"]:
                assert t[module]["validate"] == "/usr/sbin/sshd -t -f %s"
                assert t["notify"] == "Reload sshd"


def test_header_and_manual_block(benches):
    bench = benches["ubuntu-22.04"]
    text = remediation.ansible_playbook({"name": "h"}, [{"stig_id": "UBTU-22-255040"},
                                                         {"stig_id": "UBTU-22-611060"}], bench)
    assert text.startswith(f"# {HEADER}\n")
    assert "independent tool" in text
    assert "MANUAL" in text
    manual = text[text.index("MANUAL"):]
    assert "UBTU-22-611060" in manual and "fix:" in manual
    assert "UBTU-22-255040" not in manual and "UBTU-22-255040" in text


def test_values_come_from_the_check_definition(benches):
    bench = benches["ubuntu-22.04"]
    by_id = {}
    for t in tasks_of(remediation.ansible_playbook({"name": "h"}, everything_open(bench), bench)):
        by_id.setdefault(t["tags"][0], []).append(t)
    line = "ansible.builtin.lineinfile"
    assert by_id["UBTU-22-255030"][0][line]["line"] == "ClientAliveCountMax 1"
    assert by_id["UBTU-22-255035"][0][line]["line"] == "ClientAliveInterval 600"
    assert by_id["UBTU-22-411030"][0][line]["line"] == "PASS_MAX_DAYS 180"
    assert by_id["UBTU-22-611035"][0][line]["line"] == "minlen = 15"
    assert {t[line]["line"] for t in by_id["UBTU-22-653040"]} == {"space_left = 25%", "space_left_action = email"}
    assert "TMOUT=900" in by_id["UBTU-22-412030"][0]["ansible.builtin.copy"]["content"]
    assert by_id["UBTU-22-211015"][0]["ansible.builtin.systemd"] == {
        "name": "ctrl-alt-del.target", "masked": True}
    assert by_id["UBTU-22-213015"][0]["ansible.builtin.systemd"] == {
        "name": "kdump-tools.service", "state": "stopped", "masked": True}
    dropin = by_id["UBTU-22-255030"]
    assert dropin[0][line]["path"] == "/etc/ssh/sshd_config.d/00-stigwatch.conf" and dropin[0][line]["create"]
    assert "ansible.builtin.replace" in dropin[1] and dropin[1]["ansible.builtin.replace"]["regexp"] ==         r"(?i)^ClientAliveCountMax\s.*$"
    assert by_id["UBTU-22-213020"][0]["ansible.posix.sysctl"]["sysctl_file"] ==         "/etc/sysctl.d/99-zz-stigwatch.conf"
    assert by_id["UBTU-22-214015"][0][line]["create"] is True
    assert by_id["UBTU-22-215030"][0]["ansible.builtin.apt"]["state"] == "absent"
    sysctl = by_id["UBTU-22-213020"]
    assert len(sysctl) == 1 and sysctl[0]["ansible.posix.sysctl"]["value"] == "2"
    audit = by_id["UBTU-22-654155"][0]["ansible.builtin.blockinfile"]
    assert "-S chmod,fchmod,fchmodat" in audit["block"] and "arch=b32" in audit["block"]
    assert "-w /etc/passwd -p wa" in by_id["UBTU-22-654145"][0]["ansible.builtin.blockinfile"]["block"]
    assert by_id["UBTU-22-232030"][0]["ansible.builtin.file"]["mode"] == "u-x,g-wx,o-rwx,u-s,g-s,o-t"
    # fips cannot be turned on with a sysctl, and the sudo/PAM/grub rules are not mechanical
    for sid in ("UBTU-22-671010", "UBTU-22-611060", "UBTU-22-212010", "UBTU-22-431015"):
        assert sid not in by_id


def test_file_modes_never_widen():
    assert remediation._symbolic_mode("755") == "g-w,o-w,u-s,g-s,o-t"
    assert remediation._symbolic_mode("640") == "u-x,g-wx,o-rwx,u-s,g-s,o-t"
    assert remediation._symbolic_mode("600") == "u-x,g-rwx,o-rwx,u-s,g-s,o-t"
    with pytest.raises(remediation.Unsupported):
        remediation._symbolic_mode("rw")


def test_met_conditions_are_not_changed(benches):
    """Evidence that one of two directives is already right leaves only the other."""
    bench = benches["ubuntu-22.04"]
    evidence = [{"path": "sshd_config.permitemptypasswords.value", "observed": "no"},
                {"path": "sshd_config.permituserenvironment.value", "observed": "yes"}]
    tasks = tasks_of(remediation.ansible_playbook(
        {"name": "h"}, [{"stig_id": "UBTU-22-255025", "status": "Open", "evidence": evidence}], bench))
    assert [t["ansible.builtin.lineinfile"]["line"] for t in tasks if "ansible.builtin.lineinfile" in t]         == ["PermitUserEnvironment no"]
    assert len(tasks) == 2


def test_partial_fix_is_never_generated(benches):
    """A rule with one condition that has no safe mapping is manual as a whole."""
    bench = benches["ubuntu-22.04"]
    text = remediation.ansible_playbook({"name": "h"}, [{"stig_id": "UBTU-22-431015"}], bench)
    assert "Nothing to change automatically" in text and "UBTU-22-431015" in text[text.index("MANUAL"):]


def test_only_open_findings_are_remediated(benches):
    bench = benches["ubuntu-22.04"]
    items = [{"stig_id": "UBTU-22-255040", "status": "NotAFinding"},
             {"stig_id": "UBTU-22-255045", "status": "Open"}]
    tasks = tasks_of(remediation.ansible_playbook({"name": "h"}, items, bench))
    assert {t["tags"][0] for t in tasks} == {"UBTU-22-255045"}


def test_cat_i_first_and_order_is_stable(benches):
    bench = benches["ubuntu-22.04"]
    a = remediation.ansible_playbook({"name": "h"}, everything_open(bench), bench)
    b = remediation.ansible_playbook({"name": "h"}, list(reversed(everything_open(bench))), bench)
    assert a == b
    cats = [t["tags"][1] for t in tasks_of(a)]
    assert cats == sorted(cats)


def test_demo_linux_hosts_generate_valid_playbooks(seeded, benches):
    for host in db.list_hosts(seeded):
        if host["os"] != "linux":
            continue
        bench = benches[host["benchmark_id"]]
        opens = latest_open(seeded, host)
        text = remediation.ansible_playbook(host, opens, bench)
        assert text == remediation.ansible_playbook(host, opens, bench)
        for t in tasks_of(text):
            assert t["tags"] == ["stigwatch"] or t["tags"][0] in t["name"]


# -- PowerShell ------------------------------------------------------------------------------

def windows_script(bench, items=None, host=None):
    return remediation.powershell_script(host or {"name": "h"}, items or everything_open(bench), bench)


def test_script_safety_properties(benches):
    bench = benches["windows-server-2022"]
    script = windows_script(bench)
    assert HEADER in script and "independent tool" in script
    assert "Invoke-Expression" not in script and not re.search(r"\biex\b", script, re.I)
    assert "[CmdletBinding(SupportsShouldProcess = $true)]" in script
    assert "[switch]$Apply" in script
    assert "if (-not $Apply) {\n    $WhatIfPreference = $true" in script   # dry run by default
    assert "Set-StrictMode -Version Latest" in script
    assert "Start-Transcript" in script and "Stop-Transcript" in script
    # nothing that changes the host is called outside a ShouldProcess block
    body = script.split("function Set-StigRegistryValue")[0]
    for cmd in ("secedit", "auditpol", "Set-ItemProperty", "Uninstall-WindowsFeature"):
        assert cmd not in body
    helpers = script[script.index("function Set-StigRegistryValue"):script.index("function Repair-")]
    for cmd in ("Set-ItemProperty", "secedit.exe /configure", "auditpol.exe @arguments",
                "Uninstall-WindowsFeature -Name"):
        assert cmd in helpers
    assert helpers.count("ShouldProcess(") == 4
    for line in script.splitlines():
        assert line.isascii()


def test_one_function_per_automatable_open_finding(seeded, benches):
    bench = benches["windows-server-2022"]
    automated = set(remediation.automated_ids(bench))
    assert len(automated) >= 150
    for host in db.list_hosts(seeded):
        if host["os"] != "windows":
            continue
        opens = latest_open(seeded, host)
        script = windows_script(bench, opens, host)
        # user rights are generated only from known, builtin-only principals, so the demo
        # hosts' rights findings may be manual
        want = {r["stig_id"] for r in opens} & automated
        got = {n[len("Repair-"):] for n in fn_names(script)}
        assert got <= want and all(s.startswith("WN22-UR-") for s in want - got), host["name"]
        want = got
        steps = re.search(r"\$steps = @\((.*)\)", script).group(1)
        assert set(re.findall(r"'(Repair-[A-Z0-9-]+)'", steps)) == {f"Repair-{s}" for s in want}
        assert script == windows_script(bench, opens, host)       # deterministic


def test_windows_values_and_types(benches):
    bench = benches["windows-server-2022"]
    script = windows_script(bench)
    assert ("-Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\Wdigest' "
            "-Name 'UseLogonCredential' -Value 0 -Type DWord") in script
    assert "-Name 'SupportedEncryptionTypes' -Value 2147483640 -Type DWord" in script
    assert "-Name 'CachedLogonsCount' -Value '4' -Type String" in script
    assert "'MinimumPasswordLength = 14'" in script
    # without the observed principals a user right is never rewritten
    assert "SeDebugPrivilege = " not in script
    assert "the current principals of this right are not known" in script[script.index("MANUAL"):]
    assert "-Guid '{0CCE9215-69AE-11D9-BED3-505054503030}'" in script          # logon
    assert "Remove-StigWindowsFeature -StigId 'WN22-00-000360' -Name 'Telnet-Client'" in script
    # logon rights can lock administrators out, and HKCU is a per-user hive: both stay manual
    manual = script[script.index("MANUAL"):]
    assert "SeNetworkLogonRight can lock administrators out" in manual
    assert "WN22-UC-000010" in manual


def test_windows_registry_type_follows_the_value_and_the_fix_text(benches):
    bench = benches["windows-server-2022"]
    script = windows_script(bench)
    for line in script.splitlines():
        m = re.search(r"Set-StigRegistryValue -StigId .* -Value (\S+) -Type (\w+)$", line)
        if m:
            value, kind = m.groups()
            assert (kind == "String") == value.startswith("'"), line
            assert kind != "DWord" or 0 <= int(value) <= 0xFFFFFFFF
    # a fix text that names another registry type means the value type is not ours to guess
    rule = dataclasses.replace(bench.rule("WN22-CC-000020"), fix_text="Set the REG_MULTI_SZ value to 0.")
    leaves = remediation._conjunction(engine.load_checks("windows-server-2022").checks["WN22-CC-000020"].logic)
    with pytest.raises(remediation.Unsupported, match="REG_MULTI_SZ"):
        remediation._windows_steps(rule.stig_id, rule, leaves)
    ok = dataclasses.replace(rule, fix_text="Set the REG_DWORD value to 0.")
    assert remediation._windows_steps(ok.stig_id, ok, leaves)


def test_hostile_host_names_stay_in_one_comment(benches):
    nasty = "web\n#> ; Remove-Item C:\\ -Recurse\u2028\u0085$(x) \u2018'\x00" + "A" * 5000
    wb, lb = benches["windows-server-2022"], benches["ubuntu-22.04"]
    script = windows_script(wb, [{"stig_id": "WN22-CC-000020"}], {"name": nasty})
    assert "Remove-Item C:" in script.split("\n#>")[0]    # present, but inside the comment block
    assert script.count("#>") == 1 and script.isascii()
    head = script.split("\n#>")[0]
    assert head.count("\n") < 20 and len(head) < 2500
    assert "Remove-Item C:" not in script.split("\n#>", 1)[1]    # nothing of it outside the comment
    text = remediation.ansible_playbook({"name": nasty}, [{"stig_id": "UBTU-22-255040"}], lb)
    assert yaml.safe_load(text)[0]["tasks"][0]["tags"][0] == "UBTU-22-255040"
    assert all(line.startswith("#") for line in text.split("\n---", 1)[0].splitlines())


def test_unknown_and_malformed_items_are_ignored_or_manual(benches):
    bench = benches["windows-server-2022"]
    script = windows_script(bench, [{"stig_id": "WN22-ZZ-999999", "status": "Open"},
                                    {"stig_id": "not an id\n", "status": "Open"}, {"status": "Open"}])
    assert "WN22-ZZ-999999" in script[script.index("MANUAL"):]
    assert fn_names(script) == []


def test_powershell_parses_when_available(tmp_path, benches):
    """Parse the generated script with the PowerShell AST wherever PowerShell exists; CI
    runs the same check on Windows for every demo host."""
    shell = shutil.which("pwsh") or shutil.which("powershell")
    if shell is None:
        pytest.skip("PowerShell is not installed")
    f = tmp_path / "all.ps1"
    f.write_text(windows_script(benches["windows-server-2022"]), encoding="utf-8")
    cmd = ("$e=$null;$t=$null;[void][System.Management.Automation.Language.Parser]::ParseFile("
           f"'{f}',[ref]$t,[ref]$e);if($e.Count){{$e|%{{$_.Message}};exit 1}}")
    out = subprocess.run([shell, "-NoProfile", "-Command", cmd], capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stdout + out.stderr


def test_automated_rule_counts(benches):
    linux = remediation.automated_ids(benches["ubuntu-22.04"])
    windows = remediation.automated_ids(benches["windows-server-2022"])
    assert len(linux) >= 100 and len(windows) >= 150
    assert set(linux) <= {r.stig_id for r in benches["ubuntu-22.04"].rules}
    checks = engine.load_checks("windows-server-2022").checks
    assert set(windows) <= set(checks)          # never a rule without a check definition

# -- injection and validation ------------------------------------------------------------------

JINJA_HOSTS = ["{{ lookup('pipe','id') }}", "{% set x = 1 %}web", "a{{7*7}}b",
               "#{{ x }}\n- name: evil", "$(whoami) `id` {{ ansible_env }} %"]


def _strings(v, out):
    if isinstance(v, dict):
        for k, x in v.items():
            _strings(k, out)
            _strings(x, out)
    elif isinstance(v, list):
        for x in v:
            _strings(x, out)
    elif isinstance(v, str):
        out.append(v)
    return out


@pytest.mark.parametrize("name", JINJA_HOSTS)
def test_host_names_never_reach_a_templated_value(benches, name):
    bench = benches["ubuntu-22.04"]
    text = remediation.ansible_playbook({"name": name}, everything_open(bench), bench)
    strings = _strings(parse(text), [])
    for needle in ("lookup", "whoami", "ansible_env", "evil", "7*7", "set x"):
        assert not any(needle in x for x in strings), needle
    templated = {x for x in strings if "{{" in x or "{%" in x}
    allowed = ("{{ stigwatch_target }}", "{{ item }}")
    assert all(x in allowed or x.startswith("{{ ['/etc/ssh/sshd_config'] + (stigwatch_sshd_dropins")
               for x in templated), templated
    header, body = text.split("\n---", 1)
    assert all(line.startswith("#") for line in header.splitlines())
    host_line = next(ln for ln in header.splitlines() if ln.startswith("# Host:"))
    assert not any(c in host_line for c in "{}%$`<>")


def test_playbook_target_is_a_required_variable():
    text = remediation.ansible_playbook({"name": "h"}, [], demo.bundled_benchmark("ubuntu-22.04"))
    assert parse(text)["hosts"] == "{{ stigwatch_target }}" and "stigwatch_target" in text.split("---")[0]


def test_db_refuses_unsafe_host_names(conn):
    for bad in ("{{ x }}", "a b", "a/b", "a\nb", "x" * 254, "", "-lead", "a;b", "<b>", "é"):
        with pytest.raises(ValueError):
            db.add_host(conn, bad, "linux", "ubuntu-22.04")
    assert db.add_host(conn, "web-01.example.com", "linux", "ubuntu-22.04")
    assert db.add_host(conn, "x" * 253, "linux", "ubuntu-22.04")


def test_sshd_include_regexp_matches_ubuntu_default():
    import re, subprocess
    text = remediation.ansible_playbook({"name": "h"}, [{"stig_id": "UBTU-22-255025", "status": "Open"}],
                                        __import__("stigwatch.benchmarks", fromlist=["x"]).load_benchmark("ubuntu-22.04"))
    play = parse(text)
    if "pre_tasks" not in play:
        return
    pattern = play["pre_tasks"][0]["ansible.builtin.command"]["argv"][2]
    rx = re.compile(pattern.replace("[[:space:]]", r"\s"), re.I)
    assert rx.search("Include /etc/ssh/sshd_config.d/*.conf")
    assert not rx.search("#Include /etc/ssh/sshd_config.d/*.conf")


def test_playbook_lines_stay_within_ansible_lint_limit(benches):
    bench = benches["ubuntu-22.04"]
    text = remediation.ansible_playbook({"name": "h"}, everything_open(bench), bench)
    assert max(len(line) for line in text.splitlines()) <= 155
