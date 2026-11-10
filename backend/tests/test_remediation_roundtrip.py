"""Round trips: apply a generated fix to the facts it was derived from and run the check again."""

import copy
import json
import re
from pathlib import Path

import pytest
import yaml

from stigwatch import demo, remediation
from stigwatch.checks import engine

FIXTURES = Path(__file__).parent / "fixtures"
OPEN, NAF = "Open", "NotAFinding"


def load(name):
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def lbench():
    return demo.bundled_benchmark("ubuntu-22.04")


@pytest.fixture(scope="module")
def wbench():
    return demo.bundled_benchmark("windows-server-2022")


def evaluate(raw, bench):
    return {r.stig_id: r for r in engine.evaluate(raw, bench)}


# -- a tiny model of the Ansible modules the playbook uses -------------------------------------

class Files(dict):
    """path -> text; the model of the managed host's files."""


def apply_tasks(files, tasks, dropins=()):
    for t in tasks:
        if "ansible.builtin.lineinfile" in t:
            a = t["ansible.builtin.lineinfile"]
            text = files.get(a["path"])
            if text is None:
                assert a.get("create"), a["path"]
                text = ""
            lines = text.split("\n") if text else []
            idx = [i for i, ln in enumerate(lines) if re.search(a["regexp"], ln)]
            if idx:
                lines[idx[-1]] = a["line"]
            else:
                lines.append(a["line"])
            files[a["path"]] = "\n".join(lines)
        elif "ansible.builtin.replace" in t:
            a = t["ansible.builtin.replace"]
            targets = [a["path"]]
            if t.get("loop"):
                targets = ["/etc/ssh/sshd_config", *dropins]
            for path in targets:
                if path in files:
                    files[path] = re.sub(a["regexp"], a["replace"], files[path], flags=re.M)
        elif "ansible.builtin.blockinfile" in t:
            a = t["ansible.builtin.blockinfile"]
            files[a["path"]] = files.get(a["path"], "") + a["block"]
        elif "ansible.builtin.copy" in t:
            a = t["ansible.builtin.copy"]
            files[a["dest"]] = a["content"]
    return files


def playbook_tasks(sid, bench, evidence=None):
    item = {"stig_id": sid, "status": "Open"}
    if evidence is not None:
        item["evidence"] = evidence
    play = yaml.safe_load(remediation.ansible_playbook({"name": "h"}, [item], bench))[0]
    return play["tasks"]


def test_sshd_fix_on_the_stock_ubuntu_file(lbench):
    stock = (FIXTURES / "ubuntu-22.04-sshd_config").read_text(encoding="utf-8")
    assert stock.lstrip().startswith("#") and "\nInclude /etc/ssh/sshd_config.d/*.conf\n" in stock
    assert stock.index("Include /etc/ssh/sshd_config.d/*.conf") < stock.index("X11Forwarding")
    dropin = "/etc/ssh/sshd_config.d/50-cloud-init.conf"
    files = Files({"/etc/ssh/sshd_config": stock,
                   dropin: "PermitEmptyPasswords yes\nPasswordAuthentication yes\n"})

    def sshd_fact(fs):
        order = ["/etc/ssh/sshd_config"] + sorted(p for p in fs if p != "/etc/ssh/sshd_config")
        text = []
        for path in order:
            for ln in fs[path].split("\n"):
                if ln.strip() and not ln.lstrip().startswith("#"):
                    text.append(f"{path}\t{ln}")
        return {"status": "ok", "value": {"files": order, "text": "\n".join(text)},
                "reason": None, "command": "cat sshd_config"}

    raw = load("linux-compliant")
    raw["facts"]["sshd_config"] = sshd_fact(files)
    before = evaluate(raw, lbench)
    for sid in ("UBTU-22-255040", "UBTU-22-255025", "UBTU-22-255030"):
        assert before[sid].status == OPEN, sid
    for sid in ("UBTU-22-255040", "UBTU-22-255025", "UBTU-22-255030"):
        tasks = playbook_tasks(sid, lbench)
        assert tasks[0]["ansible.builtin.lineinfile"]["path"] == "/etc/ssh/sshd_config.d/00-stigwatch.conf"
        apply_tasks(files, tasks, dropins=[dropin])
    raw["facts"]["sshd_config"] = sshd_fact(files)
    after = evaluate(raw, lbench)
    for sid in ("UBTU-22-255040", "UBTU-22-255025", "UBTU-22-255030"):
        assert after[sid].status == NAF, (sid, after[sid].reason)
    assert "# STIGWatch disabled: PermitEmptyPasswords yes" in files[dropin]
    assert "PasswordAuthentication yes" in files[dropin]          # unrelated directives are left
    again = copy.deepcopy(files)
    for sid in ("UBTU-22-255040", "UBTU-22-255025"):
        apply_tasks(again, playbook_tasks(sid, lbench), dropins=[dropin])
    assert again == files                                        # idempotent


def test_key_value_file_fixes(lbench):
    raw = load("linux-compliant")
    for fact, sid, old, new in (
            ("login_defs", "UBTU-22-411030", "PASS_MAX_DAYS\t180\n", ""),
            ("pwquality_conf", "UBTU-22-611035", "minlen = 15", "minlen = 8"),
            ("pwquality_conf", "UBTU-22-611010", "ucredit = -1", "ucredit = 0"),
            ("useradd_defaults", "UBTU-22-411035", "INACTIVE=35", ""),
            ("auditd_conf", "UBTU-22-653055", "log_group = root", "log_group = adm")):
        fact_value = raw["facts"][fact]["value"]
        assert old in fact_value["text"], (fact, old)
        fact_value["text"] = fact_value["text"].replace(old, new)
        assert evaluate(raw, lbench)[sid].status == OPEN, sid
        path = {"login_defs": "/etc/login.defs", "pwquality_conf": "/etc/security/pwquality.conf",
                "useradd_defaults": "/etc/default/useradd", "auditd_conf": "/etc/audit/auditd.conf"}[fact]
        files = apply_tasks(Files({path: fact_value["text"]}), playbook_tasks(sid, lbench))
        fact_value["text"] = files[path]
        assert evaluate(raw, lbench)[sid].status == NAF, sid


def test_audit_rule_fixes_including_field_to_field_comparison(lbench):
    raw = load("linux-compliant")
    text = raw["facts"]["audit_rules"]["value"]
    kept = "\n".join(ln for ln in text.split("\n") if "execve" not in ln and "chmod" not in ln
                     and "/etc/passwd" not in ln)
    raw["facts"]["audit_rules"]["value"] = kept
    before = evaluate(raw, lbench)
    sids = ("UBTU-22-654230", "UBTU-22-654155", "UBTU-22-654145")
    assert all(before[s].status == OPEN for s in sids)
    files = Files()
    for sid in sids:
        apply_tasks(files, playbook_tasks(sid, lbench))
    block = files["/etc/audit/rules.d/99-stigwatch.rules"]
    assert "-S execve -C uid!=euid -F euid=0" in block and "-C gid!=egid -F egid=0" in block
    assert "-F uid!=euid" not in block
    raw["facts"]["audit_rules"]["value"] = kept + "\n" + block
    after = evaluate(raw, lbench)
    assert all(after[s].status == NAF for s in sids), [(s, after[s].reason) for s in sids]


def test_dash_f_is_not_dash_c(lbench):
    """-F uid!=euid compares uid with the number "euid"; only -C compares the two fields."""
    raw = load("linux-compliant")
    value = raw["facts"]["audit_rules"]["value"]
    assert evaluate(raw, lbench)["UBTU-22-654230"].status == NAF
    raw["facts"]["audit_rules"]["value"] = value.replace("-C uid!=euid", "-F uid!=euid")
    assert evaluate(raw, lbench)["UBTU-22-654230"].status != NAF
    from stigwatch.facts import linux
    a = linux.parse_audit_rule("-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0")
    b = linux.parse_audit_rule("-a always,exit -F arch=b64 -S execve -F uid!=euid -F euid=0")
    assert a["filters"] != b["filters"] and "C:uid!=euid" in a["filters"]


# -- Windows ------------------------------------------------------------------------------------

def apply_script(raw, script):
    """Model of what the generated script does to the facts."""
    facts = raw["facts"]
    for m in re.finditer(r"Set-StigRegistryValue -StigId '[^']+' -Path 'HKLM:([^']+)' -Name '([^']+)' "
                         r"-Value ('(?:[^']|'')*'|\d+) -Type (\w+)", script):
        key, name, value, rtype = "HKLM" + m[1], m[2], m[3], m[4]
        data = value[1:-1].replace("''", "'") if value.startswith("'") else int(value)
        rows = facts["registry"]["value"]["values"]
        row = next((r for r in rows if r["key"] == key and r["name"] == name), None)
        if row is None:
            row = {"key": key, "name": name}
            rows.append(row)
        row.update(state="set", type=rtype, data=data)
    for m in re.finditer(r"Invoke-StigSecedit -StigId '[^']+' -Area '(\w+)' -Section '([^']+)' "
                         r"-Lines @\(([^)]*)\)", script):
        section = m[2]
        for line in re.findall(r"'([^']*)'", m[3]):
            k, _, v = line.partition(" = ")
            if section == "Privilege Rights":
                facts["user_rights"]["value"][k] = v
            else:
                facts["security_policy"]["value"]["System Access"][k] = v
    for m in re.finditer(r"Set-StigAuditPolicy -StigId '[^']+' -Subcategory '[^']+' -Guid '([^']+)' "
                         r"-Success (\$\w+) -Failure (\$\w+)", script):
        for row in facts["audit_policy"]["value"]["subcategories"]:
            if row["guid"].upper() == m[1].upper():
                bits = int(row["setting_value"]) | (1 if m[2] == "$true" else 0) | (2 if m[3] == "$true" else 0)
                row["setting_value"] = str(bits)
    for m in re.finditer(r"Remove-StigWindowsFeature -StigId '[^']+' -Name '([^']+)'", script):
        facts["features"]["value"]["states"][m[1]] = "Removed"


def test_every_automated_windows_fix_clears_its_finding(wbench):
    raw = load("windows-noncompliant")
    results = evaluate(raw, wbench)
    opens = [r for r in results.values() if r.status == OPEN]
    assert len(opens) > 30
    script = remediation.powershell_script({"name": "h"}, opens, wbench, domain_role="member")
    done = {n[len("Repair-"):] for n in re.findall(r"^function (Repair-[A-Z0-9-]+) ", script, re.M)}
    assert len(done) >= 20
    fixed = copy.deepcopy(raw)
    apply_script(fixed, script)
    after = evaluate(fixed, wbench)
    bad = [(s, after[s].status, after[s].reason[:140]) for s in sorted(done) if after[s].status == OPEN]
    assert not bad, bad
    manual = [r.stig_id for r in opens if r.stig_id not in done]
    assert manual and all(after[s].status == OPEN for s in manual)       # untouched, still reported


def test_user_rights_only_ever_lose_principals(wbench):
    raw = load("windows-noncompliant")
    rights = raw["facts"]["user_rights"]["value"]
    rights["SeDebugPrivilege"] = "*S-1-5-32-544,*S-1-5-32-545"
    rights["SeBackupPrivilege"] = "*S-1-5-32-544,*S-1-5-21-111-222-333-1105"
    rights["SeRestorePrivilege"] = "*S-1-5-32-544,*S-1-5-32-551"
    opens = [r for r in evaluate(raw, wbench).values() if r.status == OPEN]
    by_id = {r.stig_id: r for r in opens}
    assert {"WN22-UR-000100", "WN22-UR-000040", "WN22-UR-000210"} <= set(by_id)
    script = remediation.powershell_script({"name": "h"}, opens, wbench, domain_role="member")
    assert "'SeDebugPrivilege = *S-1-5-32-544'" in script       # excess removed, nothing added
    assert "'SeRestorePrivilege = *S-1-5-32-544'" in script
    manual = script[script.index("MANUAL"):]
    assert "WN22-UR-000040" in manual and "domain, service or virtual-account" in manual
    for line in re.findall(r"'(Se\w+ = [^']*)'", script):
        name, _, sids = line.partition(" = ")
        current = {s for s in rights[name].split(",") if s}
        assert {s for s in sids.split(",") if s} <= current       # never a principal that was not there
    dc = remediation.powershell_script({"name": "h"}, opens, wbench, domain_role="dc")
    assert "SeDebugPrivilege = " not in dc and "domain controller" in dc[dc.index("MANUAL"):]
    nodata = remediation.powershell_script({"name": "h"}, [{"stig_id": "WN22-UR-000100"}], wbench)
    assert "SeDebugPrivilege" not in nodata.split("MANUAL")[0].split("function Repair-")[-1] \
        or "principals of this right are not known" in nodata


def test_access_changes_sit_behind_a_switch(wbench):
    ids = ["WN22-MS-000020", "WN22-SO-000380", "WN22-DC-000320", "WN22-SO-000310", "WN22-CC-000020"]
    script = remediation.powershell_script({"name": "h"}, [{"stig_id": s} for s in ids], wbench)
    assert "[switch]$IncludeAccessChanges" in script
    for sid in ids[:4]:
        body = script.split(f"function Repair-{sid} ")[1].split("\n}")[0]
        assert "WARNING" in body and "-AccessChange" in body, sid
    cc = script.split("function Repair-WN22-CC-000020 ")[1].split("\n}")[0]
    assert "-AccessChange" not in cc
    assert "if ($AccessChange -and -not $IncludeAccessChanges)" in script
