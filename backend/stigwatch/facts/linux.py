"""Parse and normalise the output of ``collectors/collect-linux.sh``.

The collector reports raw facts (file contents, command output, counts) and decides
nothing. Each fact is parsed here into the comparable values the checks in
``checks/linux.yml`` use. A fact the collector could not read stays ``unavailable``; a fact
whose value cannot be parsed becomes ``unavailable`` with the parse error as its reason.
Neither ever decides a rule.

Conventions for normalised values:
- a setting that is absent (file missing, directive missing or commented out) is ``None``
  ("not configured"), which never satisfies a requirement;
- a setting given more than once with different values is ``None`` with ``conflict: True``;
- something that cannot be known from the collected data is left out (unknown).
"""

from __future__ import annotations

import re
import shlex
from datetime import date, datetime
from typing import Any, Callable

from . import Operator

COLLECTOR = "linux"
SUPPORTED_VERSION = 1
BENCHMARK = "ubuntu-22.04"

# Canonical's published end of standard security maintenance for 22.04 LTS is "May 2027"
# (https://ubuntu.com/about/release-cycle, read 2026-11-10). The last day we can be sure
# of is 30 April 2027; after that the rule needs a manual check of ESM status.
STANDARD_SUPPORT_SURE_UNTIL = date(2027, 4, 30)

# The Standard Mandatory DoD Notice and Consent Banner as given in UBTU-22-255020 and
# UBTU-22-271015. Comparison ignores whitespace differences (line wrapping, double spaces).
DOD_BANNER = (
    "You are accessing a U.S. Government (USG) Information System (IS) that is provided for "
    "USG-authorized use only. By using this IS (which includes any device attached to this "
    "IS), you consent to the following conditions: -The USG routinely intercepts and "
    "monitors communications on this IS for purposes including, but not limited to, "
    "penetration testing, COMSEC monitoring, network operations and defense, personnel "
    "misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. "
    "-At any time, the USG may inspect and seize data stored on this IS. -Communications "
    "using, or data stored on, this IS are not private, are subject to routine monitoring, "
    "interception, and search, and may be disclosed or used for any USG-authorized purpose. "
    "-This IS includes security measures (e.g., authentication and access controls) to "
    "protect USG interests--not for your personal benefit or privacy. -Notwithstanding the "
    "above, using this IS does not constitute consent to PM, LE or CI investigative "
    "searching or monitoring of the content of privileged communications, or work product, "
    "related to personal representation or services by attorneys, psychotherapists, or "
    "clergy, and their assistants. Such communications and work product are private and "
    "confidential. See User Agreement for details."
)

# Packages whose presence means a graphical user interface is installed.
GUI_PACKAGES = (
    "xserver-xorg-core", "xwayland", "gnome-shell", "gdm3", "lightdm", "sddm",
    "ubuntu-desktop", "xfce4-session", "mate-session-manager", "cinnamon-session",
    "plasma-workspace",
)

FACTS: dict[str, str] = {
    "os_release": "/etc/os-release",
    "lsb_release": "/etc/lsb-release",
    "release_support": "derived: release and collection date against Canonical's support window",
    "packages": "dpkg-query status of the packages the checks use",
    "gui": "derived: whether a graphical user interface package is installed",
    "units": "systemctl show: load, active and unit-file state of the units the checks use",
    "sshd_config": "directives in /etc/ssh/sshd_config and /etc/ssh/sshd_config.d/*.conf",
    "sshd_effective": "sshd -T effective configuration",
    "ssh_banner": "the file named by the sshd Banner directive",
    "sysctl_runtime": "running kernel parameters from /proc/sys",
    "sysctl_saved": "kernel parameters saved in sysctl configuration files",
    "login_defs": "/etc/login.defs",
    "useradd_defaults": "/etc/default/useradd",
    "pam_common_auth": "/etc/pam.d/common-auth",
    "pam_common_password": "/etc/pam.d/common-password",
    "faillock_conf": "/etc/security/faillock.conf",
    "pwquality_conf": "/etc/security/pwquality.conf",
    "limits": "maxlogins lines in /etc/security/limits.conf and limits.d",
    "shell_tmout": "TMOUT lines in /etc/bash.bashrc and /etc/profile.d",
    "apt_conf": "APT AllowUnauthenticated and unattended-upgrades Remove-Unused settings",
    "grub_cfg": "/boot/grub/grub.cfg (counts only, never the password hash)",
    "default_grub": "GRUB_CMDLINE_LINUX lines in /etc/default/grub",
    "proc_cmdline": "/proc/cmdline",
    "shadow": "/etc/shadow (counts only, never hashes or names)",
    "root_password_status": "passwd -S root",
    "passwd_accounts": "/etc/passwd name, UID, GID and shell",
    "group_sudo": "members of the sudo group in /etc/group",
    "sudoers": "NOPASSWD, !authenticate and ALL lines in /etc/sudoers and /etc/sudoers.d",
    "auditd_conf": "/etc/audit/auditd.conf",
    "audit_rules": "auditctl -l (loaded audit rules)",
    "audit_status": "auditctl -s",
    "audit_rules_d": "-e lines in /etc/audit/rules.d/*.rules",
    "audit_paths": "mode and owners of audit configuration and log files",
    "path_stats": "mode and owners of /var/log, /var/log/syslog, journalctl and audit tools",
    "cmd_dirs_writable": "group/world-writable system command directories",
    "cmd_files_writable": "group/world-writable system commands",
    "lib_files_writable": "group/world-writable shared libraries",
    "cmd_dirs_owner": "system command directories not owned by root",
    "cmd_dirs_group": "system command directories not group-owned by root",
    "cmd_files_owner": "system commands not owned by root",
    "cmd_files_group": "system commands not group-owned by root (non-SGID)",
    "lib_dirs_owner": "library directories not owned by root",
    "lib_dirs_group": "library directories not group-owned by root",
    "lib_files_owner": "shared libraries not owned by root",
    "lib_files_group": "shared libraries not group-owned by root",
    "var_log_files": "files under /var/log more permissive than 640",
    "public_dirs": "world-writable directories without the sticky bit",
    "journal_entries": "mode and owners under /run/log/journal and /var/log/journal",
    "modprobe_usb": "usb-storage lines in /etc/modprobe.d",
    "timedatectl": "timedatectl show",
    "chrony_conf": "server, pool, maxpoll and makestep lines in /etc/chrony*",
    "ufw_status": "ufw status",
    "aide_cron": "SHA-1 of the AIDE cron scripts and of the packaged original",
    "aide_conf": "audit tool lines in /etc/aide/aide.conf",
    "gsettings": "gsettings values for the GNOME settings the checks use",
    "gdm_greeter": "/etc/gdm3/greeter.dconf-defaults",
    "pam_pkcs11_conf": "/etc/pam_pkcs11/pam_pkcs11.conf",
    "sssd_conf": "offline_credentials_expiration in /etc/sssd/sssd.conf and conf.d",
    "dmesg_nx": "dmesg lines about NX (Execute Disable)",
    "cpu_flags": "nx flag in /proc/cpuinfo",
    "apparmor_status": "aa-status",
    "wireless": "/proc/net/wireless",
    "block_devices": "lsblk device tree (NAME, TYPE, FSTYPE, MOUNTPOINT, PKNAME)",
    "crypttab": "/etc/crypttab",
    "audit_remote": "au-remote plugin and audisp-remote configuration",
}

DERIVED = {"release_support": ("os_release",), "gui": ("packages",)}

_SAFE_ID = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


# --------------------------------------------------------------------------- envelope

def validate(data: Any) -> dict:
    """Check the collector envelope. Raises ``ValueError`` when it is unusable."""
    if not isinstance(data, dict):
        raise ValueError("collector output must be a JSON object")
    if data.get("collector") != COLLECTOR:
        raise ValueError(f"not a Linux collector file (collector={data.get('collector')!r})")
    if data.get("version") != SUPPORTED_VERSION:
        raise ValueError(f"unsupported Linux collector version {data.get('version')!r}")
    host = data.get("host")
    if not isinstance(host, dict) or not isinstance(host.get("name"), str):
        raise ValueError("collector output needs host.name")
    for key in ("os_release", "kernel", "virtualization"):
        if host.get(key) is not None and not isinstance(host[key], str):
            raise ValueError(f"host.{key} must be a string")
    if not isinstance(data.get("collected_at"), str):
        raise ValueError("collector output needs collected_at")
    for key in ("privileged", "redacted", "utf8_bytes_dropped"):
        if data.get(key) is not None and not isinstance(data[key], bool):
            raise ValueError(f"{key} must be true, false or null")
    facts = data.get("facts")
    if not isinstance(facts, dict):
        raise ValueError("collector output has no 'facts' object")
    for fid, fact in facts.items():
        if not isinstance(fid, str) or not _SAFE_ID.match(fid):
            raise ValueError(f"invalid fact id {fid!r}")
        if not isinstance(fact, dict):
            raise ValueError(f"fact {fid!r} must be an object")
        if fact.get("status") not in ("ok", "unavailable"):
            raise ValueError(f"fact {fid!r} has an invalid status {fact.get('status')!r}")
        for key in ("reason", "command"):
            if fact.get(key) is not None and not isinstance(fact[key], str):
                raise ValueError(f"fact {fid!r} field {key!r} must be a string")
    return data


def summary(data: dict) -> dict:
    """Fact status counts for ``collect-parse``."""
    validate(data)
    parsed = facts(data)
    raw = data["facts"]
    ok = sorted(f for f in raw if parsed.get(f, {}).get("status") == "ok")
    unavailable = {f: parsed[f].get("reason") or "" for f in raw
                   if f in parsed and parsed[f].get("status") != "ok"}
    return {
        "host": data["host"].get("name"),
        "collected_at": data["collected_at"],
        "facts": len(raw),
        "ok": len(ok),
        "read": ok,
        "unavailable": unavailable,
        "unknown": sorted(f for f in raw if f not in FACTS),
        "missing": sorted(f for f in FACTS if f not in raw and f not in DERIVED),
    }


# --------------------------------------------------------------------------- helpers

def _file(value: Any) -> tuple[bool, str]:
    if not isinstance(value, dict) or not isinstance(value.get("exists"), bool):
        raise ValueError("expected {exists, text}")
    text = value.get("text")
    if value["exists"] and not isinstance(text, str):
        raise ValueError("text must be a string")
    return value["exists"], text or ""


def _lines(text: Any) -> list[str]:
    if not isinstance(text, str):
        raise ValueError("expected text")
    return [ln for ln in text.splitlines() if ln.strip()]


def _active(lines: list[str], comment: str = "#") -> list[str]:
    return [ln for ln in lines if ln.strip() and not ln.lstrip().startswith(comment)]


def _multi(value: Any) -> list[tuple[str, str]]:
    """``{"files": [...], "text": "path<TAB>line..."}`` -> [(path, line)]."""
    if not isinstance(value, dict):
        raise ValueError("expected {files, text}")
    out = []
    for ln in _lines(value.get("text", "")):
        path, sep, rest = ln.partition("\t")
        if not sep:
            raise ValueError("line without a file prefix")
        out.append((path, rest))
    return out


def _int(s: Any) -> int | None:
    try:
        return int(str(s).strip())
    except (TypeError, ValueError):
        return None


def _setting(values: list[Any]) -> dict:
    distinct: list[Any] = []
    for v in values:
        if v not in distinct:
            distinct.append(v)
    return {
        "value": distinct[0] if len(distinct) == 1 else None,
        "values": distinct,
        "conflict": len(distinct) > 1,
        "set": bool(distinct),
    }


def _kv_file(text: str, sep: str | None = None, lower_keys: bool = False) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for ln in _active(text.splitlines()):
        if sep is None:
            parts = ln.split(None, 1)
        else:
            k, s, v = ln.partition(sep)
            parts = [k, v] if s else [k]
        key = parts[0].strip()
        if lower_keys:
            key = key.lower()
        out.setdefault(key, []).append(parts[1].strip() if len(parts) > 1 else "")
    return out


def norm_ws(text: str) -> str:
    return " ".join(text.split())


def banner_matches(text: str) -> bool:
    return norm_ws(text) == norm_ws(DOD_BANNER)


def _stats(text: Any) -> list[dict]:
    out = []
    for ln in _lines(text):
        parts = ln.split("\t", 5)
        if len(parts) != 6:
            raise ValueError("stat line must have 6 tab-separated fields")
        role, mode, user, group, kind, path = parts
        entry: dict[str, Any] = {"role": role, "path": path, "type": kind}
        if kind != "missing":
            entry.update(mode=mode, user=user, group=group)
        out.append(entry)
    return out


# --------------------------------------------------------------------------- parsers

def p_os_release(v: Any) -> dict:
    exists, text = _file(v)
    if not exists:
        raise ValueError("/etc/os-release is missing")
    kv = {}
    for ln in _active(text.splitlines()):
        k, sep, val = ln.partition("=")
        if sep:
            kv[k.strip()] = val.strip().strip('"').strip("'")
    return {"id": kv.get("ID"), "version_id": kv.get("VERSION_ID"),
            "pretty_name": kv.get("PRETTY_NAME")}


def p_lsb_release(v: Any) -> dict:
    exists, text = _file(v)
    kv = {}
    for ln in _active(text.splitlines()):
        k, sep, val = ln.partition("=")
        if sep:
            kv[k.strip()] = val.strip().strip('"')
    return {"exists": exists, "description": kv.get("DISTRIB_DESCRIPTION")}


def p_packages(v: Any) -> dict:
    if not isinstance(v, dict) or not isinstance(v.get("queried"), list):
        raise ValueError("expected {queried, text}")
    found: dict[str, dict] = {}
    for ln in _lines(v.get("text", "")):
        parts = ln.split("\t")
        if len(parts) < 2:
            raise ValueError(f"unparsable dpkg-query line {ln!r}")
        name, abbrev = parts[0].split(":")[0], parts[1]
        version = parts[2] if len(parts) > 2 else ""
        state = abbrev[1:2]
        installed: bool | None
        if state == "i":
            installed = True
        elif state in ("n", "c", ""):
            installed = False
        else:  # half-installed, unpacked, triggers pending: not decidable
            installed = None
        found[name] = {"installed": installed, "version": version or None}
    out: dict[str, dict] = {}
    for name in v["queried"]:
        if not isinstance(name, str):
            raise ValueError("queried package names must be strings")
        info = found.get(name, {"installed": False, "version": None})
        entry = {"version": info["version"]}
        if info["installed"] is not None:
            entry["installed"] = info["installed"]
        out[name] = entry
    return out


def p_units(v: Any) -> dict:
    """``systemctl show`` prints one block per queried unit, in argument order. A unit
    that is an alias (an unmasked ctrl-alt-del.target is an alias of reboot.target) is
    reported under its primary Id with the alias in Names; its state is reported here
    under the name that was queried."""
    if not isinstance(v, dict) or not isinstance(v.get("text"), str):
        raise ValueError("expected {queried, text}")
    queried = v.get("queried") or []
    blocks = []
    for block in re.split(r"\n\s*\n", v["text"].strip()):
        props = {}
        for ln in block.splitlines():
            k, sep, val = ln.partition("=")
            if sep:
                props[k.strip()] = val.strip()
        if props.get("Id"):
            blocks.append(props)
    out: dict[str, dict] = {}
    for i, name in enumerate(queried):
        def names(p: dict) -> set[str]:
            return {p.get("Id", "")} | set(p.get("Names", "").split())
        match = [p for p in blocks if name in names(p)]
        if not match and len(blocks) == len(queried) and "Names" not in blocks[i]:
            match = [blocks[i]]  # older output without Names: argument order
        if not match:
            raise ValueError(f"systemctl show did not report {name}")
        p = match[0]
        out[name] = {"load": p.get("LoadState"), "active": p.get("ActiveState"),
                     "file": p.get("UnitFileState") or None, "id": p.get("Id")}
    return out


SSHD_KEYWORDS = (
    "permitemptypasswords", "permituserenvironment", "x11forwarding", "x11uselocalhost",
    "clientalivecountmax", "clientaliveinterval", "banner", "ciphers", "macs",
    "kexalgorithms", "pubkeyauthentication",
)
_SSHD_INT = {"clientalivecountmax", "clientaliveinterval"}
_SSHD_RE = re.compile(r"^\s*([A-Za-z0-9]+)(?:\s*=\s*|\s+)(.*?)\s*$")


SSHD_COLLECTED_GLOB = "/etc/ssh/sshd_config.d/*.conf"


def _sshd_include_collected(target: str) -> bool:
    """True when every file an Include target can name is among the files collected."""
    if target == SSHD_COLLECTED_GLOB:
        return True
    # Any pattern in that directory ending in a literal ".conf" names a subset of *.conf.
    head, _, name = target.rpartition("/")
    return head == "/etc/ssh/sshd_config.d" and name.endswith(".conf")


def p_sshd_config(v: Any) -> dict:
    entries = _multi(v)
    files = v.get("files") or []
    occurrences: dict[str, list[dict]] = {k: [] for k in SSHD_KEYWORDS}
    in_match: dict[str, bool] = {}
    for path, ln in entries:
        if ln.lstrip().startswith("#"):
            continue
        m = _SSHD_RE.match(ln)
        if not m:
            continue
        key, val = m.group(1).lower(), m.group(2).strip().strip('"')
        if key == "match":
            in_match[path] = val.lower() != "all"
            continue
        if key == "include":
            for target in val.split():
                target = target.strip('"')
                if not target.startswith("/"):
                    target = "/etc/ssh/" + target  # sshd resolves relative paths in /etc/ssh
                if not _sshd_include_collected(target):
                    raise ValueError(f"{path} includes {target}, which the collector does not read; "
                                     "the effective sshd settings are unknown")
            continue
        if key not in occurrences:
            continue
        if key == "banner":
            parsed: Any = val
        elif key in _SSHD_INT:
            parsed = _int(val)
            if parsed is None:
                raise ValueError(f"{key} is not a number: {val!r}")
        else:
            parsed = val.lower()
        occurrences[key].append({"file": path, "value": parsed, "match": in_match.get(path, False)})
    out: dict[str, Any] = {"files": files, "main_exists": bool(files)}
    for key, occ in occurrences.items():
        s = _setting([o["value"] for o in occ])
        s["occurrences"] = occ
        if key in ("ciphers", "macs", "kexalgorithms") and isinstance(s["value"], str):
            s["list"] = [x.strip() for x in s["value"].split(",") if x.strip()]
        elif key in ("ciphers", "macs", "kexalgorithms"):
            s["list"] = None
        out[key] = s
    return out


def p_sshd_effective(v: Any) -> dict:
    out: dict[str, str] = {}
    for ln in _lines(v):
        k, _, val = ln.strip().partition(" ")
        out.setdefault(k.lower(), val.strip())
    if not out:
        raise ValueError("sshd -T returned nothing")
    return out


def p_ssh_banner(v: Any) -> dict:
    if not isinstance(v, dict):
        raise ValueError("expected {path, exists, text}")
    path = v.get("path")
    if path is None:
        return {"path": None, "matches_dod_banner": None}
    if not v.get("exists"):
        return {"path": path, "matches_dod_banner": False}
    text = v.get("text")
    if not isinstance(text, str):
        raise ValueError("banner text missing")
    return {"path": path, "matches_dod_banner": banner_matches(text)}


SYSCTL_KEYS = (
    "kernel.dmesg_restrict", "kernel.randomize_va_space", "net.ipv4.tcp_syncookies",
    "crypto.fips_enabled",
)


def p_sysctl_runtime(v: Any) -> dict:
    out: dict[str, Any] = {}
    for ln in _lines(v):
        parts = ln.split("\t")
        if len(parts) < 2:
            raise ValueError(f"unparsable line {ln!r}")
        key, state = parts[0], parts[1]
        val = parts[2] if len(parts) > 2 else ""
        if state == "ok":
            n = _int(val)
            out[key] = n if n is not None else val.strip()
        elif state == "missing":
            out[key] = None
        # "unreadable": left out (unknown)
    return out


def p_sysctl_saved(v: Any) -> dict:
    values: dict[str, list[Any]] = {k: [] for k in SYSCTL_KEYS}
    for _, ln in _multi(v):
        s = ln.strip()
        if not s or s.startswith(("#", ";")):
            continue
        k, sep, val = s.lstrip("-").partition("=")
        if not sep:
            continue
        key = k.strip().replace("/", ".")
        if key in values:
            n = _int(val)
            values[key].append(n if n is not None else val.strip())
    return {k: _setting(vals) for k, vals in values.items()}


def p_login_defs(v: Any) -> dict:
    exists, text = _file(v)
    kv = _kv_file(text)
    out: dict[str, Any] = {"exists": exists}
    for key in ("PASS_MIN_DAYS", "PASS_MAX_DAYS"):
        vals = [_int(x) for x in kv.get(key, [])]
        out[key] = vals[-1] if vals else None
    umask = kv.get("UMASK")
    if umask:
        raw = umask[-1].strip()
        out["UMASK"] = format(int(raw, 8), "03o") if re.fullmatch(r"[0-7]{1,4}", raw) else raw
    else:
        out["UMASK"] = None
    enc = kv.get("ENCRYPT_METHOD")
    out["ENCRYPT_METHOD"] = enc[-1].upper() if enc else None
    return out


def p_useradd_defaults(v: Any) -> dict:
    exists, text = _file(v)
    kv = _kv_file(text, sep="=")
    vals = [_int(x) for x in kv.get("INACTIVE", [])]
    return {"exists": exists, "INACTIVE": vals[-1] if vals else None}


_PAM_RE = re.compile(r"^\s*(-?[a-z]+)\s+(\[[^\]]*\]|\S+)\s+(\S+)\s*(.*)$", re.I)


def _pam(text: str) -> list[dict]:
    out = []
    for ln in _active(text.splitlines()):
        if ln.lstrip().startswith("@"):
            continue
        m = _PAM_RE.match(ln)
        if not m:
            continue
        args = m.group(4).split()
        out.append({"type": m.group(1).lstrip("-").lower(), "control": m.group(2).lower(),
                    "module": m.group(3).rsplit("/", 1)[-1], "args": args})
    return out


def _arg(args: list[str], name: str) -> str | None:
    for a in args:
        k, sep, val = a.partition("=")
        if sep and k == name:
            return val
    return None


def _nullok(text: str) -> int:
    """Active lines containing "nullok", as the check text's grep counts them (whatever
    the PAM type's case or whether the line parses)."""
    return sum(1 for ln in _active(text.splitlines()) if "nullok" in ln)


def p_pam_common_auth(v: Any) -> dict:
    exists, text = _file(v)
    lines = _pam(text)
    delays = [_int(_arg(ln["args"], "delay")) for ln in lines if ln["module"] == "pam_faildelay.so"]
    delays = [d for d in delays if d is not None]
    return {
        "exists": exists,
        "nullok": _nullok(text),
        "faillock": any(ln["module"] == "pam_faillock.so" for ln in lines),
        "faildelay_delay": min(delays) if delays else None,
        "pkcs11": any(ln["module"] == "pam_pkcs11.so" for ln in lines),
        "sss": any(ln["module"] == "pam_sss.so" for ln in lines),
    }


def p_pam_common_password(v: Any) -> dict:
    exists, text = _file(v)
    lines = _pam(text)
    pwq = [ln for ln in lines if ln["module"] == "pam_pwquality.so" and "requisite" in ln["control"]]
    retry = _int(_arg(pwq[0]["args"], "retry")) if pwq else None
    unix = [ln for ln in lines if ln["module"] == "pam_unix.so" and ln["type"] == "password"]
    rounds = [_int(_arg(ln["args"], "rounds")) for ln in unix]
    return {
        "exists": exists,
        "nullok": _nullok(text),
        "pwquality_requisite": bool(pwq),
        "pwquality_retry": retry,
        "unix_sha512": all("sha512" in ln["args"] for ln in unix) if unix else False,
        "unix_rounds": (min(r for r in rounds if r is not None)
                        if unix and all(r is not None for r in rounds) else None),
    }


def p_faillock_conf(v: Any) -> dict:
    exists, text = _file(v)
    flags: set[str] = set()
    vals: dict[str, int | None] = {}
    for ln in _active(text.splitlines()):
        k, sep, val = ln.partition("=")
        if sep:
            vals[k.strip()] = _int(val)
        else:
            flags.add(ln.strip())
    return {"exists": exists, "audit": "audit" in flags, "silent": "silent" in flags,
            "deny": vals.get("deny"), "fail_interval": vals.get("fail_interval"),
            "unlock_time": vals.get("unlock_time")}


PWQUALITY_KEYS = ("ucredit", "lcredit", "dcredit", "ocredit", "dictcheck", "minlen", "difok",
                  "enforcing")


def p_pwquality_conf(v: Any) -> dict:
    exists, text = _file(v)
    kv = _kv_file(text, sep="=")
    out: dict[str, Any] = {"exists": exists}
    for key in PWQUALITY_KEYS:
        vals = [_int(x) for x in kv.get(key, [])]
        out[key] = vals[-1] if vals else None
    return out


def p_limits(v: Any) -> dict:
    entries = []
    for path, ln in _multi(v):
        parts = ln.split()
        if len(parts) >= 4 and parts[2].lower() == "maxlogins" and not parts[0].startswith("#"):
            n = _int(parts[3])
            if n is not None:
                entries.append({"file": path, "domain": parts[0], "type": parts[1], "value": n})
    star = [e["value"] for e in entries if e["domain"] == "*" and e["type"] in ("hard", "-")]
    return {
        "count": len(entries),
        "entries": entries,
        "all_users_limit": min(star) if star else None,
        "min_value": min((e["value"] for e in entries), default=None),
        "max_value": max((e["value"] for e in entries), default=None),
    }


def p_shell_tmout(v: Any) -> dict:
    values = []
    for _, ln in _multi(v):
        if ln.lstrip().startswith("#"):
            continue
        for m in re.finditer(r"(?:^|[^A-Za-z0-9_])TMOUT=([0-9]+)", ln):
            values.append(int(m.group(1)))
    return {"count": len(values), "values": values,
            "min": min(values) if values else None, "max": max(values) if values else None}


_APT_RE = re.compile(r'^\s*([A-Za-z0-9:_-]+)\s+"?([^";]*)"?\s*;')


def p_apt_conf(v: Any) -> dict:
    allow, kernel, deps = [], [], []
    for path, ln in _multi(v):
        s = ln.strip()
        if s.startswith(("//", "#")):
            continue
        m = _APT_RE.match(s)
        if not m:
            continue
        key, val = m.group(1).lower(), m.group(2).strip().lower()
        if key == "apt::get::allowunauthenticated":
            allow.append(val)
        elif path.endswith("/50unattended-upgrades"):
            if key == "unattended-upgrade::remove-unused-kernel-packages":
                kernel.append(val)
            elif key == "unattended-upgrade::remove-unused-dependencies":
                deps.append(val)
    return {"allow_unauthenticated": _setting(allow),
            "remove_unused_kernel_packages": _setting(kernel),
            "remove_unused_dependencies": _setting(deps)}


def p_grub_cfg(v: Any) -> dict:
    if not isinstance(v, dict) or not v.get("exists"):
        raise ValueError("/boot/grub/grub.cfg was not found")
    out = {}
    for key in ("pbkdf2_entries", "plain_password_entries", "superusers_lines", "linux_lines",
                "linux_lines_audit1"):
        n = v.get(key)
        if not isinstance(n, int) or isinstance(n, bool) or n < 0:
            raise ValueError(f"{key} must be a count")
        out[key] = n
    out["linux_lines_missing_audit"] = out["linux_lines"] - out["linux_lines_audit1"]
    return out


def p_default_grub(v: Any) -> dict:
    exists, text = _file(v)
    lines = [ln for ln in _active(text.splitlines())
             if re.match(r"^\s*GRUB_CMDLINE_LINUX(_DEFAULT)?=", ln)]
    missing = [ln for ln in lines if not re.search(r"(^|[\s\"'=])audit=1([\s\"']|$)", ln)]
    return {"exists": exists, "lines": len(lines), "missing_audit": len(missing)}


def p_proc_cmdline(v: Any) -> dict:
    if not isinstance(v, str):
        raise ValueError("expected text")
    params: dict[str, str] = {}
    for tok in v.split():
        k, _, val = tok.partition("=")
        params.setdefault(k, val)
    return {"audit": params.get("audit"), "fips": params.get("fips")}


def p_shadow(v: Any) -> dict:
    if not isinstance(v, dict):
        raise ValueError("expected counts")
    out = {}
    for key in ("accounts", "empty_password"):
        n = v.get(key)
        if not isinstance(n, int) or isinstance(n, bool) or n < 0:
            raise ValueError(f"{key} must be a count")
        out[key] = n
    if out["accounts"] == 0:
        raise ValueError("/etc/shadow listed no accounts")
    return out


def p_root_password_status(v: Any) -> dict:
    lines = _lines(v)
    if not lines:
        raise ValueError("passwd -S returned nothing")
    parts = lines[0].split()
    if len(parts) < 2 or parts[0] != "root":
        raise ValueError(f"unexpected passwd -S output {lines[0]!r}")
    return {"status": parts[1], "locked": parts[1] == "L"}


def _interactive(shell: str) -> bool:
    return not re.search(r"(nologin|false)$", shell)


def p_passwd_accounts(v: Any) -> dict:
    accounts = []
    for ln in _lines(v):
        parts = ln.split(":")
        if len(parts) != 4:
            raise ValueError("passwd line must be name:uid:gid:shell")
        uid = _int(parts[1])
        if uid is None:
            raise ValueError("non-numeric UID")
        accounts.append({"name": parts[0], "uid": uid, "shell": parts[3]})
    if not accounts:
        raise ValueError("/etc/passwd listed no accounts")
    by_uid: dict[int, list[dict]] = {}
    for a in accounts:
        by_uid.setdefault(a["uid"], []).append(a)
    dups = [a for group in by_uid.values() if len(group) > 1 for a in group]
    system_interactive = [
        f"{a['name']}:{a['uid']}:{a['shell']}" for a in accounts
        if 0 < a["uid"] < 1000 and a["name"] not in ("halt", "sync", "shutdown")
        and _interactive(a["shell"])
    ]
    return {
        "count": len(accounts),
        "uid0": [a["name"] for a in accounts if a["uid"] == 0],
        "duplicate_uid_accounts": len(dups),
        "duplicate_uid_interactive": [f"{a['name']}:{a['uid']}" for a in dups
                                      if _interactive(a["shell"])],
        "system_interactive": system_interactive,
    }


def p_group_sudo(v: Any) -> dict:
    exists, text = _file(v)
    members = [m for m in text.strip().split(",") if m] if exists else []
    return {"exists": exists, "members": members, "count": len(members)}


_ALL_ALL = re.compile(r"^ALL\s+ALL\s*=\s*\(\s*ALL\s*(:\s*ALL\s*)?\)\s+ALL\s*$", re.I)


def p_sudoers(v: Any) -> dict:
    nopasswd = not_auth = all_all = 0
    for path, ln in _multi(v):
        s = ln.strip()
        inc = re.match(r"^[@#](include(?:dir)?)\s+(.+?)\s*$", s)
        if inc:
            kind, target = inc.group(1), inc.group(2).strip('"')
            if not target.startswith("/"):
                target = path.rsplit("/", 1)[0] + "/" + target
            target = target.rstrip("/")
            collected = (target == "/etc/sudoers.d" if kind == "includedir"
                         else target == "/etc/sudoers" or (target.startswith("/etc/sudoers.d/")
                                                           and "%" not in target))
            if not collected:
                raise ValueError(f"{path} includes {target}, which the collector does not read; "
                                 "the sudoers rules are unknown")
            continue
        if s.startswith("#"):
            continue
        nopasswd += bool(re.search(r"NOPASSWD", s, re.I))
        not_auth += bool(re.search(r"!authenticate", s, re.I))
        all_all += bool(_ALL_ALL.match(s))
    return {"nopasswd": nopasswd, "not_authenticate": not_auth, "all_all": all_all}


def p_auditd_conf(v: Any) -> dict:
    exists, text = _file(v)
    kv = {k: vals[-1] for k, vals in _kv_file(text, sep="=", lower_keys=True).items()}
    space_left = kv.get("space_left")
    out: dict[str, Any] = {
        "exists": exists,
        "log_file": kv.get("log_file"),
        "log_group": kv.get("log_group"),
        "disk_full_action": kv["disk_full_action"].upper() if "disk_full_action" in kv else None,
        "action_mail_acct": kv.get("action_mail_acct"),
        "space_left": space_left,
        "space_left_action": kv["space_left_action"].lower() if "space_left_action" in kv else None,
    }
    if space_left is None:
        out["space_left_percent"] = None
    elif re.fullmatch(r"\d+\s*%", space_left):
        out["space_left_percent"] = int(space_left.rstrip("% "))
    # an absolute size cannot be compared with 25% and is left unknown
    return out


# --- audit rules ------------------------------------------------------------

_AUID_UNSET = {"-1", "4294967295", "unset"}
_FIELD_RE = re.compile(r"^([A-Za-z0-9_]+)(<=|>=|!=|=|<|>|&=|&)(.*)$")


def canon_path(p: str) -> str:
    p = p.rstrip("/") or "/"
    for old, new in (("/bin/", "/usr/bin/"), ("/sbin/", "/usr/sbin/"), ("/lib/", "/usr/lib/"),
                     ("/var/run/", "/run/")):
        if p.startswith(old):
            return new + p[len(old):]
    return p


def parse_audit_rule(line: str) -> dict | None:
    try:
        toks = shlex.split(line)
    except ValueError:
        toks = line.split()
    if not toks or toks[0] not in ("-a", "-w", "-A"):
        return None
    rule: dict[str, Any] = {"line": line.strip(), "kind": "watch" if toks[0] == "-w" else "syscall",
                            "syscalls": set(), "filters": set(), "arch": None, "path": None,
                            "perm": "", "action": None}
    i = 0
    while i < len(toks):
        t = toks[i]
        arg = toks[i + 1] if i + 1 < len(toks) else ""
        if t in ("-a", "-A"):
            parts = sorted(arg.split(","))
            rule["action"] = ",".join(parts)
        elif t == "-w":
            rule["path"] = canon_path(arg)
        elif t == "-p":
            rule["perm"] = arg
        elif t == "-S":
            rule["syscalls"].update(s for s in arg.split(",") if s)
        elif t in ("-F", "-C"):
            m = _FIELD_RE.match(arg)
            if m:
                name, op, val = m.groups()
                if t == "-C":
                    # -C compares two fields (uid!=euid); it is not the same as -F uid!=<value>
                    rule["filters"].add(f"C:{name}{op}{val}")
                elif name == "arch":
                    rule["arch"] = val
                elif name in ("path", "dir"):
                    rule["path"] = canon_path(val)
                elif name == "perm":
                    rule["perm"] = val
                elif name in ("key", "k"):
                    pass
                else:
                    if name in ("auid", "uid", "euid") and val in _AUID_UNSET:
                        val = "-1"
                    rule["filters"].add(f"{name}{op}{val}")
        elif t == "-k":
            pass
        else:
            i += 1
            continue
        i += 2
    # sorted lists, not sets: facts must stay JSON-serialisable (scans are stored)
    rule["syscalls"] = sorted(rule["syscalls"])
    rule["filters"] = sorted(rule["filters"])
    return rule


def p_audit_rules(v: Any) -> list[dict]:
    lines = _lines(v)
    if len(lines) == 1 and lines[0].strip().lower() == "no rules":
        return []
    rules = []
    for ln in lines:
        r = parse_audit_rule(ln)
        if r is None:
            raise ValueError(f"unrecognised auditctl -l line {ln!r}")
        rules.append(r)
    return rules


def _audit_validate(arg: Any) -> None:
    if not isinstance(arg, dict):
        raise ValueError("audit takes a mapping")
    kinds = {"watch", "exec", "syscalls"} & set(arg)
    if len(kinds) != 1:
        raise ValueError("audit needs exactly one of watch, exec, syscalls")
    if "watch" in arg:
        if not isinstance(arg["watch"], str) or not re.fullmatch(r"[rwxa]+", str(arg.get("perm", ""))):
            raise ValueError("audit watch needs a path and perm")
    if "exec" in arg and not isinstance(arg["exec"], str):
        raise ValueError("audit exec needs a path")
    if "syscalls" in arg:
        if not isinstance(arg["syscalls"], list) or not arg["syscalls"]:
            raise ValueError("audit syscalls needs a list")
        variants = arg.get("filters", [["auid>=1000", "auid!=-1"]])
        if not isinstance(variants, list) or not all(isinstance(x, list) for x in variants):
            raise ValueError("audit filters must be a list of lists")
    unknown = set(arg) - {"watch", "perm", "exec", "syscalls", "filters", "arches"}
    if unknown:
        raise ValueError(f"audit: unknown keys {sorted(unknown)}")


def _audit_mentions(rules: list[dict], arg: dict) -> list[dict]:
    if "syscalls" in arg:
        want = set(arg["syscalls"])
        return [r for r in rules if set(r["syscalls"]) & want]
    target = canon_path(arg.get("watch") or arg.get("exec"))
    return [r for r in rules if r["path"] == target]


def _audit_test(rules: Any, arg: dict) -> bool | None:
    if not isinstance(rules, list):
        return None
    mentioned = _audit_mentions(rules, arg)
    if not mentioned:
        return False  # the loaded rule set has nothing for this target
    if any("never" in (r["action"] or "").split(",") for r in mentioned):
        return None  # a "never" rule may suppress the target's events: not decidable here
    exit_rules = [r for r in mentioned if r["kind"] == "syscall" and r["action"] == "always,exit"]
    if "watch" in arg:
        need = set(arg["perm"])
        for r in mentioned:
            if need <= set(r["perm"]) and (r["kind"] == "watch" or r["action"] == "always,exit"):
                return True
        return None
    if "exec" in arg:
        for r in exit_rules:
            if ("x" in r["perm"] and set(r["syscalls"]) <= {"all"}
                    and set(r["filters"]) == {"auid>=1000", "auid!=-1"}):
                return True
        return None
    arches = arg.get("arches", ["b32", "b64"])
    variants = arg.get("filters", [["auid>=1000", "auid!=-1"]])
    want = set(arg["syscalls"])
    for arch in arches:
        for variant in variants:
            covered: set[str] = set()
            for r in exit_rules:
                if r["arch"] == arch and set(r["filters"]) == set(variant):
                    covered |= set(r["syscalls"])
            if not want <= covered:
                return None
    return True


def _audit_describe(arg: dict) -> str:
    if "watch" in arg:
        return f"an audit watch '-w {arg['watch']} -p {arg['perm']}'"
    if "exec" in arg:
        return (f"an audit rule '-a always,exit -F path={arg['exec']} -F perm=x "
                "-F auid>=1000 -F auid!=-1'")
    variants = arg.get("filters", [["auid>=1000", "auid!=-1"]])
    def flags(variant: list[str]) -> str:
        return " ".join(("-C " + f[2:]) if f.startswith("C:") else "-F " + f for f in variant)

    return (f"audit rules '-a always,exit -S {','.join(arg['syscalls'])}' for "
            f"{' and '.join(arg.get('arches', ['b32', 'b64']))} with "
            + " / ".join(flags(v) for v in variants))


def _audit_observe(rules: Any, arg: dict) -> Any:
    if not isinstance(rules, list):
        return rules
    lines = [r["line"] for r in _audit_mentions(rules, arg)]
    return lines or f"no matching rule among {len(rules)} loaded audit rules"


OPERATORS = {"audit": Operator(_audit_test, _audit_validate, _audit_describe, _audit_observe)}


def p_audit_status(v: Any) -> dict:
    kv = {}
    for ln in _lines(v):
        parts = ln.split(None, 1)
        if len(parts) == 2:
            kv[parts[0]] = parts[1].strip()
    if "enabled" not in kv:
        raise ValueError("auditctl -s did not report 'enabled'")
    return {"enabled": _int(kv["enabled"])}


def p_audit_rules_d(v: Any) -> dict:
    entries = _multi(v)
    immutable = any(re.match(r"^-e\s+2\s*$", ln.strip()) for _, ln in entries)
    return {"files": len(v.get("files") or []), "immutable": immutable}


def p_audit_paths(v: Any) -> dict:
    entries = _stats(v)
    conf = [e for e in entries if e["role"] == "conf" and e["type"] != "missing"]
    logdir = [e for e in entries if e["role"] == "logdir"]
    logs = [e for e in entries if e["role"] == "logfile" and e["type"] == "f"]
    out: dict[str, Any] = {"conf": conf, "log_files": logs}
    if logdir and logdir[0]["type"] == "d":
        out["log_dir"] = logdir[0]
    return out


def p_path_stats(v: Any) -> dict:
    entries = _stats(v)
    out: dict[str, Any] = {"audit_tools": [e for e in entries if e["role"] == "audit_tool"
                                           and e["type"] != "missing"]}
    for role in ("var_log", "syslog", "journalctl"):
        found = [e for e in entries if e["role"] == role]
        if found and found[0]["type"] != "missing":
            out[role] = found[0]
    if not out["audit_tools"]:
        del out["audit_tools"]
    return out


def p_find(v: Any) -> dict:
    if not isinstance(v, dict) or not isinstance(v.get("complete"), bool):
        raise ValueError("expected {complete, count, sample}")
    count = v.get("count")
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        raise ValueError("count must be a number")
    sample = _lines(v.get("sample", ""))
    out: dict[str, Any] = {"sample": sample[:50], "complete": v["complete"]}
    if v["complete"] or count > 0:
        out["count"] = count
    return out


def p_journal_entries(v: Any) -> dict:
    if not isinstance(v, dict) or not isinstance(v.get("complete"), bool):
        raise ValueError("expected {complete, count, sample}")
    if not v["complete"]:
        raise ValueError(v.get("error") or "the journal directories could not be fully listed")
    entries = []
    for ln in _lines(v.get("sample", "")):
        parts = ln.split("\t", 4)
        if len(parts) != 5:
            raise ValueError("journal line must have 5 tab-separated fields")
        mode, user, group, kind, path = parts
        entries.append({"mode": mode, "user": user, "group": group, "type": kind, "path": path})
    if v.get("count") != len(entries):
        raise ValueError("journal listing was truncated")

    def bad(kind: str, test: Callable[[dict], bool]) -> list[str]:
        return [f"{e['path']} {e['mode']} {e['user']}:{e['group']}" for e in entries
                if e["type"] == kind and test(e)]

    def over(limit: str) -> Callable[[dict], bool]:
        return lambda e: (int(e["mode"], 8) & ~int(limit, 8) & 0o7777) != 0

    return {
        "entries": len(entries),
        "dirs_mode_over_2750": bad("d", over("2750")),
        "files_mode_over_640": bad("f", over("640")),
        "dirs_not_root_owned": bad("d", lambda e: e["user"] != "root"),
        "dirs_not_journal_group": bad("d", lambda e: e["group"] != "systemd-journal"),
        "files_not_root_owned": bad("f", lambda e: e["user"] != "root"),
        "files_not_journal_group": bad("f", lambda e: e["group"] != "systemd-journal"),
    }


def p_modprobe_usb(v: Any) -> dict:
    install = blacklist = False
    for _, ln in _multi(v):
        s = ln.strip()
        if s.startswith("#"):
            continue
        if re.fullmatch(r"install\s+usb-storage\s+(/usr)?/bin/false", s):
            install = True
        if re.fullmatch(r"blacklist\s+usb-storage", s):
            blacklist = True
    return {"install_false": install, "blacklist": blacklist}


def p_timedatectl(v: Any) -> dict:
    kv = {}
    for ln in _lines(v):
        k, sep, val = ln.partition("=")
        if sep:
            kv[k.strip()] = val.strip()
    if "Timezone" not in kv:
        raise ValueError("timedatectl show did not report Timezone")
    return {"timezone": kv.get("Timezone"), "ntp": kv.get("NTP"),
            "synchronized": kv.get("NTPSynchronized")}


def p_chrony_conf(v: Any) -> dict:
    sources = []
    makestep = []
    for _, ln in _multi(v):
        s = ln.strip()
        if not s or s.startswith(("#", "!", ";", "%")):
            continue
        parts = s.split()
        if parts[0] in ("server", "pool", "peer") and len(parts) >= 2:
            maxpoll = None
            if "maxpoll" in parts:
                idx = parts.index("maxpoll")
                maxpoll = _int(parts[idx + 1]) if idx + 1 < len(parts) else None
            sources.append({"type": parts[0], "host": parts[1], "maxpoll": maxpoll})
        elif parts[0] == "makestep":
            makestep.append(" ".join(parts[1:]))
    with_poll = [s["maxpoll"] for s in sources if s["maxpoll"] is not None]
    return {
        "sources": sources,
        "source_count": len(sources),
        "sources_without_maxpoll": sum(1 for s in sources if s["maxpoll"] is None),
        "max_maxpoll": max(with_poll) if with_poll else None,
        "makestep": _setting(makestep),
    }


def p_ufw_status(v: Any) -> dict:
    if not isinstance(v, dict) or not isinstance(v.get("installed"), bool):
        raise ValueError("expected {installed, text}")
    if not v["installed"]:
        return {"installed": False, "status": None}
    m = re.search(r"^Status:\s*(\S+)", v.get("text") or "", re.M)
    if not m:
        raise ValueError("ufw status did not report a status")
    return {"installed": True, "status": m.group(1).lower()}


def p_aide_cron(v: Any) -> dict:
    if not isinstance(v, dict):
        raise ValueError("expected aide cron object")
    scripts = []
    for ln in _lines(v.get("cron", "")):
        path, _, sha = ln.partition("\t")
        scripts.append({"path": path, "sha1": sha.strip().lower()})
    shipped = (v.get("shipped_sha1") or "").lower() or None
    md5, dpkg_md5 = v.get("shipped_md5"), v.get("dpkg_md5")
    out: dict[str, Any] = {"scripts": scripts, "script_count": len(scripts)}
    if not scripts:
        out["default"] = False
    elif shipped and md5 and dpkg_md5 and md5.lower() == dpkg_md5.lower():
        out["default"] = all(s["sha1"] == shipped for s in scripts)
    # otherwise the packaged original could not be verified: unknown
    return out


AIDE_TOOLS = ("auditctl", "auditd", "ausearch", "aureport", "autrace", "augenrules")
AIDE_ATTRS = "p+i+n+u+g+s+b+acl+xattrs+sha512"


def p_aide_conf(v: Any) -> dict:
    exists, text = _file(v)
    found = set()
    for ln in _active(text.splitlines()):
        parts = ln.split()
        if len(parts) == 2 and parts[1] == AIDE_ATTRS:
            m = re.fullmatch(r"(?:/usr)?/sbin/(\w+)", parts[0])
            if m and m.group(1) in AIDE_TOOLS:
                found.add(m.group(1))
    return {"exists": exists, "missing_tools": [t for t in AIDE_TOOLS if t not in found]}


GSETTINGS_KEYS = {
    "org.gnome.settings-daemon.plugins.media-keys logout": "logout",
    "org.gnome.desktop.screensaver lock-enabled": "lock_enabled",
    "org.gnome.desktop.screensaver lock-delay": "lock_delay",
    "org.gnome.desktop.session idle-delay": "idle_delay",
}


def _gvariant(s: str) -> Any:
    s = s.strip()
    if s in ("true", "false"):
        return s == "true"
    m = re.fullmatch(r"(?:u?int\d+\s+)?(-?\d+)", s)
    if m:
        return int(m.group(1))
    if s in ("@as []", "[]"):
        return []
    m = re.fullmatch(r"\[(.*)\]", s)
    if m:
        return [x.strip().strip("'\"") for x in m.group(1).split(",") if x.strip()]
    raise ValueError(f"unrecognised gsettings value {s!r}")


def p_gsettings(v: Any) -> dict:
    if not isinstance(v, dict):
        raise ValueError("expected gsettings object")
    out: dict[str, Any] = {}
    for full, short in GSETTINGS_KEYS.items():
        entry = v.get(full)
        if isinstance(entry, dict) and entry.get("ok") is True:
            out[short] = _gvariant(str(entry.get("output", "")))
    return out


def p_gdm_greeter(v: Any) -> dict:
    exists, text = _file(v)
    section = ""
    enable: list[str] = []
    message: list[str] = []
    for ln in _active(text.splitlines()):
        s = ln.strip()
        if s.startswith("["):
            section = s
            continue
        if section != "[org/gnome/login-screen]":
            continue
        k, sep, val = s.partition("=")
        if not sep:
            continue
        if k.strip() == "banner-message-enable":
            enable.append(val.strip().lower())
        elif k.strip() == "banner-message-text":
            message.append(val.strip())
    out: dict[str, Any] = {"exists": exists,
                           "banner_enable": (enable[-1] == "true") if enable else None}
    if message:
        raw = message[-1]
        if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "'\"":
            raw = raw[1:-1]
        out["banner_text_matches"] = banner_matches(raw.replace("\\n", "\n"))
    else:
        out["banner_text_matches"] = None
    return out


def p_pam_pkcs11_conf(v: Any) -> dict:
    exists, text = _file(v)
    mappers: list[str] = []
    for ln in _active(text.splitlines()):
        m = re.match(r"^\s*use_mappers\s*=\s*(.*?);?\s*$", ln)
        if m:
            mappers = [x.strip() for x in m.group(1).split(",") if x.strip()]
    return {"exists": exists, "use_mappers": mappers if mappers else None}


def p_sssd_conf(v: Any) -> dict:
    vals = []
    for _, ln in _multi(v):
        m = re.match(r"^\s*offline_credentials_expiration\s*=\s*(\S+)", ln)
        if m:
            vals.append(_int(m.group(1)) if _int(m.group(1)) is not None else m.group(1))
    return {"files": len(v.get("files") or []), "offline_credentials_expiration": _setting(vals)}


def p_dmesg_nx(v: Any) -> dict:
    if not isinstance(v, str):
        raise ValueError("expected text")
    return {"active": bool(re.search(r"NX \(Execute Disable\) protection: active", v))}


def p_cpu_flags(v: Any) -> dict:
    if not isinstance(v, str):
        raise ValueError("expected text")
    return {"nx": "nx" in v.split()}


def p_apparmor_status(v: Any) -> dict:
    text = v if isinstance(v, str) else ""
    loaded = re.search(r"(\d+) profiles are loaded", text)
    enforce = re.search(r"(\d+) profiles are in enforce mode", text)
    if not loaded or not enforce:
        raise ValueError("aa-status did not report profile counts")
    return {"loaded": int(loaded.group(1)), "enforce": int(enforce.group(1))}


def p_wireless(v: Any) -> dict:
    exists, text = _file(v)
    names = []
    for ln in text.splitlines()[2:] if exists else []:
        m = re.match(r"^\s*([^:\s]+):", ln)
        if m:
            names.append(m.group(1))
    return {"interfaces": names, "count": len(names)}


_LSBLK_RE = re.compile(r'(\w[\w:-]*)="((?:[^"\\]|\\.)*)"')


def p_block_devices(v: Any) -> dict:
    devices: dict[str, dict] = {}
    for ln in _lines(v):
        props = dict(_LSBLK_RE.findall(ln))
        name = props.get("NAME")
        if not name:
            raise ValueError("lsblk line without NAME")
        d = devices.setdefault(name, {"type": props.get("TYPE", ""), "fstype": props.get("FSTYPE", ""),
                                      "mountpoint": props.get("MOUNTPOINT", ""), "parents": set()})
        if props.get("PKNAME"):
            d["parents"].add(props["PKNAME"])
    if not devices:
        raise ValueError("lsblk listed no block devices")

    def ancestors(name: str, seen: set[str] | None = None) -> set[str]:
        seen = seen if seen is not None else set()
        for p in devices.get(name, {}).get("parents", ()):
            if p not in seen:
                seen.add(p)
                ancestors(p, seen)
        return seen

    children: dict[str, set[str]] = {n: set() for n in devices}
    for n, d in devices.items():
        for p in d["parents"]:
            children.setdefault(p, set()).add(n)

    def descendants(name: str) -> set[str]:
        out: set[str] = set()
        stack = [name]
        while stack:
            for c in children.get(stack.pop(), ()):
                if c not in out:
                    out.add(c)
                    stack.append(c)
        return out

    def chain_types(names: set[str]) -> set[str]:
        return {devices[n]["type"] for n in names if n in devices}

    mounts, unencrypted = 0, []
    for n, d in devices.items():
        mp = d["mountpoint"]
        if not mp or mp in ("/boot", "/boot/efi"):
            continue
        chain = ancestors(n) | {n}
        if chain_types(chain) & {"loop", "rom"}:
            continue
        mounts += 1
        if "crypt" not in chain_types(chain):
            unencrypted.append(mp)
    unverified = []
    for n, d in devices.items():
        if d["type"] != "part" or not d["fstype"] or d["fstype"] == "crypto_LUKS":
            continue
        family = descendants(n) | {n}
        if any(devices[x]["mountpoint"] for x in family if x in devices):
            continue
        if "crypt" in chain_types(family):
            continue
        unverified.append(n)
    return {"mounts": mounts, "unencrypted_mounts": sorted(set(unencrypted)),
            "unencrypted_count": len(set(unencrypted)), "unverified_partitions": sorted(unverified),
            "unverified_count": len(unverified)}


def p_crypttab(v: Any) -> dict:
    exists, text = _file(v)
    return {"exists": exists, "entries": len(_active(text.splitlines()))}


def p_audit_remote(v: Any) -> dict:
    if not isinstance(v, dict):
        raise ValueError("expected {plugin, remote}")
    p_exists, p_text = _file(v.get("plugin"))
    r_exists, r_text = _file(v.get("remote"))
    active = _kv_file(p_text, sep="=", lower_keys=True).get("active")
    server = _kv_file(r_text, sep="=", lower_keys=True).get("remote_server")
    srv = server[-1] if server and server[-1] else None
    return {"plugin_exists": p_exists, "active": active[-1].lower() if active else None,
            "remote_server": srv,
            "remote_server_loopback": (bool(re.match(r"^(127\.|localhost$|::1$)", srv))
                                       if srv else None)}


PARSERS: dict[str, Callable[[Any], Any]] = {
    "os_release": p_os_release, "lsb_release": p_lsb_release, "packages": p_packages,
    "units": p_units, "sshd_config": p_sshd_config, "sshd_effective": p_sshd_effective,
    "ssh_banner": p_ssh_banner, "sysctl_runtime": p_sysctl_runtime,
    "sysctl_saved": p_sysctl_saved, "login_defs": p_login_defs,
    "useradd_defaults": p_useradd_defaults, "pam_common_auth": p_pam_common_auth,
    "pam_common_password": p_pam_common_password, "faillock_conf": p_faillock_conf,
    "pwquality_conf": p_pwquality_conf, "limits": p_limits, "shell_tmout": p_shell_tmout,
    "apt_conf": p_apt_conf, "grub_cfg": p_grub_cfg, "default_grub": p_default_grub,
    "proc_cmdline": p_proc_cmdline, "shadow": p_shadow,
    "root_password_status": p_root_password_status, "passwd_accounts": p_passwd_accounts,
    "group_sudo": p_group_sudo, "sudoers": p_sudoers, "auditd_conf": p_auditd_conf,
    "audit_rules": p_audit_rules, "audit_status": p_audit_status,
    "audit_rules_d": p_audit_rules_d, "audit_paths": p_audit_paths, "path_stats": p_path_stats,
    "cmd_dirs_writable": p_find, "cmd_files_writable": p_find, "lib_files_writable": p_find,
    "cmd_dirs_owner": p_find, "cmd_dirs_group": p_find, "cmd_files_owner": p_find,
    "cmd_files_group": p_find, "lib_dirs_owner": p_find, "lib_dirs_group": p_find,
    "lib_files_owner": p_find, "lib_files_group": p_find, "var_log_files": p_find,
    "public_dirs": p_find, "journal_entries": p_journal_entries, "modprobe_usb": p_modprobe_usb,
    "timedatectl": p_timedatectl, "chrony_conf": p_chrony_conf, "ufw_status": p_ufw_status,
    "aide_cron": p_aide_cron, "aide_conf": p_aide_conf, "gsettings": p_gsettings,
    "gdm_greeter": p_gdm_greeter, "pam_pkcs11_conf": p_pam_pkcs11_conf, "sssd_conf": p_sssd_conf,
    "dmesg_nx": p_dmesg_nx, "cpu_flags": p_cpu_flags, "apparmor_status": p_apparmor_status,
    "wireless": p_wireless, "block_devices": p_block_devices, "crypttab": p_crypttab,
    "audit_remote": p_audit_remote,
}


# --------------------------------------------------------------------------- facts

def _unavailable(reason: str, command: str) -> dict:
    return {"status": "unavailable", "value": None, "reason": reason, "command": command}


def _derive_release_support(osr: dict, collected_at: str) -> dict:
    try:
        when = datetime.fromisoformat(collected_at.replace("Z", "+00:00")).date()
    except ValueError as exc:
        raise ValueError(f"collected_at is not an ISO date: {collected_at!r}") from exc
    is_2204 = osr.get("id") == "ubuntu" and osr.get("version_id") == "22.04"
    out: dict[str, Any] = {"release": f"{osr.get('id')} {osr.get('version_id')}",
                           "collected_on": when.isoformat(),
                           "standard_support_sure_until": STANDARD_SUPPORT_SURE_UNTIL.isoformat()}
    if is_2204 and when <= STANDARD_SUPPORT_SURE_UNTIL:
        out["within_standard_support"] = True
    elif not is_2204:
        out["within_standard_support"] = False
    # 22.04 after the date: depends on ESM (Ubuntu Pro), left unknown
    return out


def facts(data: dict) -> dict[str, dict]:
    """Normalised facts. Call :func:`validate` first."""
    out: dict[str, dict] = {}
    raw = data.get("facts") or {}
    for fid, parser in PARSERS.items():
        fact = raw.get(fid)
        if not isinstance(fact, dict):
            continue
        command = fact.get("command") if isinstance(fact.get("command"), str) else ""
        if fact.get("status") != "ok":
            out[fid] = _unavailable(fact.get("reason") or "no reason given", command)
            continue
        try:
            value = parser(fact.get("value"))
        except (ValueError, TypeError, KeyError, AttributeError, IndexError) as exc:
            out[fid] = _unavailable(f"could not be parsed: {exc}", command)
            continue
        out[fid] = {"status": "ok", "value": value, "reason": None, "command": command}

    osr = out.get("os_release")
    if osr is None:
        pass
    elif osr["status"] != "ok":
        out["release_support"] = _unavailable(f"os_release: {osr['reason']}", "derived from os_release")
    else:
        try:
            out["release_support"] = {"status": "ok", "command": "derived from os_release",
                                      "reason": None,
                                      "value": _derive_release_support(osr["value"],
                                                                       data.get("collected_at", ""))}
        except ValueError as exc:
            out["release_support"] = _unavailable(str(exc), "derived from os_release")

    pk = out.get("packages")
    if pk is not None:
        cmd = "derived from packages: " + ", ".join(GUI_PACKAGES)
        if pk["status"] != "ok":
            out["gui"] = _unavailable(f"packages: {pk['reason']}", cmd)
        else:
            states = {p: pk["value"].get(p, {}).get("installed") for p in GUI_PACKAGES}
            if any(p not in pk["value"] for p in GUI_PACKAGES):
                out["gui"] = _unavailable("the collector did not query every GUI package", cmd)
            else:
                installed = sorted(p for p, s in states.items() if s is True)
                value: dict[str, Any] = {"packages": installed}
                if installed:
                    value["installed"] = True
                elif all(s is False for s in states.values()):
                    value["installed"] = False
                out["gui"] = {"status": "ok", "value": value, "reason": None, "command": cmd}
    return out
