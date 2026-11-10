"""Windows Server 2022 collector facts (collectors/collect-windows.ps1).

The collector writes raw values (secedit sections, auditpol rows, registry values with
their state and type, CIM/cmdlet properties). This module validates the envelope and
turns each fact into the normalised value the checks in ``checks/windows.yml`` read.

Conventions, as for Linux:
- a fact the collector could not read, or one that does not parse, is ``unavailable``
  and never decides a rule;
- a setting that is absent is ``None`` ("not configured"), which fails a requirement;
- a part of a fact that could not be read (a registry value that was access-denied, a
  user right granted to a name instead of a SID) is left out of the value and its reason
  is recorded under the fact's ``partial`` map, so the rules that need it are unknown.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Any

from . import Operator
from .linux import banner_matches

COLLECTOR = "windows"
SUPPORTED_VERSION = 1
BENCHMARK = "windows-server-2022"

# The STIG check text (WN22-00-000100): Extended Support for Windows Server 2022 ends on
# 10/15/2031; a past end date is a finding.
EXTENDED_SUPPORT_END = date(2031, 10, 15)
SERVER_2022_BUILD = "20348"

FACTS: dict[str, str] = {
    "os": "Win32_OperatingSystem, InstallationType and $env:firmware_type",
    "os_support": "derived: OS build and collection date against the STIG's end-of-support date",
    "domain_role": "Win32_ComputerSystem.DomainRole (standalone, member or domain controller)",
    "security_policy": "secedit [System Access] and [Kerberos Policy]",
    "user_rights": "secedit [Privilege Rights] (user rights assignments, by SID)",
    "audit_policy": "auditpol subcategory settings, by subcategory GUID",
    "registry": "the registry values the checks use (read-only)",
    "features": "Get-WindowsFeature install state of the roles and features the checks use",
    "services": "Get-Service state of the services the checks use",
    "local_accounts": "Win32_UserAccount and Get-LocalUser (local accounts)",
    "local_admins": "members of the local Administrators group",
    "volumes": "Win32_Volume file systems of the local fixed volumes and partition types",
    "bitlocker": "Get-BitLockerVolume protection status",
    "tpm": "Get-Tpm and Win32_Tpm",
    "secure_boot": "Confirm-SecureBootUEFI",
    "device_guard": "Win32_DeviceGuard (virtualization-based security and Credential Guard)",
    "defender": "Get-MpComputerStatus",
    "firewall": "Get-NetFirewallProfile -PolicyStore ActiveStore",
    "smb_server": "Get-SmbServerConfiguration",
    "certificates": "DoD certificates in the LocalMachine Root and Disallowed stores",
    "acls": "file permissions of the event logs, Eventvwr.exe, NTDS files and SYSVOL",
}

DERIVED = {"os_support": ("os",)}

_SAFE_ID = re.compile(r"^[a-z][a-z0-9_]{0,63}$")

# Well-known SIDs used in the checks and their names (for evidence).
SID_NAMES = {
    "S-1-1-0": "Everyone",
    "S-1-3-0": "CREATOR OWNER",
    "S-1-5-4": "INTERACTIVE",
    "S-1-5-6": "SERVICE",
    "S-1-5-7": "ANONYMOUS LOGON",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-18": "SYSTEM",
    "S-1-5-19": "LOCAL SERVICE",
    "S-1-5-20": "NETWORK SERVICE",
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-545": "Users",
    "S-1-5-32-546": "Guests",
    "S-1-5-32-549": "Server Operators",
    "S-1-5-113": "Local account",
    "S-1-5-114": "Local account and member of Administrators group",
    "S-1-5-83-0": "Virtual Machines",
    "S-1-5-80-880578595-1860270145-482643319-2788375705-1540778122": "NT SERVICE\\EventLog",
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464": "NT SERVICE\\TrustedInstaller",
    "S-1-5-21-*-512": "Domain Admins",
    "S-1-5-21-*-519": "Enterprise Admins",
}

# --------------------------------------------------------------------------- envelope


def validate(data: Any) -> dict:
    """Check the collector envelope. Raises ``ValueError`` when it is unusable."""
    if not isinstance(data, dict):
        raise ValueError("collector output must be a JSON object")
    if data.get("collector") != COLLECTOR:
        raise ValueError(f"not a Windows collector file (collector={data.get('collector')!r})")
    if data.get("version") != SUPPORTED_VERSION:
        raise ValueError(f"unsupported Windows collector version {data.get('version')!r}")
    host = data.get("host")
    if not isinstance(host, dict) or not isinstance(host.get("name"), str):
        raise ValueError("collector output needs host.name")
    for key in ("os", "build"):
        if host.get(key) is not None and not isinstance(host[key], str):
            raise ValueError(f"host.{key} must be a string")
    if not isinstance(data.get("collected_at"), str):
        raise ValueError("collector output needs collected_at")
    for key in ("privileged", "redacted"):
        if data.get(key) is not None and not isinstance(data[key], bool):
            raise ValueError(f"{key} must be true, false or null")
    if data.get("powershell") is not None and not isinstance(data["powershell"], str):
        raise ValueError("powershell must be a string")
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
        "unavailable": unavailable,
        "unknown": sorted(f for f in raw if f not in FACTS),
        "missing": sorted(f for f in FACTS if f not in raw and f not in DERIVED),
    }


# --------------------------------------------------------------------------- helpers

@dataclass(frozen=True)
class Partial:
    """A parsed value plus the parts that could not be read (``{key: reason}``, nested)."""

    value: Any
    partial: dict


def _obj(v: Any, what: str) -> dict:
    if not isinstance(v, dict):
        raise ValueError(f"{what} must be an object")
    return v


def _list(v: Any, what: str) -> list:
    if not isinstance(v, list):
        raise ValueError(f"{what} must be a list")
    return v


def _str(v: Any, what: str) -> str:
    if not isinstance(v, str):
        raise ValueError(f"{what} must be a string")
    return v


def _bool(v: Any, what: str) -> bool:
    if not isinstance(v, bool):
        raise ValueError(f"{what} must be true or false")
    return v


def _int(s: Any) -> int | None:
    if isinstance(s, bool):
        return None
    if isinstance(s, int):
        return s
    try:
        return int(str(s).strip())
    except (TypeError, ValueError):
        return None


def _when(iso: Any) -> datetime | None:
    if not isinstance(iso, str) or not iso:
        return None
    try:
        when = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    return when if when.tzinfo is not None else None


def is_sid(s: str) -> bool:
    return re.fullmatch(r"S-1-\d+(-\d+)+", s) is not None


def sid_matches(sid: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(sid, p) for p in patterns)


def sid_name(sid: str) -> str:
    if sid in SID_NAMES:
        return SID_NAMES[sid]
    for pattern, name in SID_NAMES.items():
        if "*" in pattern and fnmatch.fnmatchcase(sid, pattern):
            return name
    return sid


# --------------------------------------------------------------------------- parsers

def p_os(v: Any) -> dict:
    v = _obj(v, "os")
    out: dict[str, Any] = {}
    for k in ("caption", "version", "build_number", "installation_type", "display_version",
              "edition_id", "firmware_type"):
        val = v.get(k)
        if val is not None and not isinstance(val, str):
            raise ValueError(f"os.{k} must be a string")
        if val:  # a missing or empty value is unknown, not "not configured"
            out[k] = val
    if "build_number" not in out:
        raise ValueError("os.build_number is missing")
    for k in ("ubr", "product_type"):
        if v.get(k) is not None:
            n = _int(v[k])
            if n is None:
                raise ValueError(f"os.{k} must be a number")
            out[k] = n
    return out


ROLE_NAMES = {0: "standalone", 1: "member", 2: "standalone", 3: "member", 4: "dc", 5: "dc"}


def p_domain_role(v: Any) -> dict:
    v = _obj(v, "domain_role")
    role = v.get("domain_role")
    if isinstance(role, bool) or role not in ROLE_NAMES:
        raise ValueError(f"unknown DomainRole {role!r}")
    return {"domain_role": role, "part_of_domain": _bool(v.get("part_of_domain"), "part_of_domain"),
            "role": ROLE_NAMES[role], "server": role >= 2}


SYSTEM_ACCESS_KEYS = (
    "MinimumPasswordAge", "MaximumPasswordAge", "MinimumPasswordLength", "PasswordComplexity",
    "PasswordHistorySize", "LockoutBadCount", "ResetLockoutCount", "LockoutDuration",
    "ClearTextPassword", "LSAAnonymousNameLookup", "EnableAdminAccount", "EnableGuestAccount",
)
KERBEROS_KEYS = ("MaxTicketAge", "MaxRenewAge", "MaxServiceAge", "MaxClockSkew", "TicketValidateClient")


def _secedit_section(raw: dict, keys: tuple[str, ...]) -> dict:
    out: dict[str, Any] = {}
    for k in keys:
        val = raw.get(k)
        if val is None:
            out[k] = None  # not in the export: not configured
            continue
        n = _int(_str(val, k))
        if n is None:
            raise ValueError(f"{k} is not a number: {val!r}")
        out[k] = n
    return out


def p_security_policy(v: Any) -> dict:
    v = _obj(v, "security_policy")
    sa = v.get("System Access")
    if not isinstance(sa, dict) or not sa:
        raise ValueError("no [System Access] section")
    out: dict[str, Any] = {"system_access": _secedit_section(sa, SYSTEM_ACCESS_KEYS)}
    for key, flag, default in (("NewAdministratorName", "administrator_renamed", "administrator"),
                               ("NewGuestName", "guest_renamed", "guest")):
        raw = sa.get(key)
        if raw is not None:  # secedit always exports it; if missing the rule stays unknown
            out[flag] = _str(raw, key).strip().strip('"').lower() != default
    kp = v.get("Kerberos Policy")
    if isinstance(kp, dict):
        out["kerberos"] = _secedit_section(kp, KERBEROS_KEYS)
    return out


USER_RIGHTS = (
    "SeTrustedCredManAccessPrivilege", "SeNetworkLogonRight", "SeTcbPrivilege",
    "SeMachineAccountPrivilege", "SeInteractiveLogonRight", "SeRemoteInteractiveLogonRight",
    "SeBackupPrivilege", "SeCreatePagefilePrivilege", "SeCreateTokenPrivilege",
    "SeCreateGlobalPrivilege", "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege",
    "SeDebugPrivilege", "SeDenyNetworkLogonRight", "SeDenyBatchLogonRight",
    "SeDenyServiceLogonRight", "SeDenyInteractiveLogonRight", "SeDenyRemoteInteractiveLogonRight",
    "SeEnableDelegationPrivilege", "SeRemoteShutdownPrivilege", "SeAuditPrivilege",
    "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege", "SeLoadDriverPrivilege",
    "SeLockMemoryPrivilege", "SeSecurityPrivilege", "SeSystemEnvironmentPrivilege",
    "SeManageVolumePrivilege", "SeProfileSingleProcessPrivilege", "SeRestorePrivilege",
    "SeTakeOwnershipPrivilege",
)


def p_user_rights(v: Any) -> Partial:
    """``{right: "*S-1-5-32-544,*S-1-5-18"}`` -> ``{right: [SID, ...]}``.

    secedit omits a right nobody holds, so every known right defaults to ``[]``; that is
    only trusted when the section lists at least one known right. A right granted to a
    name rather than a ``*SID`` cannot be compared with the SIDs in the check text and is
    left out (unknown)."""
    v = _obj(v, "user_rights")
    if not any(k in v for k in USER_RIGHTS):
        raise ValueError("the [Privilege Rights] section lists no known user right")
    rights: dict[str, list[str]] = {r: [] for r in USER_RIGHTS}
    partial: dict[str, str] = {}
    for right, raw in v.items():
        entries = [e.strip() for e in _str(raw, right).split(",") if e.strip()]
        names = [e for e in entries if not (e.startswith("*") and is_sid(e[1:]))]
        if names:
            rights.pop(right, None)
            partial[right] = ("granted to names rather than SIDs (" + ", ".join(names)
                              + "), which cannot be compared with the check text")
            continue
        rights[right] = sorted({e[1:] for e in entries})
    return Partial(rights, partial)


AUDIT_GUID_SUFFIX = "-69AE-11D9-BED3-505054503030}"
AUDIT_SUBCATEGORIES = {
    "{0CCE923F": "credential_validation",
    "{0CCE923A": "other_account_management_events",
    "{0CCE9237": "security_group_management",
    "{0CCE9235": "user_account_management",
    "{0CCE9236": "computer_account_management",
    "{0CCE9248": "plug_and_play_events",
    "{0CCE922B": "process_creation",
    "{0CCE9217": "account_lockout",
    "{0CCE9249": "group_membership",
    "{0CCE9216": "logoff",
    "{0CCE9215": "logon",
    "{0CCE921B": "special_logon",
    "{0CCE9227": "other_object_access_events",
    "{0CCE9245": "removable_storage",
    "{0CCE922F": "audit_policy_change",
    "{0CCE9230": "authentication_policy_change",
    "{0CCE9231": "authorization_policy_change",
    "{0CCE9228": "sensitive_privilege_use",
    "{0CCE9213": "ipsec_driver",
    "{0CCE9214": "other_system_events",
    "{0CCE9210": "security_state_change",
    "{0CCE9211": "security_system_extension",
    "{0CCE9212": "system_integrity",
    "{0CCE923B": "directory_service_access",
    "{0CCE923C": "directory_service_changes",
    "{0CCE9223": "handle_manipulation",
    "{0CCE921E": "registry",
}
AUDIT_GUIDS = {prefix + AUDIT_GUID_SUFFIX: key for prefix, key in AUDIT_SUBCATEGORIES.items()}
# English inclusion settings of 'auditpol /get /r'. Any other text (a localized system)
# cannot be interpreted; the numeric setting from 'auditpol /backup' needs no translation.
AUDIT_ENGLISH = {"no auditing": 0, "success": 1, "failure": 2, "success and failure": 3}


def p_audit_policy(v: Any) -> dict:
    v = _obj(v, "audit_policy")
    source = _str(v.get("source"), "source")
    if source not in ("backup", "get"):
        raise ValueError(f"unknown auditpol source {source!r}")
    out: dict[str, Any] = {"source": source}
    for row in _list(v.get("subcategories"), "subcategories"):
        row = _obj(row, "subcategory")
        guid = _str(row.get("guid"), "guid").upper()
        key = AUDIT_GUIDS.get(guid)
        if key is None:
            continue
        raw_value = row.get("setting_value")
        setting = _int(raw_value) if raw_value not in (None, "") else None
        if setting is None:
            setting = AUDIT_ENGLISH.get(str(row.get("inclusion") or "").strip().lower())
            if setting is None:
                raise ValueError(f"auditpol inclusion setting {row.get('inclusion')!r} for {guid} "
                                 "is not English and no numeric setting was collected")
        if setting not in (0, 1, 2, 3):
            raise ValueError(f"auditpol setting {setting!r} for {guid} is not 0-3")
        out[key] = {"name": str(row.get("name") or ""), "setting": setting,
                    "success": bool(setting & 1), "failure": bool(setting & 2)}
    if len(out) == 1:
        raise ValueError("auditpol reported none of the subcategories the checks use")
    return out


REG_TYPES = {"DWord": "REG_DWORD", "QWord": "REG_QWORD", "String": "REG_SZ",
             "ExpandString": "REG_EXPAND_SZ", "MultiString": "REG_MULTI_SZ", "Binary": "REG_BINARY"}


def p_registry(v: Any) -> Partial:
    """``{key: {name: {set, type, value, number}}}``; read errors go to ``partial``."""
    v = _obj(v, "registry")
    out: dict[str, dict[str, dict]] = {}
    partial: dict[str, dict[str, str]] = {}
    for e in _list(v.get("values"), "values"):
        e = _obj(e, "registry value")
        key, name = _str(e.get("key"), "key"), _str(e.get("name"), "name")
        state = e.get("state")
        if state == "error":
            partial.setdefault(key, {})[name] = str(e.get("error") or "the value could not be read")
            continue
        if state == "absent":
            out.setdefault(key, {})[name] = {"set": False, "type": None, "value": None, "number": None}
            continue
        if state != "set":
            raise ValueError(f"unknown registry state {state!r}")
        rtype = REG_TYPES.get(str(e.get("type")), str(e.get("type")))
        data = e.get("data")
        number: int | None = None
        if rtype in ("REG_DWORD", "REG_QWORD"):
            if isinstance(data, bool) or not isinstance(data, int):
                raise ValueError(f"{key}\\{name}: {rtype} data must be a number")
            if rtype == "REG_DWORD":
                data &= 0xFFFFFFFF  # .NET returns DWORDs as signed 32-bit integers
            number = data
        elif rtype in ("REG_SZ", "REG_EXPAND_SZ"):
            data = _str(data, f"{key}\\{name}").rstrip("\x00")
            number = int(data) if re.fullmatch(r"\s*-?\d+\s*", data) else None
        out.setdefault(key, {})[name] = {"set": True, "type": rtype, "value": data, "number": number}
    return Partial(out, partial)


# Get-WindowsOptionalFeature names for the Server feature names the checks use.
OPTIONAL_FEATURES = {
    "TelnetClient": "Telnet-Client", "TFTP": "TFTP-Client", "SimpleTCP": "Simple-TCPIP",
    "SMB1Protocol": "FS-SMB1", "MicrosoftWindowsPowerShellV2Root": "PowerShell-v2",
    "IIS-FTPSvc": "Web-Ftp-Service",
}
OPTIONAL_STATES = {"Enabled": "Installed", "Disabled": "Available",
                   "DisabledWithPayloadRemoved": "Removed", "EnablePending": "InstallPending",
                   "DisablePending": "UninstallPending"}
INSTALL_STATES = {"Installed", "Available", "Removed", "InstallPending", "UninstallPending"}


def p_features(v: Any) -> dict:
    v = _obj(v, "features")
    source = _str(v.get("source"), "source")
    if source not in ("Get-WindowsFeature", "Get-WindowsOptionalFeature"):
        raise ValueError(f"unknown features source {source!r}")
    out: dict[str, Any] = {}
    for name, state in _obj(v.get("states"), "states").items():
        state = _str(state, name)
        if source == "Get-WindowsOptionalFeature":
            if name not in OPTIONAL_FEATURES:
                continue
            name, state = OPTIONAL_FEATURES[name], OPTIONAL_STATES.get(state, state)
        if state in INSTALL_STATES:  # anything else is left unknown
            out[name] = state
    return out


def p_services(v: Any) -> dict:
    v = _obj(v, "services")
    out = {}
    for name, s in v.items():
        s = _obj(s, name)
        present = _bool(s.get("present"), f"{name}.present")
        out[name] = {"present": present, "status": s.get("status") if present else None,
                     "start_type": s.get("start_type") if present else None}
    return out


def p_local_accounts(v: Any) -> dict:
    v = _obj(v, "local_accounts")
    accounts = []
    for a in _list(v.get("accounts"), "accounts"):
        a = _obj(a, "account")
        rid = _int(a.get("rid"))
        if rid is None:
            raise ValueError("account rid must be a number")
        accounts.append({
            "name": _str(a.get("name"), "name"), "rid": rid,
            "enabled": not _bool(a.get("disabled"), "disabled"),
            "password_required": _bool(a.get("password_required"), "password_required"),
            "password_expires": _bool(a.get("password_expires"), "password_expires"),
            "password_last_set": a.get("password_last_set"),
            "last_logon": a.get("last_logon"),
        })
    enabled = [a for a in accounts if a["enabled"]]
    return {
        "accounts": accounts,
        "enabled_password_not_required": [a["name"] for a in enabled if not a["password_required"]],
        "enabled_password_never_expires": [a["name"] for a in enabled if not a["password_expires"]],
    }


def p_local_admins(v: Any) -> dict:
    v = _obj(v, "local_admins")
    members = [_obj(m, "member") for m in _list(v.get("members"), "members")]
    return {"count": len(members),
            "members": [f"{m.get('name')} ({m.get('object_class')}, {m.get('principal_source')})"
                        for m in members]}


NTFS_LIKE = {"NTFS", "REFS", "CSVFS"}
EXCLUDED_PARTITIONS = {"System", "Recovery", "Reserved"}


def p_volumes(v: Any) -> dict:
    """Local fixed volumes, excluding system partitions (EFI system, Recovery, MSR) as the
    check text does. Without partition types only an unlettered system volume is excluded."""
    v = _obj(v, "volumes")
    types_read = _bool(v.get("partition_types_read"), "partition_types_read")
    checked, non_ntfs, unverified, excluded = [], [], [], []
    for vol in _list(v.get("volumes"), "volumes"):
        vol = _obj(vol, "volume")
        letter = str(vol.get("drive_letter") or "")
        fs = str(vol.get("file_system") or "").upper()
        ptype = vol.get("partition_type")
        label = letter or f"unlettered {fs or 'unformatted'} volume"
        if types_read and ptype in EXCLUDED_PARTITIONS:
            excluded.append(f"{label} ({ptype} partition)")
            continue
        if not types_read and vol.get("system_volume") is True and not letter:
            excluded.append(f"{label} (system volume)")
            continue
        checked.append(f"{label} {fs or 'RAW'}")
        if not fs:
            unverified.append(f"{label} (no file system reported)")
        elif fs not in NTFS_LIKE:
            if letter:
                non_ntfs.append(f"{label} {fs}")
            else:  # possibly a system partition the partition list did not identify
                unverified.append(f"{label} {fs} (no drive letter, partition type unknown)")
    return {"checked": len(checked), "volumes": checked, "non_ntfs": non_ntfs,
            "non_ntfs_count": len(non_ntfs), "unverified": unverified,
            "unverified_count": len(unverified), "excluded": excluded,
            "partition_types_read": types_read}


def p_bitlocker(v: Any) -> dict:
    v = _obj(v, "bitlocker")
    vols, on, off, unknown = [], [], [], []
    for vol in _list(v.get("volumes"), "volumes"):
        vol = _obj(vol, "volume")
        vtype = str(vol.get("volume_type") or "")
        if vtype not in ("OperatingSystem", "FixedData", "0", "1"):
            continue  # removable drives are not in scope
        mp = str(vol.get("mount_point") or "?")
        status = str(vol.get("protection_status") or "")
        vols.append(f"{mp} protection {status or 'unknown'}")
        if status in ("On", "1"):
            on.append(mp)
        elif status in ("Off", "0"):
            off.append(mp)
        else:
            unknown.append(mp)
    return {"volumes": vols, "fixed_count": len(vols), "unprotected": off,
            "unprotected_count": len(off), "unknown_count": len(unknown)}


def p_tpm(v: Any) -> dict:
    v = _obj(v, "tpm")
    present = _bool(v.get("present"), "present")
    out: dict[str, Any] = {"present": present, "ready": _bool(v.get("ready"), "ready")}
    spec = v.get("spec_version")
    if present and isinstance(spec, str) and spec.strip():
        out["spec_version"] = spec
        out["spec_major"] = spec.split(",")[0].strip()
    return out


def p_secure_boot(v: Any) -> dict:
    v = _obj(v, "secure_boot")
    return {"enabled": _bool(v.get("enabled"), "enabled")}


def p_device_guard(v: Any) -> dict:
    v = _obj(v, "device_guard")
    status = _int(v.get("vbs_status"))
    if status is None:
        raise ValueError("vbs_status must be a number")
    out: dict[str, Any] = {"vbs_status": status}
    for k in ("required_security_properties", "available_security_properties",
              "security_services_running", "security_services_configured"):
        items = _list(v.get(k, []), k)
        if any(_int(i) is None for i in items):
            raise ValueError(f"{k} must be a list of numbers")
        out[k] = [_int(i) for i in items]
    return out


def p_defender(v: Any) -> dict:
    v = _obj(v, "defender")
    out: dict[str, Any] = {k: _bool(v.get(k), k) for k in (
        "am_service_enabled", "antivirus_enabled", "realtime_protection_enabled")}
    out["running_mode"] = v.get("running_mode")
    return out


def p_firewall(v: Any) -> dict:
    v = _obj(v, "firewall")
    profiles = {}
    for name, p in v.items():
        p = _obj(p, name)
        profiles[name] = {"enabled": _bool(p.get("enabled"), f"{name}.enabled"),
                          "default_inbound_action": p.get("default_inbound_action")}
    if not {"Domain", "Private", "Public"} <= set(profiles):
        raise ValueError("the Domain, Private and Public profiles were not all reported")
    return {"profiles": profiles,
            "all_enabled": all(p["enabled"] for p in profiles.values()),
            "disabled": sorted(n for n, p in profiles.items() if not p["enabled"])}


def p_smb_server(v: Any) -> dict:
    v = _obj(v, "smb_server")
    return {k: _bool(v.get(k), k) for k in ("enable_smb1_protocol", "require_security_signature")}


def p_certificates(v: Any) -> dict:
    v = _obj(v, "certificates")
    out: dict[str, Any] = {}
    for k in ("root_dod", "disallowed_dod"):
        out[k] = [_obj(c, "certificate") for c in _list(v.get(k), k)]
    count = _int(v.get("personal_count"))
    if count is None:
        raise ValueError("personal_count must be a number")
    out["personal_count"] = count

    def show(c: dict) -> str:
        return f"{c.get('subject')} (expires {c.get('not_after')})"

    out["root_dod_subjects"] = sorted({show(c) for c in out["root_dod"]})
    out["interoperability"] = sorted({show(c) for c in out["disallowed_dod"]
                                      if "DoD Interoperability" in str(c.get("issuer"))})
    out["cceb_interoperability"] = sorted({show(c) for c in out["disallowed_dod"]
                                           if "CCEB Interoperability" in str(c.get("issuer"))})
    return out


def _acl_entry(e: Any) -> dict:
    e = _obj(e, "acl entry")
    out: dict[str, Any] = {"path": e.get("path")}
    if e.get("error"):
        out["error"] = str(e["error"])
        return out
    if e.get("exists") is False:
        out["exists"] = False
        return out
    aces = []
    for a in _list(e.get("aces"), "aces"):
        a = _obj(a, "ace")
        rights = _int(a.get("rights"))
        if rights is None or not isinstance(a.get("sid"), str):
            raise ValueError("an ACE needs a sid and numeric rights")
        aces.append({"sid": a["sid"], "type": str(a.get("type")), "rights": rights & 0xFFFFFFFF,
                     "inherited": bool(a.get("inherited"))})
    out["exists"] = True
    out["aces"] = aces
    return out


def p_acls(v: Any) -> dict:
    v = _obj(v, "acls")
    out: dict[str, Any] = {}
    for k, e in v.items():
        if k == "ntds_files":
            out[k] = [_acl_entry(x) for x in _list(e, k)]
        elif k == "ntds_dirs":
            out[k] = [_str(x, k) for x in _list(e, k)]
        else:
            out[k] = _acl_entry(e)
    return out


PARSERS = {
    "os": p_os,
    "domain_role": p_domain_role,
    "security_policy": p_security_policy,
    "user_rights": p_user_rights,
    "audit_policy": p_audit_policy,
    "registry": p_registry,
    "features": p_features,
    "services": p_services,
    "local_accounts": p_local_accounts,
    "local_admins": p_local_admins,
    "volumes": p_volumes,
    "bitlocker": p_bitlocker,
    "tpm": p_tpm,
    "secure_boot": p_secure_boot,
    "device_guard": p_device_guard,
    "defender": p_defender,
    "firewall": p_firewall,
    "smb_server": p_smb_server,
    "certificates": p_certificates,
    "acls": p_acls,
}


# --------------------------------------------------------------------------- operators

def _has_sid_validate(arg: Any) -> None:
    if not isinstance(arg, str) or not arg.startswith("S-1-"):
        raise ValueError("has_sid takes a SID or a SID pattern such as 'S-1-5-21-*-512'")


def _has_sid_test(actual: Any, arg: str) -> bool | None:
    if not isinstance(actual, list):
        return None
    return any(isinstance(s, str) and fnmatch.fnmatchcase(s, arg) for s in actual)


def _has_sid_describe(arg: str) -> str:
    name = SID_NAMES.get(arg)
    return f"an entry {arg}" + (f" ({name})" if name else "")


# FILE_GENERIC_READ | FILE_GENERIC_EXECUTE (Read & execute, with Synchronize) and the generic
# read and execute bits that appear on inherit-only entries.
READ_EXECUTE = 0x001200A9 | 0x80000000 | 0x20000000


def _acl_validate(arg: Any) -> None:
    if not isinstance(arg, dict) or set(arg) - {"full", "read", "standard"} or "full" not in arg:
        raise ValueError("acl takes {full: [SIDs], read?: any | [SIDs], standard?: [SIDs]}")
    for k in ("full", "standard"):
        if k in arg and not (isinstance(arg[k], list) and all(isinstance(s, str) for s in arg[k])):
            raise ValueError(f"acl {k} must be a list of SID patterns")
    read = arg.get("read", [])
    if read != "any" and not (isinstance(read, list) and all(isinstance(s, str) for s in read)):
        raise ValueError("acl read must be 'any' or a list of SID patterns")


def _acl_violations(entry: dict, arg: dict) -> tuple[list[str], list[str]]:
    """(entries that break the rule, entries that need a human decision)."""
    bad, unknown = [], []
    read = arg.get("read", [])
    for ace in entry["aces"]:
        if ace["type"] != "Allow":
            continue
        sid, rights = ace["sid"], ace["rights"]
        if sid_matches(sid, arg["full"]):
            continue
        desc = f"{sid_name(sid)} 0x{rights:08x}"
        may_read = read == "any" or sid_matches(sid, read)
        if may_read and rights & ~READ_EXECUTE == 0:
            continue
        if may_read and "standard" in arg and not sid_matches(sid, arg["standard"]):
            unknown.append(desc)
        else:
            bad.append(desc)
    return bad, unknown


def _acl_test(actual: Any, arg: dict) -> bool | None:
    if not isinstance(actual, dict) or "aces" not in actual:
        return None
    bad, unknown = _acl_violations(actual, arg)
    if bad:
        return False
    return None if unknown else True


def _acl_describe(arg: dict) -> str:
    text = "permissions no wider than full control for " + ", ".join(sid_name(s) for s in arg["full"])
    read = arg.get("read", [])
    if read == "any":
        text += " and read & execute for others"
    elif read:
        text += " and read & execute for " + ", ".join(sid_name(s) for s in read)
    return text


def _acl_observe(actual: Any, arg: dict) -> Any:
    if isinstance(actual, list):
        return [_acl_observe(a, arg) for a in actual]
    if not isinstance(actual, dict):
        return actual
    if "error" in actual:
        return f"{actual.get('path') or '(path unknown)'}: unreadable: {actual['error']}"
    if "aces" not in actual:
        return f"{actual.get('path')}: missing"
    bad, unknown = _acl_violations(actual, arg)
    allowed = sorted({sid_name(a["sid"]) for a in actual["aces"] if a["type"] == "Allow"})
    out = f"{actual.get('path')}: allow {', '.join(allowed)}"
    if bad:
        out += "; exceeding: " + ", ".join(bad)
    if unknown:
        out += "; to review: " + ", ".join(unknown)
    return out


def _banner_validate(arg: Any) -> None:
    if arg is not True:
        raise ValueError("dod_banner takes true")


def _banner_test(actual: Any, arg: Any) -> bool | None:
    return banner_matches(actual) if isinstance(actual, str) else None


OPERATORS = {
    "has_sid": Operator(_has_sid_test, _has_sid_validate, _has_sid_describe),
    "acl": Operator(_acl_test, _acl_validate, _acl_describe, _acl_observe),
    "dod_banner": Operator(_banner_test, _banner_validate,
                           lambda arg: "the Standard Mandatory DoD Notice and Consent Banner text"),
}


# --------------------------------------------------------------------------- facts

def _unavailable(reason: str, command: str) -> dict:
    return {"status": "unavailable", "value": None, "reason": reason, "command": command}


def _derive_os_support(osv: dict, collected: date) -> dict:
    out: dict[str, Any] = {"build": osv.get("build_number"), "caption": osv.get("caption"),
                           "collected_on": collected.isoformat(),
                           "extended_support_end": EXTENDED_SUPPORT_END.isoformat()}
    if osv.get("build_number") == SERVER_2022_BUILD and "Server 2022" in str(osv.get("caption")):
        out["within_support"] = collected <= EXTENDED_SUPPORT_END
    # Any other OS: whether it is supported is not something this benchmark settles.
    return out


def _derive_accounts(value: dict, collected: datetime) -> None:
    admin = next((a for a in value["accounts"] if a["rid"] == 500), None)
    if admin is not None:
        info: dict[str, Any] = {"enabled": admin["enabled"]}
        last = _when(admin.get("password_last_set"))
        if last is not None:
            info["password_age_days"] = (collected - last).days
        value["builtin_administrator"] = info
    cutoff = collected - timedelta(days=35)
    inactive = []
    for a in value["accounts"]:
        if not a["enabled"] or a["rid"] in (500, 501):
            continue
        last = _when(a.get("last_logon"))
        if last is None or last < cutoff:
            inactive.append(a["name"])
    value["enabled_inactive_35_days"] = inactive


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
        entry: dict[str, Any] = {"status": "ok", "value": value, "reason": None, "command": command}
        if isinstance(value, Partial):
            entry["value"] = value.value
            if value.partial:
                entry["partial"] = value.partial
        out[fid] = entry

    collected = _when(data.get("collected_at"))
    osf = out.get("os")
    if osf is not None:
        cmd = "derived from os and collected_at"
        if osf["status"] != "ok":
            out["os_support"] = _unavailable(f"os: {osf['reason']}", cmd)
        elif collected is None:
            out["os_support"] = _unavailable("collected_at is not an ISO date", cmd)
        else:
            out["os_support"] = {"status": "ok", "reason": None, "command": cmd,
                                 "value": _derive_os_support(osf["value"], collected.date())}
    acc = out.get("local_accounts")
    if acc is not None and acc["status"] == "ok":
        if collected is None:
            out["local_accounts"] = _unavailable("collected_at is not an ISO date", acc["command"])
        else:
            _derive_accounts(acc["value"], collected)
    return out
