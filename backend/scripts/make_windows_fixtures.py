"""Generate the synthetic Windows collector fixtures in tests/fixtures/.

The fixtures have the exact shape collectors/collect-windows.ps1 writes (raw secedit
sections, auditpol rows, registry values with state and type, cmdlet properties). Host
names, SIDs and account names are invented. The registry value list is read from the
collector script itself, so a value the checks need but the collector does not read
cannot appear here. Run from backend/:

    python scripts/make_windows_fixtures.py          # rewrite the fixtures
    python scripts/make_windows_fixtures.py --check  # exit 1 if they are out of date
"""

from __future__ import annotations

import copy
import json
import re
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
FIXTURES = BACKEND / "tests" / "fixtures"
COLLECTOR = BACKEND.parent / "collectors" / "collect-windows.ps1"
COLLECTED_AT = "2026-11-09T15:04:27Z"

DOMAIN = "S-1-5-21-1004336348-1177238915-682003330"
MACHINE = "S-1-5-21-2847261131-3359372870-1917415022"
DA, EA = f"{DOMAIN}-512", f"{DOMAIN}-519"
ADM, GUESTS = "S-1-5-32-544", "S-1-5-32-546"
EVENTLOG = "S-1-5-80-880578595-1860270145-482643319-2788375705-1540778122"
TRUSTED_INSTALLER = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

BANNER = (
    "You are accessing a U.S. Government (USG) Information System (IS) that is provided for "
    "USG-authorized use only.\r\nBy using this IS (which includes any device attached to this IS), "
    "you consent to the following conditions:\r\n-The USG routinely intercepts and monitors "
    "communications on this IS for purposes including, but not limited to, penetration testing, "
    "COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement "
    "(LE), and counterintelligence (CI) investigations.\r\n-At any time, the USG may inspect and "
    "seize data stored on this IS.\r\n-Communications using, or data stored on, this IS are not "
    "private, are subject to routine monitoring, interception, and search, and may be disclosed or "
    "used for any USG-authorized purpose.\r\n-This IS includes security measures (e.g., "
    "authentication and access controls) to protect USG interests--not for your personal benefit "
    "or privacy.\r\n-Notwithstanding the above, using this IS does not constitute consent to PM, LE "
    "or CI investigative searching or monitoring of the content of privileged communications, or "
    "work product, related to personal representation or services by attorneys, psychotherapists, "
    "or clergy, and their assistants. Such communications and work product are private and "
    "confidential. See User Agreement for details."
)

SECEDIT_CMD = ('secedit /export /cfg "<temp file in $env:TEMP, deleted after reading>" '
               "/areas SECURITYPOLICY USER_RIGHTS /quiet")
AUDITPOL_CMD = 'auditpol /backup /file:"<temp file in $env:TEMP, deleted after reading>"'
REGISTRY_CMD = ("registry (read-only OpenBaseKey/OpenSubKey): the values listed in collect-windows.ps1 "
                "$RegistryValues; HKCU is the account running the collector")
FEATURE_NAMES = ["Fax", "Web-Ftp-Service", "PNRP", "Simple-TCPIP", "Telnet-Client", "TFTP-Client",
                 "FS-SMB1", "PowerShell-v2", "AD-Domain-Services", "Hyper-V"]
SERVICE_NAMES = ["WinDefend", "MpsSvc", "W32Time", "FTPSVC", "SPTimerV4", "MSExchangeServiceHost", "NTDS"]
COMMANDS = {
    "os": ("Get-CimInstance Win32_OperatingSystem; registry HKLM\\SOFTWARE\\Microsoft\\Windows NT\\"
           "CurrentVersion (InstallationType, DisplayVersion, UBR, EditionID); $env:firmware_type"),
    "domain_role": "Get-CimInstance Win32_ComputerSystem (DomainRole, PartOfDomain)",
    "security_policy": SECEDIT_CMD,
    "user_rights": SECEDIT_CMD,
    "audit_policy": AUDITPOL_CMD,
    "registry": REGISTRY_CMD,
    "features": "Get-WindowsFeature -Name " + ",".join(FEATURE_NAMES),
    "services": "Get-Service -Name " + ",".join(SERVICE_NAMES),
    "local_accounts": 'Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True"; Get-LocalUser',
    "local_admins": "Get-LocalGroupMember -SID S-1-5-32-544",
    "volumes": 'Get-CimInstance Win32_Volume -Filter "DriveType=3"; Get-Partition (partition types)',
    "bitlocker": "Get-BitLockerVolume",
    "tpm": "Get-Tpm; Get-CimInstance -Namespace root\\cimv2\\Security\\MicrosoftTpm Win32_Tpm (SpecVersion)",
    "secure_boot": "Confirm-SecureBootUEFI",
    "device_guard": "Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard",
    "defender": "Get-MpComputerStatus",
    "firewall": "Get-NetFirewallProfile -PolicyStore ActiveStore",
    "smb_server": "Get-SmbServerConfiguration",
    "certificates": ("Get-ChildItem Cert:\\LocalMachine\\Root, Cert:\\LocalMachine\\Disallowed (DoD subjects "
                     "or issuers), Cert:\\LocalMachine\\My (count)"),
    "acls": ("Get-WinEvent -ListLog Application,Security,System (LogFilePath); Get-Acl on the event log "
             "files, %SystemRoot%\\System32\\Eventvwr.exe and, on domain controllers, the NTDS files and "
             "the SYSVOL folder"),
}


def registry_list() -> list[tuple[str, str, str]]:
    """The (hive, key, name) triples of $RegistryValues in the collector."""
    text = COLLECTOR.read_text(encoding="utf-8")
    block = text[text.index("$RegistryValues = @("):text.index("\n)\n", text.index("$RegistryValues = @("))]
    return re.findall(r"@\('(HKLM|HKCU)', '([^']+)', '([^']+)'\)", block)


def ok(fid: str, value) -> dict:
    return {"status": "ok", "value": value, "reason": None, "command": COMMANDS[fid]}


def unavailable(fid: str, reason: str, command: str | None = None) -> dict:
    return {"status": "unavailable", "value": None, "reason": reason, "command": command or COMMANDS[fid]}


H = "HKLM\\"
SYS = H + r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
EXP = H + r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
POLW = H + r"SOFTWARE\Policies\Microsoft\Windows"
TS = H + r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
LSA = H + r"SYSTEM\CurrentControlSet\Control\Lsa"
NETLOGON = H + r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
WKS = H + r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
SRV = H + r"SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
D, S = "DWord", "String"

COMPLIANT_REGISTRY: dict[tuple[str, str], tuple[str, object]] = {
    (POLW + r"\Personalization", "NoLockScreenSlideshow"): (D, 1),
    (H + r"SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest", "UseLogonCredential"): (D, 0),
    (H + r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters", "DisableIPSourceRouting"): (D, 2),
    (H + r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "DisableIPSourceRouting"): (D, 2),
    (H + r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "EnableICMPRedirect"): (D, 0),
    (H + r"SYSTEM\CurrentControlSet\Services\Netbt\Parameters", "NoNameReleaseOnDemand"): (D, 1),
    (POLW + r"\LanmanWorkstation", "AllowInsecureGuestAuth"): (D, 0),
    (POLW + r"\NetworkProvider\HardenedPaths", "\\\\*\\NETLOGON"): (S, "RequireMutualAuthentication=1, RequireIntegrity=1"),
    (POLW + r"\NetworkProvider\HardenedPaths", "\\\\*\\SYSVOL"): (S, "RequireMutualAuthentication=1, RequireIntegrity=1"),
    (SYS + r"\Audit", "ProcessCreationIncludeCmdLine_Enabled"): (D, 1),
    (POLW + r"\CredentialsDelegation", "AllowProtectedCreds"): (D, 1),
    (POLW + r"\DeviceGuard", "EnableVirtualizationBasedSecurity"): (D, 1),
    (POLW + r"\DeviceGuard", "RequirePlatformSecurityFeatures"): (D, 1),
    (POLW + r"\DeviceGuard", "LsaCfgFlags"): (D, 1),
    (POLW + r"\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}", "NoGPOListChanges"): (D, 0),
    (H + r"SOFTWARE\Policies\Microsoft\Windows NT\Printers", "DisableWebPnPDownload"): (D, 1),
    (H + r"SOFTWARE\Policies\Microsoft\Windows NT\Printers", "DisableHTTPPrinting"): (D, 1),
    (POLW + r"\System", "DontDisplayNetworkSelectionUI"): (D, 1),
    (POLW + r"\System", "EnableSmartScreen"): (D, 1),
    (POLW + r"\System", "EnumerateLocalUsers"): (D, 0),
    (H + r"SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51", "DCSettingIndex"): (D, 1),
    (H + r"SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51", "ACSettingIndex"): (D, 1),
    (POLW + r"\AppCompat", "DisableInventory"): (D, 1),
    (POLW + r"\Explorer", "NoAutoplayfornonVolume"): (D, 1),
    (EXP, "NoAutorun"): (D, 1),
    (EXP, "NoDriveTypeAutoRun"): (D, 255),
    (H + r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI", "EnumerateAdministrators"): (D, 0),
    (POLW + r"\DataCollection", "AllowTelemetry"): (D, 1),
    (POLW + r"\DeliveryOptimization", "DODownloadMode"): (D, 0),
    (POLW + r"\EventLog\Application", "MaxSize"): (D, 32768),
    (POLW + r"\EventLog\Security", "MaxSize"): (D, 5120000),
    (POLW + r"\EventLog\System", "MaxSize"): (D, 32768),
    (TS, "DisablePasswordSaving"): (D, 1),
    (TS, "fDisableCdm"): (D, 1),
    (TS, "fPromptForPassword"): (D, 1),
    (TS, "fEncryptRPCTraffic"): (D, 1),
    (TS, "MinEncryptionLevel"): (D, 3),
    (H + r"SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds", "DisableEnclosureDownload"): (D, 1),
    (POLW + r"\Windows Search", "AllowIndexingEncryptedStoresOrItems"): (D, 0),
    (POLW + r"\Installer", "EnableUserControl"): (D, 0),
    (POLW + r"\Installer", "AlwaysInstallElevated"): (D, 0),
    (SYS, "DisableAutomaticRestartSignOn"): (D, 1),
    (SYS, "LocalAccountTokenFilterPolicy"): (D, 0),
    (SYS, "InactivityTimeoutSecs"): (D, 900),
    (SYS, "LegalNoticeText"): (S, BANNER),
    (SYS, "LegalNoticeCaption"): (S, "DoD Notice and Consent Banner"),
    (SYS, "FilterAdministratorToken"): (D, 1),
    (SYS, "EnableUIADesktopToggle"): (D, 0),
    (SYS, "ConsentPromptBehaviorAdmin"): (D, 2),
    (SYS, "ConsentPromptBehaviorUser"): (D, 0),
    (SYS, "EnableInstallerDetection"): (D, 1),
    (SYS, "EnableSecureUIAPaths"): (D, 1),
    (SYS, "EnableLUA"): (D, 1),
    (SYS, "EnableVirtualization"): (D, 1),
    (SYS + r"\Kerberos\Parameters", "SupportedEncryptionTypes"): (D, 2147483640),
    (POLW + r"\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging"): (D, 1),
    (POLW + r"\PowerShell\Transcription", "EnableTranscripting"): (D, 1),
    (POLW + r"\PowerShell\Transcription", "OutputDirectory"): (S, r"\\logs01\ps-transcripts$"),
    (POLW + r"\WinRM\Client", "AllowBasic"): (D, 0),
    (POLW + r"\WinRM\Client", "AllowUnencryptedTraffic"): (D, 0),
    (POLW + r"\WinRM\Client", "AllowDigest"): (D, 0),
    (POLW + r"\WinRM\Service", "AllowBasic"): (D, 0),
    (POLW + r"\WinRM\Service", "AllowUnencryptedTraffic"): (D, 0),
    (POLW + r"\WinRM\Service", "DisableRunAs"): (D, 1),
    (NETLOGON, "RequireSignOrSeal"): (D, 1),
    (NETLOGON, "SealSecureChannel"): (D, 1),
    (NETLOGON, "SignSecureChannel"): (D, 1),
    (NETLOGON, "DisablePasswordChange"): (D, 0),
    (NETLOGON, "MaximumPasswordAge"): (D, 30),
    (NETLOGON, "RequireStrongKey"): (D, 1),
    (H + r"SOFTWARE\Policies\Microsoft\Windows NT\Rpc", "RestrictRemoteClients"): (D, 1),
    (H + r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "CachedLogonsCount"): (S, "4"),
    (H + r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "scremoveoption"): (S, "1"),
    (LSA, "RestrictRemoteSAM"): (S, "O:BAG:BAD:(A;;RC;;;BA)"),
    (LSA, "LimitBlankPasswordUse"): (D, 1),
    (LSA, "SCENoApplyLegacyAuditPolicy"): (D, 1),
    (LSA, "RestrictAnonymousSAM"): (D, 1),
    (LSA, "RestrictAnonymous"): (D, 1),
    (LSA, "EveryoneIncludesAnonymous"): (D, 0),
    (LSA, "UseMachineId"): (D, 1),
    (LSA, "NoLMHash"): (D, 1),
    (LSA, "LmCompatibilityLevel"): (D, 5),
    (LSA + r"\MSV1_0", "allownullsessionfallback"): (D, 0),
    (LSA + r"\MSV1_0", "NTLMMinClientSec"): (D, 537395200),
    (LSA + r"\MSV1_0", "NTLMMinServerSec"): (D, 537395200),
    (LSA + r"\pku2u", "AllowOnlineID"): (D, 0),
    (LSA + r"\FIPSAlgorithmPolicy", "Enabled"): (D, 1),
    (H + r"SYSTEM\CurrentControlSet\Services\LDAP", "LDAPClientIntegrity"): (D, 1),
    (WKS, "RequireSecuritySignature"): (D, 1),
    (WKS, "EnableSecuritySignature"): (D, 1),
    (WKS, "EnablePlainTextPassword"): (D, 0),
    (SRV, "RequireSecuritySignature"): (D, 1),
    (SRV, "EnableSecuritySignature"): (D, 1),
    (SRV, "RestrictNullSessAccess"): (D, 1),
    (SRV, "SMB1"): (D, 0),
    (H + r"SOFTWARE\Policies\Microsoft\Cryptography", "ForceKeyProtection"): (D, 2),
    (H + r"SYSTEM\CurrentControlSet\Control\Session Manager", "ProtectionMode"): (D, 1),
    (H + r"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled"): (D, 1),
    (H + r"SYSTEM\CurrentControlSet\Services\W32Time\Parameters", "Type"): (S, "NT5DS"),
    (H + r"SYSTEM\CurrentControlSet\Services\W32Time\Parameters", "NtpServer"): (S, "time.windows.com,0x9"),
    (H + r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS", "BackupDirectory"): (D, 2),
    (H + r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS", "PasswordComplexity"): (D, 4),
    (H + r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS", "PasswordLength"): (D, 14),
    (H + r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS", "PasswordAgeDays"): (D, 180),
}


def registry_v(values: dict, errors: dict | None = None) -> dict:
    out = []
    for hive, key, name in registry_list():
        full = f"{hive}\\{key}"
        entry: dict = {"key": full, "name": name, "state": "absent"}
        if errors and (full, name) in errors:
            entry = {"key": full, "name": name, "state": "error", "error": errors[(full, name)]}
        elif (full, name) in values:
            rtype, data = values[(full, name)]
            if rtype == D and isinstance(data, int) and data > 0x7FFFFFFF:
                data -= 0x100000000  # as .NET reports a DWORD
            entry.update(state="set", type=rtype, data=data)
        out.append(entry)
    return {"values": out}


def rights_v(rights: dict[str, list[str]]) -> dict:
    return {k: ",".join("*" + s if s.startswith("S-1-") else s for s in v) for k, v in rights.items()}


BASE_RIGHTS = {
    "SeAssignPrimaryTokenPrivilege": ["S-1-5-19", "S-1-5-20"],
    "SeAuditPrivilege": ["S-1-5-19", "S-1-5-20"],
    "SeBackupPrivilege": [ADM],
    "SeBatchLogonRight": [ADM, "S-1-5-32-551", "S-1-5-32-559"],
    "SeChangeNotifyPrivilege": ["S-1-1-0", "S-1-5-19", "S-1-5-20", ADM, "S-1-5-32-545", "S-1-5-32-551"],
    "SeCreateGlobalPrivilege": ["S-1-5-19", "S-1-5-20", ADM, "S-1-5-6"],
    "SeCreatePagefilePrivilege": [ADM],
    "SeCreateSymbolicLinkPrivilege": [ADM],
    "SeDebugPrivilege": [ADM],
    "SeImpersonatePrivilege": ["S-1-5-19", "S-1-5-20", ADM, "S-1-5-6"],
    "SeIncreaseBasePriorityPrivilege": [ADM],
    "SeIncreaseQuotaPrivilege": ["S-1-5-19", "S-1-5-20", ADM],
    "SeIncreaseWorkingSetPrivilege": ["S-1-5-32-545"],
    "SeInteractiveLogonRight": [ADM],
    "SeLoadDriverPrivilege": [ADM],
    "SeManageVolumePrivilege": [ADM],
    "SeProfileSingleProcessPrivilege": [ADM],
    "SeRemoteShutdownPrivilege": [ADM],
    "SeRestorePrivilege": [ADM],
    "SeSecurityPrivilege": [ADM],
    "SeServiceLogonRight": ["S-1-5-80-0"],
    "SeShutdownPrivilege": [ADM],
    "SeSystemEnvironmentPrivilege": [ADM],
    "SeSystemProfilePrivilege": [ADM, "S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420"],
    "SeSystemtimePrivilege": ["S-1-5-19", ADM],
    "SeTakeOwnershipPrivilege": [ADM],
    "SeTimeZonePrivilege": ["S-1-5-19", ADM],
}
MEMBER_RIGHTS = BASE_RIGHTS | {
    "SeNetworkLogonRight": [ADM, "S-1-5-11"],
    "SeRemoteInteractiveLogonRight": [ADM],
    "SeDenyNetworkLogonRight": [EA, DA, "S-1-5-114", GUESTS],
    "SeDenyBatchLogonRight": [EA, DA, GUESTS],
    "SeDenyServiceLogonRight": [EA, DA],
    "SeDenyInteractiveLogonRight": [EA, DA, GUESTS],
    "SeDenyRemoteInteractiveLogonRight": [EA, DA, "S-1-5-113", GUESTS],
}
DC_RIGHTS = BASE_RIGHTS | {
    "SeNetworkLogonRight": [ADM, "S-1-5-11", "S-1-5-9"],
    "SeMachineAccountPrivilege": [ADM],
    "SeRemoteInteractiveLogonRight": [ADM],
    "SeEnableDelegationPrivilege": [ADM],
    "SeDenyNetworkLogonRight": [GUESTS],
    "SeDenyBatchLogonRight": [GUESTS],
    "SeDenyInteractiveLogonRight": [GUESTS],
    "SeDenyRemoteInteractiveLogonRight": [GUESTS],
}

AUDIT_ROWS = [  # (guid prefix, English name)
    ("0CCE9210", "Security State Change"), ("0CCE9211", "Security System Extension"),
    ("0CCE9212", "System Integrity"), ("0CCE9213", "IPsec Driver"), ("0CCE9214", "Other System Events"),
    ("0CCE9215", "Logon"), ("0CCE9216", "Logoff"), ("0CCE9217", "Account Lockout"),
    ("0CCE921B", "Special Logon"), ("0CCE921C", "Other Logon/Logoff Events"),
    ("0CCE9249", "Group Membership"), ("0CCE921D", "File System"), ("0CCE921E", "Registry"),
    ("0CCE9223", "Handle Manipulation"), ("0CCE9227", "Other Object Access Events"),
    ("0CCE9245", "Removable Storage"), ("0CCE9228", "Sensitive Privilege Use"),
    ("0CCE922B", "Process Creation"), ("0CCE9248", "Plug and Play Events"),
    ("0CCE922F", "Audit Policy Change"), ("0CCE9230", "Authentication Policy Change"),
    ("0CCE9231", "Authorization Policy Change"), ("0CCE9235", "User Account Management"),
    ("0CCE9236", "Computer Account Management"), ("0CCE9237", "Security Group Management"),
    ("0CCE923A", "Other Account Management Events"), ("0CCE923B", "Directory Service Access"),
    ("0CCE923C", "Directory Service Changes"), ("0CCE923F", "Credential Validation"),
]
STIG_AUDIT = {  # the STIG settings (1 success, 2 failure, 3 both)
    "Security State Change": 1, "Security System Extension": 1, "System Integrity": 3,
    "IPsec Driver": 3, "Other System Events": 3, "Logon": 3, "Logoff": 1, "Account Lockout": 2,
    "Special Logon": 1, "Group Membership": 1, "Registry": 3, "Handle Manipulation": 2,
    "Other Object Access Events": 3, "Removable Storage": 3, "Sensitive Privilege Use": 3,
    "Process Creation": 1, "Plug and Play Events": 1, "Audit Policy Change": 3,
    "Authentication Policy Change": 1, "Authorization Policy Change": 1,
    "User Account Management": 3, "Computer Account Management": 1, "Security Group Management": 1,
    "Other Account Management Events": 1, "Directory Service Access": 3,
    "Directory Service Changes": 1, "Credential Validation": 3,
}
INCLUSION = {0: "No Auditing", 1: "Success", 2: "Failure", 3: "Success and Failure"}


def audit_v(settings: dict[str, int], source: str = "backup", inclusion: dict | None = None) -> dict:
    rows = []
    for prefix, name in AUDIT_ROWS:
        value = settings.get(name, 0)
        row = {"guid": "{" + prefix + "-69AE-11D9-BED3-505054503030}", "name": name,
               "inclusion": (inclusion or INCLUSION)[value]}
        if source == "backup":
            row["setting_value"] = str(value)
        rows.append(row)
    return {"source": source, "subcategories": rows}


def ace(sid: str, rights: int, inherited: bool = False, type_: str = "Allow") -> dict:
    return {"sid": sid, "type": type_, "rights": rights if rights <= 0x7FFFFFFF else rights - 0x100000000,
            "inherited": inherited, "inheritance": 0, "propagation": 0}


FULL, RX, MODIFY = 0x1F01FF, 0x1200A9, 0x1301BF


def acl(path: str, *aces: dict) -> dict:
    return {"path": path, "exists": True, "aces": list(aces)}


def log_acls() -> dict:
    out = {}
    for log in ("Application", "Security", "System"):
        out["log_" + log.lower()] = acl(f"C:\\Windows\\System32\\winevt\\Logs\\{log}.evtx",
                                        ace(EVENTLOG, FULL), ace("S-1-5-18", FULL), ace(ADM, FULL))
    out["eventvwr"] = acl("C:\\Windows\\System32\\Eventvwr.exe", ace(TRUSTED_INSTALLER, FULL),
                          ace(ADM, RX), ace("S-1-5-18", RX), ace("S-1-5-32-545", RX),
                          ace("S-1-15-2-1", RX), ace("S-1-15-2-2", RX))
    return out


def accounts(*extra: dict) -> dict:
    base = [
        {"name": "xadmin-local", "rid": 500, "disabled": False, "password_required": True,
         "password_expires": True, "password_last_set": "2026-09-01T10:00:00Z", "last_logon": "2026-11-02T08:00:00Z"},
        {"name": "Guest", "rid": 501, "disabled": True, "password_required": False,
         "password_expires": False, "password_last_set": None, "last_logon": None},
        {"name": "DefaultAccount", "rid": 503, "disabled": True, "password_required": False,
         "password_expires": False, "password_last_set": None, "last_logon": None},
        {"name": "WDAGUtilityAccount", "rid": 504, "disabled": True, "password_required": True,
         "password_expires": True, "password_last_set": "2026-01-14T09:00:00Z", "last_logon": None},
    ]
    return {"accounts": base + list(extra)}


def member_compliant(host: str = "ws22-app-01") -> dict:
    facts = {
        "os": ok("os", {"caption": "Microsoft Windows Server 2022 Datacenter", "version": "10.0.20348",
                        "build_number": "20348", "product_type": 3, "installation_type": "Server",
                        "display_version": "21H2", "edition_id": "ServerDatacenter", "ubr": 4405,
                        "firmware_type": "UEFI"}),
        "domain_role": ok("domain_role", {"domain_role": 3, "part_of_domain": True}),
        "security_policy": ok("security_policy", {"System Access": {
            "MinimumPasswordAge": "1", "MaximumPasswordAge": "60", "MinimumPasswordLength": "14",
            "PasswordComplexity": "1", "PasswordHistorySize": "24", "LockoutBadCount": "3",
            "ResetLockoutCount": "15", "LockoutDuration": "15", "RequireLogonToChangePassword": "0",
            "ForceLogoffWhenHourExpire": "0", "NewAdministratorName": '"xadmin-local"',
            "NewGuestName": '"xvisitor"', "ClearTextPassword": "0", "LSAAnonymousNameLookup": "0",
            "EnableAdminAccount": "1", "EnableGuestAccount": "0"}}),
        "user_rights": ok("user_rights", rights_v(MEMBER_RIGHTS)),
        "audit_policy": ok("audit_policy", audit_v(STIG_AUDIT)),
        "registry": ok("registry", registry_v(COMPLIANT_REGISTRY)),
        "features": ok("features", {"source": "Get-WindowsFeature", "states": {
            "Fax": "Available", "Web-Ftp-Service": "Available", "PNRP": "Available",
            "Simple-TCPIP": "Available", "Telnet-Client": "Available", "TFTP-Client": "Available",
            "FS-SMB1": "Removed", "PowerShell-v2": "Removed", "AD-Domain-Services": "Available",
            "Hyper-V": "Available"}}),
        "services": ok("services", {
            "WinDefend": {"present": True, "status": "Running", "start_type": "Automatic"},
            "MpsSvc": {"present": True, "status": "Running", "start_type": "Automatic"},
            "W32Time": {"present": True, "status": "Running", "start_type": "Automatic"},
            "FTPSVC": {"present": False}, "SPTimerV4": {"present": False},
            "MSExchangeServiceHost": {"present": False}, "NTDS": {"present": False}}),
        "local_accounts": ok("local_accounts", accounts()),
        "local_admins": ok("local_admins", {"count": 2, "members": [
            {"name": f"{host.upper()}\\xadmin-local", "sid": f"{MACHINE}-500", "object_class": "User",
             "principal_source": "Local"},
            {"name": "EXAMPLE\\Server Admins - APP", "sid": f"{DOMAIN}-1123", "object_class": "Group",
             "principal_source": "ActiveDirectory"}]}),
        "volumes": ok("volumes", {"partition_types_read": True, "volumes": [
            {"drive_letter": "C:", "label": "", "file_system": "NTFS", "system_volume": False,
             "boot_volume": True, "capacity": 136365211648, "partition_type": "Basic"},
            {"drive_letter": "D:", "label": "Data", "file_system": "ReFS", "system_volume": False,
             "boot_volume": False, "capacity": 536870912000, "partition_type": "Basic"},
            {"drive_letter": "", "label": "", "file_system": "FAT32", "system_volume": True,
             "boot_volume": False, "capacity": 104857600, "partition_type": "System"},
            {"drive_letter": "", "label": "", "file_system": "NTFS", "system_volume": False,
             "boot_volume": False, "capacity": 681570304, "partition_type": "Recovery"}]}),
        "bitlocker": ok("bitlocker", {"volumes": [
            {"mount_point": "C:", "volume_type": "OperatingSystem", "protection_status": "On",
             "volume_status": "FullyEncrypted", "encryption_percentage": 100},
            {"mount_point": "D:", "volume_type": "FixedData", "protection_status": "On",
             "volume_status": "FullyEncrypted", "encryption_percentage": 100}]}),
        "tpm": ok("tpm", {"present": True, "ready": True, "spec_version": "2.0, 0, 1.38"}),
        "secure_boot": ok("secure_boot", {"enabled": True}),
        "device_guard": ok("device_guard", {"vbs_status": 2, "required_security_properties": [1, 2],
                                            "available_security_properties": [1, 2, 3, 5],
                                            "security_services_running": [1, 2],
                                            "security_services_configured": [1, 2]}),
        "defender": ok("defender", {"am_service_enabled": True, "antivirus_enabled": True,
                                    "realtime_protection_enabled": True, "running_mode": "Normal"}),
        "firewall": ok("firewall", {p: {"enabled": True, "enabled_raw": "True", "default_inbound_action": "Block"}
                                    for p in ("Domain", "Private", "Public")}),
        "smb_server": ok("smb_server", {"enable_smb1_protocol": False, "require_security_signature": True}),
        "certificates": ok("certificates", {
            "root_dod": [
                {"subject": "CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US",
                 "issuer": "CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US",
                 "not_after": "2029-12-30T18:46:41Z", "thumbprint": "D73CA91102A2204A36459ED32213B467D7CE97FB"},
                {"subject": "CN=DoD Root CA 6, OU=PKI, OU=DoD, O=U.S. Government, C=US",
                 "issuer": "CN=DoD Root CA 6, OU=PKI, OU=DoD, O=U.S. Government, C=US",
                 "not_after": "2053-01-24T15:36:17Z", "thumbprint": "D37ECF61C0B4ED88681EF3630C4E2FC787B37AEF"}],
            "disallowed_dod": [
                {"subject": "CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US",
                 "issuer": "CN=DoD Interoperability Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US",
                 "not_after": "2030-11-16T14:57:16Z", "thumbprint": "49CBE933151872E17C8EAE7F0ABA97FB610F6477"}],
            "personal_count": 1}),
        "acls": ok("acls", log_acls()),
    }
    return {"collector": "windows", "version": 1, "collected_at": COLLECTED_AT,
            "host": {"name": host, "os": "Microsoft Windows Server 2022 Datacenter", "build": "20348"},
            "privileged": True, "redacted": False, "powershell": "5.1.20348.4294", "facts": facts}


def noncompliant() -> dict:
    d = member_compliant("ws22-legacy-04")
    f = d["facts"]
    sa = f["security_policy"]["value"]["System Access"]
    sa.update(MinimumPasswordAge="0", MaximumPasswordAge="-1", MinimumPasswordLength="8",
              LockoutBadCount="0", ClearTextPassword="1", NewAdministratorName='"Administrator"',
              LSAAnonymousNameLookup="1", EnableGuestAccount="1")
    for k in ("ResetLockoutCount", "LockoutDuration"):  # secedit omits them without a threshold
        sa.pop(k)
    rights = copy.deepcopy(MEMBER_RIGHTS)
    rights["SeDebugPrivilege"] = [ADM, f"{MACHINE}-1004"]
    rights["SeTcbPrivilege"] = [f"{MACHINE}-1005"]
    rights["SeDenyNetworkLogonRight"] = [GUESTS]
    rights["SeNetworkLogonRight"] = [ADM, "S-1-5-11", "S-1-1-0", "S-1-5-32-551"]
    f["user_rights"]["value"] = rights_v(rights)
    audit = dict(STIG_AUDIT, **{"Credential Validation": 0, "Logon": 1, "Removable Storage": 0})
    f["audit_policy"]["value"] = audit_v(audit)
    reg = dict(COMPLIANT_REGISTRY)
    for k in [(LSA, "NoLMHash"), (EXP, "NoAutorun"), (POLW + r"\Explorer", "NoAutoplayfornonVolume"),
              (POLW + r"\EventLog\Security", "MaxSize"), (SYS, "LegalNoticeText")]:
        reg.pop(k)
    reg.update({
        (LSA, "LmCompatibilityLevel"): (D, 3),
        (POLW + r"\WinRM\Service", "AllowBasic"): (D, 1),
        (POLW + r"\Installer", "AlwaysInstallElevated"): (D, 1),
        (EXP, "NoDriveTypeAutoRun"): (D, 145),
        (SYS, "InactivityTimeoutSecs"): (D, 0),
        (H + r"SYSTEM\CurrentControlSet\Policies\EarlyLaunch", "DriverLoadPolicy"): (D, 7),
        (POLW + r"\Explorer", "NoDataExecutionPrevention"): (D, 1),
        (H + r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "CachedLogonsCount"): (S, "10"),
        (SRV, "SMB1"): (D, 1),
        (H + r"SYSTEM\CurrentControlSet\Services\W32Time\Parameters", "Type"): (S, "NTP"),
        (H + r"SYSTEM\CurrentControlSet\Services\LDAP", "LDAPClientIntegrity"): (D, 2),
        (r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments", "SaveZoneInformation"): (D, 1),
    })
    f["registry"]["value"] = registry_v(reg)
    f["features"]["value"]["states"].update({"Telnet-Client": "Installed", "FS-SMB1": "Installed",
                                             "PowerShell-v2": "Installed", "TFTP-Client": "InstallPending"})
    f["local_accounts"]["value"] = accounts(
        {"name": "svc-backup", "rid": 1004, "disabled": False, "password_required": False,
         "password_expires": False, "password_last_set": "2024-03-01T10:00:00Z", "last_logon": "2025-12-01T03:00:00Z"})
    f["local_accounts"]["value"]["accounts"][0]["password_last_set"] = "2025-11-30T10:00:00Z"
    f["volumes"]["value"]["volumes"].append(
        {"drive_letter": "E:", "label": "Transfer", "file_system": "FAT32", "system_volume": False,
         "boot_volume": False, "capacity": 34359738368, "partition_type": "Basic"})
    f["bitlocker"]["value"]["volumes"][1]["protection_status"] = "Off"
    f["tpm"]["value"] = {"present": True, "ready": False, "spec_version": "2.0, 0, 1.38"}
    f["secure_boot"]["value"] = {"enabled": False}
    f["device_guard"]["value"].update(vbs_status=0, required_security_properties=[0], security_services_running=[0])
    f["firewall"]["value"]["Public"]["enabled"] = False
    acls = f["acls"]["value"]
    acls["log_security"]["aces"].append(ace("S-1-5-32-545", RX))
    acls["eventvwr"]["aces"].append(ace("S-1-5-32-545", MODIFY))
    d["facts"] = f
    return d


ADMIN_ONLY = {
    "security_policy": "secedit /export failed (exit 740): the requested operation requires elevation (run as administrator)",
    "user_rights": "secedit /export failed (exit 740): the requested operation requires elevation (run as administrator)",
    "audit_policy": ("auditpol failed (exit 1314): Error 0x00000522 occurred: A required privilege is not held "
                     "by the client.; auditpol /backup failed (exit 1314): Error 0x00000522 occurred: A required "
                     "privilege is not held by the client."),
    "features": "The requested operation requires elevation.",
    "bitlocker": "Access denied",
    "tpm": "Get-Tpm did not report TpmPresent",
    "secure_boot": "Unable to set proper privileges. Access was denied.",
}


def unprivileged() -> dict:
    d = member_compliant("ws22-app-02")
    d["privileged"] = False
    for fid, reason in ADMIN_ONLY.items():
        cmd = (COMMANDS[fid] if fid != "audit_policy" else
               "auditpol /get /category:* /r (auditpol /backup failed: auditpol /backup failed (exit 1314): "
               "Error 0x00000522 occurred: A required privilege is not held by the client.)")
        d["facts"][fid] = unavailable(fid, reason, cmd)
    d["facts"]["registry"]["value"] = registry_v(
        COMPLIANT_REGISTRY, errors={(SRV, "RestrictNullSessAccess"): "Requested registry access is not allowed."})
    acls = d["facts"]["acls"]["value"]
    for log in ("application", "system"):
        acls["log_" + log] = {"path": acls["log_" + log]["path"], "error": "Attempted to perform an unauthorized operation."}
    acls["log_security"] = {"path": None, "error": "the log file path could not be read"}
    return d


def domain_controller() -> dict:
    d = member_compliant("ws22-dc-01")
    f = d["facts"]
    f["os"]["value"]["product_type"] = 2
    f["domain_role"]["value"] = {"domain_role": 5, "part_of_domain": True}
    f["security_policy"]["value"]["Kerberos Policy"] = {
        "MaxTicketAge": "10", "MaxRenewAge": "7", "MaxServiceAge": "600", "MaxClockSkew": "5",
        "TicketValidateClient": "1"}
    f["user_rights"]["value"] = rights_v(DC_RIGHTS)
    f["features"]["value"]["states"]["AD-Domain-Services"] = "Installed"
    f["services"]["value"]["NTDS"] = {"present": True, "status": "Running", "start_type": "Automatic"}
    reg = dict(COMPLIANT_REGISTRY)
    for k in [(POLW + r"\System", "EnumerateLocalUsers"), (SYS, "LocalAccountTokenFilterPolicy"),
              (H + r"SOFTWARE\Policies\Microsoft\Windows NT\Rpc", "RestrictRemoteClients"),
              (LSA, "RestrictRemoteSAM"), (POLW + r"\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}", "NoGPOListChanges")]:
        reg.pop(k)
    reg.update({
        (H + r"SYSTEM\CurrentControlSet\Services\NTDS\Parameters", "LDAPServerIntegrity"): (D, 2),
        (H + r"SYSTEM\CurrentControlSet\Services\NTDS\Parameters", "DSA Database file"): (S, r"C:\Windows\NTDS\ntds.dit"),
        (H + r"SYSTEM\CurrentControlSet\Services\NTDS\Parameters", "Database log files path"): (S, r"C:\Windows\NTDS"),
        (NETLOGON, "RefusePasswordChange"): (D, 0),
        (NETLOGON, "SysVol"): (S, r"C:\Windows\SYSVOL\sysvol"),
    })
    f["registry"]["value"] = registry_v(reg)
    f["local_accounts"]["value"] = {"accounts": []}
    f["local_admins"] = unavailable("local_admins", "Failed to compare two elements in the array.")
    acls = f["acls"]["value"]
    acls["ntds_dirs"] = [r"C:\Windows\NTDS"]
    acls["ntds_files"] = [acl(rf"C:\Windows\NTDS\{n}", ace("S-1-5-18", FULL, True), ace(ADM, FULL, True))
                          for n in ("edb.chk", "edb.log", "ntds.dit", "ntds.jfm")]
    acls["sysvol"] = acl(r"C:\Windows\SYSVOL", ace("S-1-5-11", RX), ace("S-1-5-11", 0xA0000000),
                         ace("S-1-5-32-549", RX), ace("S-1-5-32-549", 0xA0000000),
                         ace(ADM, 0x1D01BF), ace(ADM, 0x10000000), ace("S-1-5-18", FULL),
                         ace("S-1-5-18", 0x10000000), ace("S-1-3-0", 0x10000000))
    f["certificates"]["value"]["personal_count"] = 2
    return d


GERMAN = {0: "Keine Überwachung", 1: "Erfolg", 2: "Fehler", 3: "Erfolg und Fehler"}


def non_english() -> dict:
    d = member_compliant("ws22-app-de")
    d["facts"]["audit_policy"] = ok("audit_policy", audit_v(STIG_AUDIT, source="get", inclusion=GERMAN))
    d["facts"]["audit_policy"]["command"] = (
        "auditpol /get /category:* /r (auditpol /backup failed: auditpol /backup failed (exit 87): "
        "Fehler 0x00000057 ist aufgetreten)")
    return d


def standalone() -> dict:
    d = member_compliant("ws22-kiosk-01")
    f = d["facts"]
    f["domain_role"]["value"] = {"domain_role": 2, "part_of_domain": False}
    rights = copy.deepcopy(MEMBER_RIGHTS)
    rights.update(SeDenyNetworkLogonRight=[GUESTS], SeDenyBatchLogonRight=[GUESTS],
                  SeDenyInteractiveLogonRight=[GUESTS], SeDenyRemoteInteractiveLogonRight=[GUESTS])
    rights.pop("SeDenyServiceLogonRight")
    f["user_rights"]["value"] = rights_v(rights)
    return d


BUILDERS = {
    "windows-member-compliant.json": member_compliant,
    "windows-noncompliant.json": noncompliant,
    "windows-unprivileged.json": unprivileged,
    "windows-dc.json": domain_controller,
    "windows-standalone.json": standalone,
    "windows-non-english.json": non_english,
}


def render(builder) -> str:
    return json.dumps(copy.deepcopy(builder()), indent=1, ensure_ascii=False) + "\n"


def main(argv: list[str]) -> int:
    check = "--check" in argv
    stale = []
    FIXTURES.mkdir(parents=True, exist_ok=True)
    for name, builder in BUILDERS.items():
        path = FIXTURES / name
        text = render(builder)
        if check:
            if not path.is_file() or path.read_text(encoding="utf-8") != text:
                stale.append(name)
        else:
            path.write_text(text, encoding="utf-8", newline="\n")
            print(f"wrote {path}")
    if stale:
        print("out of date: " + ", ".join(stale), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
