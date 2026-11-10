<#
.SYNOPSIS
  STIGWatch: read-only Windows Server 2022 fact collector.

.DESCRIPTION
  Gathers the host facts STIGWatch needs to evaluate the DISA Microsoft Windows Server
  2022 STIG and writes them to one JSON file. It decides nothing: STIGWatch evaluates
  the facts.

  Read-only. The script changes no setting, writes nothing to the registry, applies no
  policy and starts or stops nothing. Registry keys are opened read-only through
  RegistryKey.OpenBaseKey / OpenSubKey (no write access). The only files it creates are
  the output file and two temporary exports in $env:TEMP ('secedit /export' and
  'auditpol /backup'), each deleted in a finally block straight after it is read.
  (Windows itself appends a line to %windir%\security\logs\scesrv.log when secedit runs;
  that is an OS side effect.) No credentials are used or stored, and no password hash is
  ever read. Every fact records the command that produced it. A fact that cannot be
  read (for example secedit or auditpol without administrator rights) is recorded as
  "unavailable" with the reason, and STIGWatch reports the rules that depend on it as
  Not Reviewed.

  Commands run (all read-only): secedit /export, auditpol /backup,
  auditpol /get /category:* /r, Get-CimInstance (Win32_OperatingSystem,
  Win32_ComputerSystem, Win32_Volume, Win32_UserAccount, Win32_DeviceGuard,
  root\cimv2\Security\MicrosoftTpm Win32_Tpm),
  Get-Partition, Get-WindowsFeature, Get-WindowsOptionalFeature -Online, Get-Service,
  Get-LocalUser, Get-LocalGroupMember, Get-MpComputerStatus, Get-NetFirewallProfile,
  Get-SmbServerConfiguration, Get-BitLockerVolume, Get-Tpm, Confirm-SecureBootUEFI,
  Get-WinEvent -ListLog, Get-Acl, Get-ChildItem (Cert: drive and the NTDS folder only).

  Works on Windows PowerShell 5.1 and PowerShell 7. Run it elevated for full coverage.

.PARAMETER OutFile
  Where to write the JSON. Defaults to stigwatch-windows-<computer name>.json in the
  current folder.

.PARAMETER RedactNames
  Replace account names (local accounts, Administrators group members, the renamed
  built-in Administrator and Guest names, and any user right granted to a name rather
  than a SID) with account-N. SIDs, well-known group names and the host name are kept.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\collect-windows.ps1 -OutFile host.json
#>
[CmdletBinding()]
param(
    [string]$OutFile = '',
    [switch]$RedactNames
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ([Environment]::OSVersion.Platform -ne 'Win32NT') {
    throw 'collect-windows.ps1 runs on Windows only.'
}

$script:Facts = [ordered]@{}
$script:FactCommand = ''
$script:Secedit = $null
$script:SeceditError = $null
$script:Redactions = @{}
$script:CollectedAt = [datetime]::UtcNow

$IsAdmin = $false
try {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $IsAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { }

# --- helpers ---------------------------------------------------------------

function Add-Fact {
    param([string]$Id, [string]$Command, [scriptblock]$Script)
    $script:FactCommand = $Command
    $entry = [ordered]@{ status = 'unavailable'; value = $null; reason = $null; command = $Command }
    try {
        $value = & $Script
        if ($null -eq $value) { throw 'the command returned no data' }
        $entry.status = 'ok'
        $entry.value = $value
    } catch {
        $msg = (($_.Exception.Message -replace '\s+', ' ')).Trim()
        if (-not $msg) { $msg = 'unknown error' }
        $entry.reason = $msg
    }
    $entry.command = $script:FactCommand
    $script:Facts[$Id] = $entry
}

function Invoke-Native {
    param([string]$File, [string[]]$Arguments)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & $File @Arguments 2>&1
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
    $lines = @($out | ForEach-Object {
        if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message } else { "$_" }
    } | Where-Object { $_ -and $_.Trim() })
    [pscustomobject]@{ Output = $lines; ExitCode = $code }
}

function Get-Prop {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function ConvertTo-Iso {
    param($Value)
    if ($null -eq $Value) { return $null }
    try { return ([datetime]$Value).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } catch { return $null }
}

function Get-RedactedName {
    # The same name always maps to the same account-N within one run.
    param([string]$Name)
    if (-not $RedactNames) { return $Name }
    if ($null -eq $Name -or $Name -eq '') { return $Name }
    $k = $Name.ToLowerInvariant()
    if (-not $script:Redactions.ContainsKey($k)) {
        $script:Redactions[$k] = 'account-' + ($script:Redactions.Count + 1)
    }
    return $script:Redactions[$k]
}

function Read-RegistryValue {
    # Opens the key read-only. state: set | absent (key or value missing) | error.
    param([string]$Hive, [string]$SubKey, [string]$Name)
    $entry = [ordered]@{ key = ($Hive + '\' + $SubKey); name = $Name; state = 'absent' }
    $hiveId = if ($Hive -eq 'HKLM') { [Microsoft.Win32.RegistryHive]::LocalMachine } else { [Microsoft.Win32.RegistryHive]::CurrentUser }
    $base = $null
    $key = $null
    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hiveId, [Microsoft.Win32.RegistryView]::Registry64)
        $key = $base.OpenSubKey($SubKey, $false)
        if ($null -ne $key) {
            $names = @($key.GetValueNames())
            if ($names -contains $Name) {
                $kind = $key.GetValueKind($Name)
                $data = $key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                $entry.state = 'set'
                $entry.type = [string]$kind
                if ($kind -eq [Microsoft.Win32.RegistryValueKind]::Binary) {
                    $entry.data = (@($data) | ForEach-Object { '{0:x2}' -f $_ }) -join ''
                } elseif ($kind -eq [Microsoft.Win32.RegistryValueKind]::MultiString) {
                    $entry.data = @($data | ForEach-Object { [string]$_ })
                } elseif ($kind -eq [Microsoft.Win32.RegistryValueKind]::DWord -or $kind -eq [Microsoft.Win32.RegistryValueKind]::QWord) {
                    $entry.data = [int64]$data
                } else {
                    $entry.data = [string]$data
                }
            }
        }
    } catch {
        $entry.state = 'error'
        $entry.error = (($_.Exception.Message -replace '\s+', ' ')).Trim()
    } finally {
        if ($null -ne $key) { $key.Dispose() }
        if ($null -ne $base) { $base.Dispose() }
    }
    return $entry
}

function Get-SeceditExport {
    # 'secedit /export' (the local security database, where applied Group Policy security
    # settings are recorded) to a temp file; read every section; delete the file.
    if ($null -ne $script:Secedit) { return $script:Secedit }
    if ($null -ne $script:SeceditError) { throw $script:SeceditError }
    $tmp = Join-Path $env:TEMP ('stigwatch-' + [guid]::NewGuid().ToString('N') + '.inf')
    try {
        $run = Invoke-Native 'secedit.exe' @('/export', '/cfg', $tmp, '/areas', 'SECURITYPOLICY', 'USER_RIGHTS', '/quiet')
        if ($run.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $tmp)) {
            $detail = ($run.Output -join ' ').Trim()
            if ($run.ExitCode -eq 740) { $detail = 'the requested operation requires elevation (run as administrator) ' + $detail }
            $script:SeceditError = ('secedit /export failed (exit ' + $run.ExitCode + '): ' + $detail).Trim()
            throw $script:SeceditError
        }
        $sections = [ordered]@{}
        $current = $null
        foreach ($line in (Get-Content -LiteralPath $tmp -Encoding Unicode)) {
            if ($line -match '^\s*\[(.+)\]\s*$') {
                $current = $Matches[1]
                if (-not $sections.Contains($current)) { $sections[$current] = [ordered]@{} }
                continue
            }
            if ($null -ne $current -and $line -match '^\s*([^=]+?)\s*=\s*(.*?)\s*$') {
                $sections[$current][$Matches[1]] = $Matches[2]
            }
        }
        if ($sections.Count -eq 0) {
            $script:SeceditError = 'the secedit export contained no sections'
            throw $script:SeceditError
        }
        $script:Secedit = $sections
    } finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force }
    }
    return $script:Secedit
}

$seceditCmd = 'secedit /export /cfg "<temp file in $env:TEMP, deleted after reading>" /areas SECURITYPOLICY USER_RIGHTS /quiet'

# --- host ------------------------------------------------------------------

Add-Fact 'os' 'Get-CimInstance Win32_OperatingSystem; registry HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion (InstallationType, DisplayVersion, UBR, EditionID); $env:firmware_type' {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $cv = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $r = [ordered]@{
        caption           = [string]$os.Caption
        version           = [string]$os.Version
        build_number      = [string]$os.BuildNumber
        product_type      = [int]$os.ProductType
        installation_type = $null
        display_version   = $null
        edition_id        = $null
        ubr               = $null
        firmware_type     = [string]$env:firmware_type
    }
    foreach ($pair in @(@('installation_type', 'InstallationType'), @('display_version', 'DisplayVersion'), @('edition_id', 'EditionID'), @('ubr', 'UBR'))) {
        $v = Read-RegistryValue 'HKLM' $cv $pair[1]
        if ($v.state -eq 'set') { $r[$pair[0]] = $v.data }
    }
    $r
}

Add-Fact 'domain_role' 'Get-CimInstance Win32_ComputerSystem (DomainRole, PartOfDomain)' {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    [ordered]@{ domain_role = [int]$cs.DomainRole; part_of_domain = [bool]$cs.PartOfDomain }
}

# --- secedit ---------------------------------------------------------------

Add-Fact 'security_policy' $seceditCmd {
    $s = Get-SeceditExport
    $result = [ordered]@{}
    foreach ($name in @('System Access', 'Kerberos Policy')) {
        if (-not $s.Contains($name)) { continue }
        $section = [ordered]@{}
        foreach ($k in $s[$name].Keys) {
            $v = $s[$name][$k]
            if ($RedactNames -and ($k -eq 'NewAdministratorName' -or $k -eq 'NewGuestName')) {
                $plain = $v.Trim('"')
                if ($plain -ne 'Administrator' -and $plain -ne 'Guest') { $v = '"' + (Get-RedactedName $plain) + '"' }
            }
            $section[$k] = $v
        }
        $result[$name] = $section
    }
    if ($result.Count -eq 0) { throw ('the secedit export had no [System Access] section (sections: ' + (@($s.Keys) -join ', ') + ')') }
    $result
}

Add-Fact 'user_rights' $seceditCmd {
    $s = Get-SeceditExport
    if (-not $s.Contains('Privilege Rights')) { throw ('the secedit export had no [Privilege Rights] section (sections: ' + (@($s.Keys) -join ', ') + ')') }
    $rights = [ordered]@{}
    foreach ($k in $s['Privilege Rights'].Keys) {
        $entries = @($s['Privilege Rights'][$k] -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $out = @(foreach ($e in $entries) { if ($e.StartsWith('*')) { $e } else { Get-RedactedName $e } })
        $rights[$k] = ($out -join ',')
    }
    $rights
}

# --- audit policy ----------------------------------------------------------

Add-Fact 'audit_policy' 'auditpol /backup /file:"<temp file in $env:TEMP, deleted after reading>"' {
    # /backup writes the numeric "Setting Value" (0-3), which does not depend on the display
    # language. When it fails, 'auditpol /get /category:* /r' is used; its inclusion setting
    # text is localized and only English text is interpreted (by STIGWatch, not here).
    $rows = @()
    $source = 'backup'
    $tmp = Join-Path $env:TEMP ('stigwatch-' + [guid]::NewGuid().ToString('N') + '.csv')
    $backupError = $null
    try {
        $run = Invoke-Native 'auditpol.exe' @('/backup', ('/file:' + $tmp))
        if ($run.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $tmp)) {
            $backupError = 'auditpol /backup failed (exit ' + $run.ExitCode + '): ' + ($run.Output -join ' ')
        } else {
            $lines = @([System.IO.File]::ReadAllLines($tmp) | Where-Object { $_.Trim() })
            $rows = @($lines | ConvertFrom-Csv -Header 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7')
        }
    } finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force }
    }
    if ($null -ne $backupError) {
        $source = 'get'
        $script:FactCommand = 'auditpol /get /category:* /r (auditpol /backup failed: ' + $backupError + ')'
        $run = Invoke-Native 'auditpol.exe' @('/get', '/category:*', '/r')
        if ($run.ExitCode -ne 0) { throw ('auditpol failed (exit ' + $run.ExitCode + '): ' + ($run.Output -join ' ') + '; ' + $backupError) }
        $rows = @($run.Output | Where-Object { $_.Trim() } | ConvertFrom-Csv -Header 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7')
    }
    $subs = @()
    foreach ($row in $rows) {
        if ($row.c4 -match '^\{[0-9A-Fa-f\-]{36}\}$' -and $row.c2 -ne 'Policy Target' -and $row.c2 -notmatch '^S-1-') {
            $entry = [ordered]@{ guid = $row.c4.ToUpperInvariant(); name = [string]$row.c3; inclusion = [string]$row.c5 }
            if ($source -eq 'backup') { $entry.setting_value = [string]$row.c7 }
            $subs += $entry
        }
    }
    if ($subs.Count -eq 0) { throw 'auditpol output had no audit subcategory rows' }
    [ordered]@{ source = $source; subcategories = $subs }
}

# --- registry --------------------------------------------------------------

# Every registry value the checks read: hive, key, value name.
$RegistryValues = @(
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows\Personalization', 'NoLockScreenSlideshow'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest', 'UseLogonCredential'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters', 'DisableIPSourceRouting'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters', 'DisableIPSourceRouting'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters', 'EnableICMPRedirect'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Services\Netbt\Parameters', 'NoNameReleaseOnDemand'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation', 'AllowInsecureGuestAuth'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths', '\\*\NETLOGON'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths', '\\*\SYSVOL'),
    @('HKLM', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit', 'ProcessCreationIncludeCmdLine_Enabled'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation', 'AllowProtectedCreds'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows\DeviceGuard', 'EnableVirtualizationBasedSecurity'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows\DeviceGuard', 'RequirePlatformSecurityFeatures'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows\DeviceGuard', 'LsaCfgFlags'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Policies\EarlyLaunch', 'DriverLoadPolicy'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}', 'NoGPOListChanges'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows NT\Printers', 'DisableWebPnPDownload'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows NT\Printers', 'DisableHTTPPrinting'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows\System', 'DontDisplayNetworkSelectionUI'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows\System', 'EnableSmartScreen'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows\System', 'EnumerateLocalUsers'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51', 'DCSettingIndex'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51', 'ACSettingIndex'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows\AppCompat', 'DisableInventory'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows\Explorer', 'NoAutoplayfornonVolume'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows\Explorer', 'NoDataExecutionPrevention'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows\Explorer', 'NoHeapTerminationOnCorruption'),
    @('HKLM', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer', 'NoAutorun'),
    @('HKLM', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer', 'NoDriveTypeAutoRun'),
    @('HKLM', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer', 'PreXPSP2ShellProtocolBehavior'),
    @('HKLM', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI', 'EnumerateAdministrators'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows\DataCollection', 'AllowTelemetry'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization', 'DODownloadMode'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows\EventLog\Application', 'MaxSize'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows\EventLog\Security', 'MaxSize'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows\EventLog\System', 'MaxSize'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services', 'DisablePasswordSaving'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services', 'fDisableCdm'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services', 'fPromptForPassword'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services', 'fEncryptRPCTraffic'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services', 'MinEncryptionLevel'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds', 'DisableEnclosureDownload'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds', 'AllowBasicAuthInClear'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows\Windows Search', 'AllowIndexingEncryptedStoresOrItems'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows\Installer', 'EnableUserControl'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows\Installer', 'AlwaysInstallElevated'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows\Installer', 'SafeForScripting'),
    @('HKLM', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'DisableAutomaticRestartSignOn'),
    @('HKLM', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'LocalAccountTokenFilterPolicy'),
    @('HKLM', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'InactivityTimeoutSecs'),
    @('HKLM', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'LegalNoticeText'),
    @('HKLM', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'LegalNoticeCaption'),
    @('HKLM', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'FilterAdministratorToken'),
    @('HKLM', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'EnableUIADesktopToggle'),
    @('HKLM', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'ConsentPromptBehaviorAdmin'),
    @('HKLM', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'ConsentPromptBehaviorUser'),
    @('HKLM', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'EnableInstallerDetection'),
    @('HKLM', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'EnableSecureUIAPaths'),
    @('HKLM', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'EnableLUA'),
    @('HKLM', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'EnableVirtualization'),
    @('HKLM', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters', 'SupportedEncryptionTypes'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging', 'EnableScriptBlockLogging'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription', 'EnableTranscripting'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription', 'OutputDirectory'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Client', 'AllowBasic'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Client', 'AllowUnencryptedTraffic'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Client', 'AllowDigest'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Service', 'AllowBasic'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Service', 'AllowUnencryptedTraffic'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Service', 'DisableRunAs'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters', 'LDAPServerIntegrity'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters', 'DSA Database file'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters', 'Database log files path'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Services\Netlogon\Parameters', 'RefusePasswordChange'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Services\Netlogon\Parameters', 'RequireSignOrSeal'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Services\Netlogon\Parameters', 'SealSecureChannel'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Services\Netlogon\Parameters', 'SignSecureChannel'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Services\Netlogon\Parameters', 'DisablePasswordChange'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Services\Netlogon\Parameters', 'MaximumPasswordAge'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Services\Netlogon\Parameters', 'RequireStrongKey'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Services\Netlogon\Parameters', 'SysVol'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Windows NT\Rpc', 'RestrictRemoteClients'),
    @('HKLM', 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', 'CachedLogonsCount'),
    @('HKLM', 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', 'scremoveoption'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Control\Lsa', 'RestrictRemoteSAM'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Control\Lsa', 'LimitBlankPasswordUse'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Control\Lsa', 'SCENoApplyLegacyAuditPolicy'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Control\Lsa', 'RestrictAnonymousSAM'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Control\Lsa', 'RestrictAnonymous'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Control\Lsa', 'EveryoneIncludesAnonymous'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Control\Lsa', 'UseMachineId'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Control\Lsa', 'NoLMHash'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Control\Lsa', 'LmCompatibilityLevel'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0', 'allownullsessionfallback'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0', 'NTLMMinClientSec'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0', 'NTLMMinServerSec'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Control\Lsa\pku2u', 'AllowOnlineID'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy', 'Enabled'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Services\LDAP', 'LDAPClientIntegrity'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters', 'RequireSecuritySignature'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters', 'EnableSecuritySignature'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters', 'EnablePlainTextPassword'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Services\LanManServer\Parameters', 'RequireSecuritySignature'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Services\LanManServer\Parameters', 'EnableSecuritySignature'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Services\LanManServer\Parameters', 'RestrictNullSessAccess'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Services\LanManServer\Parameters', 'SMB1'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Services\mrxsmb10', 'Start'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\Cryptography', 'ForceKeyProtection'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Control\Session Manager', 'ProtectionMode'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Control\SecureBoot\State', 'UEFISecureBootEnabled'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Services\W32Time\Parameters', 'Type'),
    @('HKLM', 'SYSTEM\CurrentControlSet\Services\W32Time\Parameters', 'NtpServer'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\W32time\Parameters', 'Type'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft\W32time\Parameters', 'NtpServer'),
    @('HKLM', 'SOFTWARE\Microsoft\Policies\LAPS', 'BackupDirectory'),
    @('HKLM', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS', 'BackupDirectory'),
    @('HKLM', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS', 'PasswordComplexity'),
    @('HKLM', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS', 'PasswordLength'),
    @('HKLM', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS', 'PasswordAgeDays'),
    @('HKLM', 'SOFTWARE\Policies\Microsoft Services\AdmPwd', 'AdmPwdEnabled'),
    @('HKCU', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments', 'SaveZoneInformation')
)

Add-Fact 'registry' 'registry (read-only OpenBaseKey/OpenSubKey): the values listed in collect-windows.ps1 $RegistryValues; HKCU is the account running the collector' {
    $values = @(foreach ($r in $RegistryValues) { Read-RegistryValue $r[0] $r[1] $r[2] })
    [ordered]@{ values = $values }
}

# --- roles, features and services ------------------------------------------

$FeatureNames = @('Fax', 'Web-Ftp-Service', 'PNRP', 'Simple-TCPIP', 'Telnet-Client', 'TFTP-Client', 'FS-SMB1', 'PowerShell-v2', 'AD-Domain-Services', 'Hyper-V')
$OptionalFeatureNames = @('Microsoft-Hyper-V', 'TelnetClient', 'TFTP', 'SimpleTCP', 'SMB1Protocol', 'MicrosoftWindowsPowerShellV2Root', 'IIS-FTPSvc')

Add-Fact 'features' ('Get-WindowsFeature -Name ' + ($FeatureNames -join ',')) {
    if (Get-Command -Name Get-WindowsFeature -ErrorAction SilentlyContinue) {
        $states = [ordered]@{}
        foreach ($f in @(Get-WindowsFeature -Name $FeatureNames -ErrorAction Stop)) {
            $states[[string]$f.Name] = [string]$f.InstallState
        }
        if ($states.Count -eq 0) { throw 'Get-WindowsFeature returned no features' }
        return [ordered]@{ source = 'Get-WindowsFeature'; states = $states }
    }
    $script:FactCommand = 'Get-WindowsOptionalFeature -Online -FeatureName ' + ($OptionalFeatureNames -join ',') + ' (Get-WindowsFeature is not available)'
    $states = [ordered]@{}
    foreach ($n in $OptionalFeatureNames) {
        $f = Get-WindowsOptionalFeature -Online -FeatureName $n -ErrorAction Stop
        if ($null -ne $f) { $states[$n] = [string]$f.State }
    }
    if ($states.Count -eq 0) { throw 'Get-WindowsOptionalFeature returned no features' }
    [ordered]@{ source = 'Get-WindowsOptionalFeature'; states = $states }
}

$ServiceNames = @('WinDefend', 'MpsSvc', 'W32Time', 'FTPSVC', 'SPTimerV4', 'MSExchangeServiceHost', 'NTDS')

Add-Fact 'services' ('Get-Service -Name ' + ($ServiceNames -join ',')) {
    $result = [ordered]@{}
    foreach ($n in $ServiceNames) {
        $svc = Get-Service -Name $n -ErrorAction SilentlyContinue
        if ($null -eq $svc) {
            $result[$n] = [ordered]@{ present = $false }
        } else {
            $result[$n] = [ordered]@{ present = $true; status = [string]$svc.Status; start_type = [string](Get-Prop $svc 'StartType') }
        }
    }
    $result
}

# --- accounts --------------------------------------------------------------

Add-Fact 'local_accounts' 'Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True"; Get-LocalUser' {
    $byName = @{}
    foreach ($u in @(Get-LocalUser -ErrorAction Stop)) { $byName[[string]$u.Name] = $u }
    $accounts = @()
    foreach ($a in @(Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop)) {
        $sid = [string]$a.SID
        $entry = [ordered]@{
            name              = Get-RedactedName ([string]$a.Name)
            rid               = [int64]($sid.Substring($sid.LastIndexOf('-') + 1))
            disabled          = [bool]$a.Disabled
            password_required = [bool]$a.PasswordRequired
            password_expires  = [bool]$a.PasswordExpires
        }
        $lu = $byName[[string]$a.Name]
        if ($null -ne $lu) {
            $entry.password_last_set = ConvertTo-Iso (Get-Prop $lu 'PasswordLastSet')
            $entry.last_logon = ConvertTo-Iso (Get-Prop $lu 'LastLogon')
        }
        $accounts += $entry
    }
    [ordered]@{ accounts = $accounts }
}

Add-Fact 'local_admins' 'Get-LocalGroupMember -SID S-1-5-32-544' {
    $members = @()
    foreach ($m in @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)) {
        $sid = [string](Get-Prop $m 'SID')
        $members += [ordered]@{
            name             = Get-RedactedName ([string]$m.Name)
            sid              = $sid
            object_class     = [string]$m.ObjectClass
            principal_source = [string](Get-Prop $m 'PrincipalSource')
        }
    }
    [ordered]@{ count = $members.Count; members = $members }
}

# --- storage and platform --------------------------------------------------

Add-Fact 'volumes' 'Get-CimInstance Win32_Volume -Filter "DriveType=3"; Get-Partition (partition types)' {
    $partTypes = @{}
    $partError = $null
    try {
        foreach ($p in @(Get-Partition -ErrorAction Stop)) {
            foreach ($ap in @(Get-Prop $p 'AccessPaths')) {
                if ($ap -and $ap -like '\\?\Volume*') { $partTypes[$ap.ToLowerInvariant()] = [string]$p.Type }
            }
        }
    } catch { $partError = (($_.Exception.Message -replace '\s+', ' ')).Trim() }
    $volumes = @()
    foreach ($v in @(Get-CimInstance -ClassName Win32_Volume -Filter 'DriveType=3' -ErrorAction Stop)) {
        $id = [string]$v.DeviceID
        $entry = [ordered]@{
            drive_letter  = [string]$v.DriveLetter
            label         = [string]$v.Label
            file_system   = [string]$v.FileSystem
            system_volume = [bool]$v.SystemVolume
            boot_volume   = [bool]$v.BootVolume
            capacity      = [int64]$v.Capacity
        }
        if ($null -eq $partError) {
            $t = $partTypes[$id.ToLowerInvariant()]
            $entry.partition_type = if ($t) { $t } else { $null }
        }
        $volumes += $entry
    }
    $r = [ordered]@{ volumes = $volumes; partition_types_read = ($null -eq $partError) }
    if ($null -ne $partError) { $r.partition_error = $partError }
    $r
}

Add-Fact 'bitlocker' 'Get-BitLockerVolume' {
    $volumes = @()
    foreach ($v in @(Get-BitLockerVolume -ErrorAction Stop)) {
        $volumes += [ordered]@{
            mount_point           = [string]$v.MountPoint
            volume_type           = [string]$v.VolumeType
            protection_status     = [string]$v.ProtectionStatus
            volume_status         = [string]$v.VolumeStatus
            encryption_percentage = $v.EncryptionPercentage
        }
    }
    if ($volumes.Count -eq 0) { throw 'Get-BitLockerVolume returned no volumes' }
    [ordered]@{ volumes = $volumes }
}

Add-Fact 'tpm' 'Get-Tpm; Get-CimInstance -Namespace root\cimv2\Security\MicrosoftTpm Win32_Tpm (SpecVersion)' {
    $t = Get-Tpm -ErrorAction Stop
    $present = Get-Prop $t 'TpmPresent'
    if ($null -eq $present) { throw 'Get-Tpm did not report TpmPresent' }
    $r = [ordered]@{ present = [bool]$present; ready = [bool](Get-Prop $t 'TpmReady'); spec_version = $null }
    if ([bool]$present) {
        $w = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction Stop
        $r.spec_version = [string](Get-Prop $w 'SpecVersion')
    }
    $r
}

Add-Fact 'secure_boot' 'Confirm-SecureBootUEFI' {
    [ordered]@{ enabled = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) }
}

Add-Fact 'device_guard' 'Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard' {
    $d = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' -ErrorAction Stop
    [ordered]@{
        vbs_status                    = [int](Get-Prop $d 'VirtualizationBasedSecurityStatus')
        required_security_properties  = @(@(Get-Prop $d 'RequiredSecurityProperties') | Where-Object { $null -ne $_ } | ForEach-Object { [int]$_ })
        available_security_properties = @(@(Get-Prop $d 'AvailableSecurityProperties') | Where-Object { $null -ne $_ } | ForEach-Object { [int]$_ })
        security_services_running     = @(@(Get-Prop $d 'SecurityServicesRunning') | Where-Object { $null -ne $_ } | ForEach-Object { [int]$_ })
        security_services_configured  = @(@(Get-Prop $d 'SecurityServicesConfigured') | Where-Object { $null -ne $_ } | ForEach-Object { [int]$_ })
    }
}

# --- protection ------------------------------------------------------------

Add-Fact 'defender' 'Get-MpComputerStatus' {
    $s = Get-MpComputerStatus -ErrorAction Stop
    [ordered]@{
        am_service_enabled          = [bool](Get-Prop $s 'AMServiceEnabled')
        antivirus_enabled           = [bool](Get-Prop $s 'AntivirusEnabled')
        realtime_protection_enabled = [bool](Get-Prop $s 'RealTimeProtectionEnabled')
        running_mode                = [string](Get-Prop $s 'AMRunningMode')
    }
}

Add-Fact 'firewall' 'Get-NetFirewallProfile -PolicyStore ActiveStore' {
    $profiles = [ordered]@{}
    foreach ($p in @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)) {
        $enabled = "$($p.Enabled)"
        $profiles[[string]$p.Name] = [ordered]@{
            enabled                = ($enabled -eq 'True' -or $enabled -eq '1')
            enabled_raw            = $enabled
            default_inbound_action = "$($p.DefaultInboundAction)"
        }
    }
    if ($profiles.Count -eq 0) { throw 'no firewall profiles were returned' }
    $profiles
}

Add-Fact 'smb_server' 'Get-SmbServerConfiguration' {
    $c = Get-SmbServerConfiguration -ErrorAction Stop
    [ordered]@{
        enable_smb1_protocol       = [bool]$c.EnableSMB1Protocol
        require_security_signature = [bool]$c.RequireSecuritySignature
    }
}

Add-Fact 'certificates' 'Get-ChildItem Cert:\LocalMachine\Root, Cert:\LocalMachine\Disallowed (DoD subjects or issuers), Cert:\LocalMachine\My (count)' {
    $describe = {
        param($c)
        [ordered]@{ subject = [string]$c.Subject; issuer = [string]$c.Issuer; not_after = ConvertTo-Iso $c.NotAfter; thumbprint = [string]$c.Thumbprint }
    }
    $root = @(Get-ChildItem -Path 'Cert:\LocalMachine\Root' -ErrorAction Stop | Where-Object { $_.Subject -like '*DoD*' } | ForEach-Object { & $describe $_ })
    $disallowed = @(Get-ChildItem -Path 'Cert:\LocalMachine\Disallowed' -ErrorAction Stop | Where-Object { $_.Issuer -like '*DoD*' -or $_.Subject -like '*DoD*' } | ForEach-Object { & $describe $_ })
    $my = @(Get-ChildItem -Path 'Cert:\LocalMachine\My' -ErrorAction Stop)
    [ordered]@{ root_dod = $root; disallowed_dod = $disallowed; personal_count = $my.Count }
}

# --- file permissions ------------------------------------------------------

function Get-AclEntry {
    param([string]$Path)
    $entry = [ordered]@{ path = $Path }
    try {
        if (-not (Test-Path -LiteralPath $Path)) { $entry.exists = $false; return $entry }
        $entry.exists = $true
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $aces = @()
        foreach ($rule in @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))) {
            $aces += [ordered]@{
                sid         = [string]$rule.IdentityReference.Value
                type        = [string]$rule.AccessControlType
                rights      = [int64][int]$rule.FileSystemRights
                inherited   = [bool]$rule.IsInherited
                inheritance = [int]$rule.InheritanceFlags
                propagation = [int]$rule.PropagationFlags
            }
        }
        $entry.aces = $aces
    } catch {
        $entry.error = (($_.Exception.Message -replace '\s+', ' ')).Trim()
    }
    return $entry
}

Add-Fact 'acls' 'Get-WinEvent -ListLog Application,Security,System (LogFilePath); Get-Acl on the event log files, %SystemRoot%\System32\Eventvwr.exe and, on domain controllers, the NTDS files and the SYSVOL folder' {
    $result = [ordered]@{}
    foreach ($log in @('Application', 'Security', 'System')) {
        $path = $null
        try { $path = (Get-WinEvent -ListLog $log -ErrorAction Stop).LogFilePath } catch {
            $v = Read-RegistryValue 'HKLM' ('SYSTEM\CurrentControlSet\Services\EventLog\' + $log) 'File'
            if ($v.state -eq 'set') { $path = [string]$v.data }
        }
        if ($path) {
            $result['log_' + $log.ToLowerInvariant()] = Get-AclEntry ([Environment]::ExpandEnvironmentVariables($path))
        } else {
            $result['log_' + $log.ToLowerInvariant()] = [ordered]@{ path = $null; error = 'the log file path could not be read' }
        }
    }
    $result.eventvwr = Get-AclEntry (Join-Path $env:SystemRoot 'System32\Eventvwr.exe')
    $role = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).DomainRole
    if ($role -ge 4) {
        $ntds = 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
        $dirs = @()
        foreach ($n in @('DSA Database file', 'Database log files path')) {
            $v = Read-RegistryValue 'HKLM' $ntds $n
            if ($v.state -eq 'set') {
                $p = [Environment]::ExpandEnvironmentVariables([string]$v.data)
                if ($n -eq 'DSA Database file') { $p = Split-Path -Parent $p }
                if ($dirs -notcontains $p) { $dirs += $p }
            }
        }
        $files = @()
        foreach ($d in $dirs) {
            # One unreadable folder becomes an error entry; the other permissions are kept.
            try {
                foreach ($f in @(Get-ChildItem -LiteralPath $d -File -ErrorAction Stop)) { $files += Get-AclEntry $f.FullName }
            } catch {
                $files += [ordered]@{ path = $d; error = (($_.Exception.Message -replace '\s+', ' ')).Trim() }
            }
        }
        $result.ntds_dirs = $dirs
        $result.ntds_files = $files
        $sv = Read-RegistryValue 'HKLM' 'SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'SysVol'
        if ($sv.state -eq 'set') {
            $result.sysvol = Get-AclEntry (Split-Path -Parent ([Environment]::ExpandEnvironmentVariables([string]$sv.data)))
        }
    }
    $result
}

# --- output ----------------------------------------------------------------

$hostInfo = [ordered]@{ name = $env:COMPUTERNAME; os = $null; build = $null }
if ($script:Facts['os'].status -eq 'ok') {
    $hostInfo.os = $script:Facts['os'].value.caption
    $hostInfo.build = $script:Facts['os'].value.build_number
}

$document = [ordered]@{
    collector    = 'windows'
    version      = 1
    collected_at = $script:CollectedAt.ToString('yyyy-MM-ddTHH:mm:ssZ')
    host         = $hostInfo
    privileged   = $IsAdmin
    redacted     = [bool]$RedactNames
    powershell   = $PSVersionTable.PSVersion.ToString()
    facts        = $script:Facts
}

if (-not $OutFile) { $OutFile = 'stigwatch-windows-' + $env:COMPUTERNAME + '.json' }
$json = $document | ConvertTo-Json -Depth 12
$target = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)
[System.IO.File]::WriteAllText($target, $json + "`n", (New-Object System.Text.UTF8Encoding($false)))

$ok = @($script:Facts.Values | Where-Object { $_.status -eq 'ok' }).Count
$unavailable = $script:Facts.Count - $ok
Write-Host "STIGWatch Windows collector: $($script:Facts.Count) facts, $ok read, $unavailable unavailable (elevated: $IsAdmin)."
Write-Host "Wrote $target"
