# STIGWatch

A DISA STIG compliance scanner for Ubuntu 22.04 LTS and Windows Server 2022: read-only host collectors, a declarative check engine, per-host findings, drift tracking, generated remediation and STIG Viewer checklist exports.

> STIGWatch is an independent tool. It is not a DISA product and does not replace the SCAP Compliance Checker, Evaluate-STIG or an assessor's review.

Status: scaffold (version 0.1.0). Full documentation arrives with the release.

## Ubuntu 22.04 collector

```sh
sudo sh collectors/collect-linux.sh -o host.json      # -r redacts account names
cd backend
python -m stigwatch collect-parse linux ../host.json  # validate and summarise the facts
python -m stigwatch scan ../host.json                 # per-status counts and Open findings by CAT
python -m stigwatch coverage ubuntu-22.04             # automated and manual rules by CAT
```

The collector is read-only. It writes only the output file and a temporary directory it removes on exit, and it never outputs password hashes: /etc/shadow and grub.cfg yield counts only. The only digests it reports are the SHA-1 and MD5 checksums of the AIDE cron scripts, which are not secrets. Without root, privileged facts are recorded as unavailable and the rules that need them are reported Not Reviewed. Every command it runs:

- reads: `cat`, `grep`, `awk`, `sed`, `head`, `wc`, `tr`, `cut`, `sort`, `ls -d`, `dirname`, `find` (with `-printf`, never `-delete` or `-exec`), `sha1sum`, `md5sum`, `iconv`
- host and package state: `hostname`, `uname`, `id -u`, `date -u`, `systemd-detect-virt`, `dpkg-query -W`, `systemctl show`, `timedatectl show`, `lsblk -P`, `dmesg`
- security state: `sshd -T`, `auditctl -l`, `auditctl -s`, `passwd -S root`, `ufw status`, `aa-status`, `gsettings get`
- housekeeping: `mktemp -d` and `rm -rf` of that temporary directory

## Windows Server 2022 collector

```powershell
# elevated PowerShell 5.1 or 7; -RedactNames replaces account names with account-N
powershell -ExecutionPolicy Bypass -File collectors\collect-windows.ps1 -OutFile host.json
cd backend
python -m stigwatch collect-parse windows ..\host.json  # validate and summarise the facts
python -m stigwatch scan ..\host.json                   # the collector type is detected from the file
python -m stigwatch coverage windows-server-2022
```

The collector is read-only. It changes no setting, opens registry keys read-only and writes only the output file and two temporary exports in `%TEMP%` (from `secedit` and `auditpol`), each deleted straight after it is read. It never reads password hashes or the content of the Active Directory database. Without administrator rights, secedit, auditpol, the feature list, BitLocker, the TPM and Secure Boot are recorded as unavailable and the rules that need them are reported Not Reviewed. Every command it runs:

- native tools: `secedit /export /areas SECURITYPOLICY USER_RIGHTS`, `auditpol /backup` (falls back to `auditpol /get /category:* /r`)
- CIM: `Get-CimInstance` for `Win32_OperatingSystem`, `Win32_ComputerSystem`, `Win32_Volume`, `Win32_UserAccount`, `Win32_DeviceGuard` and `Win32_Tpm`
- cmdlets: `Get-Partition`, `Get-WindowsFeature` (or `Get-WindowsOptionalFeature -Online` when it is missing), `Get-Service`, `Get-LocalUser`, `Get-LocalGroupMember`, `Get-MpComputerStatus`, `Get-NetFirewallProfile`, `Get-SmbServerConfiguration`, `Get-BitLockerVolume`, `Get-Tpm`, `Confirm-SecureBootUEFI`, `Get-WinEvent -ListLog`, `Get-Acl`, `Get-ChildItem` (the `Cert:` stores, and the NTDS folder on domain controllers to list its files)
- registry: the values listed in `$RegistryValues` in the script, read with `RegistryKey.OpenBaseKey`/`OpenSubKey` without write access
- housekeeping: `Remove-Item` of the two temporary exports, and one write of the output file
