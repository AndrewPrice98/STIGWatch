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
