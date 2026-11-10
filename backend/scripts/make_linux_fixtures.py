"""Generate the synthetic Linux collector fixtures in tests/fixtures/.

The fixtures have the exact shape collectors/collect-linux.sh writes (raw file contents,
command output and counts). Host names are invented. Run from backend/:

    python scripts/make_linux_fixtures.py          # rewrite the fixtures
    python scripts/make_linux_fixtures.py --check  # exit 1 if they are out of date
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures"
COLLECTED_AT = "2026-11-09T14:02:11Z"

BANNER = """You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants.  Such communications and work product are private and confidential.  See User Agreement for details."""

PKGS = ("openssh-server telnetd rsh-server ntp chrony systemd-timesyncd libpam-pwquality ufw auditd "
        "audispd-plugins aide aide-common apparmor rsyslog opensc-pkcs11 libpam-pkcs11 libpam-sss sssd "
        "vlock nfs-kernel-server kdump-tools xserver-xorg-core xwayland gnome-shell gdm3 lightdm sddm "
        "ubuntu-desktop xfce4-session mate-session-manager cinnamon-session plasma-workspace").split()
UNITS = ("ssh.service auditd.service apparmor.service rsyslog.service ufw.service kdump-tools.service "
         "ctrl-alt-del.target sssd.service chrony.service").split()

VERSIONS = {
    "openssh-server": "1:8.9p1-3ubuntu0.10", "telnetd": "0.17-44build1", "rsh-server": "0.17-22",
    "ntp": "1:4.2.8p15+dfsg-1ubuntu2", "chrony": "4.2-2ubuntu2", "systemd-timesyncd": "249.11-0ubuntu3.12",
    "libpam-pwquality": "1.4.4-1build2", "ufw": "0.36.1-4ubuntu0.1", "auditd": "1:3.0.7-1build1",
    "audispd-plugins": "1:3.0.7-1build1", "aide": "0.17.4-1", "aide-common": "0.17.4-1",
    "apparmor": "3.0.4-2ubuntu2.4", "rsyslog": "8.2112.0-2ubuntu2.2", "opensc-pkcs11": "0.22.0-1ubuntu2",
    "libpam-pkcs11": "0.6.11-4build2", "libpam-sss": "2.6.3-1ubuntu3.3", "sssd": "2.6.3-1ubuntu3.3",
    "vlock": "2.2.2-10", "nfs-kernel-server": "1:2.6.1-1ubuntu1.2", "kdump-tools": "1:1.6.10ubuntu2",
    "xserver-xorg-core": "2:21.1.4-2ubuntu1.7~22.04.12", "xwayland": "2:22.1.1-1ubuntu0.15",
    "gnome-shell": "42.9-0ubuntu2.2", "gdm3": "42.0-1ubuntu7.22.04.4", "ubuntu-desktop": "1.481.3",
}

AIDE_SHA1 = "b71bb2cafaedf15ec3ac2f566f209d3260a37af0"
AIDE_MD5 = "4f1c3c1bd1f2b0d9a0e8f8d5f4d3c2b1"

AUDIT_RULES_STIG = """-a always,exit -S all -F path=/sbin/apparmor_parser -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_chng
-a always,exit -S all -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_chng
-a always,exit -S all -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-chage
-a always,exit -S all -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_chng
-a always,exit -S all -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-chfn
-a always,exit -S all -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd
-a always,exit -S all -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-crontab
-w /etc/cron.d -p wa -k cronjobs
-w /var/spool/cron -p wa -k cronjobs
-w /usr/sbin/fdisk -p x -k fdisk
-a always,exit -S all -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-gpasswd
-w /bin/kmod -p x -k module
-w /sbin/modprobe -p x -k modules
-a always,exit -S all -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-mount
-a always,exit -S all -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd
-a always,exit -S all -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-pam_timestamp_check
-a always,exit -S all -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-passwd
-a always,exit -S all -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_chng
-a always,exit -S all -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-ssh
-a always,exit -S all -F path=/usr/lib/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-ssh
-a always,exit -S all -F path=/bin/su -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-priv_change
-a always,exit -S all -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd
-a always,exit -S all -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd
-a always,exit -S all -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-umount
-a always,exit -S all -F path=/sbin/unix_update -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-unix-update
-a always,exit -S all -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-usermod
-a always,exit -S all -F path=/usr/sbin/useradd -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-useradd
-w /etc/group -p wa -k usergroup_modification
-w /etc/gshadow -p wa -k usergroup_modification
-w /etc/security/opasswd -p wa -k usergroup_modification
-w /etc/passwd -p wa -k usergroup_modification
-w /etc/shadow -p wa -k usergroup_modification
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_chng
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_chng
-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=-1 -F key=perm_chng
-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=-1 -F key=perm_chng
-a always,exit -F arch=b32 -S open,truncate,ftruncate,creat,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access
-a always,exit -F arch=b32 -S open,truncate,ftruncate,creat,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access
-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access
-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access
-a always,exit -F arch=b32 -S delete_module -F auid>=1000 -F auid!=-1 -F key=module_chng
-a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=-1 -F key=module_chng
-a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=-1 -F key=module_chng
-a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=-1 -F key=module_chng
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid=0 -F key=perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid=0 -F key=perm_mod
-a always,exit -F arch=b64 -S rename,rmdir,unlink,unlinkat,renameat -F auid>=1000 -F auid!=-1 -F key=delete
-a always,exit -F arch=b32 -S unlink,rename,rmdir,unlinkat,renameat -F auid>=1000 -F auid!=-1 -F key=delete
-w /var/log/journal -p wa -k systemd_journal
-w /var/log/btmp -p wa -k logins
-w /var/log/wtmp -p wa -k logins
-w /var/run/utmp -p wa -k logins
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /etc/sudoers -p wa -k privilege_modification
-w /etc/sudoers.d -p wa -k privilege_modification
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F key=execpriv
-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -F key=execpriv
-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -F key=execpriv
-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -F key=execpriv
-w /var/log/sudo.log -p wa -k maintenance"""

PASSWD = """root:0:0:/bin/bash
daemon:1:1:/usr/sbin/nologin
bin:2:2:/usr/sbin/nologin
sys:3:3:/usr/sbin/nologin
sync:4:65534:/bin/sync
games:5:60:/usr/sbin/nologin
man:6:12:/usr/sbin/nologin
lp:7:7:/usr/sbin/nologin
mail:8:8:/usr/sbin/nologin
news:9:9:/usr/sbin/nologin
uucp:10:10:/usr/sbin/nologin
proxy:13:13:/usr/sbin/nologin
www-data:33:33:/usr/sbin/nologin
backup:34:34:/usr/sbin/nologin
list:38:38:/usr/sbin/nologin
irc:39:39:/usr/sbin/nologin
gnats:41:41:/usr/sbin/nologin
nobody:65534:65534:/usr/sbin/nologin
_apt:100:65534:/usr/sbin/nologin
systemd-network:101:102:/usr/sbin/nologin
systemd-resolve:102:103:/usr/sbin/nologin
messagebus:103:104:/usr/sbin/nologin
systemd-timesync:104:105:/usr/sbin/nologin
syslog:105:111:/usr/sbin/nologin
_chrony:106:113:/usr/sbin/nologin
sshd:107:65534:/usr/sbin/nologin
account-1:1000:1000:/bin/bash
account-2:1001:1001:/bin/bash"""


def ok(value, command):
    return {"status": "ok", "value": value, "reason": None, "command": command}


def unavailable(reason, command):
    return {"status": "unavailable", "value": None, "reason": reason, "command": command}


def file_v(text):
    return {"exists": text is not None, "text": text}


def lines_v(entries):
    files = []
    for path, _ in entries:
        if path not in files:
            files.append(path)
    return {"files": files, "text": "\n".join(f"{p}\t{ln}" for p, ln in entries)}


def find_v(entries=(), complete=True, error=None):
    return {"complete": complete, "count": len(entries), "sample": "\n".join(entries), "error": error}


def packages_v(installed, removed=()):
    rows = []
    for name in PKGS:
        if name in installed:
            rows.append(f"{name}\tii \t{VERSIONS.get(name, '1.0-1')}")
        elif name in removed:
            rows.append(f"{name}\trc \t{VERSIONS.get(name, '1.0-1')}")
    return {"queried": PKGS, "text": "\n".join(rows)}


# What systemd reports for aliases: an unmasked ctrl-alt-del.target is shown as its
# target, reboot.target, with the alias in Names; ssh, chrony and rsyslog carry aliases too.
ALIASES = {"ssh.service": ("ssh.service", "ssh.service sshd.service"),
           "chrony.service": ("chrony.service", "chrony.service chronyd.service"),
           "rsyslog.service": ("rsyslog.service", "rsyslog.service syslog.service")}


def units_v(states):
    blocks = []
    for unit in UNITS:
        load, active, file_state = states.get(unit, ("not-found", "inactive", ""))
        uid, names = ALIASES.get(unit, (unit, unit)) if load != "not-found" else (unit, unit)
        if unit == "ctrl-alt-del.target" and load != "masked":
            uid, names = "reboot.target", "reboot.target ctrl-alt-del.target"
        blocks.append(f"Id={uid}\nNames={names}\nLoadState={load}\nActiveState={active}\n"
                      f"UnitFileState={file_state}")
    return {"queried": UNITS, "text": "\n\n".join(blocks)}


def stat(role, mode, user, group, kind, path):
    return f"{role}\t{mode}\t{user}\t{group}\t{kind}\t{path}"


DPKG_CMD = ("dpkg-query -W -f '${Package}\\t${db:Status-Abbrev}\\t${Version}\\n' " + " ".join(PKGS))
UNITS_CMD = "systemctl show -p Id -p Names -p LoadState -p ActiveState -p UnitFileState " + " ".join(UNITS)
MACHINE = "3b018e681c904487b11671b9c1987cce"


def compliant(host: str = "jammy-stig-01") -> dict:
    installed = {"openssh-server", "chrony", "libpam-pwquality", "ufw", "auditd", "audispd-plugins",
                 "aide", "aide-common", "apparmor", "rsyslog", "opensc-pkcs11", "libpam-pkcs11",
                 "libpam-sss", "sssd", "vlock"}
    running = ("loaded", "active", "enabled")
    facts = {
        "os_release": ok(file_v('PRETTY_NAME="Ubuntu 22.04.5 LTS"\nNAME="Ubuntu"\nVERSION_ID="22.04"\n'
                                'VERSION="22.04.5 LTS (Jammy Jellyfish)"\nVERSION_CODENAME=jammy\nID=ubuntu\n'
                                'ID_LIKE=debian\nHOME_URL="https://www.ubuntu.com/"\nUBUNTU_CODENAME=jammy'),
                         "cat /etc/os-release"),
        "lsb_release": ok(file_v('DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE=22.04\nDISTRIB_CODENAME=jammy\n'
                                 'DISTRIB_DESCRIPTION="Ubuntu 22.04.5 LTS"'), "cat /etc/lsb-release"),
        "packages": ok(packages_v(installed, removed={"systemd-timesyncd"}), DPKG_CMD),
        "units": ok(units_v({
            "ssh.service": running, "auditd.service": running, "apparmor.service": running,
            "rsyslog.service": running, "ufw.service": running, "chrony.service": running,
            "sssd.service": running, "ctrl-alt-del.target": ("masked", "inactive", "masked"),
        }), UNITS_CMD),
        "sshd_config": ok(lines_v([
            ("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf"),
            ("/etc/ssh/sshd_config", "KbdInteractiveAuthentication no"),
            ("/etc/ssh/sshd_config", "UsePAM yes"),
            ("/etc/ssh/sshd_config", "X11Forwarding no"),
            ("/etc/ssh/sshd_config", "PrintMotd no"),
            ("/etc/ssh/sshd_config", "AcceptEnv LANG LC_*"),
            ("/etc/ssh/sshd_config", "Subsystem sftp /usr/lib/openssh/sftp-server"),
            ("/etc/ssh/sshd_config.d/99-stig.conf", "Banner /etc/issue.net"),
            ("/etc/ssh/sshd_config.d/99-stig.conf", "PermitEmptyPasswords no"),
            ("/etc/ssh/sshd_config.d/99-stig.conf", "PermitUserEnvironment no"),
            ("/etc/ssh/sshd_config.d/99-stig.conf", "X11UseLocalhost yes"),
            ("/etc/ssh/sshd_config.d/99-stig.conf", "ClientAliveCountMax 1"),
            ("/etc/ssh/sshd_config.d/99-stig.conf", "ClientAliveInterval 600"),
            ("/etc/ssh/sshd_config.d/99-stig.conf", "PubkeyAuthentication yes"),
            ("/etc/ssh/sshd_config.d/99-stig.conf",
             "Ciphers aes256-ctr,aes256-gcm@openssh.com,aes128-ctr,aes128-gcm@openssh.com"),
            ("/etc/ssh/sshd_config.d/99-stig.conf",
             "MACs hmac-sha2-512,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-256-etm@openssh.com"),
            ("/etc/ssh/sshd_config.d/99-stig.conf",
             "KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256"),
        ]), "cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf (active lines)"),
        "ssh_banner": ok({"path": "/etc/issue.net", "exists": True, "text": BANNER}, "cat /etc/issue.net"),
        "sshd_effective": ok("port 22\naddressfamily any\nlistenaddress 0.0.0.0:22\npermitemptypasswords no\n"
                             "permituserenvironment no\nx11forwarding no\nx11uselocalhost yes\n"
                             "clientalivecountmax 1\nclientaliveinterval 600\nbanner /etc/issue.net\n"
                             "ciphers aes256-ctr,aes256-gcm@openssh.com,aes128-ctr,aes128-gcm@openssh.com",
                             "sshd -T"),
        "sysctl_runtime": ok("kernel.dmesg_restrict\tok\t1\nkernel.randomize_va_space\tok\t2\n"
                             "net.ipv4.tcp_syncookies\tok\t1\ncrypto.fips_enabled\tok\t1",
                             "cat /proc/sys/<key> for kernel.dmesg_restrict kernel.randomize_va_space "
                             "net.ipv4.tcp_syncookies crypto.fips_enabled"),
        "sysctl_saved": ok(lines_v([
            ("/etc/sysctl.d/10-kernel-hardening.conf", "kernel.dmesg_restrict = 1"),
            ("/etc/sysctl.d/99-stig.conf", "net.ipv4.tcp_syncookies = 1"),
            ("/etc/sysctl.d/99-stig.conf", "kernel.randomize_va_space = 2"),
        ]), "grep the sysctl keys in /run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf "
            "/usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf"),
        "login_defs": ok(file_v("MAIL_DIR        /var/mail\nFAILLOG_ENAB\t\tyes\nLOG_UNKFAIL_ENAB\tno\n"
                                "SYSLOG_SU_ENAB\t\tyes\nFTMP_FILE\t/var/log/btmp\nUMASK\t\t077\n"
                                "PASS_MAX_DAYS\t180\nPASS_MIN_DAYS\t1\nPASS_WARN_AGE\t7\nUID_MIN\t\t\t 1000\n"
                                "UID_MAX\t\t\t60000\nENCRYPT_METHOD SHA512"), "cat /etc/login.defs"),
        "useradd_defaults": ok(file_v("SHELL=/bin/sh\nINACTIVE=35"), "cat /etc/default/useradd"),
        "pam_common_auth": ok(file_v(
            "auth\trequired\t\t\tpam_faildelay.so\tdelay=4000000\n"
            "auth\t[success=3 default=ignore]\tpam_pkcs11.so\n"
            "auth\t[success=2 default=ignore]\tpam_unix.so try_first_pass\n"
            "auth\t[default=die]\t\t\tpam_faillock.so authfail\n"
            "auth\tsufficient\t\t\tpam_faillock.so authsucc\n"
            "auth\trequisite\t\t\tpam_deny.so\n"
            "auth\trequired\t\t\tpam_permit.so\n"
            "auth\toptional\t\t\tpam_cap.so"), "cat /etc/pam.d/common-auth"),
        "pam_common_password": ok(file_v(
            "password\trequisite\t\t\tpam_pwquality.so retry=3\n"
            "password\t[success=1 default=ignore]\tpam_unix.so obscure use_authtok try_first_pass sha512 shadow rounds=100000\n"
            "password\trequisite\t\t\tpam_deny.so\n"
            "password\trequired\t\t\tpam_permit.so"), "cat /etc/pam.d/common-password"),
        "faillock_conf": ok(file_v("audit\nsilent\ndeny = 3\nfail_interval = 900\nunlock_time = 0"),
                            "cat /etc/security/faillock.conf"),
        "pwquality_conf": ok(file_v("difok = 8\nminlen = 15\ndcredit = -1\nucredit = -1\nlcredit = -1\n"
                                    "ocredit = -1\ndictcheck = 1\nenforcing = 1"),
                             "cat /etc/security/pwquality.conf"),
        "pam_pkcs11_conf": ok(file_v("pam_pkcs11 {\nnullok = false;\ndebug = false;\nuse_first_pass = false;\n"
                                     "use_pkcs11_module = opensc;\nuse_mappers = pwent, null;\n}"),
                              "cat /etc/pam_pkcs11/pam_pkcs11.conf"),
        "limits": ok(lines_v([("/etc/security/limits.d/99-stig.conf", "* hard maxlogins 10")]),
                     "grep maxlogins /etc/security/limits.conf /etc/security/limits.d/*.conf"),
        "shell_tmout": ok(lines_v([("/etc/profile.d/99-terminal_tmout.sh", "TMOUT=900")]),
                          "grep TMOUT= /etc/bash.bashrc /etc/profile.d/*"),
        "apt_conf": ok(lines_v([
            ("/etc/apt/apt.conf.d/01-vendor-ubuntu", 'APT::Get::AllowUnauthenticated "false";'),
            ("/etc/apt/apt.conf.d/50unattended-upgrades", 'Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";'),
            ("/etc/apt/apt.conf.d/50unattended-upgrades", 'Unattended-Upgrade::Remove-Unused-Dependencies "true";'),
        ]), "grep -i 'allowunauthenticated|remove-unused' /etc/apt/apt.conf.d/*"),
        "modprobe_usb": ok(lines_v([("/etc/modprobe.d/stig.conf", "install usb-storage /bin/false"),
                                    ("/etc/modprobe.d/stig.conf", "blacklist usb-storage")]),
                           "grep usb-storage /etc/modprobe.d/*"),
        "sssd_conf": ok(lines_v([("/etc/sssd/sssd.conf", "offline_credentials_expiration = 1")]),
                        "grep offline_credentials_expiration /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf"),
        "grub_cfg": ok({"exists": True, "pbkdf2_entries": 1, "plain_password_entries": 0, "superusers_lines": 1,
                        "linux_lines": 4, "linux_lines_audit1": 4},
                       "grep -c (password_pbkdf2, password, set superusers, linux, audit=1) /boot/grub/grub.cfg"),
        "default_grub": ok(file_v('GRUB_CMDLINE_LINUX_DEFAULT="quiet splash audit=1"\nGRUB_CMDLINE_LINUX="audit=1"'),
                           "cat /etc/default/grub"),
        "proc_cmdline": ok("BOOT_IMAGE=/vmlinuz-5.15.0-126-fips root=/dev/mapper/ubuntu--vg-ubuntu--lv ro "
                           "quiet splash audit=1 fips=1", "cat /proc/cmdline"),
        "shadow": ok({"accounts": 28, "empty_password": 0},
                     "awk -F: count of accounts and of empty password fields in /etc/shadow"),
        "root_password_status": ok("root L 08/09/2022 0 99999 7 -1", "passwd -S root"),
        "passwd_accounts": ok(PASSWD, "awk -F: '{print $1\":\"$3\":\"$4\":\"$7}' /etc/passwd"),
        "group_sudo": ok(file_v("account-1"), "grep '^sudo:' /etc/group (members)"),
        "sudoers": ok(lines_v([("/etc/sudoers", "root\tALL=(ALL:ALL) ALL"),
                               ("/etc/sudoers", "%admin ALL=(ALL) ALL"),
                               ("/etc/sudoers", "%sudo\tALL=(ALL:ALL) ALL")]),
                      "grep -iwE 'NOPASSWD|!authenticate|ALL' /etc/sudoers /etc/sudoers.d/*"),
        "auditd_conf": ok(file_v("local_events = yes\nwrite_logs = yes\nlog_file = /var/log/audit/audit.log\n"
                                 "log_group = root\nlog_format = ENRICHED\nflush = INCREMENTAL_ASYNC\nfreq = 50\n"
                                 "max_log_file = 8\nnum_logs = 5\nspace_left = 25%\nspace_left_action = email\n"
                                 "action_mail_acct = isso@example.test\nadmin_space_left = 50\n"
                                 "admin_space_left_action = SUSPEND\ndisk_full_action = HALT\ndisk_error_action = SUSPEND"),
                          "cat /etc/audit/auditd.conf"),
        "audit_rules": ok(AUDIT_RULES_STIG, "auditctl -l"),
        "audit_status": ok("enabled 2\nfailure 1\npid 812\nrate_limit 0\nbacklog_limit 8192\nlost 0\nbacklog 0\n"
                           "backlog_wait_time 60000\nbacklog_wait_time_actual 0\nloginuid_immutable 0 unlocked",
                           "auditctl -s"),
        "audit_rules_d": ok(lines_v([("/etc/audit/rules.d/99-finalize.rules", "-e 2")]),
                            "grep '^-e' /etc/audit/rules.d/*.rules"),
        "audit_paths": ok("\n".join([
            stat("conf", "640", "root", "root", "f", "/etc/audit/audit.rules"),
            stat("conf", "640", "root", "root", "f", "/etc/audit/auditd.conf"),
            stat("conf", "640", "root", "root", "f", "/etc/audit/rules.d/stig.rules"),
            stat("conf", "640", "root", "root", "f", "/etc/audit/rules.d/99-finalize.rules"),
            stat("logdir", "750", "root", "root", "d", "/var/log/audit"),
            stat("logfile", "600", "root", "root", "f", "/var/log/audit/audit.log"),
            stat("logfile", "400", "root", "root", "f", "/var/log/audit/audit.log.1"),
        ]), "find <path> -maxdepth 0 -printf '%m %u %g %y %p' for /etc/audit/audit.rules, /etc/audit/auditd.conf, "
            "/etc/audit/rules.d/*, the log_file directory and its files"),
        "audit_remote": ok({"plugin": file_v("active = yes\ndirection = out\npath = /sbin/audisp-remote\n"
                                             "type = always\nformat = string"),
                            "remote": file_v("remote_server = 192.0.2.50\nport = 60\ntransport = tcp")},
                           "cat /etc/audit/plugins.d/au-remote.conf /etc/audit/audisp-remote.conf"),
        "path_stats": ok("\n".join([
            stat("var_log", "755", "root", "syslog", "d", "/var/log"),
            stat("syslog", "640", "syslog", "adm", "f", "/var/log/syslog"),
            stat("journalctl", "740", "root", "root", "f", "/usr/bin/journalctl"),
        ] + [stat("audit_tool", "755", "root", "root", "f", f"/sbin/{t}")
             for t in ("auditctl", "aureport", "ausearch", "autrace", "auditd", "augenrules")]
          + [stat("audit_tool", "755", "root", "root", "f", "/sbin/audisp-remote")]),
            "find <path> -maxdepth 0 -printf '%m %u %g %y %p' for /var/log, /var/log/syslog, "
            "/usr/bin/journalctl and the audit tools in /sbin"),
        "journal_entries": ok(find_v([
            "2750\troot\tsystemd-journal\td\t/run/log/journal",
            "2750\troot\tsystemd-journal\td\t/var/log/journal",
            f"2750\troot\tsystemd-journal\td\t/var/log/journal/{MACHINE}",
            f"640\troot\tsystemd-journal\tf\t/var/log/journal/{MACHINE}/system.journal",
            f"640\troot\tsystemd-journal\tf\t/var/log/journal/{MACHINE}/user-1000.journal",
        ]), "find /run/log/journal /var/log/journal -printf '%m %u %g %y %p'"),
        "timedatectl": ok("Timezone=Etc/UTC\nLocalRTC=no\nCanNTP=yes\nNTP=yes\nNTPSynchronized=yes\n"
                          "TimeUSec=Mon 2026-11-09 14:02:11 UTC\nRTCTimeUSec=Mon 2026-11-09 14:02:11 UTC",
                          "timedatectl show"),
        "chrony_conf": ok(lines_v([
            ("/etc/chrony/chrony.conf", "server tick.usno.navy.mil iburst maxpoll 16"),
            ("/etc/chrony/chrony.conf", "server tock.usno.navy.mil iburst maxpoll 16"),
            ("/etc/chrony/chrony.conf", "server ntp2.usno.navy.mil iburst maxpoll 16"),
            ("/etc/chrony/chrony.conf", "makestep 1 -1"),
        ]), "grep -E 'server|pool|peer|makestep' /etc/chrony/chrony.conf /etc/chrony/conf.d/*.conf "
            "/etc/chrony/sources.d/*.sources"),
        "ufw_status": ok({"installed": True, "text": "Status: active\n\nTo                         Action      From\n"
                                                      "--                         ------      ----\n"
                                                      "22/tcp                     LIMIT       Anywhere"}, "ufw status"),
        "apparmor_status": ok("apparmor module is loaded.\n34 profiles are loaded.\n34 profiles are in enforce mode.\n"
                              "0 profiles are in complain mode.\n0 profiles are in kill mode.\n"
                              "0 profiles are in unconfined mode.\n2 processes have profiles defined.", "aa-status"),
        "aide_cron": ok({"cron": f"/etc/cron.daily/aide\t{AIDE_SHA1}", "shipped_sha1": AIDE_SHA1,
                         "shipped_md5": AIDE_MD5, "dpkg_md5": AIDE_MD5},
                        "sha1sum /etc/cron.daily/aide /etc/cron.monthly/aide /usr/share/aide/config/cron.daily/aide; "
                        "md5sum of the latter; its md5 in /var/lib/dpkg/info/aide-common.md5sums"),
        "aide_conf": ok(file_v("\n".join(f"/sbin/{t} p+i+n+u+g+s+b+acl+xattrs+sha512"
                                         for t in ("auditctl", "auditd", "ausearch", "aureport", "autrace",
                                                   "augenrules"))), "cat /etc/aide/aide.conf"),
        "gdm_greeter": ok(file_v(None), "cat /etc/gdm3/greeter.dconf-defaults"),
        "gsettings": unavailable("gsettings not found (no GNOME settings installed)",
                                 "gsettings get <schema> <key> for media-keys logout, screensaver lock-enabled "
                                 "and lock-delay, session idle-delay"),
        "dmesg_nx": ok("[    0.000000] NX (Execute Disable) protection: active", "dmesg | grep -i 'execute disable'"),
        "cpu_flags": ok("nx", "grep flags /proc/cpuinfo | grep -o -w nx"),
        "wireless": ok(file_v("Inter-| sta-|   Quality        |   Discarded packets               | Missed | WE\n"
                              " face | tus | link level noise |  nwid  crypt   frag  retry   misc | beacon | 22"),
                       "cat /proc/net/wireless"),
        "block_devices": ok("\n".join([
            'NAME="/dev/loop0" TYPE="loop" FSTYPE="squashfs" MOUNTPOINT="/snap/core22/1663" PKNAME=""',
            'NAME="/dev/sda" TYPE="disk" FSTYPE="" MOUNTPOINT="" PKNAME=""',
            'NAME="/dev/sda1" TYPE="part" FSTYPE="vfat" MOUNTPOINT="/boot/efi" PKNAME="/dev/sda"',
            'NAME="/dev/sda2" TYPE="part" FSTYPE="ext4" MOUNTPOINT="/boot" PKNAME="/dev/sda"',
            'NAME="/dev/sda3" TYPE="part" FSTYPE="crypto_LUKS" MOUNTPOINT="" PKNAME="/dev/sda"',
            'NAME="/dev/mapper/dm_crypt-0" TYPE="crypt" FSTYPE="LVM2_member" MOUNTPOINT="" PKNAME="/dev/sda3"',
            'NAME="/dev/mapper/ubuntu--vg-ubuntu--lv" TYPE="lvm" FSTYPE="ext4" MOUNTPOINT="/" '
            'PKNAME="/dev/mapper/dm_crypt-0"',
            'NAME="/dev/mapper/ubuntu--vg-swap" TYPE="lvm" FSTYPE="swap" MOUNTPOINT="[SWAP]" '
            'PKNAME="/dev/mapper/dm_crypt-0"',
        ]), "lsblk -P -p -o NAME,TYPE,FSTYPE,MOUNTPOINT,PKNAME"),
        "crypttab": ok(file_v("dm_crypt-0 UUID=5d6e2a1c-7b2f-4c9e-9a51-0f0d3f2e6b11 none luks"), "cat /etc/crypttab"),
    }
    for fid, cmd in (
        ("cmd_dirs_writable", "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d"),
        ("cmd_files_writable", "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f"),
        ("lib_files_writable", "find /lib /lib64 /usr/lib -type f -name '*.so*' -perm /022"),
        ("cmd_dirs_owner", "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d"),
        ("cmd_dirs_group", "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type d"),
        ("cmd_files_owner", "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type f"),
        ("cmd_files_group", "find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root "
                            "-type f ! -perm /2000"),
        ("lib_dirs_owner", "find /lib /usr/lib /lib64 ! -user root -type d"),
        ("lib_dirs_group", "find /lib /usr/lib /lib64 ! -group root -type d"),
        ("lib_files_owner", "find /lib /lib64 /usr/lib -type f -name '*.so*' ! -user root"),
        ("lib_files_group", "find /lib /lib64 /usr/lib -type f -name '*.so*' ! -group root"),
        ("var_log_files", "find /var/log -perm /137 ! -name '*[bw]tmp' ! -name '*lastlog' ! -name history.log "
                          "! -name eipp.log.xz -type f"),
        ("public_dirs", "find / /boot /boot/efi /dev/shm /run /run/lock /run/user/1000 -xdev -type d -perm -0002 "
                        "! -perm -1000"),
    ):
        facts[fid] = ok(find_v(), cmd)
    return {
        "collector": "linux", "version": 1, "collected_at": COLLECTED_AT, "privileged": True, "redacted": True,
        "escaper": "awk", "utf8_bytes_dropped": False,
        "host": {"name": host, "os_release": "Ubuntu 22.04.5 LTS", "kernel": "5.15.0-126-fips",
                 "virtualization": "kvm"},
        "facts": facts,
    }


def noncompliant() -> dict:
    """A stock Ubuntu 22.04 cloud server with a few extra bad habits."""
    d = compliant("jammy-legacy-07")
    f = d["facts"]
    d["host"]["kernel"] = "5.15.0-126-generic"
    installed = {"openssh-server", "telnetd", "ntp", "systemd-timesyncd", "rsyslog", "apparmor", "ufw",
                 "nfs-kernel-server", "kdump-tools"}
    f["packages"]["value"] = packages_v(installed)
    f["units"]["value"] = units_v({
        "ssh.service": ("loaded", "active", "enabled"), "apparmor.service": ("loaded", "active", "enabled"),
        "rsyslog.service": ("loaded", "inactive", "disabled"), "ufw.service": ("loaded", "inactive", "disabled"),
        "kdump-tools.service": ("loaded", "active", "enabled"),
        "ctrl-alt-del.target": ("loaded", "inactive", "static"),
    })
    f["sshd_config"]["value"] = lines_v([
        ("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf"),
        ("/etc/ssh/sshd_config", "KbdInteractiveAuthentication no"),
        ("/etc/ssh/sshd_config", "UsePAM yes"),
        ("/etc/ssh/sshd_config", "X11Forwarding yes"),
        ("/etc/ssh/sshd_config", "PrintMotd no"),
        ("/etc/ssh/sshd_config", "ClientAliveInterval 900"),
        ("/etc/ssh/sshd_config", "Ciphers aes256-ctr,chacha20-poly1305@openssh.com"),
        ("/etc/ssh/sshd_config.d/60-cloudimg-settings.conf", "PasswordAuthentication no"),
        ("/etc/ssh/sshd_config.d/60-cloudimg-settings.conf", "PermitUserEnvironment yes"),
        ("/etc/ssh/sshd_config.d/70-local.conf", "PermitUserEnvironment no"),
    ])
    f["ssh_banner"]["value"] = {"path": None, "exists": False, "text": None}
    f["ssh_banner"]["command"] = "no Banner directive in the sshd configuration"
    f["sysctl_runtime"]["value"] = ("kernel.dmesg_restrict\tok\t0\nkernel.randomize_va_space\tok\t2\n"
                                    "net.ipv4.tcp_syncookies\tok\t1\ncrypto.fips_enabled\tmissing\t")
    f["sysctl_saved"]["value"] = lines_v([
        ("/etc/sysctl.d/10-kernel-hardening.conf", "kernel.dmesg_restrict = 0"),
        ("/etc/sysctl.d/99-tuning.conf", "kernel.randomize_va_space = 0"),
        ("/etc/sysctl.d/10-network-security.conf", "net.ipv4.tcp_syncookies = 1"),
        ("/etc/sysctl.d/99-tuning.conf", "net.ipv4.tcp_syncookies = 0"),
    ])
    f["login_defs"]["value"] = file_v("MAIL_DIR        /var/mail\nUMASK\t\t022\nPASS_MAX_DAYS\t99999\n"
                                      "PASS_MIN_DAYS\t0\nPASS_WARN_AGE\t7\nENCRYPT_METHOD SHA512")
    f["useradd_defaults"]["value"] = file_v("SHELL=/bin/sh")
    f["pam_common_auth"]["value"] = file_v(
        "auth\t[success=1 default=ignore]\tpam_unix.so nullok\nauth\trequisite\t\t\tpam_deny.so\n"
        "auth\trequired\t\t\tpam_permit.so\nauth\toptional\t\t\tpam_cap.so")
    f["pam_common_password"]["value"] = file_v(
        "password\t[success=1 default=ignore]\tpam_unix.so obscure yescrypt\n"
        "password\trequisite\t\t\tpam_deny.so\npassword\trequired\t\t\tpam_permit.so")
    f["faillock_conf"]["value"] = file_v(None)
    f["pwquality_conf"]["value"] = file_v(None)
    f["pam_pkcs11_conf"]["value"] = file_v(None)
    f["limits"]["value"] = lines_v([])
    f["shell_tmout"]["value"] = lines_v([])
    f["apt_conf"]["value"] = lines_v([
        ("/etc/apt/apt.conf.d/50unattended-upgrades",
         'Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";'),
    ])
    f["modprobe_usb"]["value"] = lines_v([])
    f["sssd_conf"]["value"] = lines_v([])
    f["grub_cfg"]["value"] = {"exists": True, "pbkdf2_entries": 0, "plain_password_entries": 0,
                              "superusers_lines": 0, "linux_lines": 4, "linux_lines_audit1": 0}
    f["default_grub"]["value"] = file_v('GRUB_CMDLINE_LINUX_DEFAULT="console=tty1 console=ttyS0"\nGRUB_CMDLINE_LINUX=""')
    f["proc_cmdline"]["value"] = "BOOT_IMAGE=/vmlinuz-5.15.0-126-generic root=LABEL=cloudimg-rootfs ro console=tty1"
    f["shadow"]["value"] = {"accounts": 29, "empty_password": 1}
    f["root_password_status"]["value"] = "root P 03/14/2025 0 99999 7 -1"
    f["passwd_accounts"]["value"] = PASSWD + "\naccount-3:1000:1000:/bin/bash\nlp:107:7:/bin/sh"
    f["group_sudo"]["value"] = file_v("account-1,account-2")
    f["sudoers"]["value"] = lines_v([
        ("/etc/sudoers", "root\tALL=(ALL:ALL) ALL"),
        ("/etc/sudoers", "%sudo\tALL=(ALL:ALL) ALL"),
        ("/etc/sudoers.d/90-cloud-init-users", "account-1 ALL=(ALL) NOPASSWD:ALL"),
        ("/etc/sudoers.d/99-ops", "Defaults:account-2 !authenticate"),
        ("/etc/sudoers.d/99-ops", "ALL ALL=(ALL:ALL) ALL"),
    ])
    f["auditd_conf"]["value"] = file_v(None)
    f["audit_rules"] = unavailable("auditctl not found (auditd not installed)", "auditctl -l")
    f["audit_status"] = unavailable("auditctl not found (auditd not installed)", "auditctl -s")
    f["audit_rules_d"]["value"] = lines_v([])
    f["audit_paths"] = unavailable("/etc/audit/auditd.conf not found (auditd not installed)",
                                   f["audit_paths"]["command"])
    f["audit_remote"]["value"] = {"plugin": file_v(None), "remote": file_v(None)}
    f["path_stats"]["value"] = "\n".join([
        stat("var_log", "775", "root", "syslog", "d", "/var/log"),
        stat("syslog", "644", "syslog", "adm", "f", "/var/log/syslog"),
        stat("journalctl", "755", "root", "root", "f", "/usr/bin/journalctl"),
    ] + [stat("audit_tool", "-", "-", "-", "missing", f"/sbin/{t}")
         for t in ("auditctl", "aureport", "ausearch", "autrace", "auditd", "augenrules")])
    f["cmd_files_writable"]["value"] = find_v(["777\troot\troot\t/usr/local/bin/backup.sh"])
    f["var_log_files"]["value"] = find_v(["644\troot\troot\t/var/log/cloud-init.log",
                                          "644\troot\troot\t/var/log/dpkg.log"])
    f["public_dirs"]["value"] = find_v(["777\troot\troot\t/srv/share"])
    f["journal_entries"]["value"] = find_v([
        "2755\troot\tsystemd-journal\td\t/var/log/journal",
        f"2755\troot\tsystemd-journal\td\t/var/log/journal/{MACHINE}",
        f"644\troot\tsystemd-journal\tf\t/var/log/journal/{MACHINE}/system.journal",
    ])
    f["timedatectl"]["value"] = ("Timezone=America/New_York\nLocalRTC=no\nCanNTP=yes\nNTP=yes\n"
                                 "NTPSynchronized=no")
    f["chrony_conf"]["value"] = lines_v([])
    f["ufw_status"]["value"] = {"installed": True, "text": "Status: inactive"}
    f["aide_cron"]["value"] = {"cron": "", "shipped_sha1": None, "shipped_md5": None, "dpkg_md5": None}
    f["aide_conf"]["value"] = file_v(None)
    f["wireless"]["value"] = file_v("Inter-| sta-|   Quality        |   Discarded packets               | Missed | WE\n"
                                    " face | tus | link level noise |  nwid  crypt   frag  retry   misc | beacon | 22\n"
                                    " wlp2s0: 0000   54.  -56.  -256        0      0      0      0      0        0")
    f["block_devices"]["value"] = "\n".join([
        'NAME="/dev/vda" TYPE="disk" FSTYPE="" MOUNTPOINT="" PKNAME=""',
        'NAME="/dev/vda1" TYPE="part" FSTYPE="ext4" MOUNTPOINT="/" PKNAME="/dev/vda"',
        'NAME="/dev/vda15" TYPE="part" FSTYPE="vfat" MOUNTPOINT="/boot/efi" PKNAME="/dev/vda"',
    ])
    f["crypttab"]["value"] = file_v(None)
    return d


ROOT_ONLY = {
    "sshd_effective": "requires root (run the collector with sudo)",
    "grub_cfg": "cannot read /boot/grub/grub.cfg: cat: /boot/grub/grub.cfg: Permission denied",
    "shadow": "awk: cannot open /etc/shadow (Permission denied)",
    "root_password_status": "requires root (run the collector with sudo)",
    "sudoers": "cannot read /etc/sudoers: cat: /etc/sudoers: Permission denied",
    "auditd_conf": "cannot read /etc/audit/auditd.conf (permission denied)",
    "audit_rules": "requires root (run the collector with sudo)",
    "audit_status": "requires root (run the collector with sudo)",
    "audit_rules_d": "cannot list /etc/audit/rules.d (permission denied)",
    "audit_paths": "cannot read /etc/audit/auditd.conf: cat: /etc/audit/auditd.conf: Permission denied",
    "audit_remote": "cannot read /etc/audit/plugins.d/au-remote.conf (permission denied)",
    "sssd_conf": "cannot list /etc/sssd (permission denied)",
    "ufw_status": "requires root (run the collector with sudo)",
    "apparmor_status": "requires root (run the collector with sudo)",
    "dmesg_nx": "dmesg: read kernel buffer failed: Operation not permitted",
}


def unprivileged() -> dict:
    """The compliant host, collected without root."""
    d = compliant("jammy-stig-01")
    d["privileged"] = False
    for fid, reason in ROOT_ONLY.items():
        d["facts"][fid] = unavailable(reason, d["facts"][fid]["command"])
    d["facts"]["public_dirs"]["value"] = find_v(
        complete=False, error="find: '/var/lib/private': Permission denied")
    return d


def minimal() -> dict:
    """A minimal image: no auditd, no AIDE, no GNOME tools, no systemd-detect-virt."""
    d = compliant("jammy-minimal-03")
    f = d["facts"]
    d["host"]["virtualization"] = "unknown"
    installed = {"openssh-server", "chrony", "libpam-pwquality", "apparmor", "rsyslog", "vlock", "ufw"}
    f["packages"]["value"] = packages_v(installed)
    for fid in ("audit_rules", "audit_status"):
        f[fid] = unavailable("auditctl not found (auditd not installed)", f[fid]["command"])
    f["audit_paths"] = unavailable("/etc/audit/auditd.conf not found (auditd not installed)", f["audit_paths"]["command"])
    f["auditd_conf"]["value"] = file_v(None)
    f["audit_rules_d"]["value"] = lines_v([])
    f["audit_remote"]["value"] = {"plugin": file_v(None), "remote": file_v(None)}
    f["path_stats"]["value"] = "\n".join([
        stat("var_log", "755", "root", "syslog", "d", "/var/log"),
        stat("syslog", "640", "syslog", "adm", "f", "/var/log/syslog"),
        stat("journalctl", "740", "root", "root", "f", "/usr/bin/journalctl"),
    ] + [stat("audit_tool", "-", "-", "-", "missing", f"/sbin/{t}")
         for t in ("auditctl", "aureport", "ausearch", "autrace", "auditd", "augenrules")])
    f["aide_cron"]["value"] = {"cron": "", "shipped_sha1": None, "shipped_md5": None, "dpkg_md5": None}
    f["aide_conf"]["value"] = file_v(None)
    f["apparmor_status"]["value"] = ("apparmor module is loaded.\n12 profiles are loaded.\n"
                                     "12 profiles are in enforce mode.\n0 profiles are in complain mode.")
    f["sssd_conf"]["value"] = lines_v([])
    f["pam_pkcs11_conf"]["value"] = file_v(None)
    f["pam_common_auth"]["value"]["text"] = f["pam_common_auth"]["value"]["text"].replace(
        "auth\t[success=3 default=ignore]\tpam_pkcs11.so\n", "")
    f["block_devices"] = unavailable("lsblk not found", "lsblk -P -p -o NAME,TYPE,FSTYPE,MOUNTPOINT,PKNAME")
    return d


def gui() -> dict:
    """A compliant workstation with GNOME."""
    d = compliant("jammy-ws-12")
    f = d["facts"]
    pk = f["packages"]["value"]
    pk["text"] += "\n" + "\n".join(f"{p}\tii \t{VERSIONS[p]}"
                                   for p in ("xserver-xorg-core", "xwayland", "gnome-shell", "gdm3",
                                             "ubuntu-desktop"))
    f["gdm_greeter"]["value"] = file_v(
        "[org/gnome/login-screen]\nbanner-message-enable=true\nbanner-message-text='"
        + BANNER.replace("\n", "\\n") + "'\ndisable-user-list=true")
    f["gsettings"] = ok({
        "org.gnome.settings-daemon.plugins.media-keys logout": {"ok": True, "output": "@as []"},
        "org.gnome.desktop.screensaver lock-enabled": {"ok": True, "output": "true"},
        "org.gnome.desktop.screensaver lock-delay": {"ok": True, "output": "uint32 0"},
        "org.gnome.desktop.session idle-delay": {"ok": True, "output": "uint32 600"},
    }, "gsettings get <schema> <key> for media-keys logout, screensaver lock-enabled and lock-delay, "
       "session idle-delay")
    return d


def server_no_gui() -> dict:
    d = compliant("jammy-db-02")
    d["host"]["virtualization"] = "vmware"
    return d


BUILDERS = {
    "linux-compliant.json": compliant,
    "linux-noncompliant.json": noncompliant,
    "linux-unprivileged.json": unprivileged,
    "linux-minimal.json": minimal,
    "linux-gui.json": gui,
    "linux-server-nogui.json": server_no_gui,
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
