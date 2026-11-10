#!/bin/sh
# STIGWatch: read-only Ubuntu 22.04 LTS fact collector.
#
# Gathers the host facts STIGWatch needs to evaluate the DISA Canonical Ubuntu 22.04 LTS
# STIG and writes them to one JSON file. It decides nothing: STIGWatch evaluates the facts.
#
# Read-only. The script changes no setting, starts or stops nothing and writes nothing
# except the output file and a private temporary directory (mktemp -d) that is removed on
# exit. It never outputs password hashes: /etc/shadow and grub.cfg yield counts only (the
# only digests it reports are SHA-1/MD5 of the AIDE cron scripts, which are not secrets).
# Every fact records the command that produced it. A fact that cannot be read (for example
# /etc/shadow without root, or auditctl not installed) is recorded as "unavailable" with
# the reason, and STIGWatch reports the rules that depend on it as Not Reviewed.
#
# Usage: sh collect-linux.sh [-o FILE] [-r]
#   -o FILE  output path (default: ./stigwatch-linux-<hostname>.json)
#   -r       redact account names (every account except root becomes account-N)
# Run as root (sudo) for full coverage; without root, privileged facts are unavailable.
#
# POSIX sh (dash-compatible). JSON strings are escaped with awk (POSIX; mawk is part of
# every Ubuntu install); python3 is used only as a fallback when awk is missing.
#
# Commands run (all read-only): cat, grep, awk, sed, head, wc, tr, cut, sort, find, ls -d,
# dirname, id, hostname, uname, date, mktemp, rm (temporary directory only), iconv,
# sha1sum, md5sum, dpkg-query -W, systemctl show, systemd-detect-virt, sshd -T,
# timedatectl show, auditctl -l, auditctl -s, passwd -S root, ufw status, aa-status,
# dmesg, lsblk, gsettings get.

set -u
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
LC_ALL=C
export LC_ALL

REDACT=0
OUT=""

usage() {
    echo "usage: sh collect-linux.sh [-o FILE] [-r]"
    echo "  -o FILE  output path (default: ./stigwatch-linux-<hostname>.json)"
    echo "  -r       redact account names"
}

while getopts "o:rh" opt; do
    case $opt in
        o) OUT=$OPTARG ;;
        r) REDACT=1 ;;
        h) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done
shift $((OPTIND - 1))
if [ $# -ne 0 ]; then
    usage >&2
    exit 2
fi

if [ "$(uname -s 2>/dev/null)" != "Linux" ]; then
    echo "warning: this collector is meant for Linux; most facts will be unavailable" >&2
fi

HOST=$(hostname 2>/dev/null || uname -n 2>/dev/null || echo unknown)
if [ -z "$OUT" ]; then
    OUT="stigwatch-linux-$(printf '%s' "$HOST" | tr -c 'A-Za-z0-9._-' '_' | cut -c1-64).json"
fi

TMP=$(mktemp -d "${TMPDIR:-/tmp}/stigwatch.XXXXXXXX") || {
    echo "error: cannot create a temporary directory" >&2
    exit 1
}
cleanup() { rm -rf "$TMP"; }
trap cleanup 0
trap 'exit 1' 1 2 15

IS_ROOT=0
if [ "$(id -u 2>/dev/null)" = "0" ]; then IS_ROOT=1; fi

# --------------------------------------------------------------------------- JSON helpers

if command -v awk >/dev/null 2>&1; then
    ESCAPER=awk
elif command -v python3 >/dev/null 2>&1; then
    ESCAPER=python3
else
    echo "error: neither awk nor python3 is available to write JSON" >&2
    exit 1
fi

# stdin -> one JSON string literal (lines joined with \n, control characters escaped).
jstr() {
    if [ "$ESCAPER" = awk ]; then
        tr -d '\000' | awk '
            BEGIN { for (i = 1; i < 32; i++) ctl = ctl sprintf("%c", i); printf "\"" }
            {
                if (NR > 1) printf "\\n"
                s = $0; o = ""; n = length(s)
                for (i = 1; i <= n; i++) {
                    c = substr(s, i, 1)
                    if (c == "\\") o = o "\\\\"
                    else if (c == "\"") o = o "\\\""
                    else if (c == "\t") o = o "\\t"
                    else if (c == "\r") o = o "\\r"
                    else if (index(ctl, c) > 0) o = o sprintf("\\u%04x", index(ctl, c))
                    else o = o c
                }
                printf "%s", o
            }
            END { printf "\"" }'
    else
        python3 -c 'import json,sys; d=sys.stdin.buffer.read().replace(b"\0", b"").decode("utf-8","replace"); sys.stdout.write(json.dumps(d[:-1] if d.endswith("\n") else d))'
    fi
}

jstr_s() { printf '%s' "$1" | jstr; }

# stdin lines -> JSON array of strings
json_array() {
    first=1
    printf '['
    while IFS= read -r item; do
        if [ "$first" -eq 0 ]; then printf ', '; fi
        first=0
        jstr_s "$item"
    done
    printf ']'
}

have() { command -v "$1" >/dev/null 2>&1; }

err_line() {
    line=$(sed -n '1p' "$TMP/err" 2>/dev/null | cut -c1-300)
    if [ -n "$line" ]; then printf '%s' "$line"; else printf 'exit status %s' "${1:-unknown}"; fi
}

FACTS="$TMP/facts"
: > "$FACTS"
NFACT=0
NUNAVAIL=0

# emit ID STATUS VALUE_FILE REASON COMMAND
emit() {
    if [ "$NFACT" -gt 0 ]; then printf ',\n' >> "$FACTS"; fi
    NFACT=$((NFACT + 1))
    {
        printf '    "%s": {"status": "%s", "value": ' "$1" "$2"
        if [ -n "$3" ]; then cat "$3"; else printf 'null'; fi
        printf ', "reason": '
        if [ -n "$4" ]; then jstr_s "$4"; else printf 'null'; fi
        printf ', "command": '
        jstr_s "$5"
        printf '}'
    } >> "$FACTS"
}

ok() { emit "$1" ok "$TMP/val" "" "$2"; }                                  # ID COMMAND
unavail() { NUNAVAIL=$((NUNAVAIL + 1)); emit "$1" unavailable "" "$3" "$2"; }  # ID COMMAND REASON

# keep active lines: drop blank lines and lines starting with #
# (with KEEP_INCLUDE=1, sudoers' "#include" and "#includedir" directives are kept)
active() {
    awk -v k="${KEEP_INCLUDE:-0}" '
        /^[[:space:]]*$/ { next }
        /^[[:space:]]*#/ { if (k == 1 && $0 ~ /^[[:space:]]*#include/) print; next }
        { print }'
}

# path_state PATH -> present | absent | denied. A path inside a directory we may not
# search looks absent to "test -e"; ls tells the two apart, so an unreadable location is
# never reported as a missing file.
path_state() {
    if [ -e "$1" ] || [ -L "$1" ]; then
        echo present
    elif ls -d "$1" 2>&1 >/dev/null | grep -q -i 'permission denied'; then
        echo denied
    else
        echo absent
    fi
}

# file_value PATH [PATTERN]: {"exists", "text"} of the active lines of PATH (optionally
# only those matching the extended regular expression PATTERN). Returns 1 with REASON set
# when the file exists but cannot be read.
file_value() {
    fv_path=$1
    fv_pat=${2:-}
    case $(path_state "$fv_path") in
        absent)
            printf '{"exists": false, "text": null}' > "$TMP/val"
            return 0 ;;
        denied)
            REASON="cannot read $fv_path (permission denied)"
            return 1 ;;
    esac
    if ! cat "$fv_path" > "$TMP/raw" 2> "$TMP/err"; then
        REASON="cannot read $fv_path: $(err_line)"
        return 1
    fi
    if [ -n "$fv_pat" ]; then
        active < "$TMP/raw" | { grep -E -e "$fv_pat" || true; } > "$TMP/flt"
    else
        active < "$TMP/raw" > "$TMP/flt"
    fi
    { printf '{"exists": true, "text": '; jstr < "$TMP/flt"; printf '}'; } > "$TMP/val"
    return 0
}

file_fact() {  # ID PATH [PATTERN]
    if file_value "$2" "${3:-}"; then ok "$1" "cat $2"; else unavail "$1" "cat $2" "$REASON"; fi
}

# dir_ok DIR...: every existing directory must be listable, else REASON is set.
dir_ok() {
    for d in "$@"; do
        case $(path_state "$d") in
            denied)
                REASON="cannot list $d (permission denied)"
                return 1 ;;
            present)
                if [ ! -r "$d" ] || [ ! -x "$d" ]; then
                    REASON="cannot list $d (permission denied)"
                    return 1
                fi ;;
        esac
    done
    return 0
}

# lines_value PATTERN FILE...: {"files", "text"} with "path<TAB>line" for the active lines
# matching PATTERN (case-insensitive ERE; empty = all) of every existing regular file.
lines_value() {
    lv_pat=$1
    shift
    : > "$TMP/lines"
    : > "$TMP/flist"
    for lv_f in "$@"; do
        case $(path_state "$lv_f") in
            denied)
                REASON="cannot read $lv_f (permission denied)"
                return 1 ;;
            absent) continue ;;
        esac
        [ -f "$lv_f" ] || continue
        if ! cat "$lv_f" > "$TMP/raw" 2> "$TMP/err"; then
            REASON="cannot read $lv_f: $(err_line)"
            return 1
        fi
        printf '%s\n' "$lv_f" >> "$TMP/flist"
        if [ -n "$lv_pat" ]; then
            active < "$TMP/raw" | { grep -i -E -e "$lv_pat" || true; } > "$TMP/flt"
        else
            active < "$TMP/raw" > "$TMP/flt"
        fi
        awk -v f="$lv_f" '{ print f "\t" $0 }' "$TMP/flt" >> "$TMP/lines"
    done
    { printf '{"files": '; json_array < "$TMP/flist"; printf ', "text": '; jstr < "$TMP/lines"; printf '}'; } > "$TMP/val"
    return 0
}

# run CMD ARGS...: stdout -> $TMP/out, stderr -> $TMP/err, returns the exit status.
run() {
    "$@" > "$TMP/out" 2> "$TMP/err"
}

text_fact() {  # ID COMMAND-STRING: $TMP/out as a JSON string
    jstr < "$TMP/out" > "$TMP/val"
    ok "$1" "$2"
}

needs_root() {  # ID COMMAND
    unavail "$1" "$2" "requires root (run the collector with sudo)"
}

# stat_line ROLE PATH: "role<TAB>mode<TAB>user<TAB>group<TAB>type<TAB>path"
stat_line() {
    case $(path_state "$2") in
        absent)
            printf '%s\t-\t-\t-\tmissing\t%s\n' "$1" "$2"
            return 0 ;;
        denied)
            echo "cannot stat $2 (permission denied)" >> "$TMP/err"
            return 0 ;;
    esac
    find "$2" -maxdepth 0 -printf "$1\t%m\t%u\t%g\t%y\t%p\n" 2>> "$TMP/err"
}

# find_fact ID COMMAND-STRING FIND-ARGS...: {"complete", "count", "sample", "error"}
find_fact() {
    ff_id=$1
    ff_cmd=$2
    shift 2
    find "$@" > "$TMP/found" 2> "$TMP/err"
    ff_rc=$?
    ff_count=$(wc -l < "$TMP/found" | tr -d ' ')
    ff_complete=true
    if [ "$ff_rc" -ne 0 ]; then ff_complete=false; fi
    head -n "${FIND_SAMPLE:-50}" "$TMP/found" > "$TMP/sample"
    {
        printf '{"complete": %s, "count": %s, "sample": ' "$ff_complete" "$ff_count"
        jstr < "$TMP/sample"
        printf ', "error": '
        if [ "$ff_rc" -ne 0 ]; then jstr_s "$(err_line "$ff_rc")"; else printf 'null'; fi
        printf '}'
    } > "$TMP/val"
    ok "$ff_id" "$ff_cmd"
}

existing() {  # print the arguments that exist
    for e in "$@"; do
        if [ -e "$e" ]; then printf '%s ' "$e"; fi
    done
}

# --------------------------------------------------------------------------- facts

collect_release() {
    file_fact os_release /etc/os-release
    file_fact lsb_release /etc/lsb-release
}

GUI_PKGS="xserver-xorg-core xwayland gnome-shell gdm3 lightdm sddm ubuntu-desktop xfce4-session mate-session-manager cinnamon-session plasma-workspace"
PKGS="openssh-server telnetd rsh-server ntp chrony systemd-timesyncd libpam-pwquality ufw auditd audispd-plugins aide aide-common apparmor rsyslog opensc-pkcs11 libpam-pkcs11 libpam-sss sssd vlock nfs-kernel-server kdump-tools $GUI_PKGS"

collect_packages() {
    cmd="dpkg-query -W -f '\${Package}\\t\${db:Status-Abbrev}\\t\${Version}\\n' $PKGS"
    if ! have dpkg-query; then
        unavail packages "$cmd" "dpkg-query not found (not a Debian-based system)"
        return
    fi
    # shellcheck disable=SC2086
    run dpkg-query -W -f='${Package}\t${db:Status-Abbrev}\t${Version}\n' $PKGS
    rc=$?
    if [ "$rc" -gt 1 ]; then  # 1 only means some packages are unknown to dpkg
        unavail packages "$cmd" "$(err_line "$rc")"
        return
    fi
    # shellcheck disable=SC2086
    { printf '{"queried": '; printf '%s\n' $PKGS | json_array; printf ', "text": '; jstr < "$TMP/out"; printf '}'; } > "$TMP/val"
    ok packages "$cmd"
}

UNITS="ssh.service auditd.service apparmor.service rsyslog.service ufw.service kdump-tools.service ctrl-alt-del.target sssd.service chrony.service"

collect_units() {
    cmd="systemctl show -p Id -p Names -p LoadState -p ActiveState -p UnitFileState $UNITS"
    if ! have systemctl; then unavail units "$cmd" "systemctl not found"; return; fi
    # shellcheck disable=SC2086
    if ! run systemctl show -p Id -p Names -p LoadState -p ActiveState -p UnitFileState $UNITS; then
        unavail units "$cmd" "$(err_line)"
        return
    fi
    # shellcheck disable=SC2086
    { printf '{"queried": '; printf '%s\n' $UNITS | json_array; printf ', "text": '; jstr < "$TMP/out"; printf '}'; } > "$TMP/val"
    ok units "$cmd"
}

collect_ssh() {
    cmd="cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf (active lines)"
    if ! dir_ok /etc/ssh/sshd_config.d; then
        unavail sshd_config "$cmd" "$REASON"
        unavail ssh_banner "cat <Banner file>" "the sshd configuration could not be read"
    elif ! lines_value '' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; then
        unavail sshd_config "$cmd" "$REASON"
        unavail ssh_banner "cat <Banner file>" "the sshd configuration could not be read"
    else
        cp_lines=$(cat "$TMP/lines")
        ok sshd_config "$cmd"
        banner=$(printf '%s\n' "$cp_lines" | awk -F'\t' '
            { line = $2; sub(/^[[:space:]]+/, "", line)
              if (tolower(line) ~ /^banner([[:space:]]|=)/) {
                  sub(/^[^[:space:]=]+[[:space:]]*=?[[:space:]]*/, "", line)
                  sub(/[[:space:]]+$/, "", line); print line; exit } }')
        if [ -z "$banner" ]; then
            printf '{"path": null, "exists": false, "text": null}' > "$TMP/val"
            ok ssh_banner "no Banner directive in the sshd configuration"
        elif [ "$(path_state "$banner")" = denied ]; then
            unavail ssh_banner "cat $banner" "cannot read $banner (permission denied)"
        elif [ "$(path_state "$banner")" = absent ]; then
            { printf '{"path": '; jstr_s "$banner"; printf ', "exists": false, "text": null}'; } > "$TMP/val"
            ok ssh_banner "cat $banner"
        elif cat "$banner" > "$TMP/raw" 2> "$TMP/err"; then
            { printf '{"path": '; jstr_s "$banner"; printf ', "exists": true, "text": '; jstr < "$TMP/raw"; printf '}'; } > "$TMP/val"
            ok ssh_banner "cat $banner"
        else
            unavail ssh_banner "cat $banner" "$(err_line)"
        fi
    fi

    cmd="sshd -T"
    if ! have sshd; then
        unavail sshd_effective "$cmd" "sshd not found (openssh-server not installed)"
    elif [ "$IS_ROOT" -ne 1 ]; then
        needs_root sshd_effective "$cmd"
    elif run sshd -T; then
        text_fact sshd_effective "$cmd"
    else
        unavail sshd_effective "$cmd" "$(err_line)"
    fi
}

SYSCTL_KEYS="kernel.dmesg_restrict kernel.randomize_va_space net.ipv4.tcp_syncookies crypto.fips_enabled"

collect_sysctl() {
    cmd="cat /proc/sys/<key> for $SYSCTL_KEYS"
    if [ ! -d /proc/sys ]; then
        unavail sysctl_runtime "$cmd" "/proc/sys not found"
    else
        : > "$TMP/out"
        for key in $SYSCTL_KEYS; do
            p="/proc/sys/$(printf '%s' "$key" | tr . /)"
            if [ ! -e "$p" ]; then
                printf '%s\tmissing\t\n' "$key" >> "$TMP/out"
            elif v=$(cat "$p" 2>/dev/null); then
                printf '%s\tok\t%s\n' "$key" "$(printf '%s' "$v" | head -n 1)" >> "$TMP/out"
            else
                printf '%s\tunreadable\t\n' "$key" >> "$TMP/out"
            fi
        done
        text_fact sysctl_runtime "$cmd"
    fi

    cmd="grep the sysctl keys in /run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf"
    if dir_ok /run/sysctl.d /etc/sysctl.d /usr/local/lib/sysctl.d /usr/lib/sysctl.d /lib/sysctl.d \
        && lines_value 'dmesg_restrict|randomize_va_space|tcp_syncookies|fips_enabled' \
            /run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf \
            /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf; then
        ok sysctl_saved "$cmd"
    else
        unavail sysctl_saved "$cmd" "$REASON"
    fi
}

collect_accounts_config() {
    file_fact login_defs /etc/login.defs
    file_fact useradd_defaults /etc/default/useradd
    file_fact pam_common_auth /etc/pam.d/common-auth
    file_fact pam_common_password /etc/pam.d/common-password
    file_fact faillock_conf /etc/security/faillock.conf
    file_fact pwquality_conf /etc/security/pwquality.conf
    file_fact pam_pkcs11_conf /etc/pam_pkcs11/pam_pkcs11.conf

    cmd="grep maxlogins /etc/security/limits.conf /etc/security/limits.d/*.conf"
    if dir_ok /etc/security/limits.d && lines_value 'maxlogins' /etc/security/limits.conf /etc/security/limits.d/*.conf; then
        ok limits "$cmd"
    else
        unavail limits "$cmd" "$REASON"
    fi

    cmd="grep TMOUT= /etc/bash.bashrc /etc/profile.d/*"
    if dir_ok /etc/profile.d && lines_value 'TMOUT=[0-9]' /etc/bash.bashrc /etc/profile.d/*; then
        ok shell_tmout "$cmd"
    else
        unavail shell_tmout "$cmd" "$REASON"
    fi

    cmd="grep -i 'allowunauthenticated|remove-unused' /etc/apt/apt.conf.d/*"
    if dir_ok /etc/apt/apt.conf.d && lines_value 'allowunauthenticated|remove-unused' /etc/apt/apt.conf.d/*; then
        ok apt_conf "$cmd"
    else
        unavail apt_conf "$cmd" "$REASON"
    fi

    cmd="grep usb-storage /etc/modprobe.d/*"
    if dir_ok /etc/modprobe.d && lines_value 'usb-storage' /etc/modprobe.d/*; then
        ok modprobe_usb "$cmd"
    else
        unavail modprobe_usb "$cmd" "$REASON"
    fi

    cmd="grep offline_credentials_expiration /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf"
    if dir_ok /etc/sssd /etc/sssd/conf.d && lines_value 'offline_credentials_expiration' /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf; then
        ok sssd_conf "$cmd"
    else
        unavail sssd_conf "$cmd" "$REASON"
    fi
}

collect_boot() {
    f=/boot/grub/grub.cfg
    cmd="grep -c (password_pbkdf2, password, set superusers, linux, audit=1) $f"
    if [ ! -e "$f" ]; then
        unavail grub_cfg "$cmd" "$f not found"
    elif ! cat "$f" > "$TMP/raw" 2> "$TMP/err"; then
        unavail grub_cfg "$cmd" "cannot read $f: $(err_line)"
    else
        pb=$(grep -c -E '^[[:space:]]*password_pbkdf2[[:space:]]+[^[:space:]]+[[:space:]]+grub\.pbkdf2\.' "$TMP/raw")
        pl=$(grep -c -E '^[[:space:]]*password[[:space:]]+' "$TMP/raw")
        su=$(grep -c -E '^[[:space:]]*set[[:space:]]+superusers=' "$TMP/raw")
        ll=$(grep -c -E '^[[:space:]]*linux' "$TMP/raw")
        la=$(grep -E '^[[:space:]]*linux' "$TMP/raw" | grep -c -E '(^|[[:space:]])audit=1([[:space:]]|$)')
        printf '{"exists": true, "pbkdf2_entries": %s, "plain_password_entries": %s, "superusers_lines": %s, "linux_lines": %s, "linux_lines_audit1": %s}' \
            "$pb" "$pl" "$su" "$ll" "$la" > "$TMP/val"
        : > "$TMP/raw"
        ok grub_cfg "$cmd"
    fi
    file_fact default_grub /etc/default/grub 'GRUB_CMDLINE_LINUX'

    if run cat /proc/cmdline; then text_fact proc_cmdline "cat /proc/cmdline"; else unavail proc_cmdline "cat /proc/cmdline" "$(err_line)"; fi
}

collect_users() {
    cmd="awk -F: count of accounts and of empty password fields in /etc/shadow"
    if awk -F: '{ a++ } $2 == "" { e++ } END { printf "{\"accounts\": %d, \"empty_password\": %d}", a, e }' /etc/shadow > "$TMP/val" 2> "$TMP/err"; then
        ok shadow "$cmd"
    else
        unavail shadow "$cmd" "$(err_line)"
    fi

    cmd="passwd -S root"
    if ! have passwd; then
        unavail root_password_status "$cmd" "passwd not found"
    elif [ "$IS_ROOT" -ne 1 ]; then
        needs_root root_password_status "$cmd"
    elif run passwd -S root; then
        text_fact root_password_status "$cmd"
    else
        unavail root_password_status "$cmd" "$(err_line)"
    fi

    cmd="awk -F: '{print \$1\":\"\$3\":\"\$4\":\"\$7}' /etc/passwd"
    if awk -F: -v r="$REDACT" '{ n = $1; if (r == 1 && $3 >= 1000 && $3 != 65534) { k++; n = "account-" k } print n ":" $3 ":" $4 ":" $7 }' /etc/passwd > "$TMP/out" 2> "$TMP/err"; then
        text_fact passwd_accounts "$cmd"
    else
        unavail passwd_accounts "$cmd" "$(err_line)"
    fi

    cmd="grep '^sudo:' /etc/group (members)"
    if awk -F: -v r="$REDACT" '
        $1 == "sudo" { found = 1; m = $4
            if (r == 1) { n = split($4, a, ","); m = ""
                for (i = 1; i <= n; i++) if (a[i] != "") m = m (m == "" ? "" : ",") "account-" i }
            print m }
        END { if (!found) exit 3 }' /etc/group > "$TMP/out" 2> "$TMP/err"; then
        { printf '{"exists": true, "text": '; jstr < "$TMP/out"; printf '}'; } > "$TMP/val"
        ok group_sudo "$cmd"
    elif [ -r /etc/group ]; then
        printf '{"exists": false, "text": null}' > "$TMP/val"
        ok group_sudo "$cmd"
    else
        unavail group_sudo "$cmd" "$(err_line)"
    fi

    cmd="grep -iwE 'NOPASSWD|!authenticate|ALL' /etc/sudoers /etc/sudoers.d/*"
    KEEP_INCLUDE=1
    if ! dir_ok /etc/sudoers.d; then
        unavail sudoers "$cmd" "$REASON"
    elif lines_value '' /etc/sudoers /etc/sudoers.d/*; then
        # keep the matching lines and the include directives (#include is not a comment in
        # sudoers); with -r replace the user or group field
        awk -F'\t' -v r="$REDACT" '
            { line = $2 }
            line ~ /^[[:space:]]*[@#]include/ { print $1 "\t" line; next }
            tolower(line) ~ /nopasswd|!authenticate/ || line ~ /(^|[^A-Za-z0-9_])ALL([^A-Za-z0-9_]|$)/ {
                if (r == 1) {
                    split(line, w, /[[:space:]]+/)
                    first = w[1]
                    if (first != "ALL" && first !~ /^Defaults/ && first !~ /_Alias$/ && first !~ /^[@#]include/) {
                        k++; sub(/^[^[:space:]]+/, "account-" k, line)
                    }
                }
                print $1 "\t" line
            }' "$TMP/lines" > "$TMP/flt"
        { printf '{"files": '; json_array < "$TMP/flist"; printf ', "text": '; jstr < "$TMP/flt"; printf '}'; } > "$TMP/val"
        ok sudoers "$cmd"
    else
        unavail sudoers "$cmd" "$REASON"
    fi
    KEEP_INCLUDE=0
}

collect_audit() {
    file_fact auditd_conf /etc/audit/auditd.conf

    for spec in "audit_rules:-l" "audit_status:-s"; do
        id=${spec%%:*}
        flag=${spec#*:}
        cmd="auditctl $flag"
        if ! have auditctl; then
            unavail "$id" "$cmd" "auditctl not found (auditd not installed)"
        elif [ "$IS_ROOT" -ne 1 ]; then
            needs_root "$id" "$cmd"
        elif run auditctl "$flag"; then
            text_fact "$id" "$cmd"
        else
            unavail "$id" "$cmd" "$(err_line)"
        fi
    done

    cmd="grep '^-e' /etc/audit/rules.d/*.rules"
    if dir_ok /etc/audit/rules.d && lines_value '^-e' /etc/audit/rules.d/*.rules; then
        ok audit_rules_d "$cmd"
    else
        unavail audit_rules_d "$cmd" "$REASON"
    fi

    cmd="find <path> -maxdepth 0 -printf '%m %u %g %y %p' for /etc/audit/audit.rules, /etc/audit/auditd.conf, /etc/audit/rules.d/*, the log_file directory and its files"
    conf=/etc/audit/auditd.conf
    if [ ! -e "$conf" ]; then
        unavail audit_paths "$cmd" "$conf not found (auditd not installed)"
    elif ! cat "$conf" > "$TMP/raw" 2> "$TMP/err"; then
        unavail audit_paths "$cmd" "cannot read $conf: $(err_line)"
    else
        logfile=$(awk -F= '/^[[:space:]]*log_file[[:space:]]*=/ { v = $2; gsub(/^[[:space:]]+|[[:space:]]+$/, "", v) } END { print v }' "$TMP/raw")
        [ -n "$logfile" ] || logfile=/var/log/audit/audit.log
        logdir=$(dirname "$logfile")
        if ! dir_ok /etc/audit/rules.d "$logdir"; then
            unavail audit_paths "$cmd" "$REASON"
        else
            : > "$TMP/err"
            {
                stat_line conf /etc/audit/audit.rules
                stat_line conf /etc/audit/auditd.conf
                for f in /etc/audit/rules.d/*; do [ -e "$f" ] && stat_line conf "$f"; done
                stat_line logdir "$logdir"
                for f in "$logdir"/*; do [ -f "$f" ] && stat_line logfile "$f"; done
            } > "$TMP/out"
            if [ -s "$TMP/err" ]; then
                unavail audit_paths "$cmd" "$(err_line)"
            else
                text_fact audit_paths "$cmd"
            fi
        fi
    fi

    cmd="cat /etc/audit/plugins.d/au-remote.conf /etc/audit/audisp-remote.conf"
    REASON=""
    if file_value /etc/audit/plugins.d/au-remote.conf && cat "$TMP/val" > "$TMP/val.plugin" \
        && file_value /etc/audit/audisp-remote.conf; then
        { printf '{"plugin": '; cat "$TMP/val.plugin"; printf ', "remote": '; cat "$TMP/val"; printf '}'; } > "$TMP/val.ar"
        cat "$TMP/val.ar" > "$TMP/val"
        ok audit_remote "$cmd"
    else
        unavail audit_remote "$cmd" "${REASON:-cannot read the audit remote configuration}"
    fi
}

collect_paths() {
    cmd="find <path> -maxdepth 0 -printf '%m %u %g %y %p' for /var/log, /var/log/syslog, /usr/bin/journalctl and the audit tools in /sbin"
    : > "$TMP/err"
    {
        stat_line var_log /var/log
        stat_line syslog /var/log/syslog
        stat_line journalctl /usr/bin/journalctl
        for t in auditctl aureport ausearch autrace auditd augenrules; do stat_line audit_tool "/sbin/$t"; done
        for t in /sbin/audisp*; do [ -e "$t" ] && stat_line audit_tool "$t"; done
    } > "$TMP/out"
    if [ -s "$TMP/err" ]; then unavail path_stats "$cmd" "$(err_line)"; else text_fact path_stats "$cmd"; fi

    CMD_DIRS=$(existing /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin)
    LIB_DIRS=$(existing /lib /lib64 /usr/lib /usr/lib64)
    LIBD_DIRS=$(existing /lib /usr/lib /lib64)
    P="-printf %m\t%u\t%g\t%p\n"
    # shellcheck disable=SC2086
    {
        find_fact cmd_dirs_writable "find $CMD_DIRS -perm /022 -type d" $CMD_DIRS -perm /022 -type d $P
        find_fact cmd_files_writable "find $CMD_DIRS -perm /022 -type f" $CMD_DIRS -perm /022 -type f $P
        find_fact lib_files_writable "find $LIB_DIRS -type f -name '*.so*' -perm /022" $LIB_DIRS -type f -name '*.so*' -perm /022 $P
        find_fact cmd_dirs_owner "find $CMD_DIRS ! -user root -type d" $CMD_DIRS ! -user root -type d $P
        find_fact cmd_dirs_group "find $CMD_DIRS ! -group root -type d" $CMD_DIRS ! -group root -type d $P
        find_fact cmd_files_owner "find $CMD_DIRS ! -user root -type f" $CMD_DIRS ! -user root -type f $P
        find_fact cmd_files_group "find -L $CMD_DIRS ! -group root -type f ! -perm /2000" -L $CMD_DIRS ! -group root -type f ! -perm /2000 $P
        find_fact lib_dirs_owner "find $LIBD_DIRS ! -user root -type d" $LIBD_DIRS ! -user root -type d $P
        find_fact lib_dirs_group "find $LIBD_DIRS ! -group root -type d" $LIBD_DIRS ! -group root -type d $P
        find_fact lib_files_owner "find $LIB_DIRS -type f -name '*.so*' ! -user root" $LIB_DIRS -type f -name '*.so*' ! -user root $P
        find_fact lib_files_group "find $LIB_DIRS -type f -name '*.so*' ! -group root" $LIB_DIRS -type f -name '*.so*' ! -group root $P
        find_fact var_log_files "find /var/log -perm /137 ! -name '*[bw]tmp' ! -name '*lastlog' ! -name history.log ! -name eipp.log.xz -type f" \
            /var/log -perm /137 ! -name '*[bw]tmp' ! -name '*lastlog' ! -name history.log ! -name eipp.log.xz -type f $P
    }

    LOCAL_MOUNTS=$(awk '$3 ~ /^(ext2|ext3|ext4|xfs|btrfs|tmpfs|vfat|f2fs|zfs)$/ && $2 !~ /\\/ { print $2 }' /proc/mounts 2>/dev/null | sort -u | tr '\n' ' ')
    if [ -z "$LOCAL_MOUNTS" ]; then
        unavail public_dirs "find <local mounts> -xdev -type d -perm -0002 ! -perm -1000" "no local filesystems found in /proc/mounts"
    else
        # shellcheck disable=SC2086
        find_fact public_dirs "find $LOCAL_MOUNTS -xdev -type d -perm -0002 ! -perm -1000" \
            $LOCAL_MOUNTS -xdev -type d -perm -0002 ! -perm -1000 $P
    fi

    JOURNAL_DIRS=$(existing /run/log/journal /var/log/journal)
    cmd="find /run/log/journal /var/log/journal -printf '%m %u %g %y %p'"
    if [ -z "$JOURNAL_DIRS" ]; then
        printf '{"complete": true, "count": 0, "sample": "", "error": null}' > "$TMP/val"
        ok journal_entries "$cmd"
    else
        FIND_SAMPLE=5000
        # shellcheck disable=SC2086
        find_fact journal_entries "$cmd" $JOURNAL_DIRS -printf '%m\t%u\t%g\t%y\t%p\n'
        FIND_SAMPLE=50
    fi
}

collect_time() {
    cmd="timedatectl show"
    if ! have timedatectl; then
        unavail timedatectl "$cmd" "timedatectl not found"
    elif run timedatectl show; then
        text_fact timedatectl "$cmd"
    else
        unavail timedatectl "$cmd" "$(err_line)"
    fi

    cmd="grep -E 'server|pool|peer|makestep' /etc/chrony/chrony.conf /etc/chrony/conf.d/*.conf /etc/chrony/sources.d/*.sources"
    if dir_ok /etc/chrony /etc/chrony/conf.d /etc/chrony/sources.d \
        && lines_value '^[[:space:]]*(server|pool|peer|makestep)' /etc/chrony/chrony.conf \
            /etc/chrony/conf.d/*.conf /etc/chrony/sources.d/*.sources; then
        ok chrony_conf "$cmd"
    else
        unavail chrony_conf "$cmd" "$REASON"
    fi
}

collect_security_services() {
    cmd="ufw status"
    if ! have ufw; then
        printf '{"installed": false, "text": null}' > "$TMP/val"
        ok ufw_status "command -v ufw (not found)"
    elif [ "$IS_ROOT" -ne 1 ]; then
        needs_root ufw_status "$cmd"
    else
        run ufw status
        { printf '{"installed": true, "text": '; cat "$TMP/out" "$TMP/err" | jstr; printf '}'; } > "$TMP/val"
        ok ufw_status "$cmd"
    fi

    cmd="aa-status"
    if ! have aa-status; then
        unavail apparmor_status "$cmd" "aa-status not found (apparmor not installed)"
    elif [ "$IS_ROOT" -ne 1 ]; then
        needs_root apparmor_status "$cmd"
    else
        run aa-status
        rc=$?
        if [ "$rc" -le 2 ]; then text_fact apparmor_status "$cmd"; else unavail apparmor_status "$cmd" "$(err_line "$rc")"; fi
    fi

    cmd="sha1sum /etc/cron.daily/aide /etc/cron.monthly/aide /usr/share/aide/config/cron.daily/aide; md5sum of the latter; its md5 in /var/lib/dpkg/info/aide-common.md5sums"
    : > "$TMP/out"
    aide_err=""
    for f in /etc/cron.daily/aide /etc/cron.monthly/aide; do
        if [ -f "$f" ]; then
            if s=$(sha1sum < "$f" 2> "$TMP/err" | cut -d' ' -f1) && [ -n "$s" ]; then
                printf '%s\t%s\n' "$f" "$s" >> "$TMP/out"
            else
                aide_err="cannot read $f"
            fi
        fi
    done
    shipped=/usr/share/aide/config/cron.daily/aide
    s1="" m5="" dm=""
    if [ -f "$shipped" ]; then
        s1=$(sha1sum < "$shipped" 2>/dev/null | cut -d' ' -f1)
        m5=$(md5sum < "$shipped" 2>/dev/null | cut -d' ' -f1)
    fi
    if [ -f /var/lib/dpkg/info/aide-common.md5sums ]; then
        dm=$(awk '$2 == "usr/share/aide/config/cron.daily/aide" { print $1 }' /var/lib/dpkg/info/aide-common.md5sums 2>/dev/null)
    fi
    if [ -n "$aide_err" ]; then
        unavail aide_cron "$cmd" "$aide_err"
    else
        {
            printf '{"cron": '; jstr < "$TMP/out"
            for pair in "shipped_sha1:$s1" "shipped_md5:$m5" "dpkg_md5:$dm"; do
                printf ', "%s": ' "${pair%%:*}"
                v=${pair#*:}
                if [ -n "$v" ]; then jstr_s "$v"; else printf 'null'; fi
            done
            printf '}'
        } > "$TMP/val"
        ok aide_cron "$cmd"
    fi

    file_fact aide_conf /etc/aide/aide.conf '/sbin/(audit|au)'
}

collect_gui() {
    file_fact gdm_greeter /etc/gdm3/greeter.dconf-defaults

    cmd="gsettings get <schema> <key> for media-keys logout, screensaver lock-enabled and lock-delay, session idle-delay"
    if ! have gsettings; then
        unavail gsettings "$cmd" "gsettings not found (no GNOME settings installed)"
        return
    fi
    first=1
    {
        printf '{'
        for pair in "org.gnome.settings-daemon.plugins.media-keys logout" \
                    "org.gnome.desktop.screensaver lock-enabled" \
                    "org.gnome.desktop.screensaver lock-delay" \
                    "org.gnome.desktop.session idle-delay"; do
            # shellcheck disable=SC2086
            gsettings get $pair > "$TMP/gs.out" 2> "$TMP/gs.err"
            rc=$?
            gs_ok=false
            if [ "$rc" -eq 0 ] && ! grep -q -i "memory" "$TMP/gs.err"; then gs_ok=true; fi
            if [ "$first" -eq 0 ]; then printf ', '; fi
            first=0
            jstr_s "$pair"
            printf ': {"ok": %s, "output": ' "$gs_ok"
            cat "$TMP/gs.out" "$TMP/gs.err" | head -n 3 | jstr
            printf '}'
        done
        printf '}'
    } > "$TMP/val"
    ok gsettings "$cmd"
}

collect_hardware() {
    cmd="dmesg | grep -i 'execute disable'"
    if ! have dmesg; then
        unavail dmesg_nx "$cmd" "dmesg not found"
    elif run dmesg; then
        grep -i 'execute disable' "$TMP/out" > "$TMP/flt" || true
        cat "$TMP/flt" > "$TMP/out"
        text_fact dmesg_nx "$cmd"
    else
        unavail dmesg_nx "$cmd" "$(err_line)"
    fi

    cmd="grep flags /proc/cpuinfo | grep -o -w nx"
    if [ ! -r /proc/cpuinfo ]; then
        unavail cpu_flags "$cmd" "/proc/cpuinfo not readable"
    elif ! grep -q '^flags' /proc/cpuinfo; then
        unavail cpu_flags "$cmd" "/proc/cpuinfo has no x86 flags line"
    else
        awk '/^flags/ { for (i = 1; i <= NF; i++) if ($i == "nx") f = 1 } END { if (f) print "nx" }' /proc/cpuinfo > "$TMP/out"
        text_fact cpu_flags "$cmd"
    fi

    file_fact wireless /proc/net/wireless

    cmd="lsblk -P -p -o NAME,TYPE,FSTYPE,MOUNTPOINT,PKNAME"
    if ! have lsblk; then
        unavail block_devices "$cmd" "lsblk not found"
    elif run lsblk -P -p -o NAME,TYPE,FSTYPE,MOUNTPOINT,PKNAME; then
        text_fact block_devices "$cmd"
    else
        unavail block_devices "$cmd" "$(err_line)"
    fi
    file_fact crypttab /etc/crypttab
}

# write_output: $TMP/result.json -> $OUT. Drops any bytes that are not valid UTF-8 so
# the file is always valid JSON text. iconv -c exits 1 when it dropped something, so the
# cleaned output is used whenever it is non-empty, and the envelope's utf8_bytes_dropped
# placeholder becomes true, false, or null when iconv is missing.
write_output() {
    DROPPED=null
    cat "$TMP/result.json" > "$TMP/final.json"
    if have iconv; then
        iconv -c -f UTF-8 -t UTF-8 < "$TMP/result.json" > "$TMP/clean.json" 2>/dev/null
        if [ -s "$TMP/clean.json" ]; then
            DROPPED=false
            if [ "$(wc -c < "$TMP/clean.json")" -ne "$(wc -c < "$TMP/result.json")" ]; then DROPPED=true; fi
            cat "$TMP/clean.json" > "$TMP/final.json"
        fi
    fi
    if ! awk -v d="$DROPPED" '!done && $0 == "  \"utf8_bytes_dropped\": UTF8_PLACEHOLDER," {
            print "  \"utf8_bytes_dropped\": " d ","; done = 1; next } { print }' \
            "$TMP/final.json" > "$OUT"; then
        echo "error: cannot write $OUT" >&2
        return 1
    fi
}

# --------------------------------------------------------------------------- run

collect_release
collect_packages
collect_units
collect_ssh
collect_sysctl
collect_accounts_config
collect_boot
collect_users
collect_audit
collect_paths
collect_time
collect_security_services
collect_gui
collect_hardware

NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
PRETTY=$(awk -F= '$1 == "PRETTY_NAME" { v = $2; gsub(/^"|"$/, "", v); print v }' /etc/os-release 2>/dev/null)
KERNEL=$(uname -r 2>/dev/null)
VIRT=$(systemd-detect-virt 2>/dev/null)
[ -n "$VIRT" ] || VIRT=unknown
PRIV=false
[ "$IS_ROOT" -eq 1 ] && PRIV=true
RED=false
[ "$REDACT" -eq 1 ] && RED=true

{
    printf '{\n  "collector": "linux",\n  "version": 1,\n  "collected_at": "%s",\n' "$NOW"
    printf '  "privileged": %s,\n  "redacted": %s,\n  "escaper": "%s",\n' "$PRIV" "$RED" "$ESCAPER"
    printf '  "utf8_bytes_dropped": UTF8_PLACEHOLDER,\n'
    printf '  "host": {"name": '; jstr_s "$HOST"
    printf ', "os_release": '; jstr_s "$PRETTY"
    printf ', "kernel": '; jstr_s "$KERNEL"
    printf ', "virtualization": '; jstr_s "$VIRT"
    printf '},\n  "facts": {\n'
    cat "$FACTS"
    printf '\n  }\n}\n'
} > "$TMP/result.json"

write_output || exit 1

echo "wrote $OUT: $NFACT facts, $NUNAVAIL unavailable$( [ "$IS_ROOT" -eq 1 ] || printf ' (not run as root)')" >&2
