# Decisions

## Sources and verified facts

Verified 2026-11-10. Where a source could not be reached, that is stated; nothing below is cited from memory.

### 1. Current DISA benchmark releases

Located by probing the public DISA download host directly (the library page at https://www.cyber.mil/stigs/downloads/ is rendered by JavaScript and returned no listing to automated clients). The package names follow DISA's `U_<product>_V<v>R<r>_STIG.zip` pattern; a request for the next release of each returned HTTP 404 on 2026-11-10, so these are the newest published packages.

| Benchmark | Version | Release | Benchmark date | XCCDF status date | Download |
|---|---|---|---|---|---|
| Canonical Ubuntu 22.04 LTS STIG (`CAN_Ubuntu_22-04_LTS_STIG`) | 2 | 10 | 30 Sep 2026 | 2026-09-09 | https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CAN_Ubuntu_22-04_LTS_V2R10_STIG.zip |
| Microsoft Windows Server 2022 STIG (`MS_Windows_Server_2022_STIG`) | 2 | 11 | 30 Sep 2026 | 2026-08-19 | https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2022_V2R11_STIG.zip |

Version, release and benchmark date were read from the downloaded XCCDF files themselves (`<version>`, `<plain-text id="release-info">`, `<status date>`) and cross-checked against the Ubuntu Overview PDF cover ("Version 2, Release 10, 30 September 2026").

Rule counts from the XCCDF (the numbers Task 2 must reproduce):

| Benchmark | Rules | CAT I (high) | CAT II (medium) | CAT III (low) |
|---|---|---|---|---|
| Ubuntu 22.04 V2R10 | 191 | 16 | 158 | 17 |
| Windows Server 2022 V2R11 | 277 | 31 | 235 | 11 |

Package SHA-256 (as downloaded 2026-11-10): Ubuntu `2229b5be3224000e92b4ca2feac688ecd7990a3046971a6c1077e617d1bf398a`, Windows `808e83970c4f27590f31435856be9810e02d8f72d3c0a67c0a195cae46dbf48e`.

XCCDF identity mapping (XCCDF 1.1, namespace `http://checklists.nist.gov/xccdf/1.1`): `Group@id` is the Group ID (`V-260469`); `Rule@id` is the Rule ID (`SV-260469r1268251_rule`); `Rule/version` is the STIG ID (`UBTU-22-211015`); `Rule@severity` is high/medium/low; `Rule/ident` with system `http://cyber.mil/cci` holds the CCI.

Other versions seen in third-party listings (not used): NIST NCP lists Ubuntu 22.04 "Ver 2, Rel 9" (https://ncp.nist.gov/checklist/revision/6873); search results also mention Rel 6 and Rel 8. All are older than the DISA package above. The NCP pages are JavaScript-rendered and could not be read directly.

### 2. Distribution statement and redistribution

NOT CONFIRMED. No explicit "Distribution Statement A" (or any other distribution statement) was found.

What was checked:
- Both packages (XCCDF, Overview PDF, Revision History PDF, SRG/STIG Readme PDF; the Ubuntu release memo too) were searched for "distribution statement", "approved for public release", "redistribut", "copyright" and "terms of use". None appear. The documents are marked only "UNCLASSIFIED". The XCCDF contains an empty `<notice id="terms-of-use">` element.
- The Overview PDFs (section 1.4 "STIG Distribution") say DoW/federal parties obtain STIGs from https://cyber.mil/ and that those without a common access card (CAC) can obtain them from https://public.cyber.mil/. That establishes public availability, not a redistribution licence.
- The packages download without authentication from `dl.dod.cyber.mil`.
- DoD Cyber Exchange FAQ and terms pages (https://www.cyber.mil/stigs/faqs, https://www.cyber.mil/terms-of-use, https://www.cyber.mil/?p=456) were fetched but are JavaScript-rendered shells ("Welcome to LWC Communities!"); no text could be read. A web search found no DISA statement on redistribution.

Decision: see "Benchmark content" below (controller ruling supersedes the earlier conservative default).

### 3. STIG Viewer 2 `.ckl` structure (XML)

Sources: published STIG Viewer 2 format samples, https://raw.githubusercontent.com/NUWCDIVNPT/stig-manager/main/docs/STIG-Manager-OSS.ckl (STIG Manager, MIT) and https://raw.githubusercontent.com/NUWCDIVNPT/stig-manager-client-modules/main/test-files/parsers/ckl/Asset_a-VPN_TRUNCATED-V2R5.ckl (MIT; the same folder has the matching `.cklb`). DISA's STIG Viewer 3.x User Guide V1R7 (13 Feb 2026), https://dl.dod.cyber.mil/wp-content/uploads/stigs/pdf/U_STIG_Viewer_3-x_User_Guide_V1R7.pdf, confirms "CKL (SV v2 format)" and "CKLB" as export formats but does not publish the XML layout. DISA's own `.ckl` schema was not reachable.

Layout observed in those samples:
- `CHECKLIST` root with children `ASSET` and `STIGS`.
- `ASSET`: `ROLE, ASSET_TYPE, MARKING, HOST_NAME, HOST_IP, HOST_MAC, HOST_GUID, HOST_FQDN, TECH_AREA, TARGET_KEY, WEB_OR_DATABASE, WEB_DB_SITE, WEB_DB_INSTANCE`.
- `STIGS` contains one `iSTIG` per STIG; each has `STIG_INFO` then `VULN` elements.
- `STIG_INFO` contains `SI_DATA` elements, each `SID_NAME` plus optional `SID_DATA`. Names seen: `version, classification, customname, stigid, description, filename, releaseinfo, title, uuid, notice, source`.
- `VULN` contains `STIG_DATA` elements (`VULN_ATTRIBUTE` + `ATTRIBUTE_DATA`), then `STATUS, FINDING_DETAILS, COMMENTS, SEVERITY_OVERRIDE, SEVERITY_JUSTIFICATION`.
- `VULN_ATTRIBUTE` names seen: `Vuln_Num` (Group ID), `Severity`, `Group_Title`, `Rule_ID` (the `SV-..._rule` ID), `Rule_Ver` (the STIG ID), `Rule_Title`, `Vuln_Discuss`, `IA_Controls`, `Check_Content`, `Fix_Text`, `False_Positives`, `False_Negatives`, `Documentable`, `Mitigations`, `Potential_Impact`, `Third_Party_Tools`, `Mitigation_Control`, `Responsibility`, `Security_Override_Guidance`, `STIGRef`, `CCI_REF` (repeated per CCI), plus `Weight` in the STIG Manager samples.

The samples are third-party writers of the format, not DISA artifacts; Task 7 tests should assert against this structure.

### 4. STIG Viewer 3 `.cklb` structure (JSON)

Source: the published sample https://raw.githubusercontent.com/NUWCDIVNPT/stig-manager-client-modules/main/test-files/parsers/ckl/Asset_a-VPN_TRUNCATED-V2R5.cklb (MIT), parsed directly. DISA's "Stig Viewer 3 CKLB JSON Schema" is listed on https://public.cyber.mil/stigs/srg-stig-tools (per search results), but that page is JavaScript-rendered and the schema file could not be reached. DISA's User Guide V1R7 mentions CKLB only as an import/export format.

- Top level: `title, id (uuid), active (bool), mode (int), has_path (bool), target_data, stigs`.
- `target_data`: `target_type, host_name, ip_address, mac_address, fqdn, comments, role, is_web_database, technology_area, web_db_site, web_db_instance`.
- `stigs[]`: `stig_name, display_name, stig_id, version (int), release_info ("Release: 5 Benchmark Date: 07 Jun 2023"), uuid, reference_identifier, size, rules[]`.
- `rules[]`: `uuid, stig_uuid, target_key, stig_ref, group_id, rule_id, rule_id_src, weight, classification, severity, rule_version (the STIG ID), group_title, rule_title, fix_text, false_positives, false_negatives, discussion, check_content, documentable, mitigations, potential_impacts, third_party_tools, mitigation_control, responsibility, security_override_guidance, ia_controls, check_content_ref {href, name}, legacy_ids, group_tree [{id, title, description}], createdAt, updatedAt, STIGUuid, status, overrides, comments, finding_details, ccis`.
- `rule_id` omits the `_rule` suffix; `rule_id_src` includes it.

### 5. Status vocabulary

- Meaning, from DISA's STIG Viewer 3.x User Guide V1R7, section 5.4.1 "Changing the Status of Rules": a rule can be marked Open, Not A Finding, Not Reviewed or Not Applicable; the default state is Not Reviewed. The guide's import section accepts "Open, Not A Finding, Not Applicable, or Not Reviewed (case-insensitive)". The guide gives no prose definitions beyond the names and icons.
- `.ckl` `STATUS` values observed in the published samples: `Open`, `NotAFinding`, `Not_Applicable`, `Not_Reviewed`.
- `.cklb` `status` values observed in the published sample: `open`, `not_a_finding`, `not_applicable`, `not_reviewed` (the sample contained all four).
- STIGWatch semantics (project decision, consistent with the plan's no-overclaiming rule): Open = facts show the check text is failed; Not a Finding = facts fully prove the check text is met; Not Applicable = a gathered fact proves non-applicability; Not Reviewed = facts unreadable, insufficient, or the rule is manual.

## Project decisions

- The local venv uses Python 3.14; code targets `>=3.12` and CI uses 3.12.
- The CI backend job runs on `ubuntu-22.04` per the plan. The Windows runner job arrives with Task 4. The frontend job is inherited from the CMMC Ready skeleton and passes once Task 9 adds `package.json`; the `benchmarks --check` step passes once Task 2 implements it.
- Dependabot lists the root pip and npm ecosystems ahead of the Vercel function and frontend (Tasks 9 and 11).

## Benchmark content (Task 2)

- **Redistribution.** No distribution statement was found (section 2), so the controller ruled to commit the full rule text: title, discussion (VulnDiscussion), check text, fix text, CCIs, severity and all IDs. Reasoning: DISA STIGs are works of the U.S. Government (17 U.S.C. 105 gives no copyright in them) and are published for unrestricted public download from the DoD Cyber Exchange. Each catalog file carries the DISA title, version, release, benchmark date, the download URL and the SHA-256 of the source zip. Content is reproduced unmodified apart from whitespace normalisation (CRLF to LF, trailing spaces removed, outer whitespace trimmed) and attributed to DISA. This is a project decision, not legal advice; if DISA states otherwise, set `metadata_only` and rebuild (the catalog supports metadata-only files).
- **Catalog files.** `backend/data/benchmarks/ubuntu-22.04.json` (Canonical Ubuntu 22.04 LTS STIG V2R10, 191 rules) and `windows-server-2022.json` (Microsoft Windows Server 2022 STIG V2R11, 277 rules). Benchmark ids `ubuntu-22.04` and `windows-server-2022` are the stable keys used by the rest of the app. Rules keep XCCDF order. Recorded counts per severity match the rules.
- **Parsing.** XCCDF is untrusted: defusedxml with DTDs refused, read from the zip in memory with size limits, nothing extracted. The embedded escaped description markup is unescaped and parsed the same way to extract `VulnDiscussion`.
- **Verification.** `python -m stigwatch benchmarks --check` validates the committed JSON (required fields, unique Group/Rule/STIG IDs, recorded counts equal to the rules, check and fix text present unless `metadata_only`). CI runs this because it cannot download the zips. Maintainers run `python scripts/build_benchmarks.py --check ZIP...` locally to rebuild from the official zips and compare byte for byte with the committed JSON.
- **Newer releases.** `python -m stigwatch benchmarks import FILE.zip [--out DIR] [--source-url URL]` parses a DISA STIG zip and writes `<benchmark_id>.json` into `$STIGWATCH_DATA_DIR/benchmarks` (default `~/.stigwatch/benchmarks`). A locally imported file with the same id overrides the bundled one; unrelated products are imported under an id derived from the XCCDF Benchmark id.

## Ubuntu collector and checks (Task 3)

### Engine

- `backend/stigwatch/checks/engine.py` is a port of CMMC Ready's evidence engine and is collector-agnostic: a collector module (`stigwatch/facts/linux.py`, later `windows.py`) supplies `validate()`, `facts()` (normalised facts, each `ok` or `unavailable` with the command it ran) and optional operators; a YAML checks file per benchmark (`checks/linux.yml`) supplies the rules. CMMC Ready's `met_if` / `unmet_if` / `fail_result` / `met_result` became `logic` / `unmet_if` / `result_if_false` / `result_if_true`; `na_if` is new.
- Conditions are tri-state. A fact that was not read, or a value the parser could not interpret, is unknown and never decides a rule. A setting that is absent (file missing, directive missing or commented out) is `null` ("not configured") and fails a requirement, because the check texts treat "missing or commented out" as a finding. A directive given more than once with different values is `null` with `conflict: true` (the check texts call conflicting results a finding).
- Order per rule: `na_if` true gives Not_Applicable, and the reason names the fact; `na_if` unknown gives Not_Reviewed (applicability unproven, so neither a finding nor a pass is claimed); then `logic` true gives NotAFinding (or Not_Reviewed for evidence-only results); `logic` false gives Open, or Not_Reviewed when an `unmet_if` is given and is not proven; `logic` unknown gives Not_Reviewed naming each unreadable fact, its reason and its command. Rules without a check are Not_Reviewed "Manual review". An exception during evaluation gives Not_Reviewed.
- A readable fact can prove a finding even when another fact of the same rule is unreadable (for example UBTU-22-654240 is Open on a host without `-e 2` in rules.d even when `auditctl -s` is unavailable), because each "If ..., this is a finding" clause of the check text stands alone. A finding is never derived from an unreadable fact.
- Status strings follow the `.ckl` vocabulary: `Open`, `NotAFinding`, `Not_Applicable`, `Not_Reviewed`.
- The YAML operator for "is not set" is `unset`, not `null` (YAML parses a `null:` key as None).

### Interpretations of the Ubuntu 22.04 V2R10 check texts

- **Documented exceptions.** Where the check text excuses a setting "if documented with the ISSO" (X11Forwarding, NOPASSWD, kdump-tools, wireless, nfs-kernel-server, disk encryption), the host cannot show the documentation, so the result is Open and the rationale says so; the assessor records the exception.
- **Judgements the host cannot make** give partial checks (one decisive outcome, Not_Reviewed otherwise): UBTU-22-432015 sudo group membership (an empty group is NotAFinding, otherwise the members are listed for review); UBTU-22-211000 vendor support (see below); UBTU-22-252010 authoritative DoD time source; UBTU-22-653020 remote audit server; UBTU-22-653025 the ISSO's mail address; UBTU-22-651010 and UBTU-22-251010 ("ask the administrator about another tool"); UBTU-22-232045, 232050 and 232055 ("required system account" owners).
- **sshd settings** are read from `/etc/ssh/sshd_config` and `/etc/ssh/sshd_config.d/*.conf`, as the check texts grep the files sshd parses; `sshd -T` is collected as supporting evidence only. A directive inside a `Match` block counts towards conflicting results. An `Include` of anything other than files matching `/etc/ssh/sshd_config.d/*.conf` (relative paths resolve in /etc/ssh) makes the whole sshd configuration unknown, so the SSH rules are Not_Reviewed.
- **UBTU-22-611060** counts every active (not commented-out) line of common-auth and common-password that contains `nullok`, whatever the case of the PAM type or whether the line parses, as the check text's grep does; only commented-out lines are excluded.
- **UBTU-22-215025** checks the package named `ntp`, not every package whose name contains "ntp" (`dpkg -l | grep ntp` would also match ntpsec, ntpdate and others).
- **UBTU-22-411030**: the check text calls PASS_MAX_DAYS "less than 180" a finding while the title requires a 180-day maximum. Only 180 satisfies both readings (NotAFinding); missing is Open; any other value is Not_Reviewed.
- **UBTU-22-411035** requires INACTIVE 35. -1, missing or longer is Open; a shorter period (which the check text also flags) is Not_Reviewed.
- **UBTU-22-255035**: ClientAliveInterval 1 to 600 is NotAFinding, over 600 or missing is Open; 0 (which disables the timeout but is literally "600 or less") is Not_Reviewed. **UBTU-22-411045**: `deny = 0` is Not_Reviewed for the same reason.
- **Banners** (UBTU-22-255020, 271015) are compared with the Standard Mandatory DoD Notice and Consent Banner ignoring whitespace (the two check texts themselves wrap and space it differently). A test asserts the constant is contained in both check texts.
- **UBTU-22-231010** uses the `lsblk` device tree: every mounted filesystem and swap except /boot and /boot/efi (loop and rom devices excluded) must sit on a dm-crypt device; an unencrypted mount is Open; a formatted, unmounted, unencrypted partition makes the result Not_Reviewed.
- **UBTU-22-651025** compares the SHA-1 of /etc/cron.{daily,monthly}/aide with the packaged original `/usr/share/aide/config/cron.daily/aide` already on the host, after checking that copy against the md5sum dpkg recorded for aide-common. This replaces the check text's `apt download` (the collector downloads nothing). If the packaged copy cannot be verified the result is Not_Reviewed.
- **UBTU-22-211000**: Canonical lists standard security maintenance for 22.04 until "May 2027" (https://ubuntu.com/about/release-cycle, read 2026-11-10). A 22.04 host collected on or before 2027-04-30 is NotAFinding; later, support depends on Ubuntu Pro ESM, which is not collected, so the result is Not_Reviewed.
- **UBTU-22-232025**: the check text makes the rule not applicable when rsyslog is active and enabled; the engine applies that note literally.
- **UBTU-22-631015** is Not_Applicable only when neither libpam-pkcs11 nor libpam-sss is installed and common-auth uses neither pam_pkcs11 nor pam_sss: with no smart-card PAM module, smart-card authentication cannot be in use.
- **GUI rules** (UBTU-22-271010 to 271030) are Not_Applicable when none of these packages is installed: xserver-xorg-core, xwayland, gnome-shell, gdm3, lightdm, sddm, ubuntu-desktop, xfce4-session, mate-session-manager, cinnamon-session, plasma-workspace. A half-installed package or an unreadable package database leaves applicability unknown (Not_Reviewed). gsettings values read through GLib's "memory" fallback backend are discarded.
- **UBTU-22-213025** is NotAFinding when dmesg reports NX active or /proc/cpuinfo has the nx flag, and Open only when the CPU flags were read and lack nx. Non-x86 CPUs give Not_Reviewed.
- **Audit rules** (UBTU-22-654xxx) are matched against `auditctl -l` (the loaded rules, as the check texts do). NotAFinding needs a rule of the example's form: `-a always,exit` with the path, `perm=x` and exactly `auid>=1000 auid!=-1` for commands; `-w PATH -p` with the listed permissions (or the equivalent `-F path= -F perm=`) for files; for system calls, every listed call covered for both b32 and b64 with exactly the example's filters (the open/creat rule needs both the EPERM and EACCES variants, the xattr rule both the auid>=1000 and auid=0 variants, execve both the uid!=euid and gid!=egid variants). Keys are ignored; `/bin`, `/sbin` and `/lib` equal their `/usr` paths, `/var/run` equals `/run`, and `auid!=unset` and `auid!=4294967295` equal `auid!=-1`. Open only when no loaded rule mentions the command, file or calls; rules in another form give Not_Reviewed.
- **find-based permission checks** are Open when violations are listed; a `find` that hit unreadable directories can prove a violation but never NotAFinding (Not_Reviewed).
- **Not automated (17, all CAT II/III, Manual review):** UBTU-22-251025 and 251030 (site PPSM CAL and rate-limit policy), 255065 (authenticators for nonlocal maintenance), 411040 (which accounts are temporary), 612025, 612030 and 612035 (pam_pkcs11 module-block cert_policy and CRL cache, deferred), 631010 (AO approval of every root certificate), 651015 (requires running a full `aide --check`, which takes minutes and writes AIDE's own log), 651020 (notification process), 651035 (offload process), 652015 (rsyslog remote-access monitoring rules), 653035 (adequate audit storage is a judgement), and 254010, 254015, 254020 and 254030 (SSSD rules, deferred).
- **CAT I:** all 16 rules are automated; UBTU-22-432015 and UBTU-22-211000 are partial for the reasons above. No CAT I rule was judged not host-checkable.

### Collector (`collectors/collect-linux.sh`)

- POSIX sh: `#!/bin/sh`, `set -u`, `LC_ALL=C`, no bashisms (dash is the target; CI runs it with Ubuntu's `/bin/sh`). JSON strings are escaped by an awk function, character by character (quote, backslash, tab, CR, other control characters as `\uXXXX`; NUL removed); the finished file passes through `iconv -c` to drop invalid UTF-8. awk is POSIX and mawk is part of every Ubuntu install, so python3 is only a fallback when awk is missing.
- Read-only: it writes only its output file and a `mktemp -d` directory removed by an EXIT trap. Every fact records the command it ran. `auditctl` is only called with `-l` and `-s`, `systemctl` only with `show`, `passwd` only with `-S root`, `gsettings` only with `get`. A static test scans the script for redirects outside the temp directory and output file and for state-changing commands; a mutation check confirmed it catches chmod, sed -i, systemctl stop, auditctl -D, passwd -l, rm and redirects into /etc.
- Never outputs password hashes: /etc/shadow yields two counts (accounts, empty password fields); grub.cfg yields counts of password_pbkdf2, password, superusers, linux and audit=1 lines, never the hash. /etc/passwd yields name, UID, GID and shell only (no GECOS or home directory). The only digests in the output are the SHA-1 and MD5 checksums of the AIDE cron scripts (UBTU-22-651025), which are not secrets.
- `-r` redacts account names: accounts with UID 1000 and above (except nobody, 65534) become `account-N` in the passwd fact, sudo group members become `account-N`, and the user or group field of a sudoers line becomes `account-N` unless it is `ALL`, `Defaults`, an alias or an include. System accounts (UID below 1000) keep their package-defined names. Numbering is per fact.
- A path inside a directory the collector cannot search looks absent to `test -e`; the collector uses `ls -d` to tell "permission denied" from "no such file", so an unreadable location is reported unavailable rather than as a missing (non-compliant) file.
- Real run: no WSL distribution or Docker is installed on the development machine, so the collector was not run on Ubuntu here. It was run under Git for Windows' sh (not Linux; most facts unavailable) to check that it completes and writes valid JSON. The Linux-only tests (`test_collector_runs_on_linux`, `test_collector_path_state_tells_denied_from_absent`) run on the CI `ubuntu-22.04` runner in the `linux-collector` job, which also runs the collector under dash and mawk as a normal user and as root and uploads both outputs as workflow artifacts.
- Fixtures under `backend/tests/fixtures/linux-*.json` are synthetic (invented host names), generated by `backend/scripts/make_linux_fixtures.py`; its `--check` mode, run by the tests, fails when they are out of date. Unit output follows real systemd behaviour: an unmasked ctrl-alt-del.target is reported as `Id=reboot.target` with `Names=reboot.target ctrl-alt-del.target`.
- **Facts not collected.** /etc/fstab mount options, the modes and owners of /etc/passwd, /etc/shadow and /etc/group, /etc/issue, and the list of UID 0 accounts are not collected, because no rule of the Ubuntu 22.04 V2R10 STIG checks them. (The UID 0 names are still visible in the passwd fact.)

### Review fix round 1 (2026-11-10)

Changes:
- **systemd aliases.** `systemctl show` reports an alias under its primary unit: an unmasked ctrl-alt-del.target appears as `Id=reboot.target`. The parser used to raise on that, which made the whole `units` fact unavailable, so UBTU-22-211015 and 255015 (plus 213015, 431015, 652010, 653015 and 232025) were Not_Reviewed on default hosts. The collector now also queries `Names`, and `p_units` finds each queried unit by `Id` or `Names` (falling back to argument order when `Names` is absent), reporting the state under the queried name with the primary `id` kept. The other units queried (ssh, auditd, apparmor, rsyslog, ufw, kdump-tools, sssd, chrony) are primary names; their aliases (sshd, syslog, chronyd) appear only in `Names`.
- **Invalid UTF-8.** `iconv -c` exits 1 when it drops bytes, so the old fallback wrote the raw file. The collector now uses the cleaned output whenever it is non-empty. The envelope records `"utf8_bytes_dropped"` as true, false, or null when iconv is missing, and the parser validates its type.
- **UBTU-22-271025.** idle-delay 0 (never idle) is now Not_Reviewed, consistent with ClientAliveInterval 0. NotAFinding requires idle-delay from 1 to 600; above 600, lock-enabled false or lock-delay above 0 is Open.
- **sshd Include.** Include targets are parsed. A target that is not covered by the collected `/etc/ssh/sshd_config.d/*.conf` makes the sshd_config fact unavailable ("... includes X, which the collector does not read"), so every SSH rule is Not_Reviewed.
- **UBTU-22-412020.** NotAFinding needs a `*` hard limit of 10 or less and every maxlogins entry at 10 or less. Any entry above 10 is Open: `* hard maxlogins 10` plus `@ops hard maxlogins 50` is Open.
- **Minor fixes:**
  - nullok is counted as the check text's grep does (see UBTU-22-611060 above).
  - Audit rule facts hold sorted lists, not sets, so every fact and result is JSON-serialisable.
  - The ssh_banner fact uses `path_state`, so a banner in an unsearchable directory is unavailable, not missing.
  - sudoers `@include`/`#include`/`#includedir` lines are collected; `#include` is no longer treated as a comment. An include of anything outside /etc/sudoers and /etc/sudoers.d, or with a `%h` escape, makes the sudoers fact unavailable.
  - Any `-a never,...` audit rule that mentions a target makes that target's audit check Not_Reviewed.
  - The wording "never outputs password hashes" was changed in the README, this file and the collector header, which also notes that the AIDE checksums are the only digests reported.
- **CI.** A new `linux-collector` job on ubuntu-22.04:
  - switches awk to mawk with update-alternatives;
  - runs the collector tests under dash and mawk (`STIGWATCH_TEST_AWK=mawk`, `STIGWATCH_RUN_COLLECTOR=1`);
  - runs the collector as a normal user (`out-user.json`) and as root (`out-root.json`);
  - validates both with `collect-parse --min-ok 30` / `--min-ok 40` (out of 63 facts) and scans the root output;
  - uploads both files as the `linux-collector-output` artifact.
  
  The full collector run test is skipped in the regular backend job, so the 15-minute limit is not spent on the filesystem-wide `find`.

Regression tests are in `backend/tests/test_linux_hardening.py` (19 tests). RED: with the source reverted to commit 1ce16a9 (by stashing only `backend/stigwatch`, `collectors` and README), the new tests gave `15 failed, 4 passed`. The 4 that passed were the already-correct Include cases and the wording check. In particular, the HEAD parser on the new real-alias fixture gave `units: unavailable - could not be parsed: systemctl show did not report ctrl-alt-del.target`.

GREEN, with real output:

```
$ python -m pytest -q
86 passed, 2 skipped in 5.06s
$ python scripts/make_linux_fixtures.py --check      (exit 0)
$ python -m stigwatch coverage ubuntu-22.04
ubuntu-22.04 V2R10: 174 of 191 rules automated, 17 manual review
CAT I        16         16    14        2         0       0
CAT II      158        143   138        5         0      15
CAT III      17         15    12        3         0       2
$ python -m stigwatch benchmarks --check
ubuntu-22.04 V2R10: 191 rules (CAT I 16, CAT II 158, CAT III 17)
windows-server-2022 V2R11: 277 rules (CAT I 31, CAT II 235, CAT III 11)
$ python -m stigwatch scan tests/fixtures/linux-<name>.json   (Open / NotAFinding / Not_Applicable / Not_Reviewed)
compliant 0/164/6/21, noncompliant 80/29/6/76, unprivileged 0/94/6/91, minimal 13/94/7/77, gui 0/169/1/21, server-nogui 0/164/6/21
$ sh collectors/collect-linux.sh -r -o win2.json    (Git for Windows sh; not Linux)
wrote .../win2.json: 63 facts, 18 unavailable (not run as root); utf8_bytes_dropped = false
```

The two skips are Linux-only (the full collector run and the permission-denied path test); they run in the new CI job. The collector has still not run on a real Ubuntu host; the CI artifacts will be the first real output.

## Windows Server 2022 collector and checks (Task 4)

### Engine (shared, no Windows special cases)

- `CHECK_FILES` and `COLLECTORS` register `windows.yml` and `stigwatch/facts/windows.py`; `scan` detects the collector from the file, and `collect-parse` accepts `windows`.
- New generic feature: a fact may carry `partial`, a mapping that follows its value's keys and gives the reason a part could not be read. The evidence then shows `unavailable: <reason>` instead of "not reported". Windows uses it for a registry value that was access-denied and for a user right granted to a name rather than a SID.
- A Not_Applicable result names only the facts of `na_if` (context `observe` paths are no longer listed there).
- `show_path` brackets segments containing a backslash, so registry keys read as `registry[HKLM\...].Name.value`.
- The coverage headline separates checks that can decide a result from evidence/applicability-only checks: `254 of 277 rules automated (228 can decide a result, 26 evidence or applicability only), 23 manual review`.
- Windows-specific operators live in `facts/windows.py`: `has_sid` (a user right lists a SID or a pattern such as `S-1-5-21-*-512`), `acl` (Allow entries no wider than full control for named SIDs and read & execute for others; a "standard" list says which wider grants are findings and which need review) and `dod_banner` (the Linux banner comparison).

### Collector (`collectors/collect-windows.ps1`)

- Ported from CMMC Ready's collector: per-fact try/catch, `secedit /export` to a temp file deleted in `finally`, auditpol keyed by subcategory GUID, registry reads through `OpenBaseKey`/`OpenSubKey($key, $false)`, `-RedactNames`, UTF-8 without BOM, PowerShell 5.1 and 7. 20 facts; each records the exact command. Envelope: `{"collector":"windows","version":1,"collected_at","host":{name,os,build},"privileged","redacted","powershell","facts":{...}}`.
- secedit uses `/mergedpolicy` so domain policy merged into the local database is exported (account, lockout and Kerberos policy, security options, user rights). A secedit exit 740 is reported as "requires elevation".
- **Audit policy, locale independence.** `auditpol /backup /file:<temp>` writes a numeric "Setting Value" (0 none, 1 success, 2 failure, 3 both) that does not depend on the display language; the collector uses it first. If it fails, `auditpol /get /category:* /r` is used and the parser interprets only the English inclusion texts ("No Auditing", "Success", "Failure", "Success and Failure"). Any other text makes the whole `audit_policy` fact unavailable ("not English"), so every audit rule is Not_Reviewed. The subcategory GUIDs were confirmed with `auditpol /list /subcategory:* /v` on the development machine.
- **Registry.** One fact holds every value the checks read (the `$RegistryValues` table). Each value is `set` (with its type), `absent` (key or value missing: "not configured") or `error` (unreadable: unknown). REG_DWORD data is normalised to unsigned. A value of the wrong type (REG_SZ "1" where the check text asks for REG_DWORD 1) is never treated as compliant: the comparison is unknown, so the rule is Not_Reviewed. A test checks that every registry value the checks use is in the collector's table.
- **User rights** are SIDs from `[Privilege Rights]`. secedit omits a right nobody holds, so every known right defaults to an empty list, but only when the section lists at least one known right (otherwise the fact is unavailable). A right granted to a name instead of a `*SID` is left unknown. Domain Admins and Enterprise Admins are matched as `S-1-5-21-*-512` and `S-1-5-21-*-519`: a local SAM never has those RIDs, and -519 exists only in the forest root domain.
- **Domain role** is `Win32_ComputerSystem.DomainRole`: 0/2 standalone, 1/3 member, 4/5 domain controller. It is the `na_if` fact for every DC-only rule (Not_Applicable on member and standalone servers) and every member-only rule (Not_Applicable on domain controllers; MS-000020/030/050 also on standalone systems, as their check texts say).
- **Features** come from `Get-WindowsFeature`; on a system without it, from `Get-WindowsOptionalFeature -Online` with a fixed name map (TelnetClient, TFTP, SimpleTCP, SMB1Protocol, MicrosoftWindowsPowerShellV2Root, IIS-FTPSvc; Fax and PNRP have no optional-feature equivalent and stay unknown). `Installed` is a finding, `Available`/`Removed` are not, pending states are Not_Reviewed.
- **Volumes**: `Win32_Volume` (DriveType 3) with partition types from `Get-Partition`. System (EFI), Recovery and Reserved partitions are excluded as the check text allows. Without partition types only an unlettered system volume is excluded, and any other unlettered non-NTFS volume is unverified (Not_Reviewed). NTFS, ReFS and CSVFS pass; a lettered FAT/exFAT volume is Open.
- **File permissions** (`Get-Acl`, SIDs only): the Application, Security and System event logs (path from `Get-WinEvent -ListLog`, registry fallback), Eventvwr.exe, and on domain controllers the files in the NTDS database and log folders (from the NTDS registry values; files are listed, never opened) and the SYSVOL folder (the parent of the Netlogon `SysVol` value, the "first SYSVOL directory level").
- **Firmware**: UEFI mode is `$env:firmware_type` (what System Information shows as BIOS Mode); Secure Boot is `Confirm-SecureBootUEFI`, as in the check text.
- **Local run** (development machine, Windows 11, not elevated, Windows PowerShell 5.1): completed in about 10 s with 13 of 20 facts read. Unavailable: security_policy and user_rights (secedit exit 740), audit_policy (0x522, privilege not held), features (requires elevation), bitlocker (access denied), tpm, secure_boot. No `stigwatch-*` temporary file was left in `%TEMP%`. The output was not committed. PowerShell 7 is not installed locally; the CI job runs it.

### Interpretations of the Windows Server 2022 V2R11 check texts

- **Documented exceptions** are not visible on the host, so the result is Open and the rationale says so, as for Ubuntu. Examples: "If an application requires this user right ... documented with the ISSO", an external password filter, a documented FTP server role, smart card removal exceptions, and event logs written straight to an audit server.
- **Partial checks** (one decisive outcome, Not_Reviewed otherwise):
  - 00-000110 antivirus and 00-000280 firewall: Defender / Windows Firewall prove compliance; their absence may mean a third-party product.
  - 00-000190 and 00-000210: the check text excludes application accounts, which cannot be identified.
  - AU-000240/250 removable storage: VM and NAS systems may leave it not configured.
  - CC-000280 Security log size: a missing value is a finding, but "one week of records" depends on the environment.
  - CC-000300 SmartScreen: applies to unclassified systems only.
  - CC-000530 PowerShell transcription: the output folder permissions are not collected.
  - DC-000280: an empty LocalMachine\My store is a finding; otherwise review.
  - UC-000010: only the collector account's HKCU is read, so a value of 1 is a finding but a compliant value does not cover other profiles.
  - UR-000170: an Auditors group may also hold the right.
- **Evidence or applicability only** (Not_Applicable when the domain role proves it, otherwise Not_Reviewed with the facts shown):
  - DC-000010 and MS-000010: who may administer the system is a judgement; members are listed.
  - DC-000090 to 000220, 000290 to 000310, 000406 and 000430: Active Directory objects, auditing, mappings and PKI judgements, or an LDAP bind the read-only collector does not make.
  - 00-000420/430: the IIS FTP configuration is not collected; Not_Applicable when the FTP service is not installed.
  - PK-000010 to 000030: DoD certificate presence is supporting evidence only.
- **Absent values the check text accepts**: CC-000130 (not set, 1, 3 or 8; 7 is a finding; other values need review) and CC-000310/320/330/400/440 (not set or 0; 1 is a finding).
- **AC-000010 / AC-000030**: secedit omits LockoutDuration and ResetLockoutCount when there is no lockout threshold. That is Not_Reviewed here (AC-000020 reports the threshold). A LockoutDuration of 0 or -1 (until an administrator unlocks) is not a finding.
- **AC-000050**: MaximumPasswordAge must be 1 to 180; 0 and -1 (never expires) are findings.
- **SO-000320**: LDAPClientIntegrity 1 is not a finding, missing or 0 is. 2 (require signing) is stricter than the check text's value and is Not_Reviewed.
- **SO-000360** is Not_Applicable when the SharePoint Timer service (SPTimerV4) is running. **MS-000140** is Not_Applicable when MSExchangeServiceHost is present (an Exchange server), as well as on domain controllers and standalone systems.
- **SO-000380 to 000450 and AU-000060** are Not_Applicable on Server Core (`InstallationType` "Server Core").
- **00-000020**: Not_Applicable when the built-in Administrator (RID 500) is disabled on a non-DC; Open when its password is older than 180 days; NotAFinding only on standalone systems (on domain members the LAPS portion needs review; the LAPS policy values are shown).
- **00-000100**: Not a finding on Windows Server 2022 (build 20348) collected on or before 10/15/2031, the Extended Support end the check text gives; any other OS is Not_Reviewed.
- **00-000440**: domain members must use NT5DS (the W32Time policy value wins over the service value). Standalone systems and domain controllers need a DoD time source, which is Not_Reviewed.
- **DC Kerberos rules (DC-000020 to 000060)** read the effective Kerberos policy that secedit exports on the domain controller. The check text names the Default Domain Policy; account policies take effect only from domain-level GPOs, so the effective value is the one in force.
- **MS-000080 to 000120**: Guests is required on all systems. Enterprise Admins and Domain Admins (and Local account where the rule names it) are required on domain-joined members only. MS-000100 must be empty on standalone systems.

### Not automated (23, Manual review)

- 00-000010, 040, 050, 060 and 070: account practices.
- 00-000030: CAT I, see below.
- 00-000080: application allow-listing policy.
- 00-000120: HIDS/HIPS product.
- 00-000140, 150, 160 and 170: folder and registry permissions compared with defaults, with inheritance and "applies to" semantics (deferred).
- 00-000180: printer share permissions.
- 00-000220: file integrity monitoring process.
- 00-000230: share permissions need judgement.
- 00-000240: searching every drive for .p12/.pfx is too slow, and the exceptions need judgement.
- 00-000260 and 00-000270: documentation.
- 00-000300 and 00-000310: temporary and emergency accounts cannot be identified.
- 00-000450: orphaned SIDs need SID resolution against the domain.
- AU-000010 and AU-000020: processes.

### CAT I

- **Decided from host facts (22):** 00-000130, 00-000250, AC-000090, CC-000210/220/230/430/470/500, DC-000070, DC-000080, MS-000140, SO-000020/210/220/230/250/300/310 and UR-000020/060/100.
- **Evidence or applicability only (8):**
  - DC-000010 and MS-000010: who is "responsible for administration" is a judgement; members are listed.
  - DC-000090, 000100 and 000110: Active Directory object permissions, not host facts.
  - DC-000150: needs an anonymous LDAP bind, an active test.
  - DC-000290 and DC-000300: DoD PKI / ECA issuer and UPN mapping judgements.
  
  On member and standalone servers the six DC rules among them are Not_Applicable from the domain role.
- **Not host-checkable (1): WN22-00-000030.** It requires an organisational policy that keeps administrative accounts away from internet-facing applications, with technical enforcement "except as approved by the AO". AppLocker rules could be collected as evidence but cannot show the policy or the approvals.

### Fixtures and tests

- Synthetic fixtures `backend/tests/fixtures/windows-*.json` (member-compliant, noncompliant, unprivileged, dc, standalone, non-english) are generated by `backend/scripts/make_windows_fixtures.py`, which reads the registry list from the collector script. The tests run its `--check` mode.
- `tests/test_windows_checks.py` covers the Task 3 test set for Windows: `test_unreadable_facts_not_reviewed`, `test_not_applicable_requires_fact`, every STIG ID in the benchmark, coverage with the CAT I list, and a static no-write test of the collector. It adds tests for non-English auditpol, registry types, the ACL and SID operators, volumes, Kerberos and the CLI.
- `test_collector_runs_on_windows` runs the real collector when `STIGWATCH_RUN_COLLECTOR=1` on Windows.

### CI

- A new `windows-collector` job runs on `windows-2022` (elevated by default):
  - the collector tests under Windows PowerShell 5.1;
  - the collector under `pwsh` and under `powershell`, in separate steps, each native exit code checked;
  - `collect-parse windows --min-ok 15` and `scan` for each output;
  - both outputs uploaded as the `windows-collector-output` artifact.
- The `frontend` job is gated per step with `if: hashFiles('package.json') != ''` (`hashFiles()` is not available in a job-level `if`), so it passes as a no-op until Task 9 adds the dashboard.
