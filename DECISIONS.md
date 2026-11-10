# Decisions

Standing decisions for STIGWatch: what was decided, why, and what follows from it. Sources were read on 2026-11-10; where a source could not be reached, that is stated.

## Sources and verified facts

### 1. Current DISA benchmark releases

Located by probing the public DISA download host directly (the library page at https://www.cyber.mil/stigs/downloads/ is rendered by JavaScript and returns no listing to automated clients). The package names follow DISA's `U_<product>_V<v>R<r>_STIG.zip` pattern; a request for the next release of each returned HTTP 404 on 2026-11-10, so these are the newest published packages.

| Benchmark | Version | Release | Benchmark date | XCCDF status date | Download |
|---|---|---|---|---|---|
| Canonical Ubuntu 22.04 LTS STIG (`CAN_Ubuntu_22-04_LTS_STIG`) | 2 | 10 | 30 Sep 2026 | 2026-09-09 | https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CAN_Ubuntu_22-04_LTS_V2R10_STIG.zip |
| Microsoft Windows Server 2022 STIG (`MS_Windows_Server_2022_STIG`) | 2 | 11 | 30 Sep 2026 | 2026-08-19 | https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2022_V2R11_STIG.zip |

Version, release and benchmark date are read from the XCCDF files themselves (`<version>`, `<plain-text id="release-info">`, `<status date>`) and cross-checked against the Ubuntu Overview PDF cover ("Version 2, Release 10, 30 September 2026").

Rule counts from the XCCDF, which the catalog reproduces:

| Benchmark | Rules | CAT I (high) | CAT II (medium) | CAT III (low) |
|---|---|---|---|---|
| Ubuntu 22.04 V2R10 | 191 | 16 | 158 | 17 |
| Windows Server 2022 V2R11 | 277 | 31 | 235 | 11 |

Package SHA-256 (as downloaded 2026-11-10): Ubuntu `2229b5be3224000e92b4ca2feac688ecd7990a3046971a6c1077e617d1bf398a`, Windows `808e83970c4f27590f31435856be9810e02d8f72d3c0a67c0a195cae46dbf48e`.

XCCDF identity mapping (XCCDF 1.1, namespace `http://checklists.nist.gov/xccdf/1.1`):

- `Group@id` is the Group ID (`V-260469`); `Group/title` is the SRG requirement id (`SRG-OS-000480-GPOS-00227`).
- `Rule@id` is the Rule ID (`SV-260469r1268251_rule`); `Rule/version` is the STIG ID (`UBTU-22-211015`); `Rule@severity` is high, medium or low.
- `Rule/ident` with system `http://cyber.mil/cci` holds the CCI; with system `http://cyber.mil/legacy` it would hold legacy V- and SV- ids (neither shipped package lists any).
- `Rule/reference/dc:identifier` is the DPMS target key (`5594` for Ubuntu 22.04).

Other versions seen in third-party listings (not used): NIST NCP lists Ubuntu 22.04 "Ver 2, Rel 9" (https://ncp.nist.gov/checklist/revision/6873); search results also mention Rel 6 and Rel 8. All are older than the DISA package above. The NCP pages are JavaScript-rendered and could not be read directly.

### 2. Distribution statement and redistribution

No explicit "Distribution Statement A" (or any other distribution statement) was found.

What was checked:

- Both packages (XCCDF, Overview PDF, Revision History PDF, SRG/STIG Readme PDF; the Ubuntu release memo too) were searched for "distribution statement", "approved for public release", "redistribut", "copyright" and "terms of use". None appear. The documents are marked only "UNCLASSIFIED". The XCCDF contains an empty `<notice id="terms-of-use">` element.
- The Overview PDFs (section 1.4 "STIG Distribution") say DoW/federal parties obtain STIGs from https://cyber.mil/ and that those without a common access card (CAC) can obtain them from https://public.cyber.mil/. That establishes public availability, not a redistribution licence.
- The packages download without authentication from `dl.dod.cyber.mil`.
- DoD Cyber Exchange FAQ and terms pages (https://www.cyber.mil/stigs/faqs, https://www.cyber.mil/terms-of-use, https://www.cyber.mil/?p=456) are JavaScript-rendered shells ("Welcome to LWC Communities!"); no text could be read. A web search found no DISA statement on redistribution.

The decision is under "Benchmark content" below.

### 3. Checklist formats

DISA's own checklist schemas were not reachable, and STIG Viewer was not downloaded or run. The layouts are therefore built from DISA's public benchmark data and from published checklists written by tools that target STIG Viewer. Sources:

- STIG Manager's sample checklist, https://raw.githubusercontent.com/NUWCDIVNPT/stig-manager/main/docs/STIG-Manager-OSS.ckl (MIT), and its client-module test files, https://raw.githubusercontent.com/NUWCDIVNPT/stig-manager-client-modules/main/test-files/parsers/ckl/Asset_a-VPN_TRUNCATED-V2R5.ckl with the matching `.cklb` (MIT). These show the element and key names, and that `Group_Title` is the SRG requirement id (for example `SRG-NET-000019`), not the rule title.
- PowerSTIG's checklist writer, https://www.powershellgallery.com/packages/PowerSTIG/4.2.0/Content/Module%5CSTIG%5CFunctions.Checklist.ps1, which writes a checklist for STIG Viewer 2 and shows the `VULN_ATTRIBUTE` order, `Check_Content_Ref`, `Class` (`Unclass`), `TargetKey`, and `classification` `UNCLASSIFIED` in `STIG_INFO`.
- DISA's STIG Viewer 3.x User Guide V1R7 (13 Feb 2026), https://dl.dod.cyber.mil/wp-content/uploads/stigs/pdf/U_STIG_Viewer_3-x_User_Guide_V1R7.pdf, which confirms "CKL (SV v2 format)" and "CKLB" as export formats but does not publish the layouts. DISA's "Stig Viewer 3 CKLB JSON Schema" is listed on https://public.cyber.mil/stigs/srg-stig-tools (per search results); that page is JavaScript-rendered and the schema file could not be reached.

None of those three sources writes `TARGET_COMMENT`, `STIG_UUID` or `LEGACY_ID` for a rule. They are part of the structure STIG Viewer itself writes and are included, with the values STIGWatch can honestly supply (see "Checklist formats"); an empty or generated value is used where the benchmark data has none.

#### `.ckl` structure (XML)

- `CHECKLIST` root with children `ASSET` and `STIGS`.
- `ASSET`: `ROLE, ASSET_TYPE, MARKING, HOST_NAME, HOST_IP, HOST_MAC, HOST_GUID, HOST_FQDN, TARGET_COMMENT, TECH_AREA, TARGET_KEY, WEB_OR_DATABASE, WEB_DB_SITE, WEB_DB_INSTANCE`.
- `STIGS` contains one `iSTIG` per STIG; each has `STIG_INFO` then `VULN` elements.
- `STIG_INFO` contains `SI_DATA` elements, each `SID_NAME` plus optional `SID_DATA`: `version, classification, customname, stigid, description, filename, releaseinfo, title, uuid, notice, source`.
- `VULN` contains `STIG_DATA` elements (`VULN_ATTRIBUTE` + `ATTRIBUTE_DATA`), then `STATUS, FINDING_DETAILS, COMMENTS, SEVERITY_OVERRIDE, SEVERITY_JUSTIFICATION`.
- `VULN_ATTRIBUTE` names in order: `Vuln_Num` (Group ID), `Severity`, `Group_Title`, `Rule_ID` (the `SV-..._rule` ID), `Rule_Ver` (the STIG ID), `Rule_Title`, `Vuln_Discuss`, `IA_Controls`, `Check_Content`, `Fix_Text`, `False_Positives`, `False_Negatives`, `Documentable`, `Mitigations`, `Potential_Impact`, `Third_Party_Tools`, `Mitigation_Control`, `Responsibility`, `Security_Override_Guidance`, `Check_Content_Ref`, `Weight`, `Class`, `STIGRef`, `TargetKey`, `STIG_UUID`, `LEGACY_ID` (repeated), `CCI_REF` (repeated per CCI).

#### `.cklb` structure (JSON)

- Top level: `title, id (uuid), active (bool), mode (int), has_path (bool), target_data, stigs`.
- `target_data`: `target_type, host_name, ip_address, mac_address, fqdn, comments, role, is_web_database, technology_area, web_db_site, web_db_instance`.
- `stigs[]`: `stig_name, display_name, stig_id, version (int), release_info ("Release: 5 Benchmark Date: 07 Jun 2023"), uuid, reference_identifier, size, rules[]`.
- `rules[]`: `uuid, stig_uuid, target_key, stig_ref, group_id, rule_id, rule_id_src, weight, classification, severity, rule_version (the STIG ID), group_title, rule_title, fix_text, false_positives, false_negatives, discussion, check_content, documentable, mitigations, potential_impacts, third_party_tools, mitigation_control, responsibility, security_override_guidance, ia_controls, check_content_ref {href, name}, legacy_ids, group_tree [{id, title, description}], createdAt, updatedAt, STIGUuid, status, overrides, comments, finding_details, ccis`.
- `rule_id` omits the `_rule` suffix; `rule_id_src` includes it.

### 4. Status vocabulary

- Meaning, from DISA's STIG Viewer 3.x User Guide V1R7, section 5.4.1 "Changing the Status of Rules": a rule can be marked Open, Not A Finding, Not Reviewed or Not Applicable; the default state is Not Reviewed. The guide's import section accepts "Open, Not A Finding, Not Applicable, or Not Reviewed (case-insensitive)". The guide gives no prose definitions beyond the names and icons.
- `.ckl` `STATUS` values: `Open`, `NotAFinding`, `Not_Applicable`, `Not_Reviewed`. `.cklb` `status` values: `open`, `not_a_finding`, `not_applicable`, `not_reviewed`. Both vocabularies appear in the published samples.
- STIGWatch semantics (a project decision, following the no-overclaiming principle): Open = facts show the check text is failed; Not a Finding = facts fully prove the check text is met; Not Applicable = a gathered fact proves non-applicability; Not Reviewed = facts unreadable, insufficient, or the rule is manual.

## Project decisions

- The local virtual environment uses Python 3.14; code targets `>=3.12` and CI uses 3.12.
- The CI backend job runs on `ubuntu-22.04`, the Linux collector job on `ubuntu-22.04` as root and as a normal user, and the Windows collector job on `windows-2022`. The frontend and e2e jobs build the dashboard and drive it against the demo API.
- Dependabot watches the backend and root pip files, the root and `e2e/` npm packages, and GitHub Actions.

### Dependencies outside the core list

- **uvicorn** (`uvicorn[standard]`) serves the API for `serve` and `demo --serve`; it is the standard ASGI server for FastAPI. The Vercel function does not need it, so the root `requirements.txt` omits it.
- **httpx** is a development dependency only: Starlette's `TestClient`, which the API tests use, requires it.
- **Playwright** (`e2e/`, a separate `package.json` so the dashboard's dependency tree stays free of a browser downloader) drives the built dashboard against the demo API: guests are read-only, and a rule that lost visibility is never shown as fixed. It also produces the README screenshots.
- **ansible-core and ansible-lint** are installed only in the CI job that checks the generated playbooks (syntax check and lint); the app does not depend on them. The `ansible.posix` collection is installed there because the playbooks use it.
- **PyYAML** reads the check files, **PyJWT** signs session tokens, **python-multipart** parses uploads, and **defusedxml** parses XCCDF (DTDs and entities refused).

## Benchmark content

- **Redistribution.** No distribution statement was found (section 2), so the catalog carries the full rule text: title, discussion (VulnDiscussion), check text, fix text, CCIs, severity, all IDs, the group title (SRG id), the target key and any legacy ids. Reasoning: DISA STIGs are works of the U.S. Government (17 U.S.C. 105 gives no copyright in them) and are published for unrestricted public download from the DoD Cyber Exchange. Each catalog file carries the DISA title, version, release, benchmark date, the download URL and the SHA-256 of the source zip. Content is reproduced unmodified apart from whitespace normalisation (CRLF to LF, trailing spaces removed, outer whitespace trimmed) and attributed to DISA. This is a project decision, not legal advice; if DISA states otherwise, set `metadata_only` and rebuild (the catalog supports metadata-only files).
- **Catalog files.** `backend/data/benchmarks/ubuntu-22.04.json` (Canonical Ubuntu 22.04 LTS STIG V2R10, 191 rules) and `windows-server-2022.json` (Microsoft Windows Server 2022 STIG V2R11, 277 rules). Benchmark ids `ubuntu-22.04` and `windows-server-2022` are the stable keys used by the rest of the app. Rules keep XCCDF order. Recorded counts per severity match the rules.
- **Parsing.** XCCDF is untrusted: defusedxml with DTDs refused, read from the zip in memory with size limits, nothing extracted. The embedded escaped description markup is unescaped and parsed the same way to extract `VulnDiscussion`. The group title, target key and legacy ids are kept so the checklist exports can write them; a catalog built without them (an older import) still loads and writes those fields empty.
- **Verification.** `python -m stigwatch benchmarks --check` validates the committed JSON (required fields, unique Group/Rule/STIG IDs, recorded counts equal to the rules, check and fix text present unless `metadata_only`). CI runs this because it cannot download the zips. Maintainers run `python scripts/build_benchmarks.py --check ZIP...` locally to rebuild from the official zips and compare byte for byte with the committed JSON. The rebuild test in `backend/tests/test_benchmarks.py` does the same when the environment variable `STIGWATCH_SOURCES_DIR` points at a folder holding the source zips (`ubuntu.zip`, `win.zip`); without it that test is skipped.

## Benchmark releases

`python -m stigwatch benchmarks import FILE.zip [--out DIR] [--source-url URL]` parses a DISA STIG zip and writes `<benchmark_id>.json` into `$STIGWATCH_DATA_DIR/benchmarks` (default `~/.stigwatch/benchmarks`). A locally imported file with the same id overrides the bundled one; unrelated products are imported under an id derived from the XCCDF Benchmark id.

**One release per benchmark is installed at a time.** Storing releases side by side would also need one set of checks per release, which is out of scope. The consequences, and how each is handled:

- **Scanning against a release that dropped rules.** A check whose STIG ID the installed release does not contain is skipped when the checks load, and a warning names the skipped IDs. Every rule of the new release is still evaluated, so uploads keep working. A rule the new release adds has no check and is Not Reviewed ("Manual review"). Tests import a V2R11 with one checked rule removed and show that uploads still work.
- **Exports of scans made under an earlier release.** Every scan stores the release it was evaluated against. Checklists (CKL and CKLB) and finding details are labelled from that stored release, never from the installed one, so a V2R10 scan exports "Release: 10" even after V2R11 is installed. The benchmark date of the older release is not known once it is replaced, so the release line then has no date.
- **Release mismatch is warned about, not refused.** Refusing would make every historical checklist unavailable after an import, while the results themselves are still correct for their release. Instead, when the scan's release differs from the installed one, the checklist says so in the asset comment (`TARGET_COMMENT` / `target_data.comments`) and, in the CKL, in the STIG description, and the download carries an `X-STIGWatch-Notice` header. The notice states that rule text (titles, discussion, check and fix text) comes from the installed release, and counts the results for rules the installed release no longer contains, which cannot be listed. Fleet reports are labelled by each host's latest scan release.
- **Drift across releases** compares by STIG ID: a rule present in only one release is listed as new or removed, never as fixed or regressed, and the drift result records both releases.

## Check engine

- `backend/stigwatch/checks/engine.py` is collector-agnostic: a collector module (`stigwatch/facts/linux.py`, `windows.py`) supplies `validate()`, `facts()` (normalised facts, each `ok` or `unavailable` with the command it ran) and optional operators; a YAML checks file per benchmark (`checks/linux.yml`, `windows.yml`) supplies the rules. The engine descends from an evidence engine whose `met_if` / `unmet_if` / `fail_result` / `met_result` became `logic` / `unmet_if` / `result_if_false` / `result_if_true`; `na_if` was added.
- Conditions are tri-state. A fact that was not read, or a value the parser could not interpret, is unknown and never decides a rule. A setting that is absent (file missing, directive missing or commented out) is `null` ("not configured") and fails a requirement, because the check texts treat "missing or commented out" as a finding. A directive given more than once with different values is `null` with `conflict: true` (the check texts call conflicting results a finding).
- Order per rule: `na_if` true gives Not_Applicable, and the reason names the fact; `na_if` unknown gives Not_Reviewed (applicability unproven, so neither a finding nor a pass is claimed); then `logic` true gives NotAFinding (or Not_Reviewed for evidence-only results); `logic` false gives Open, or Not_Reviewed when an `unmet_if` is given and is not proven; `logic` unknown gives Not_Reviewed naming each unreadable fact, its reason and its command. Rules without a check are Not_Reviewed "Manual review". An exception during evaluation gives Not_Reviewed.
- A readable fact can prove a finding even when another fact of the same rule is unreadable (for example UBTU-22-654240 is Open on a host without `-e 2` in rules.d even when `auditctl -s` is unavailable), because each "If ..., this is a finding" clause of the check text stands alone. A finding is never derived from an unreadable fact.
- A fact may carry `partial`, a mapping that follows its value's keys and gives the reason a part could not be read, so the evidence shows `unavailable: <reason>` instead of "not reported". Windows uses it for a registry value that was access-denied and for a user right granted to a name rather than a SID.
- A Not_Applicable result names only the facts of `na_if`; context `observe` paths are not listed there. `show_path` brackets segments containing a backslash, so registry keys read as `registry[HKLM\...].Name.value`.
- Status strings follow the `.ckl` vocabulary: `Open`, `NotAFinding`, `Not_Applicable`, `Not_Reviewed`. The YAML operator for "is not set" is `unset`, not `null` (YAML parses a `null:` key as None). Constants shared by modules (statuses, CATs, the disclaimer, the compliance formula) live in `stigwatch/constants.py`.
- The coverage headline separates checks that can decide a result from evidence or applicability-only checks.

## Ubuntu collector and checks

### Interpretations of the Ubuntu 22.04 V2R10 check texts

- **Documented exceptions.** Where the check text excuses a setting "if documented with the ISSO" (X11Forwarding, NOPASSWD, kdump-tools, wireless, nfs-kernel-server, disk encryption), the host cannot show the documentation, so the result is Open and the rationale says so; the assessor records the exception.
- **Judgements the host cannot make** give partial checks (one decisive outcome, Not_Reviewed otherwise): UBTU-22-432015 sudo group membership (an empty group is NotAFinding, otherwise the members are listed for review); UBTU-22-211000 vendor support (see below); UBTU-22-252010 authoritative DoD time source; UBTU-22-653020 remote audit server; UBTU-22-653025 the ISSO's mail address; UBTU-22-651010 and UBTU-22-251010 ("ask the administrator about another tool"); UBTU-22-232045, 232050 and 232055 ("required system account" owners).
- **sshd settings** are read from `/etc/ssh/sshd_config` and `/etc/ssh/sshd_config.d/*.conf`, as the check texts grep the files sshd parses; `sshd -T` is collected as supporting evidence only. A directive inside a `Match` block counts towards conflicting results. `Include` targets are parsed: an `Include` of anything other than files matching `/etc/ssh/sshd_config.d/*.conf` (relative paths resolve in /etc/ssh) makes the whole sshd configuration unknown, so the SSH rules are Not_Reviewed. Each line is matched with a linear-time pattern (the line is right-stripped, so no pattern backtracks over whitespace), because collector files come from untrusted hosts and a long whitespace line must not cost seconds.
- **UBTU-22-611060** counts every active (not commented-out) line of common-auth and common-password that contains `nullok`, whatever the case of the PAM type or whether the line parses, as the check text's grep does; only commented-out lines are excluded.
- **UBTU-22-215025** checks the package named `ntp`, not every package whose name contains "ntp" (`dpkg -l | grep ntp` would also match ntpsec, ntpdate and others).
- **UBTU-22-411030**: the check text calls PASS_MAX_DAYS "less than 180" a finding while the title requires a 180-day maximum. Only 180 satisfies both readings (NotAFinding); missing is Open; any other value is Not_Reviewed.
- **UBTU-22-411035** requires INACTIVE 35. -1, missing or longer is Open; a shorter period (which the check text also flags) is Not_Reviewed.
- **UBTU-22-255035**: ClientAliveInterval 1 to 600 is NotAFinding, over 600 or missing is Open; 0 (which disables the timeout but is literally "600 or less") is Not_Reviewed. **UBTU-22-411045**: `deny = 0` is Not_Reviewed for the same reason. **UBTU-22-271025**: idle-delay 0 (never idle) is Not_Reviewed; NotAFinding requires idle-delay from 1 to 600; above 600, lock-enabled false or lock-delay above 0 is Open.
- **Banners** (UBTU-22-255020, 271015) are compared with the Standard Mandatory DoD Notice and Consent Banner ignoring whitespace (the two check texts themselves wrap and space it differently). A test asserts the constant is contained in both check texts. The ssh_banner fact uses `path_state`, so a banner in an unsearchable directory is unavailable, not missing.
- **UBTU-22-231010** uses the `lsblk` device tree: every mounted filesystem and swap except /boot and /boot/efi (loop and rom devices excluded) must sit on a dm-crypt device; an unencrypted mount is Open; a formatted, unmounted, unencrypted partition makes the result Not_Reviewed.
- **UBTU-22-651025** compares the SHA-1 of /etc/cron.{daily,monthly}/aide with the packaged original `/usr/share/aide/config/cron.daily/aide` already on the host, after checking that copy against the md5sum dpkg recorded for aide-common. This replaces the check text's `apt download` (the collector downloads nothing). If the packaged copy cannot be verified the result is Not_Reviewed.
- **UBTU-22-211000**: Canonical lists standard security maintenance for 22.04 until "May 2027" (https://ubuntu.com/about/release-cycle, read 2026-11-10). A 22.04 host collected on or before 2027-04-30 is NotAFinding; later, support depends on Ubuntu Pro ESM, which is not collected, so the result is Not_Reviewed.
- **UBTU-22-232025**: the check text makes the rule not applicable when rsyslog is active and enabled; the engine applies that note literally.
- **UBTU-22-631015** is Not_Applicable only when neither libpam-pkcs11 nor libpam-sss is installed and common-auth uses neither pam_pkcs11 nor pam_sss: with no smart-card PAM module, smart-card authentication cannot be in use.
- **UBTU-22-412020**: NotAFinding needs a `*` hard limit of 10 or less and every maxlogins entry at 10 or less. Any entry above 10 is Open: `* hard maxlogins 10` plus `@ops hard maxlogins 50` is Open.
- **GUI rules** (UBTU-22-271010 to 271030) are Not_Applicable when none of these packages is installed: xserver-xorg-core, xwayland, gnome-shell, gdm3, lightdm, sddm, ubuntu-desktop, xfce4-session, mate-session-manager, cinnamon-session, plasma-workspace. A half-installed package or an unreadable package database leaves applicability unknown (Not_Reviewed). gsettings values read through GLib's "memory" fallback backend are discarded.
- **UBTU-22-213025** is NotAFinding when dmesg reports NX active or /proc/cpuinfo has the nx flag, and Open only when the CPU flags were read and lack nx. Non-x86 CPUs give Not_Reviewed.
- **Audit rules** (UBTU-22-654xxx) are matched against `auditctl -l` (the loaded rules, as the check texts do). NotAFinding needs a rule of the example's form: `-a always,exit` with the path, `perm=x` and exactly `auid>=1000 auid!=-1` for commands; `-w PATH -p` with the listed permissions (or the equivalent `-F path= -F perm=`) for files; for system calls, every listed call covered for both b32 and b64 with exactly the example's filters (the open/creat rule needs both the EPERM and EACCES variants, the xattr rule both the auid>=1000 and auid=0 variants, execve both the uid!=euid and gid!=egid variants). Keys are ignored; `/bin`, `/sbin` and `/lib` equal their `/usr` paths, `/var/run` equals `/run`, and `auid!=unset` and `auid!=4294967295` equal `auid!=-1`. Open only when no loaded rule mentions the command, file or calls; rules in another form, and any `-a never,...` rule that mentions the target, give Not_Reviewed. Audit rule facts hold sorted lists, not sets, so every fact and result is JSON-serialisable.
- **find-based permission checks** are Open when violations are listed; a `find` that hit unreadable directories can prove a violation but never NotAFinding (Not_Reviewed).
- **sudoers** `@include`/`#include`/`#includedir` lines are collected; `#include` is not treated as a comment. An include of anything outside /etc/sudoers and /etc/sudoers.d, or with a `%h` escape, makes the sudoers fact unavailable.
- **Not automated (17, all CAT II/III, Manual review):** UBTU-22-251025 and 251030 (site PPSM CAL and rate-limit policy), 255065 (authenticators for nonlocal maintenance), 411040 (which accounts are temporary), 612025, 612030 and 612035 (pam_pkcs11 module-block cert_policy and CRL cache, deferred), 631010 (AO approval of every root certificate), 651015 (requires running a full `aide --check`, which takes minutes and writes AIDE's own log), 651020 (notification process), 651035 (offload process), 652015 (rsyslog remote-access monitoring rules), 653035 (adequate audit storage is a judgement), and 254010, 254015, 254020 and 254030 (SSSD rules, deferred).
- **CAT I:** all 16 rules are automated; UBTU-22-432015 and UBTU-22-211000 are partial for the reasons above. No CAT I rule was judged not host-checkable.
- Coverage: 174 of 191 rules automated (CAT I 16 of 16, CAT II 143 of 158, CAT III 15 of 17); `python -m stigwatch coverage ubuntu-22.04` prints the current figures.

### Collector (`collectors/collect-linux.sh`)

- POSIX sh: `#!/bin/sh`, `set -u`, `LC_ALL=C`, no bashisms (dash is the target; CI runs it with Ubuntu's `/bin/sh`). JSON strings are escaped by an awk function, character by character (quote, backslash, tab, CR, other control characters as `\uXXXX`; NUL removed); the finished file passes through `iconv -c` to drop invalid UTF-8, and the cleaned output is used whenever it is non-empty. The envelope records `"utf8_bytes_dropped"` as true, false, or null when iconv is missing. awk is POSIX and mawk is part of every Ubuntu install, so python3 is only a fallback when awk is missing.
- Read-only: it writes only its output file and a `mktemp -d` directory removed by an EXIT trap. Every fact records the command it ran. `auditctl` is only called with `-l` and `-s`, `systemctl` only with `show`, `passwd` only with `-S root`, `gsettings` only with `get`. `gsettings get` runs through `env` with `XDG_RUNTIME_DIR` and `XDG_CACHE_HOME` pointed at the private temporary directory and `DBUS_SESSION_BUS_ADDRESS=disabled:`, because dconf would otherwise create its shared-memory file under the runtime directory (or `~/.cache`, `/root/.cache` under sudo) and GLib may autolaunch a session bus; with these set it writes nothing outside the temporary directory and starts nothing. A static test scans the script for redirects outside the temporary directory and output file and for state-changing commands.
- `systemctl show` reports an alias under its primary unit (an unmasked ctrl-alt-del.target appears as `Id=reboot.target`), so the collector also queries `Names`, and the parser finds each queried unit by `Id` or `Names`, falling back to argument order when `Names` is absent, and reports the state under the queried name with the primary `id` kept. Unit output in the fixtures follows this real behaviour. A parser that raised on an alias would make the whole `units` fact unavailable and many rules Not_Reviewed on default hosts.
- Never outputs password hashes: /etc/shadow yields two counts (accounts, empty password fields); grub.cfg yields counts of password_pbkdf2, password, superusers, linux and audit=1 lines, never the hash. /etc/passwd yields name, UID, GID and shell only (no GECOS or home directory). The only digests in the output are the SHA-1 and MD5 checksums of the AIDE cron scripts (UBTU-22-651025), which are not secrets.
- `-r` redacts account names: accounts with UID 1000 and above (except nobody, 65534) become `account-N` in the passwd fact, sudo group members become `account-N`, and the user or group field of a sudoers line becomes `account-N` unless it is `ALL`, `Defaults`, an alias or an include. System accounts (UID below 1000) keep their package-defined names. Numbering is per fact.
- A path inside a directory the collector cannot search looks absent to `test -e`; the collector uses `ls -d` to tell "permission denied" from "no such file", so an unreadable location is reported unavailable rather than as a missing (non-compliant) file.
- **Where it is exercised.** The `linux-collector` CI job runs on `ubuntu-22.04`: it switches awk to mawk, runs the collector tests under dash and mawk (`STIGWATCH_TEST_AWK=mawk`, `STIGWATCH_RUN_COLLECTOR=1`), runs the collector as a normal user and as root (`sudo sh collectors/collect-linux.sh`, the documented command), validates the root output with `collect-parse linux --min-ok 40 --require sshd_config,packages,units,login_defs,shadow,audit_rules,sysctl_runtime` (a count alone would pass if a key fact went unreadable) and the normal-user output with `--min-ok 30`, scans the root output, and uploads both files as the `linux-collector-output` artifact. The full collector run test is skipped in the regular backend job, so that job does not spend its time on the filesystem-wide `find`; pytest runs with `-rs` so every skip is named.
- Fixtures under `backend/tests/fixtures/linux-*.json` are synthetic (invented host names), generated by `backend/scripts/make_linux_fixtures.py`; its `--check` mode, run by the tests, fails when they are out of date.
- **Facts not collected.** /etc/fstab mount options, the modes and owners of /etc/passwd, /etc/shadow and /etc/group, /etc/issue, and the list of UID 0 accounts are not collected, because no rule of the Ubuntu 22.04 V2R10 STIG checks them. (The UID 0 names are still visible in the passwd fact.)

## Windows Server 2022 collector and checks

### Collector (`collectors/collect-windows.ps1`)

- Per-fact try/catch, `secedit /export` to a temp file deleted in `finally`, auditpol keyed by subcategory GUID, registry reads through `OpenBaseKey`/`OpenSubKey($key, $false)`, `-RedactNames`, UTF-8 without BOM, PowerShell 5.1 and 7. 20 facts; each records the exact command. Envelope: `{"collector":"windows","version":1,"collected_at","host":{name,os,build},"privileged","redacted","powershell","facts":{...}}`.
- **Timestamps use the invariant culture.** `collected_at` and the account-age timestamps are formatted with `[Globalization.CultureInfo]::InvariantCulture`. With the host culture, fi-FI writes "." as the time separator and th-TH writes the Buddhist-calendar year (2569), which the server's strict `collected_at` check rejects. A test formats the collector's own expression under fi-FI and th-TH.
- `secedit /export /areas SECURITYPOLICY USER_RIGHTS` exports the local security database, where the security settings applied by Group Policy are recorded (account, lockout and Kerberos policy, security options, user rights). `/mergedpolicy` was rejected: on an unjoined runner that export had neither a [System Access] nor a [Privilege Rights] section (it holds only policy-defined settings), so the fact was unavailable and, on a domain member, missing keys could have read as "not configured". A secedit exit 740 is reported as "requires elevation"; a missing section is reported with the sections that were present.
- **Audit policy, locale independence.** `auditpol /backup /file:<temp>` writes a numeric "Setting Value" (0 none, 1 success, 2 failure, 3 both) that does not depend on the display language; the collector uses it first. If it fails, `auditpol /get /category:* /r` is used and the parser interprets only the English inclusion texts ("No Auditing", "Success", "Failure", "Success and Failure"). Any other text makes the whole `audit_policy` fact unavailable ("not English"), so every audit rule is Not_Reviewed. The subcategory GUIDs were confirmed with `auditpol /list /subcategory:* /v`.
- **Registry.** One fact holds every value the checks read (the `$RegistryValues` table). Each value is `set` (with its type), `absent` (key or value missing: "not configured") or `error` (unreadable: unknown). REG_DWORD data is normalised to unsigned. A value of the wrong type (REG_SZ "1" where the check text asks for REG_DWORD 1) is never treated as compliant: the comparison is unknown, so the rule is Not_Reviewed. A test checks that every registry value the checks use is in the collector's table.
- **User rights** are SIDs from `[Privilege Rights]`. secedit omits a right nobody holds, so every known right defaults to an empty list, but only when the section lists at least one known right (otherwise the fact is unavailable). A right granted to a name instead of a `*SID` is left unknown. Domain Admins and Enterprise Admins are matched as `S-1-5-21-*-512` and `S-1-5-21-*-519`: a local SAM never has those RIDs, and -519 exists only in the forest root domain.
- **Domain role** is `Win32_ComputerSystem.DomainRole`: 0/2 standalone, 1/3 member, 4/5 domain controller. It is the `na_if` fact for every DC-only rule (Not_Applicable on member and standalone servers) and every member-only rule (Not_Applicable on domain controllers; MS-000020/030/050 also on standalone systems, as their check texts say).
- **Features** come from `Get-WindowsFeature`; on a system without it, from `Get-WindowsOptionalFeature -Online` with a fixed name map (TelnetClient, TFTP, SimpleTCP, SMB1Protocol, MicrosoftWindowsPowerShellV2Root, IIS-FTPSvc, and `Microsoft-Hyper-V` for the Hyper-V role; Fax and PNRP have no optional-feature equivalent and stay unknown). `Installed` is a finding, `Available`/`Removed` are not, pending states are Not_Reviewed.
- **Volumes**: `Win32_Volume` (DriveType 3) with partition types from `Get-Partition`. System (EFI), Recovery and Reserved partitions are excluded as the check text allows. Without partition types only an unlettered system volume is excluded, and any other unlettered non-NTFS volume is unverified (Not_Reviewed). NTFS, ReFS and CSVFS pass; a lettered FAT/exFAT volume is Open.
- **File permissions** (`Get-Acl`, SIDs only): the Application, Security and System event logs (path from `Get-WinEvent -ListLog`, registry fallback), Eventvwr.exe, and on domain controllers the files in the NTDS database and log folders (from the NTDS registry values; files are listed, never opened) and the SYSVOL folder (the parent of the Netlogon `SysVol` value, the "first SYSVOL directory level"). Each NTDS folder is read inside its own try/catch: a folder that cannot be listed becomes an error entry in `ntds_files`, so WN22-DC-000070 is Not_Reviewed while the event log, Eventvwr and SYSVOL permissions survive. `local_admins` keeps each member's SID.
- **Firmware**: UEFI mode is `$env:firmware_type` (what System Information shows as BIOS Mode); Secure Boot is `Confirm-SecureBootUEFI`, as in the check text.
- **Where it is exercised.** The `windows-collector` CI job runs on `windows-2022` (elevated by default): the collector tests under Windows PowerShell 5.1; the collector under `pwsh` and under `powershell`, in separate steps, each native exit code checked; `collect-parse windows --min-ok 20 --require security_policy,user_rights,audit_policy,registry,features,domain_role,local_accounts,acls` and `scan` for each output, plus an assertion that `audit_policy` came from `auditpol /backup`; and both outputs uploaded as the `windows-collector-output` artifact. It also writes a summary of each output (facts read, unavailable facts with reasons, scan counts) as a workflow annotation. The collector-run test points `TEMP` and `TMP` at a fresh folder for the subprocess and asserts the folder is empty afterwards, since that is where secedit and auditpol write.
- An unelevated local run completes in about 10 s with 13 of 20 facts read: security_policy and user_rights (secedit exit 740), audit_policy, features, bitlocker, tpm and secure_boot are unavailable, and no `stigwatch-*` temporary file is left in `%TEMP%`.

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
  - DC-000010: who may administer the system is a judgement; members are listed.
  - DC-000090 to 000220, 000290 to 000310, 000406 and 000430: Active Directory objects, auditing, mappings and PKI judgements, or an LDAP bind the read-only collector does not make.
  - 00-000420/430: the IIS FTP configuration is not collected; Not_Applicable when the FTP service is not installed.
  - PK-000010 to 000030: DoD certificate presence is supporting evidence only.
- **Absent values the check text accepts**: CC-000130 (not set, 1, 3 or 8; 7 is a finding; other values need review) and CC-000310/320/330/400/440 (not set or 0; 1 is a finding).
- **AC-000010 / AC-000030**: secedit omits LockoutDuration and ResetLockoutCount when there is no lockout threshold. That is Not_Reviewed here (AC-000020 reports the threshold). A LockoutDuration of 0 or -1 (until an administrator unlocks) is not a finding.
- **AC-000050**: MaximumPasswordAge must be 1 to 180; 0 and -1 (never expires) are findings.
- **SO-000320**: LDAPClientIntegrity 1 is not a finding, missing or 0 is. 2 (require signing) is stricter than the check text's value and is Not_Reviewed.
- **SO-000360** is Not_Applicable when SharePoint is installed; the exception rests on product presence (the SharePoint Timer service SPTimerV4 is present, running or not). **MS-000140** is Not_Applicable when MSExchangeServiceHost is present (an Exchange server), as well as on domain controllers and standalone systems.
- **SO-000380 to 000450 and AU-000060** are Not_Applicable on Server Core (`InstallationType` "Server Core"). **AU-000060**: the `acl` operator takes `finding: modify`; a principal other than TrustedInstaller with Full control or Modify (all Modify bits, or GENERIC_ALL) is Open, and any other grant beyond read & execute, for example write only, is not what the check text names and is Not_Reviewed.
- **00-000020**: Not_Applicable when the built-in Administrator (RID 500) is disabled on a non-DC; Open when its password is older than 180 days; NotAFinding only on standalone systems (on domain members the LAPS portion needs review; the LAPS policy values are shown).
- **00-000100**: Not a finding on Windows Server 2022 (build 20348) collected on or before 10/15/2031, the Extended Support end the check text gives; any other OS is Not_Reviewed.
- **00-000250**: NotAFinding needs every protected fixed volume fully encrypted (`VolumeStatus` FullyEncrypted, or `EncryptionPercentage` 100). Protection on with encryption in progress is Not_Reviewed; protection off is still Open.
- **00-000440**: domain members must use NT5DS (the W32Time policy value wins over the service value). Standalone systems and domain controllers need a DoD time source, which is Not_Reviewed.
- **DC Kerberos rules (DC-000020 to 000060)** read the effective Kerberos policy that secedit exports on the domain controller. The check text names the Default Domain Policy; account policies take effect only from domain-level GPOs, so the effective value is the one in force.
- **MS-000080 to 000120**: Guests is required on all systems. Enterprise Admins and Domain Admins (and Local account where the rule names it) are required on domain-joined members only. MS-000100 must be empty on standalone systems. Nested Domain Admins membership is not resolved; such a rule is Not_Reviewed (fail-safe).
- **UR-000090**: Virtual Machines (S-1-5-83-0) is allowed only when the Hyper-V role is installed; with the feature list unreadable, a grant to Virtual Machines is Not_Reviewed. (S-1-5-82-0 is the IIS application pool authority, not Virtual Machines.)

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
- **Partial (1):** MS-000010. On a domain-joined member server, Domain Admins (any `S-1-5-21-*-512` member of the local Administrators group) is Open, because the check text requires it to be replaced by a member server administrator group. `domain_admins_member` is set only when every member has a SID. Otherwise the result is Not_Reviewed with the members and SIDs listed: whether the replacement group and the other members are "responsible for administration" cannot be proven on the host. Not_Applicable on domain controllers; standalone systems stay Not_Reviewed (the check text applies to them, and there are no Domain Admins to replace).
- **Evidence or applicability only (7):**
  - DC-000010: who is "responsible for administration" is a judgement; members are listed.
  - DC-000090, 000100 and 000110: Active Directory object permissions, not host facts.
  - DC-000150: needs an anonymous LDAP bind, an active test.
  - DC-000290 and DC-000300: DoD PKI / ECA issuer and UPN mapping judgements.

  All seven are domain-controller rules and are Not_Applicable on member and standalone servers, from the domain role.
- **Not host-checkable (1): WN22-00-000030.** It requires an organisational policy that keeps administrative accounts away from internet-facing applications, with technical enforcement "except as approved by the AO". AppLocker rules could be collected as evidence but cannot show the policy or the approvals.
- Coverage: 254 of 277 rules automated (229 can decide a result, 25 evidence or applicability only), 23 manual review. CAT I: 22 full, 1 partial (MS-000010), 7 evidence, 1 manual (00-000030).

### Fixtures and tests

- Synthetic fixtures `backend/tests/fixtures/windows-*.json` (member-compliant, noncompliant, unprivileged, dc, standalone, non-english) are generated by `backend/scripts/make_windows_fixtures.py`, which reads the registry list from the collector script. The tests run its `--check` mode.
- `tests/test_windows_checks.py` covers the Windows checks: unreadable facts are Not_Reviewed, Not_Applicable requires a fact, every STIG ID in the benchmark, coverage with the CAT I list, non-English auditpol, registry types, the ACL and SID operators, volumes, Kerberos, the CLI and a static no-write test of the collector. `test_collector_runs_on_windows` runs the real collector when `STIGWATCH_RUN_COLLECTOR=1` on Windows.
- There is no Hyper-V fixture for the WN22-UR-000090 branch that allows Virtual Machines on a Hyper-V host; that branch is covered by unit-level cases only.

## Remediation

- `remediation.py` derives each fix from the rule's check definition; a rule with any condition lacking a safe mapping is listed as manual, never half-fixed. Conditions the evidence already shows as met are skipped. A fully failing rule is automatable for 109 of 191 Ubuntu rules and 150 of 277 Windows rules (the README states the same figures, and a test asserts them against the generators). User-right rules are automated only when the scan shows who holds the right, so a script never removes a right wholesale. Excluded on purpose: user rights that can lock administrators out (network, interactive and remote-interactive logon rights), HKCU values, `in` lists with several acceptable values, PAM/grub/sudo/ACL rules.
- Registry type comes from the check value (number is DWord, text is String) and is refused when the rule's fix text names another REG_ type. File modes use chmod-style removal of excess bits so a file is never widened. The audit-rules handler reports that a reboot is needed for immutable rules. The sshd play first asserts that `/etc/ssh/sshd_config` has an Include of `sshd_config.d/*.conf`, and sshd changes are validated with `sshd -t`.
- **Access-affecting changes run only with `-IncludeAccessChanges`.** The Windows script is a dry run by default (`-Apply` changes anything). Registry values that decide who or what may connect or authenticate (signing, NTLM, anonymous access, UAC) and the user-right lists are marked `-AccessChange`, and so are the account-policy values that can deny sign-in: `LockoutBadCount`, `LockoutDuration`, `ResetLockoutCount` (a lockout threshold locks out service accounts with stale saved credentials) and `MaximumPasswordAge` (a shorter maximum age expires old passwords at once). Other account-policy values (length, complexity, history) stay with `-Apply` alone.
- Host names are sanitised for comments (a `#>` in a name once closed the PowerShell block comment; a test covers it) and never reach a templated Ansible field. CI parses every generated script with the PowerShell AST and dry-runs it, and runs `ansible-playbook --syntax-check` and `ansible-lint` on the generated playbooks. `.ansible-lint` skips only `command-instead-of-module` (SIGHUP to auditd is sent with `systemctl kill`).
- Windows remediation passes `domain_role_of(raw)`, as does `generate_remediation_samples.py`.

## Checklist formats

- Checklists (`exports.py`) follow section 3. A test compares the element and key names with a names-only fixture (`tests/fixtures/stig_viewer_field_names.json`). **The checklists have not been opened in STIG Viewer** (not downloaded, not run); the README says so under Limitations. The layout is DISA's public field set as written by tools that target STIG Viewer, so a checklist is expected to import, but that is not verified.
- **Fields.** `Group_Title` / `group_title` is the group's SRG requirement id, which the catalog keeps from the XCCDF `Group/title`. Classification is `UNCLASSIFIED` (the public benchmarks are marked so) in the CKL `STIG_INFO` and the CKLB `classification`; `VULN` `Class` is `Unclass`. `ASSET` has `TARGET_COMMENT` (the disclaimer, plus any release-mismatch notice), `Check_Content_Ref` is `M` (manual), `TargetKey` / `target_key` is the DPMS target key, `STIG_UUID` is the checklist's STIG uuid, and `LEGACY_ID` / `legacy_ids` carry the legacy ids the XCCDF lists (none today, so one empty `LEGACY_ID` entry per rule). `ROLE` comes from the stored domain_role fact (Windows), else `None`.
- UUIDs are UUIDv5 over host, benchmark and rule, so every scan of a host shares them (STIG Viewer's handling of a repeated checklist id is unknown); timestamps are the scan's `collected_at`. Output is deterministic.
- **Comments follow the scan.** The host's latest scan exports the live assessor comment (a deleted comment stays deleted); an earlier scan exports the comment as it was when that scan was stored, so history is never rewritten and deleted comments are not resurrected.
- **Release labelling** is described under "Benchmark releases".
- Compliance in the fleet report and `/api/fleet` is NotAFinding / (Open + NotAFinding), computed in one function (`constants.compliance_percent`).
- Fleet reports: CSV with formula-looking cells neutralised, and one self-contained, script-free HTML file served as a download with `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; sandbox`, `X-Frame-Options: DENY` and a sanitised file name.

## REST API and uploads

- All routes live under `/api`. Uploads: `POST /api/scans` matches the host named in the collector file (case-insensitive) or creates it; `POST /api/hosts/{id}/scans` adds to an existing host and answers 409 when the file's host name differs. Multipart (`file` part) or a raw JSON body. The guest/writer check runs before an upload body is read. (JSON routes read their small, size-capped body first, because FastAPI parses it before resolving dependencies; the 64 KiB cap bounds that.)
- Host-name reuse: a file for an existing name is accepted only when the collector's fingerprint (os and benchmark) matches the host; otherwise 409 with a message. Invalid host names (anything outside `[A-Za-z0-9._-]`, over 253 characters, path separators, newlines) are 400 on upload and 422 on `POST /api/hosts`.
- `collected_at` must be ISO 8601 with `Z` or an explicit offset; it is stored as `YYYY-MM-DDTHH:MM:SSZ` (UTC). Naive, date-only, pre-2000 and more-than-one-day-future values are 400.
- Out-of-order uploads are accepted. Drift is computed on demand from the host's ordering, so only CAT I alerts need work: the alerts of the scan that now follows are deleted and recomputed against its new predecessor (`db.rebuild_next_alerts`); the response says `out_of_order` and which scan was recomputed.
- Upload limits: 413 over `STIGWATCH_MAX_UPLOAD_MB` (Content-Length precheck and streamed count) or a line over 65,536 characters, 415 for NUL bytes, non-UTF-8 or an unsupported content type, 400 for invalid JSON, nesting deeper than 32 levels, an unknown collector or a bad envelope. Body caps: 64 KiB for every route except the scan uploads (`/api/scans`, `/api/hosts/{id}/scans`, with or without a trailing slash), which keep the upload cap plus a multipart allowance; a declared Content-Length over the cap is refused before any byte is read, and chunked bodies are counted as they arrive.
- Drift responses carry `newly_visible_cat1` (CAT I rules Open now that were Not_Reviewed before); `/api/fleet` lists them for every host's latest scan. `/api/fleet` also reports, per week, the findings that lost visibility (Open to Not_Reviewed) so the dashboard does not present them as fixed.
- `/api/alerts` returns each alert with the `collected_at` of its scan and the `from_status` the rule regressed from, so clients need neither to parse the message nor to join scan lists. Alerts are stored with the scan date as `created_at`.
- `/docs`, `/redoc` and `/openapi.json` are off; `/api/openapi.json` is served to writers only.
- **Demo seeding** is lazy, once per process and database (double-checked under a lock). A failure is logged once and remembered for 60 s; during that time every data route answers 503 `{"detail": "Demo data is not available yet"}` with `Retry-After: 60`, then seeding is tried again. `/api/health` and the auth routes do not need the data. The first request on an empty demo database seeds the 14-host, 8-week fleet in about 0.6 s on a development machine, so a cold serverless instance answers its first data request slowly.
- **`privileged`:** scan objects carry `privileged`, read from the collector's own top-level `privileged` flag in the stored scan JSON. It is tri-state: `true` or `false` only when the stored value is that JSON boolean, `null` when it is missing or null (unknown is not the same as not privileged; the UI makes no claim on null).
- **Environment values.** A blank environment variable counts as unset everywhere in `config.py` (database path, upload cap, session hours, data directory, admin user), so copying `.env.example` verbatim works; malformed or non-positive numbers fall back to the default. A blank `STIGWATCH_DB` used to resolve to the working directory and made every data route fail.
- **Client address and `X-Forwarded-For`.** The login rate limit keys on the client address. `X-Forwarded-For` is trusted only when configured: `STIGWATCH_TRUST_PROXY=true` (one proxy) or `STIGWATCH_TRUSTED_PROXIES=<count>`. The address is the entry that many places from the right, never the left-most, because proxies that append (Render, Fly, nginx's `$proxy_add_x_forwarded_for`) leave the client's own header on the left, and rotating it would dodge the limiter. Vercel overwrites the header, so its entry point sets `STIGWATCH_TRUST_PROXY`; `create-admin --print` says so and gives the hop-count alternative.
- **Known N+1:** `/api/hosts`, `/api/fleet` and the fleet exports run a few queries per host (summary counts, latest scan, drift). That is fine for tens of hosts (the demo fleet is 14) and would be replaced by grouped queries before hundreds.
- Downloaded fleet HTML and checklists use `attachment` with a sanitised file name.

## Dashboard

- **Fleet report preview.** The HTML report is served as an attachment with `X-Frame-Options: DENY` and a `sandbox` CSP, so it cannot be framed. The Reports page therefore draws the preview as React text from `/api/fleet` and `/api/hosts` (same numbers) and never inserts report HTML into the page.
- **Syntax highlighting** is a small tokeniser (`src/highlight.js`) returning plain data; the page renders each token as a React span with a text child. No `innerHTML` is used anywhere.
- **Fleet drift** has no backend endpoint of its own: the page reads each host's scan list, takes the fleet trend for the weekly totals, and loads per-scan drift only for the selected week. Drift and Findings read each host's scan list and latest results from the browser, so they cost O(hosts) requests: fine at the demo's 14 hosts, while a larger fleet needs a server-side aggregate (and the grouped queries noted above).
- **Lost visibility is not improvement.** The KPI delta on the Fleet page treats a decrease that includes findings which went from Open to Not_Reviewed as neutral and says how many lost visibility; only a decrease without them is shown as "fewer" in the good tone.
- **Privilege.** The "ran without root" notice uses the tri-state `scan.privileged` (only `false` shows it); reason-text matching is not used anywhere, including the per-rule callout.
- **Router.** react-router-dom 7; URL filters live in `useUrlFilters`, which builds each update on the last one sent so quick changes do not undo each other.
- The disclaimer text in `src/lib.js` and in the backend is the same; a test compares them. The week bucketing (Monday of the week, UTC) is implemented in `db._week_start` and `lib.weekStart`; both are tested against the same dates.

## Deployment, documentation and CI

- **Entry point.** `api/index.py`: `vercel.json` rewrites `/api/*` to it, FastAPI routes on the original path, and the function includes `backend/stigwatch/**` (the package and its check YAML) and `backend/data/**` (benchmarks and demo fixture). The demo database lives in `/tmp` and is seeded lazily per instance; data routes answer 503 with `Retry-After` until it is ready and the dashboard retries. The live demo linked in the README runs on this entry point.
- **Upload size on Vercel.** Vercel Functions accept at most 4.5 MB for a request body and answer larger ones with `413 FUNCTION_PAYLOAD_TOO_LARGE` before the app runs (https://vercel.com/docs/functions/limitations#request-body-size, https://vercel.com/docs/errors/function_payload_too_large, read 2026-11-10). The app's default upload cap is 10 MB, so the entry point lowers `STIGWATCH_MAX_UPLOAD_MB` to 4 and never allows more (4 MB plus the 64 KiB multipart allowance stays under 4.5 MB). A platform rejection is plain text, not the API's JSON, so the dashboard shows a fixed sentence for any 413 that did not carry the API's own `detail`, and 502/504 get their own message. `/api/health` reports `max_upload_mb` and the upload form refuses a larger file before sending it. Self-hosted installs keep the 10 MB default.
- **Path through the rewrite.** The body cap matches `scope["path"]`. `tests/test_entrypoint.py` imports `api/index.py` and checks that `/api/scans`, `/api/scans/` and `/api/hosts/{id}/scans` get the upload cap (200 KB passes, 5 MB is the app's 413) while every other route keeps 64 KiB. That is what the entry point does when the path is preserved; it can only be observed on Vercel itself after a deployment (a 200 KB POST to `/api/scans` as a guest should answer 403, not 413).
- **Admin writes on the hosted demo are deliberate.** An admin login exists only if the owner sets `STIGWATCH_ADMIN_PASSWORD_HASH` and `STIGWATCH_SECRET_KEY`; the public demo is deployed without them, so visitors are read-only guests. When the owner does enable an admin, the writes they make (uploads, hosts, assessor comments) are visible to every visitor whose request lands on the same instance. That is acceptable because the password is the owner's alone, login attempts are rate-limited, and the SQLite file is in `/tmp`, which is discarded when the instance is replaced, so the demo resets itself. The dashboard shows "Demo: changes you make are visible to other visitors until the demo resets." beside every admin control while the session is in demo mode and not a guest. Sessions are stateless signed tokens with an 8-hour expiry and no server-side revocation, and the login limiter is per instance and in memory, which suits a serverless demo.
- **Coverage tables** are generated, not typed: `python -m stigwatch coverage --write` rewrites `docs/COVERAGE.md` and the README summary between the `coverage:start`/`coverage:end` markers, and `coverage --check` (CI) fails when either is stale. Every coverage figure in the README text (Ubuntu 174 automated checks, Windows 254 automated and 150 of 277 with remediation, Ubuntu remediation 109 of 191) is asserted against the generators by a test.
- **`demo --check`** seeds a scratch database from the committed fixture and requires the stored open CAT I/II/III counts of every host and week to equal the counts recorded in the fixture; a seeding failure is reported as a failed check. `demo --serve` serves the demo on its own database in demo mode; `serve` runs the API.
- **CI.** The real collector jobs run the documented commands: `sudo sh collectors/collect-linux.sh` then `collect-parse linux out.json` on `ubuntu-22.04`, and the PowerShell collector under PowerShell 7 and Windows PowerShell 5.1 in separate steps on `windows-2022`. pytest runs with `-rs` so every skipped test is named; the sshd `grep` test must appear as passed, not skipped, on Linux. An `e2e` job drives the built dashboard against the demo API with Playwright. CI also runs `pip-audit`, `npm audit` and gitleaks.
- **Public-source claims in the README** are limited to what DISA's own STIG Overview documents state (section 1.2 Authority, 1.3 severity categories, 1.7 other considerations), which ship in the DISA packages listed in section 1; the DoDI 8500.01 wording is quoted as DISA quotes it, because the DoD issuances site refused automated access (HTTP 403) and the cyber.mil pages are JavaScript-rendered.
- Known limitation: optional SSH scanning is not implemented; collectors are run on the host and their output uploaded.
