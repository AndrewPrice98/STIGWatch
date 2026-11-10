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
