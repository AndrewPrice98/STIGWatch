"""Build backend/data/demo_fixture.json, the fictional demo fleet.

Deterministic: running it twice gives identical output, and a test checks that the
committed fixture equals a fresh build. Everything here is invented: 14 hosts (8 Ubuntu
22.04, 6 Windows Server 2022) with 8 weekly scans each. The fixture holds the inputs
(templates from tests/fixtures, small named defects and the weeks they are present);
stigwatch.demo rebuilds each scan's collector JSON from them and runs the real engine.
The build also runs the engine to record the expected open CAT I/II/III counts, which
the tests compare with what seeding stores.

The story:
  - most hosts improve week over week as defects are fixed (a few have a short relapse);
  - in week 6 a change re-opens CAT I findings on two prod hosts: web-01 (an old sshd
    drop-in restored: PermitEmptyPasswords and X11Forwarding) and file-01 (a GPO
    rollback: reversible password encryption, anonymous SID/name translation, SMBv1);
  - week 8 fixes part of it (X11Forwarding and the anonymous translation);
  - ci-01 is scanned by a normal user in every week, so most of its rules are Not Reviewed.

    python scripts/build_demo.py            # write the fixture
    python scripts/build_demo.py --check    # exit 1 if the committed file is stale
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from stigwatch import benchmarks, demo  # noqa: E402
from stigwatch.checks import engine  # noqa: E402

OUT = BACKEND / "data" / "demo_fixture.json"
FIXTURES = BACKEND / "tests" / "fixtures"
START = "2026-09-21"   # Monday of week 1; week 8 is 2026-11-09
WEEKS = 8

TEMPLATE_FILES = {
    "linux-compliant": "linux-compliant.json",
    "linux-unprivileged": "linux-unprivileged.json",
    "windows-member-compliant": "windows-member-compliant.json",
    "windows-dc": "windows-dc.json",
}
DONOR_FILES = {"linux": "linux-noncompliant.json", "windows": "windows-noncompliant.json"}
BENCHMARK = {"linux": "ubuntu-22.04", "windows": "windows-server-2022"}
# Facts that carry the story defects below; the generic defect pool leaves them alone so
# the week-6 rules are compliant until the story re-opens them.
STORY_FACTS = {"linux": {"sshd_config"}, "windows": {"security_policy", "features"}}

STORY_DEFECTS = {
    "linux": {
        "sshd.permit_empty_passwords": {
            "op": "text", "fact": "sshd_config",
            "find": "PermitEmptyPasswords no", "replace": "PermitEmptyPasswords yes"},
        "sshd.x11_forwarding": {
            "op": "text", "fact": "sshd_config",
            "find": "X11Forwarding no", "replace": "X11Forwarding yes"},
    },
    "windows": {
        "secpol.reversible_passwords": {
            "op": "set", "fact": "security_policy",
            "path": ["System Access", "ClearTextPassword"], "value": "1"},
        "secpol.anonymous_sid_translation": {
            "op": "set", "fact": "security_policy",
            "path": ["System Access", "LSAAnonymousNameLookup"], "value": "1"},
        "feature.smb1": {
            "op": "set", "fact": "features", "path": ["states", "FS-SMB1"], "value": "Installed"},
    },
}

# name, os, template, environment, owner, tags, initial defects, defects that stay open,
# whether the host relapses once (a fixed defect comes back for two weeks), how many CAT I
# defects are never fixed
HOSTS = [
    ("web-01", "linux", "linux-compliant", "prod", "Platform Web", ["web", "internet-facing"], 16, 1, False, 0),
    ("web-02", "linux", "linux-compliant", "prod", "Platform Web", ["web", "internet-facing"], 14, 2, False, 0),
    ("api-01", "linux", "linux-compliant", "prod", "Backend Services", ["api"], 12, 1, True, 0),
    ("db-01", "linux", "linux-compliant", "prod", "Data Platform", ["database"], 10, 0, False, 0),
    ("db-02", "linux", "linux-compliant", "staging", "Data Platform", ["database"], 20, 4, False, 1),
    ("jump-01", "linux", "linux-compliant", "prod", "Infrastructure", ["bastion"], 9, 1, False, 0),
    ("ci-01", "linux", "linux-unprivileged", "dev", "DevOps", ["ci", "unprivileged-scan"], 6, 2, False, 0),
    ("log-01", "linux", "linux-compliant", "staging", "Security Operations", ["logging"], 18, 3, True, 0),
    ("dc-01", "windows", "windows-dc", "prod", "Identity", ["domain-controller"], 5, 1, False, 0),
    ("app-01", "windows", "windows-member-compliant", "staging", "Line of Business", ["app"], 9, 2, False, 0),
    ("file-01", "windows", "windows-member-compliant", "prod", "Infrastructure", ["file-server"], 7, 1, False, 0),
    ("rds-01", "windows", "windows-member-compliant", "prod", "End User Computing", ["remote-desktop"], 10, 3, True, 0),
    ("mgmt-01", "windows", "windows-member-compliant", "dev", "Infrastructure", ["management"], 11, 4, False, 0),
    ("bkp-01", "windows", "windows-member-compliant", "dev", "Data Platform", ["backup"], 8, 2, False, 1),
]

# host -> list of (defect id -> spans) added by the story: [start week, end week) spans
STORY_INTERVALS = {
    "web-01": {"sshd.permit_empty_passwords": [[6, 9]], "sshd.x11_forwarding": [[6, 8]]},
    "file-01": {"secpol.reversible_passwords": [[6, 9]], "secpol.anonymous_sid_translation": [[6, 8]],
                "feature.smb1": [[6, 9]]},
}

COMMENTS = [
    ("ci-01", "UBTU-22-611065", 1,
     "The scan ran as a normal user, so /etc/shadow could not be read. Re-run the collector with sudo."),
    ("web-01", "UBTU-22-255025", 6,
     "Re-opened by CHG-2291, which restored an old sshd drop-in. INC-5530 raised; owner Platform Web."),
    ("web-01", "UBTU-22-255025", 8,
     "X11Forwarding is fixed. PermitEmptyPasswords still waits for the CHG-2291 rollback window on Friday."),
    ("file-01", "WN22-AC-000090", 6,
     "A group policy rollback re-enabled reversible encryption. INC-5534 raised; Infrastructure is restoring the baseline GPO."),
    ("db-02", "UBTU-22-215035", 2,
     "Vendor support tool needs telnetd on staging only. Exception RA-114 expires 2027-01-31."),
]


def _digest(*parts: str) -> int:
    return int(hashlib.sha256(":".join(parts).encode()).hexdigest()[:12], 16)


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _pool(os: str, template: dict, donor: dict, compliant: dict) -> list[str]:
    """Facts whose value differs between the compliant and the non-compliant fixture and
    that are readable in this template: swapping one in re-creates its findings."""
    return [f for f in compliant["facts"]
            if f not in STORY_FACTS[os] and compliant["facts"][f] != donor["facts"].get(f)
            and template["facts"][f]["status"] == "ok" and donor["facts"][f]["status"] == "ok"]


def cat1_impact(os: str, template: dict, donor: dict, pool: list[str]) -> dict[str, int]:
    """Open CAT I rules each pool defect adds to the template (from the real engine)."""
    bench = benchmarks.load_benchmark(BENCHMARK[os])
    cat1 = {r.stig_id for r in bench.rules if r.cat == "CAT I"}
    base = {r.stig_id for r in engine.evaluate(template, bench) if r.status == engine.OPEN}
    out = {}
    for fact in pool:
        raw = copy.deepcopy(template)
        raw["facts"][fact] = donor["facts"][fact]
        opened = {r.stig_id for r in engine.evaluate(raw, bench) if r.status == engine.OPEN}
        out[fact] = len((opened - base) & cat1)
    return out


def _intervals(name: str, pool: list[str], impact: dict[str, int], initial: int, stay: int,
               keep_cat1: int, relapse: bool) -> dict:
    """Which weeks each generic defect is present. The first `initial` defects (in a
    per-host hash order) are present from week 1. Defects that cause CAT I findings are
    fixed first (weeks 2 to 5, so the week-6 story stands out), the rest one after another
    up to week 8. The last `stay` defects are never fixed; `keep_cat1` of those are CAT I
    ones. A relapse brings one early fix back for two weeks."""
    chosen = sorted(pool, key=lambda d: _digest(name, d))[:initial]
    cat1 = [d for d in chosen if impact[d]]
    rest = [d for d in chosen if not impact[d]]
    kept = cat1[len(cat1) - keep_cat1:] if keep_cat1 else []
    fixed_cat1 = [d for d in cat1 if d not in kept]
    never = (rest[len(rest) - stay:] if stay else []) + kept
    fixed_rest = [d for d in rest if d not in never]
    spans: dict[str, list[list[int]]] = {}
    fix_weeks = []
    for j, d in enumerate(fixed_cat1):
        fixed = 2 + (j * 4) // len(fixed_cat1)
        spans[f"fact.{d}"] = [[1, fixed]]
        fix_weeks.append((fixed, f"fact.{d}"))
    for j, d in enumerate(fixed_rest):
        fixed = 2 + (j * (WEEKS - 1)) // len(fixed_rest)
        spans[f"fact.{d}"] = [[1, fixed]]
        fix_weeks.append((fixed, f"fact.{d}"))
    for d in never:
        spans[f"fact.{d}"] = [[1, WEEKS + 1]]
    if relapse:
        fixed, defect = min(fw for fw in fix_weeks if fw[0] >= 2 and not impact[fw[1][5:]])
        spans[defect].append([fixed + 2, fixed + 4])
    return spans


def build() -> dict:
    templates = {k: _load(v) for k, v in TEMPLATE_FILES.items()}
    donors = {k: _load(v) for k, v in DONOR_FILES.items()}
    compliant = {"linux": templates["linux-compliant"], "windows": templates["windows-member-compliant"]}
    defects: dict[str, dict] = {"linux": {}, "windows": {}}
    used_donors: dict[str, dict] = {"linux": {}, "windows": {}}
    hosts = []
    for name, os, template, env, owner, tags, initial, stay, relapse, keep in HOSTS:
        pool = _pool(os, templates[template], donors[os], compliant[os])
        impact = cat1_impact(os, templates[template], donors[os], pool)
        spans = _intervals(name, pool, impact, initial, stay, keep, relapse)
        for key in spans:
            fact = key.removeprefix("fact.")
            defects[os][key] = {"op": "swap", "fact": fact}
            used_donors[os][fact] = donors[os]["facts"][fact]
        for key, value in STORY_INTERVALS.get(name, {}).items():
            spans[key] = value
            defects[os][key] = STORY_DEFECTS[os][key]
        hosts.append({
            "name": name, "os": os, "benchmark_id": BENCHMARK[os], "environment": env,
            "owner": owner, "tags": tags, "template": template,
            "offset_minutes": _digest(name) % 150,
            "intervals": {k: spans[k] for k in sorted(spans)},
        })
    fixture = {
        "format": demo.FIXTURE_FORMAT,
        "note": "Fictional demo fleet. Inputs only; stigwatch.demo rebuilds and evaluates each scan.",
        "start": START, "weeks": WEEKS,
        "templates": templates,
        "donors": {os: dict(sorted(d.items())) for os, d in used_donors.items()},
        "defects": {os: dict(sorted(d.items())) for os, d in defects.items()},
        "hosts": hosts,
        "comments": [{"host": h, "stig_id": s, "week": w, "text": t} for h, s, w, t in COMMENTS],
    }
    evaluate(fixture)
    return fixture


def evaluate(fixture: dict) -> None:
    """Run the real engine over every scan and record the outcome in the fixture: the
    distinct rule results per OS (``results``), the rule lists of the distinct scan states
    (``states``), each host's state per week and the open CAT I/II/III counts (``expected``)."""
    plan = demo.scan_plan(fixture)
    outcome = demo.evaluate_plan(plan)
    cats = {b: {r.stig_id: r.cat for r in demo.bundled_benchmark(b).rules}
            for b in set(BENCHMARK.values())}
    table: dict[str, list] = {"linux": [], "windows": []}
    index: dict[str, dict[str, int]] = {"linux": {}, "windows": {}}
    states: dict[str, list[list[int]]] = {"linux": [], "windows": []}
    state_ids: dict[tuple, int] = {}
    for host in fixture["hosts"]:
        host["states"] = []
    expected: dict[str, list[list[int]]] = {}
    for host, week, _raw in plan:
        os, key = host["os"], demo.state_key(host, week)
        if key not in state_ids:
            ids = []
            for r in outcome[key]:
                row = [r.stig_id, r.status, r.reason, [dict(e) for e in r.evidence]]
                dedup = json.dumps(row, separators=(",", ":"), ensure_ascii=False)
                if dedup not in index[os]:
                    index[os][dedup] = len(table[os])
                    table[os].append(row)
                ids.append(index[os][dedup])
            state_ids[key] = len(states[os])
            states[os].append(ids)
        host["states"].append(state_ids[key])
        c = cats[host["benchmark_id"]]
        opened = [r.stig_id for r in outcome[key] if r.status == engine.OPEN]
        expected.setdefault(host["name"], []).append(
            [sum(1 for s in opened if c[s] == cat) for cat in ("CAT I", "CAT II", "CAT III")])
    fixture["results"], fixture["states"], fixture["expected"] = table, states, expected


def render(fixture: dict) -> str:
    """One top-level key per line, compact values: stable and reviewable in a diff."""
    dump = lambda v: json.dumps(v, separators=(",", ":"), ensure_ascii=False)  # noqa: E731
    return "{\n" + ",\n".join(f"{dump(k)}:{dump(v)}" for k, v in fixture.items()) + "\n}\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--check", action="store_true", help="exit 1 if the committed fixture is stale")
    args = parser.parse_args(argv)
    text = render(build())
    if args.check:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != text:
            print(f"{OUT} is out of date; run: python scripts/build_demo.py", file=sys.stderr)
            return 1
        print("demo fixture is current")
        return 0
    OUT.write_bytes(text.encode("utf-8"))
    print(f"wrote {OUT} ({len(text) / 1024:.0f} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
