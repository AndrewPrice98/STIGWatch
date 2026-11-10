"""The fictional demo fleet: 14 invented hosts, 8 weekly scans each, loaded into an empty database.

``backend/data/demo_fixture.json`` is built by ``backend/scripts/build_demo.py`` and holds the
*inputs* of the fleet, not its results:

  templates   fixture-shaped collector JSON (the synthetic fixtures in tests/fixtures)
  donors      fact values from the non-compliant fixtures, used to re-create findings
  defects     named, small mutations of a template (swap a fact, edit a config line, set a value)
  hosts       name, OS, environment, owner, the weeks in which each defect is present and,
              per week, the index of the scan state whose results the scan has
  results     per OS, the distinct rule results the engine produced (status, reason, evidence)
  states      per OS, one list of indices into ``results`` per distinct scan state
  comments    assessor comments (they persist across later scans of the host)
  expected    open CAT I/II/III counts per host and week

Every scan is produced by applying that week's defects to the host's template (fixture-shaped
collector JSON) and running the real check engine. build_demo.py does that and records the
outcome in ``results`` and ``states``, so no result is written by hand. Seeding rebuilds each
scan's collector JSON and stores it with the recorded results: evaluating the 90-odd distinct
states at every cold start would take over a second and the full results are about 20 MB, so
the fixture keeps each distinct rule result once (about 2 MB). Tests re-run the engine over
every seeded scan's stored raw JSON and require the same results, and require the committed
fixture to equal a fresh build. Everything in the fixture is invented.
"""

from __future__ import annotations

import copy
import json
import logging
import sqlite3
import threading
from datetime import date, timedelta

from . import benchmarks, config, db
from .checks import engine

log = logging.getLogger(__name__)
_seed_lock = threading.Lock()

FIXTURE_FORMAT = 1


def load_fixture() -> dict:
    with open(config.DEMO_FIXTURE, encoding="utf-8") as handle:
        return json.load(handle)


# -- rebuilding a scan from the fixture ----------------------------------------------------

def active_defects(host: dict, week: int) -> list[str]:
    """Defect ids present on the host in the given week (1-based), in a fixed order."""
    return sorted(d for d, spans in host["intervals"].items()
                  if any(start <= week < end for start, end in spans))


def apply_defect(raw: dict, spec: dict, donors: dict) -> None:
    """Mutate fixture-shaped collector JSON in place. Raises if the defect does not fit
    the template, so a fixture that drifted from the collector shape fails loudly."""
    fact = raw["facts"][spec["fact"]]
    op = spec["op"]
    if op == "swap":
        if fact["status"] != "ok":
            raise ValueError(f"cannot swap unreadable fact {spec['fact']}")
        raw["facts"][spec["fact"]] = copy.deepcopy(donors[spec["fact"]])
    elif op == "text":
        value = fact["value"]
        key = spec.get("key", "text")
        if spec["find"] not in value[key]:
            raise ValueError(f"{spec['find']!r} not found in {spec['fact']}.{key}")
        value[key] = value[key].replace(spec["find"], spec["replace"], 1)
    elif op == "set":
        node = fact["value"]
        for step in spec["path"][:-1]:
            node = node[step]
        node[spec["path"][-1]] = spec["value"]
    else:
        raise ValueError(f"unknown defect operation {op!r}")


def collected_at(fixture: dict, host: dict, week: int) -> str:
    day = date.fromisoformat(fixture["start"]) + timedelta(days=7 * (week - 1))
    minutes = host["offset_minutes"]
    return f"{day.isoformat()}T{2 + minutes // 60:02d}:{minutes % 60:02d}:{(minutes * 7) % 60:02d}Z"


def build_raw(fixture: dict, host: dict, week: int) -> dict:
    """The collector JSON the host would have produced in the given week."""
    raw = copy.deepcopy(fixture["templates"][host["template"]])
    donors = fixture["donors"][host["os"]]
    specs = fixture["defects"][host["os"]]
    for defect in active_defects(host, week):
        apply_defect(raw, specs[defect], donors)
    raw["host"]["name"] = host["name"]
    raw["collected_at"] = collected_at(fixture, host, week)
    return raw


def state_key(host: dict, week: int) -> tuple:
    """Scans with the same template, active defects and collection day have identical
    results: the host name does not matter, but some facts (for example the age of the
    built-in administrator's password) are computed from the collection date."""
    return (host["template"], tuple(active_defects(host, week)), week)


def scan_plan(fixture: dict) -> list[tuple[dict, int, dict]]:
    """(host, week, raw collector JSON) for every scan, host by host."""
    return [(host, week, build_raw(fixture, host, week))
            for host in fixture["hosts"] for week in range(1, fixture["weeks"] + 1)]


def bundled_benchmark(benchmark_id: str) -> benchmarks.Benchmark:
    """The benchmark shipped with STIGWatch, never a locally imported release, so the demo
    is the same on every machine."""
    return benchmarks.load_benchmark_file(benchmarks.BUNDLED_DIR / f"{benchmark_id}.json")


def evaluate_plan(plan: list) -> dict[tuple, list]:
    """Run the real engine once per distinct state. Used by build_demo.py, which stores the
    outcome in the fixture, and by the tests that check the stored results against the engine."""
    cache: dict[tuple, list] = {}
    bench: dict[str, benchmarks.Benchmark] = {}
    for host, week, raw in plan:
        key = state_key(host, week)
        if key not in cache:
            if host["benchmark_id"] not in bench:
                bench[host["benchmark_id"]] = bundled_benchmark(host["benchmark_id"])
            cache[key] = engine.evaluate(raw, bench[host["benchmark_id"]])
    return cache


# -- seeding -------------------------------------------------------------------------------

def _already_seeded(conn: sqlite3.Connection) -> bool:
    return conn.execute("SELECT 1 FROM hosts LIMIT 1").fetchone() is not None


def prepared_states(fixture: dict) -> dict[str, list[list[tuple]]]:
    """Per OS, per state: result rows (stig_id, status, cat, reason, evidence_json) ready to
    insert. Each distinct result is serialised once and shared by every state that has it."""
    out: dict[str, list[list[tuple]]] = {}
    for os, table in fixture["results"].items():
        benchmark_id = next(h["benchmark_id"] for h in fixture["hosts"] if h["os"] == os)
        cats = {r.stig_id: r.cat for r in bundled_benchmark(benchmark_id).rules}
        rows = [(sid, status, cats[sid], reason,
                 json.dumps(evidence, separators=(",", ":"), ensure_ascii=False))
                for sid, status, reason, evidence in table]
        out[os] = [[rows[i] for i in state] for state in fixture["states"][os]]
    return out


def seed(conn: sqlite3.Connection) -> bool:
    """Load the demo fleet in one transaction: either everything is stored or nothing is.
    Returns False (and does nothing) if the database already has hosts, so calling it
    twice is safe."""
    if _already_seeded(conn):
        return False
    fixture = load_fixture()
    if fixture.get("format") != FIXTURE_FORMAT:
        raise ValueError("unsupported demo fixture format")
    # Everything that takes time is prepared before the write lock is taken.
    plan = scan_plan(fixture)
    states = prepared_states(fixture)
    comments: dict[tuple[str, int], list[dict]] = {}
    for c in fixture["comments"]:
        comments.setdefault((c["host"], c["week"]), []).append(c)
    benches = {b: bundled_benchmark(b) for b in {h["benchmark_id"] for h in fixture["hosts"]}}

    conn.commit()  # no transaction may be open when taking the write lock
    conn.execute("BEGIN IMMEDIATE")
    try:
        # Re-check under the write lock: another process may have seeded meanwhile.
        if _already_seeded(conn):
            conn.rollback()
            return False
        host_ids = {}
        for h in fixture["hosts"]:
            host_ids[h["name"]] = db.add_host(
                conn, h["name"], h["os"], h["benchmark_id"], environment=h["environment"],
                owner=h["owner"], tags=h["tags"], commit=False)
        for host, week, raw in plan:
            host_id = host_ids[host["name"]]
            for c in comments.get((host["name"], week), []):
                db.set_comment(conn, host_id, c["stig_id"], c["text"],
                               updated_at=raw["collected_at"], commit=False)
            db.add_scan(conn, host_id, raw, benches[host["benchmark_id"]],
                        prepared=states[host["os"]][host["states"][week - 1]],
                        uploaded_at=raw["collected_at"], commit=False)
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    return True


def ensure_seeded() -> None:
    """Create and seed the database if this instance does not have one yet."""
    with _seed_lock:
        conn = db.connect()
        try:
            if seed(conn):
                log.info("Seeded demo database at %s", config.db_path())
        finally:
            conn.close()
