"""SQLite storage for hosts, scans, results, assessor comments and CAT I alerts.

The raw collector JSON of every scan is kept, so a scan can be re-evaluated against a
newer benchmark release. Results are stored as the engine produced them; counts and
trends are always computed from ``results``. All SQL is parameterized.
"""

from __future__ import annotations

import json
import re
import sqlite3
import time
from contextlib import nullcontext
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from . import config
from . import drift as drift_mod
from .benchmarks import Benchmark, load_benchmark
from .checks import engine

SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL UNIQUE,
    os            TEXT NOT NULL CHECK (os IN ('linux','windows')),
    benchmark_id  TEXT NOT NULL,
    environment   TEXT NOT NULL DEFAULT '',
    owner         TEXT NOT NULL DEFAULT '',
    tags          TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS scans (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id            INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    benchmark_id       TEXT NOT NULL,
    benchmark_release  TEXT NOT NULL,
    collected_at       TEXT NOT NULL,
    uploaded_at        TEXT NOT NULL,
    raw_json           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_host ON scans(host_id, collected_at, id);

-- cat is the rule's severity category in the benchmark release the scan used.
-- comment is the assessor comment that applied when the scan was stored (a snapshot);
-- the live comment is in the comments table.
CREATE TABLE IF NOT EXISTS results (
    scan_id       INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    stig_id       TEXT NOT NULL,
    status        TEXT NOT NULL CHECK (status IN ('Open','NotAFinding','Not_Applicable','Not_Reviewed')),
    cat           TEXT NOT NULL CHECK (cat IN ('CAT I','CAT II','CAT III')),
    reason        TEXT NOT NULL DEFAULT '',
    evidence_json TEXT NOT NULL DEFAULT '[]',
    comment       TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (scan_id, stig_id)
);

-- Assessor comments belong to a host and a STIG ID, not to a scan, so they persist.
CREATE TABLE IF NOT EXISTS comments (
    host_id    INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    stig_id    TEXT NOT NULL,
    text       TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (host_id, stig_id)
);

CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id      INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    scan_id      INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    prev_scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    stig_id      TEXT NOT NULL,
    cat          TEXT NOT NULL,
    kind         TEXT NOT NULL DEFAULT 'cat1_regression',
    message      TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    UNIQUE (scan_id, stig_id, kind)
);
CREATE INDEX IF NOT EXISTS idx_alerts_host ON alerts(host_id, created_at);
"""

BUSY_TIMEOUT_SECONDS = 15.0
CATS = ("CAT I", "CAT II", "CAT III")


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _tx(conn: sqlite3.Connection, commit: bool):
    """Commit on success when ``commit`` is true; otherwise leave the surrounding
    transaction (opened by the caller) alone."""
    return conn if commit else nullcontext()


def connect(path: Path | None = None) -> sqlite3.Connection:
    """Open the database, creating it and its schema if needed."""
    path = Path(path or config.db_path())
    path.parent.mkdir(parents=True, exist_ok=True)
    # FastAPI may run a dependency and its endpoint on different worker threads;
    # each request still gets its own connection.
    conn = sqlite3.connect(path, timeout=BUSY_TIMEOUT_SECONDS, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    _use_wal(conn)
    conn.executescript(SCHEMA)
    return conn


def _use_wal(conn: sqlite3.Connection) -> None:
    """Switch a new database to WAL. The switch needs an exclusive lock and SQLite does not
    wait for it, so concurrent first connections retry briefly instead of failing with
    "database is locked". WAL is persistent: later connections see it already set."""
    deadline = time.monotonic() + BUSY_TIMEOUT_SECONDS
    while True:
        try:
            if conn.execute("PRAGMA journal_mode").fetchone()[0].lower() != "wal":
                conn.execute("PRAGMA journal_mode = WAL")
            return
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc) or time.monotonic() > deadline:
                raise
            time.sleep(0.02)


# -- hosts ---------------------------------------------------------------------------------

def _host_dict(row: sqlite3.Row) -> dict:
    out = dict(row)
    out["tags"] = json.loads(out["tags"])
    return out


HOST_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,252}")


def validate_host_name(name: Any) -> str:
    """Host names are letters, digits, dot, dash and underscore (RFC 1123 plus underscore,
    1 to 253 characters). Anything else is refused, so a name can never carry markup,
    template syntax, path separators or control characters into an export or a script."""
    if not isinstance(name, str) or not HOST_NAME_RE.fullmatch(name):
        raise ValueError("host name must be 1 to 253 characters from A-Z a-z 0-9 . _ - "
                         "and start with a letter or digit")
    return name


def add_host(conn: sqlite3.Connection, name: str, os: str, benchmark_id: str, *,
             environment: str = "", owner: str = "", tags: list[str] | None = None,
             commit: bool = True) -> int:
    validate_host_name(name)
    with _tx(conn, commit):
        cur = conn.execute(
            "INSERT INTO hosts (name, os, benchmark_id, environment, owner, tags) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (name, os, benchmark_id, environment, owner, json.dumps(tags or [])))
    return int(cur.lastrowid)


def get_host(conn: sqlite3.Connection, host_id: int) -> dict | None:
    row = conn.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()
    return _host_dict(row) if row else None


def get_host_by_name(conn: sqlite3.Connection, name: str) -> dict | None:
    row = conn.execute("SELECT * FROM hosts WHERE name = ?", (name,)).fetchone()
    return _host_dict(row) if row else None


def find_host(conn: sqlite3.Connection, name: str) -> dict | None:
    """The host with this name, ignoring case (host names are case-insensitive)."""
    row = conn.execute("SELECT * FROM hosts WHERE name = ? COLLATE NOCASE ORDER BY id LIMIT 1",
                       (name,)).fetchone()
    return _host_dict(row) if row else None


def list_hosts(conn: sqlite3.Connection) -> list[dict]:
    return [_host_dict(r) for r in conn.execute("SELECT * FROM hosts ORDER BY name")]


# -- scans and results ---------------------------------------------------------------------

def _prepare(results: list[engine.RuleResult], cats: dict[str, str]) -> list[tuple]:
    return [(r.stig_id, r.status, cats[r.stig_id], r.reason,
             json.dumps([dict(e) for e in r.evidence], separators=(",", ":"), ensure_ascii=False))
            for r in results]


_INSERT_RESULT = ("INSERT INTO results (scan_id, stig_id, status, cat, reason, evidence_json, comment) "
                  "VALUES (?, ?, ?, ?, ?, ?, ?)")


def _comment_texts(conn: sqlite3.Connection, host_id: int) -> dict[str, str]:
    return {r["stig_id"]: r["text"] for r in
            conn.execute("SELECT stig_id, text FROM comments WHERE host_id = ?", (host_id,))}


def add_scan(conn: sqlite3.Connection, host_id: int, collector_json: dict,
             benchmark: Benchmark | None = None, *,
             results: list[engine.RuleResult] | None = None,
             prepared: list[tuple] | None = None,
             uploaded_at: str | None = None, commit: bool = True) -> int:
    """Store a scan, its results and any CAT I regression alerts.

    ``results`` may carry the engine output for ``collector_json`` when the caller already
    evaluated it; ``prepared`` carries it as ready-to-insert rows (stig_id, status, cat,
    reason, evidence_json), which the demo seeder uses. With neither, the engine runs here.
    Raises ValueError for collector output the engine rejects.
    """
    host = get_host(conn, host_id)
    if host is None:
        raise ValueError(f"unknown host {host_id}")
    benchmark = benchmark or load_benchmark(host["benchmark_id"])
    if results is None and prepared is None:
        results = engine.evaluate(collector_json, benchmark)
    collected_at = str(collector_json.get("collected_at") or "")
    if not collected_at:
        raise ValueError("collector output has no collected_at")
    comments = _comment_texts(conn, host_id)
    if prepared is None:
        prepared = _prepare(results, {r.stig_id: r.cat for r in benchmark.rules})
    raw = json.dumps(collector_json, separators=(",", ":"), ensure_ascii=False)
    with _tx(conn, commit):
        scan_id = int(conn.execute(
            "INSERT INTO scans (host_id, benchmark_id, benchmark_release, collected_at, "
            "uploaded_at, raw_json) VALUES (?, ?, ?, ?, ?, ?)",
            (host_id, benchmark.benchmark_id, benchmark.label, collected_at,
             uploaded_at or now_utc(), raw)).lastrowid)
        conn.executemany(_INSERT_RESULT, [(scan_id, *row, comments.get(row[0], ""))
                                          for row in prepared])
        _record_alerts(conn, host_id, scan_id)
    return scan_id


# ``privileged`` is the collector's own statement that it ran as root / Administrator
# (top-level ``privileged`` in the stored collector JSON); missing or null counts as False.
_SCAN_COLUMNS = ("id, host_id, benchmark_id, benchmark_release, collected_at, uploaded_at, "
                 "COALESCE(json_extract(raw_json, '$.privileged') = 1, 0) AS privileged")


def _scan_dict(row: sqlite3.Row) -> dict:
    out = dict(row)
    out["privileged"] = bool(out["privileged"])
    return out


def get_scan(conn: sqlite3.Connection, scan_id: int) -> dict | None:
    row = conn.execute(f"SELECT {_SCAN_COLUMNS} FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return _scan_dict(row) if row else None


def get_raw(conn: sqlite3.Connection, scan_id: int) -> dict | None:
    row = conn.execute("SELECT raw_json FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return json.loads(row["raw_json"]) if row else None


def list_scans(conn: sqlite3.Connection, host_id: int) -> list[dict]:
    rows = conn.execute(f"SELECT {_SCAN_COLUMNS} FROM scans WHERE host_id = ? "
                        "ORDER BY collected_at, id", (host_id,))
    return [_scan_dict(r) for r in rows]


def previous_scan_id(conn: sqlite3.Connection, scan_id: int) -> int | None:
    """The scan of the same host collected just before this one."""
    scan = get_scan(conn, scan_id)
    if scan is None:
        return None
    prev = conn.execute(
        "SELECT id FROM scans WHERE host_id = ? AND (collected_at < ? OR (collected_at = ? AND id < ?)) "
        "ORDER BY collected_at DESC, id DESC LIMIT 1",
        (scan["host_id"], scan["collected_at"], scan["collected_at"], scan_id)).fetchone()
    return int(prev["id"]) if prev else None


def scan_view(conn: sqlite3.Connection, scan_id: int) -> dict | None:
    """The scan in the shape ``drift.drift`` compares."""
    scan = get_scan(conn, scan_id)
    if scan is None:
        return None
    results = {r["stig_id"]: {"status": r["status"], "cat": r["cat"]} for r in conn.execute(
        "SELECT stig_id, status, cat FROM results WHERE scan_id = ?", (scan_id,))}
    return {"id": scan_id, "benchmark_release": scan["benchmark_release"],
            "collected_at": scan["collected_at"], "results": results}


def scan_results(conn: sqlite3.Connection, scan_id: int) -> list[dict]:
    """Results of a scan with the live assessor comment (``comment``) and the snapshot
    taken when the scan was stored (``comment_at_scan``)."""
    scan = get_scan(conn, scan_id)
    if scan is None:
        return []
    rows = conn.execute(
        "SELECT r.stig_id, r.status, r.cat, r.reason, r.evidence_json, r.comment AS comment_at_scan, "
        "COALESCE(c.text, '') AS comment FROM results r "
        "LEFT JOIN comments c ON c.host_id = ? AND c.stig_id = r.stig_id "
        "WHERE r.scan_id = ? ORDER BY r.rowid", (scan["host_id"], scan_id))
    out = []
    for r in rows:
        d = dict(r)
        d["evidence"] = json.loads(d.pop("evidence_json"))
        out.append(d)
    return out


def reevaluate_scan(conn: sqlite3.Connection, scan_id: int, benchmark: Benchmark | None = None,
                    *, commit: bool = True) -> None:
    """Replace a scan's results by running the engine on its stored raw JSON again
    (for example against a newer benchmark release). Alerts already raised stay."""
    scan = get_scan(conn, scan_id)
    if scan is None:
        raise ValueError(f"unknown scan {scan_id}")
    benchmark = benchmark or load_benchmark(scan["benchmark_id"])
    results = engine.evaluate(get_raw(conn, scan_id), benchmark)
    cats = {r.stig_id: r.cat for r in benchmark.rules}
    comments = _comment_texts(conn, scan["host_id"])
    with _tx(conn, commit):
        conn.execute("DELETE FROM results WHERE scan_id = ?", (scan_id,))
        conn.executemany(_INSERT_RESULT, [(scan_id, *row, comments.get(row[0], ""))
                                          for row in _prepare(results, cats)])
        conn.execute("UPDATE scans SET benchmark_id = ?, benchmark_release = ? WHERE id = ?",
                     (benchmark.benchmark_id, benchmark.label, scan_id))


def delete_scan(conn: sqlite3.Connection, scan_id: int) -> None:
    with conn:
        conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))


# -- drift and alerts ----------------------------------------------------------------------

def drift_for_scan(conn: sqlite3.Connection, scan_id: int) -> dict | None:
    """Drift from the host's previous scan to this one; None for a host's first scan."""
    prev_id = previous_scan_id(conn, scan_id)
    if prev_id is None:
        return None
    return drift_mod.drift(scan_view(conn, prev_id), scan_view(conn, scan_id))


def _record_alerts(conn: sqlite3.Connection, host_id: int, scan_id: int) -> None:
    result = drift_for_scan(conn, scan_id)
    if result is None:
        return
    host = conn.execute("SELECT name FROM hosts WHERE id = ?", (host_id,)).fetchone()["name"]
    when = conn.execute("SELECT collected_at FROM scans WHERE id = ?", (scan_id,)).fetchone()[0]
    for item in drift_mod.cat1_regressions(result):
        conn.execute(
            "INSERT OR IGNORE INTO alerts (host_id, scan_id, prev_scan_id, stig_id, cat, kind, "
            "message, created_at) VALUES (?, ?, ?, ?, ?, 'cat1_regression', ?, ?)",
            (host_id, scan_id, result["prev_scan_id"], item["stig_id"], item["cat"],
             f"{host}: {item['stig_id']} (CAT I) went from {item['from']} to Open.", when))


def rebuild_next_alerts(conn: sqlite3.Connection, scan_id: int, *, commit: bool = True) -> int | None:
    """After a scan was stored out of order (collected before the host's latest scan), the
    scan collected just after it has a new predecessor. Its CAT I alerts are recomputed
    against that predecessor. Returns that scan's id, or None when the scan is the newest."""
    scan = get_scan(conn, scan_id)
    if scan is None:
        return None
    nxt = conn.execute(
        "SELECT id FROM scans WHERE host_id = ? AND (collected_at > ? OR (collected_at = ? AND id > ?)) "
        "ORDER BY collected_at, id LIMIT 1",
        (scan["host_id"], scan["collected_at"], scan["collected_at"], scan_id)).fetchone()
    if nxt is None:
        return None
    with _tx(conn, commit):
        conn.execute("DELETE FROM alerts WHERE scan_id = ? AND kind = 'cat1_regression'", (nxt["id"],))
        _record_alerts(conn, scan["host_id"], int(nxt["id"]))
    return int(nxt["id"])


def list_alerts(conn: sqlite3.Connection, host_id: int | None = None) -> list[dict]:
    sql = "SELECT a.*, h.name AS host_name FROM alerts a JOIN hosts h ON h.id = a.host_id"
    args: tuple = ()
    if host_id is not None:
        sql += " WHERE a.host_id = ?"
        args = (host_id,)
    return [dict(r) for r in conn.execute(sql + " ORDER BY a.created_at DESC, a.id DESC", args)]


# -- assessor comments ---------------------------------------------------------------------

def set_comment(conn: sqlite3.Connection, host_id: int, stig_id: str, text: str, *,
                updated_at: str | None = None, commit: bool = True) -> None:
    """Set (or, with empty text, remove) the comment for a rule on a host."""
    with _tx(conn, commit):
        if text.strip():
            conn.execute(
                "INSERT INTO comments (host_id, stig_id, text, updated_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(host_id, stig_id) DO UPDATE SET text = excluded.text, "
                "updated_at = excluded.updated_at",
                (host_id, stig_id, text, updated_at or now_utc()))
        else:
            conn.execute("DELETE FROM comments WHERE host_id = ? AND stig_id = ?", (host_id, stig_id))


def get_comments(conn: sqlite3.Connection, host_id: int) -> dict[str, dict]:
    return {r["stig_id"]: {"text": r["text"], "updated_at": r["updated_at"]} for r in
            conn.execute("SELECT stig_id, text, updated_at FROM comments WHERE host_id = ?",
                         (host_id,))}


# -- trends --------------------------------------------------------------------------------

def _open_by_scan(conn: sqlite3.Connection, host_id: int | None = None) -> dict[int, dict[str, int]]:
    sql = ("SELECT s.id AS scan_id, r.cat AS cat, COUNT(*) AS n FROM scans s "
           "JOIN results r ON r.scan_id = s.id AND r.status = 'Open'")
    args: tuple = ()
    if host_id is not None:
        sql += " WHERE s.host_id = ?"
        args = (host_id,)
    out: dict[int, dict[str, int]] = {}
    for r in conn.execute(sql + " GROUP BY s.id, r.cat", args):
        out.setdefault(r["scan_id"], {c: 0 for c in CATS})[r["cat"]] = r["n"]
    return out


def host_trend(conn: sqlite3.Connection, host_id: int) -> list[dict]:
    """Open CAT I/II/III per scan of one host, oldest first."""
    opens = _open_by_scan(conn, host_id)
    return [{"scan_id": s["id"], "collected_at": s["collected_at"],
             "benchmark_release": s["benchmark_release"],
             "open": opens.get(s["id"], {c: 0 for c in CATS})}
            for s in list_scans(conn, host_id)]


def _week_start(collected_at: str) -> date:
    d = date.fromisoformat(collected_at[:10])
    return d - timedelta(days=d.weekday())


def fleet_trend(conn: sqlite3.Connection) -> list[dict]:
    """Open CAT I/II/III over time for the whole fleet, one point per ISO week.

    In each week every host contributes its latest scan collected up to the end of that
    week, so a host that skipped a week keeps its last known state and a host counts only
    from its first scan on. ``hosts`` is how many hosts contributed."""
    opens = _open_by_scan(conn)
    scans = conn.execute("SELECT id, host_id, collected_at FROM scans ORDER BY collected_at, id").fetchall()
    series = []
    for week in sorted({_week_start(s["collected_at"]) for s in scans}):
        end = (week + timedelta(days=7)).isoformat()
        latest = {s["host_id"]: s["id"] for s in scans if s["collected_at"][:10] < end}
        total = {c: 0 for c in CATS}
        for scan_id in latest.values():
            for c, n in opens.get(scan_id, {}).items():
                total[c] += n
        series.append({"week": week.isoformat(), "hosts": len(latest), "open": total})
    return series
