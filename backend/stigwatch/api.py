"""REST API for STIGWatch. All routes live under /api.

Conventions follow CMMC Ready: a single admin (cookie or bearer token), a read-only guest in
demo mode, security headers on every response, a body-size cap in front of everything, junk
numeric ids are 404, filters come from allow-lists, downloads use safe file names.

Uploads: ``POST /api/scans`` matches the host named in the collector file (case-insensitively)
or creates it; ``POST /api/hosts/{id}/scans`` adds a scan to a host that already exists. Both
check the guest/writer rule before the request body is read.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import threading
import time
from contextlib import asynccontextmanager
from typing import Annotated, Any, Iterator, Literal

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import __version__, auth, benchmarks, config, db, demo, exports, remediation, uploads
from .benchmarks import Benchmark, BenchmarkError
from .checks import engine

log = logging.getLogger("stigwatch.api")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    if config.demo_mode():
        await run_in_threadpool(_lazy_seed)
    yield


# The interactive docs load scripts from a CDN (blocked by the CSP) and would expose the
# write endpoints to anonymous demo visitors, so the built-in docs routes are off. The
# OpenAPI document is served at /api/openapi.json to logged-in writers only.
app = FastAPI(
    lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None,
    title="STIGWatch API",
    version=__version__,
    description="DISA STIG compliance scanner for Ubuntu 22.04 LTS and Windows Server 2022. "
                "An independent tool; not a DISA product.",
)

STATUSES = ("Open", "NotAFinding", "Not_Applicable", "Not_Reviewed")
CATS = ("CAT I", "CAT II", "CAT III")
SEVERITY_CAT = {"high": "CAT I", "medium": "CAT II", "low": "CAT III",
                "CAT I": "CAT I", "CAT II": "CAT II", "CAT III": "CAT III"}

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; "
        "form-action 'self'"),
    "Cache-Control": "no-store",
}
# A downloaded report is opened from disk; it gets no network, no script and a sandbox.
REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; sandbox"


@app.middleware("http")
async def security_headers(request: Request, call_next):
    try:
        response = await call_next(request)
    except Exception:  # last resort: never leak a traceback or drop the security headers
        log.exception("Unhandled error in %s %s", request.method, request.url.path)
        response = JSONResponse({"detail": "Internal server error"}, status_code=500)
    for key, value in SECURITY_HEADERS.items():
        response.headers.setdefault(key, value)
    return response


MULTIPART_OVERHEAD = 64 * 1024
DEFAULT_BODY_LIMIT = 64 * 1024     # every JSON route except the scan uploads
_UPLOAD_PATH = re.compile(r"^/api/(?:scans|hosts/[0-9]{1,9}/scans)/?$")


class _TooLarge(Exception):
    pass


class BodyLimitMiddleware:
    """Refuse request bodies over the upload cap (plus multipart overhead) with 413.

    An announced Content-Length is checked before any of the body is read. Bytes are also
    counted as they arrive, so a chunked request with no Content-Length cannot stream past
    the cap either."""

    def __init__(self, app):
        self.app = app

    @staticmethod
    def _limit(path: str) -> int:
        if _UPLOAD_PATH.match(path):
            return config.max_upload_bytes() + MULTIPART_OVERHEAD
        return DEFAULT_BODY_LIMIT

    @staticmethod
    async def _reject(send, limit: int) -> None:
        message = (f"Request too large (max {limit // (1024 * 1024)} MB)" if limit >= 1024 * 1024
                   else f"Request too large (max {limit // 1024} KB)")
        await JSONResponse({"detail": message}, status_code=413, headers=SECURITY_HEADERS)(
            {"type": "http"}, _noop_receive, send)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] not in ("POST", "PUT", "PATCH"):
            await self.app(scope, receive, send)
            return
        limit = self._limit(scope.get("path", ""))
        declared = dict(scope["headers"]).get(b"content-length", b"")
        if declared.isdigit() and int(declared) > limit:
            await self._reject(send, limit)
            return

        received = 0
        exceeded = False
        sent_any = False

        async def counting_receive():
            nonlocal received, exceeded
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    exceeded = True
                    raise _TooLarge
            return message

        async def guarded_send(message):
            nonlocal sent_any
            if exceeded and not sent_any:
                return  # the framework's own "bad body" answer is replaced by the 413 below
            sent_any = True
            await send(message)

        try:
            await self.app(scope, counting_receive, guarded_send)
        except _TooLarge:
            pass
        if exceeded and not sent_any:
            await self._reject(send, limit)


async def _noop_receive():
    return {"type": "http.disconnect"}


app.add_middleware(BodyLimitMiddleware)


# -- database and lazy demo seeding -----------------------------------------------------------

_seed_lock = threading.Lock()
_seeded: set[str] = set()
_seed_failed_until: dict[str, float] = {}
SEED_RETRY_SECONDS = 60.0


def _lazy_seed() -> bool:
    """Seed the demo fleet once per process and database, on the first request. Serverless
    hosts may never run the lifespan hook, so the first request does it (double-checked under
    a lock; seeding is itself idempotent, so concurrent processes cannot double-seed).
    A failure is logged once and remembered for SEED_RETRY_SECONDS, during which this returns
    False without trying again. Returns True when the data is available."""
    key = str(config.db_path())
    if key in _seeded:
        return True
    if _seed_failed_until.get(key, 0.0) > time.monotonic():
        return False
    with _seed_lock:
        if key in _seeded:
            return True
        if _seed_failed_until.get(key, 0.0) > time.monotonic():
            return False
        try:
            demo.ensure_seeded()
        except Exception:
            _seed_failed_until[key] = time.monotonic() + SEED_RETRY_SECONDS
            log.exception("Demo seeding failed; not retrying for %d s", SEED_RETRY_SECONDS)
            return False
        _seed_failed_until.pop(key, None)
        _seeded.add(key)
        return True


def get_conn() -> Iterator[sqlite3.Connection]:
    if config.demo_mode() and not _lazy_seed():
        raise HTTPException(503, "Demo data is not available yet",
                            headers={"Retry-After": str(int(SEED_RETRY_SECONDS))})
    conn = db.connect()
    try:
        yield conn
    finally:
        conn.close()


Conn = Annotated[sqlite3.Connection, Depends(get_conn)]
Writer = Depends(auth.require_writer)

_DIGITS = re.compile(r"^[0-9]{1,9}$")
_STIG_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,39}$")


def _int_id(raw: str, what: str) -> int:
    """Junk ids are 404 without touching the database."""
    if not _DIGITS.match(raw):
        raise HTTPException(404, f"{what} not found")
    return int(raw)


def host_dep(host_id: str, conn: Conn) -> dict:
    host = db.get_host(conn, _int_id(host_id, "host"))
    if host is None:
        raise HTTPException(404, "host not found")
    return host


def scan_dep(scan_id: str, conn: Conn) -> dict:
    scan = db.get_scan(conn, _int_id(scan_id, "scan"))
    if scan is None:
        raise HTTPException(404, "scan not found")
    return scan


Host = Annotated[dict, Depends(host_dep)]
Scan = Annotated[dict, Depends(scan_dep)]


def _bench(benchmark_id: str) -> Benchmark | None:
    try:
        return benchmarks.load_benchmark(benchmark_id)
    except BenchmarkError:
        return None


def _need_bench(benchmark_id: str) -> Benchmark:
    bench = _bench(benchmark_id)
    if bench is None:
        raise HTTPException(409, f"benchmark {benchmark_id!r} is not available on this server")
    return bench


# -- public endpoints -------------------------------------------------------------------------

@app.get("/api/health")
def health():
    return {"status": "ok", "version": __version__, "auth_configured": auth.is_configured(),
            "demo": config.demo_mode(), "guest": config.guest_enabled()}


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


def _set_session_cookie(response: Response, token: str, expires) -> None:
    response.set_cookie(
        auth.COOKIE_NAME, token, expires=expires,
        httponly=True, secure=config.cookie_secure(), samesite="strict", path="/api",
    )


@app.post("/api/auth/login")
def login(body: LoginRequest, request: Request, response: Response):
    if not auth.is_configured():
        raise HTTPException(503, "Authentication is not configured. Run: python -m stigwatch create-admin")
    ip = auth.client_ip(request)
    wait = auth.limiter.retry_after(ip)
    if wait:
        raise HTTPException(429, "Too many failed logins. Try again later.",
                            headers={"Retry-After": str(wait)})
    if not auth.check_credentials(body.username, body.password):
        auth.limiter.record_failure(ip)
        raise HTTPException(401, "Invalid username or password")
    auth.limiter.reset(ip)
    token, expires = auth.issue_token(body.username)
    _set_session_cookie(response, token, expires)
    # The token travels only in the httpOnly cookie, never in the response body.
    return {"username": body.username, "expires_at": expires.strftime("%Y-%m-%dT%H:%M:%SZ")}


@app.post("/api/auth/logout")
def logout(response: Response):
    response.delete_cookie(auth.COOKIE_NAME, path="/api", httponly=True,
                           secure=config.cookie_secure(), samesite="strict")
    return {"ok": True}


# -- authenticated endpoints ------------------------------------------------------------------

protected = APIRouter(dependencies=[Depends(auth.require_user)])


@protected.get("/api/auth/me")
def me(user: Annotated[str, Depends(auth.require_user)]):
    return {"username": user, "guest": user == auth.GUEST_USER}


@protected.get("/api/openapi.json", include_in_schema=False)
def openapi_document(_w: Annotated[str, Writer]):
    return JSONResponse(app.openapi())


# -- summaries --------------------------------------------------------------------------------

def _counts(conn: sqlite3.Connection, scan_id: int) -> dict:
    """Result counts of a scan: ``status`` per status, ``open`` per CAT, and ``compliance``
    (NotAFinding / (Open + NotAFinding) in percent; None when neither occurs)."""
    status = {s: 0 for s in STATUSES}
    open_by_cat = {c: 0 for c in CATS}
    for r in conn.execute("SELECT status, cat, COUNT(*) AS n FROM results WHERE scan_id = ? "
                          "GROUP BY status, cat", (scan_id,)):
        status[r["status"]] += r["n"]
        if r["status"] == "Open":
            open_by_cat[r["cat"]] += r["n"]
    decided = status["Open"] + status["NotAFinding"]
    compliance = round(100.0 * status["NotAFinding"] / decided, 1) if decided else None
    return {"status": status, "open": open_by_cat, "compliance": compliance}


def _scan_out(conn: sqlite3.Connection, scan: dict) -> dict:
    return {**scan, **_counts(conn, scan["id"])}


def _latest_scan(conn: sqlite3.Connection, host_id: int) -> dict | None:
    row = conn.execute(f"SELECT {db._SCAN_COLUMNS} FROM scans WHERE host_id = ? "
                       "ORDER BY collected_at DESC, id DESC LIMIT 1", (host_id,)).fetchone()
    return db._scan_dict(row) if row else None


def _host_summary(conn: sqlite3.Connection, host: dict) -> dict:
    latest = _latest_scan(conn, host["id"])
    n = conn.execute("SELECT COUNT(*) FROM scans WHERE host_id = ?", (host["id"],)).fetchone()[0]
    out = {**host, "scan_count": n, "latest_scan": None,
           "status": {s: 0 for s in STATUSES}, "open": {c: 0 for c in CATS}, "compliance": None}
    if latest:
        out["latest_scan"] = latest
        out.update(_counts(conn, latest["id"]))
    return out


def _drift_out(conn: sqlite3.Connection, scan_id: int) -> dict:
    """Drift from the host's previous scan. ``newly_visible_cat1`` lists CAT I rules that are
    Open now and were Not_Reviewed before: the finding may be old, it was not visible."""
    result = db.drift_for_scan(conn, scan_id)
    if result is None:
        return {"scan_id": scan_id, "first_scan": True, "prev_scan_id": None}
    return {**result, "first_scan": False,
            "newly_visible_cat1": [r for r in result["newly_open"] if r["cat"] == "CAT I"]}


# -- fleet ------------------------------------------------------------------------------------

@protected.get("/api/fleet")
def fleet(conn: Conn):
    data = exports.fleet_rows(conn)
    rows = data["hosts"]
    open_total = {c: sum(r["open"][c] for r in rows) for c in CATS}
    status = {s: sum(r["status"][s] for r in rows) for s in STATUSES}
    decided = status["Open"] + status["NotAFinding"]
    newly_visible: list[dict] = []
    for host in db.list_hosts(conn):
        latest = _latest_scan(conn, host["id"])
        if latest:
            for item in _drift_out(conn, latest["id"]).get("newly_visible_cat1", []):
                newly_visible.append({"host": host["name"], "host_id": host["id"], **item,
                                      "when": latest["collected_at"]})
    return {
        "hosts": len(rows),
        "scans": sum(r["scans"] for r in rows),
        "open": open_total,
        "status": status,
        "compliance": round(100.0 * status["NotAFinding"] / decided, 1) if decided else None,
        "trend": data["trend"],
        "regressions": data["regressions"],
        "newly_visible_cat1": newly_visible,
        "disclaimer": exports.DISCLAIMER,
    }


# -- hosts ------------------------------------------------------------------------------------

@protected.get("/api/hosts")
def hosts(conn: Conn,
          os: Annotated[Literal["linux", "windows"] | None, Query()] = None,
          environment: Annotated[str | None, Query(max_length=100)] = None,
          q: Annotated[str | None, Query(max_length=100)] = None,
          has_cat1: Annotated[bool | None, Query()] = None):
    out = []
    needle = q.strip().lower() if q else ""
    for host in db.list_hosts(conn):
        if os and host["os"] != os:
            continue
        if environment is not None and host["environment"].lower() != environment.lower():
            continue
        if needle and needle not in f"{host['name']} {host['owner']} {host['environment']}".lower():
            continue
        summary = _host_summary(conn, host)
        if has_cat1 is not None and (summary["open"]["CAT I"] > 0) != has_cat1:
            continue
        out.append(summary)
    return out


class HostBody(BaseModel):
    name: str = Field(min_length=1, max_length=5000)
    os: Literal["linux", "windows"]
    environment: str = Field(default="", max_length=100)
    owner: str = Field(default="", max_length=100)
    tags: list[Annotated[str, Field(max_length=50)]] = Field(default_factory=list, max_length=20)


OS_BENCHMARK = {"linux": "ubuntu-22.04", "windows": "windows-server-2022"}


@protected.post("/api/hosts", status_code=201)
def create_host(_w: Annotated[str, Writer], body: HostBody, conn: Conn):
    try:
        name = db.validate_host_name(body.name)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    conn.commit()
    conn.execute("BEGIN IMMEDIATE")  # the name check and the insert are one step
    try:
        if db.find_host(conn, name) is not None:
            raise HTTPException(409, f"a host named {name!r} already exists")
        host_id = db.add_host(conn, name, body.os, OS_BENCHMARK[body.os], environment=body.environment,
                              owner=body.owner, tags=body.tags, commit=False)
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    return _host_summary(conn, db.get_host(conn, host_id))


@protected.get("/api/hosts/{host_id}")
def host_detail(host: Host, conn: Conn):
    return {**_host_summary(conn, host), "trend": db.host_trend(conn, host["id"]),
            "alerts": db.list_alerts(conn, host["id"])}


@protected.get("/api/hosts/{host_id}/scans")
def host_scans(host: Host, conn: Conn):
    return [_scan_out(conn, s) for s in reversed(db.list_scans(conn, host["id"]))]


# -- scans ------------------------------------------------------------------------------------

@protected.get("/api/scans/{scan_id}/results")
def scan_results(scan: Scan, conn: Conn,
                 status: Annotated[Literal["Open", "NotAFinding", "Not_Applicable", "Not_Reviewed"] | None,
                                   Query()] = None,
                 severity: Annotated[Literal["high", "medium", "low", "CAT I", "CAT II", "CAT III"] | None,
                                     Query()] = None,
                 q: Annotated[str | None, Query(max_length=100)] = None):
    bench = _bench(scan["benchmark_id"])
    cat = SEVERITY_CAT.get(severity) if severity else None
    needle = q.strip().lower() if q else ""
    out = []
    for r in db.scan_results(conn, scan["id"]):
        if status and r["status"] != status:
            continue
        if cat and r["cat"] != cat:
            continue
        rule = bench.rule(r["stig_id"]) if bench else None
        title = rule.title if rule else ""
        if needle and needle not in f"{r['stig_id']} {title} {r['reason']}".lower():
            continue
        evidence = r.pop("evidence")
        out.append({**r, "title": title, "group_id": rule.group_id if rule else "",
                    "evidence_count": len(evidence)})
    return {"scan": _scan_out(conn, scan), "count": len(out), "results": out}


@protected.get("/api/scans/{scan_id}/drift")
def scan_drift(scan: Scan, conn: Conn):
    return _drift_out(conn, scan["id"])


# -- rules ------------------------------------------------------------------------------------

@protected.get("/api/hosts/{host_id}/rules/{stig_id}")
def host_rule(stig_id: str, host: Host, conn: Conn):
    if not _STIG_ID.match(stig_id):
        raise HTTPException(404, "rule not found")
    bench = _bench(host["benchmark_id"])
    rule = bench.rule(stig_id) if bench else None
    history = []
    latest_evidence: list = []
    for row in conn.execute(
            "SELECT s.id AS scan_id, s.collected_at, s.benchmark_release, r.status, r.cat, r.reason, "
            "r.evidence_json, r.comment AS comment_at_scan FROM results r JOIN scans s ON s.id = r.scan_id "
            "WHERE s.host_id = ? AND r.stig_id = ? ORDER BY s.collected_at, s.id", (host["id"], stig_id)):
        d = dict(row)
        latest_evidence = json.loads(d.pop("evidence_json"))
        history.append(d)
    if rule is None and not history:
        raise HTTPException(404, "rule not found")
    comment = db.get_comments(conn, host["id"]).get(stig_id)
    return {
        "host_id": host["id"], "stig_id": stig_id,
        "rule": None if rule is None else {
            "group_id": rule.group_id, "rule_id": rule.rule_id, "stig_id": rule.stig_id,
            "severity": rule.severity, "cat": rule.cat, "title": rule.title,
            "discussion": rule.discussion, "check_text": rule.check_text, "fix_text": rule.fix_text,
            "ccis": list(rule.ccis)},
        "history": history,
        "evidence": latest_evidence,
        "comment": comment,
    }


class CommentBody(BaseModel):
    text: str = Field(max_length=5000)


@protected.put("/api/hosts/{host_id}/rules/{stig_id}/comment")
def put_comment(_w: Annotated[str, Writer], stig_id: str, host: Host, body: CommentBody, conn: Conn):
    if not _STIG_ID.match(stig_id):
        raise HTTPException(404, "rule not found")
    bench = _bench(host["benchmark_id"])
    if bench is None or bench.rule(stig_id) is None:
        raise HTTPException(404, "rule not found")
    db.set_comment(conn, host["id"], stig_id, body.text)
    return {"host_id": host["id"], "stig_id": stig_id, "comment": db.get_comments(conn, host["id"]).get(stig_id)}


# -- alerts and benchmarks --------------------------------------------------------------------

@protected.get("/api/alerts")
def alerts(conn: Conn, host_id: Annotated[str | None, Query(max_length=9)] = None):
    only = None
    if host_id is not None:
        only = _int_id(host_id, "host")
    return db.list_alerts(conn, only)


def _benchmark_out(b: Benchmark) -> dict:
    counts = b.counts()
    return {"id": b.benchmark_id, "title": b.title, "version": b.version, "release": b.release,
            "date": b.date, "label": b.label, "source_url": b.source_url, "rules": len(b.rules),
            "metadata_only": b.metadata_only,
            "severity": {"CAT I": counts["high"], "CAT II": counts["medium"], "CAT III": counts["low"]}}


@protected.get("/api/benchmarks")
def benchmark_list():
    out = []
    for bid in benchmarks.list_benchmarks():
        b = _bench(bid)
        if b is not None:
            out.append(_benchmark_out(b))
    return out


@protected.get("/api/benchmarks/{benchmark_id}/coverage")
def benchmark_coverage(benchmark_id: str):
    if benchmark_id not in benchmarks.list_benchmarks():
        raise HTTPException(404, "benchmark not found")
    try:
        cov = engine.coverage(benchmark_id)
    except (ValueError, BenchmarkError):
        raise HTTPException(404, "no automated checks for this benchmark") from None
    return {"benchmark": benchmark_id, "label": cov.label, "by_cat": cov.by_cat,
            "automated": [{"stig_id": s, "cat": c, "kind": k} for s, c, k in cov.automated],
            "manual": [{"stig_id": s, "cat": c} for s, c in cov.manual]}


# -- uploads ----------------------------------------------------------------------------------

async def _read_body(request: Request, limit: int) -> bytes:
    ctype = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if ctype == "multipart/form-data":
        form = await request.form(max_files=1, max_fields=10)
        try:
            part = form.get("file")
            if part is None or isinstance(part, str):
                raise HTTPException(400, "multipart upload needs a 'file' part with the collector JSON")
            data = await part.read(limit + 1)
        finally:
            await form.close()
    elif ctype in ("", "application/json", "application/octet-stream", "text/plain"):
        chunks, size = [], 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > limit:
                break
            chunks.append(chunk)
        data = b"".join(chunks) if size <= limit else b"x" * (limit + 1)
    else:
        raise HTTPException(415, "Send the collector JSON as multipart/form-data (field 'file') "
                                 "or as an application/json body")
    if len(data) > limit:
        raise HTTPException(413, f"File too large (max {limit // (1024 * 1024)} MB)")
    return data


def _parse_collector(data: bytes) -> dict:
    if not data.strip():
        raise HTTPException(400, "Empty upload")
    try:
        text = uploads.decode_json_upload(data)
    except uploads.UploadError as exc:
        raise HTTPException(exc.status, str(exc)) from None
    try:
        parsed = json.loads(text)
        uploads.check_depth(parsed)
    except RecursionError:
        raise HTTPException(400, "JSON is nested too deeply") from None
    except ValueError as exc:
        if isinstance(exc, json.JSONDecodeError):
            raise HTTPException(400, "File is not valid JSON") from None
        raise HTTPException(400, str(exc)) from None
    return parsed


def _ingest(conn: sqlite3.Connection, parsed: Any, host: dict | None) -> dict:
    """Validate, evaluate and store one collector file; ``host`` is the host the caller named
    (``POST /hosts/{id}/scans``) or None to match by the name in the file. Errors are
    HTTPExceptions: 400 for bad content, 409 when the file does not belong to the host."""
    if not isinstance(parsed, dict) or not isinstance(parsed.get("collector"), str):
        raise HTTPException(400, "Not a collector file: expected a JSON object with a 'collector' field")
    try:
        module = engine.collector_module(parsed)
    except ValueError:
        raise HTTPException(400, f"Unknown collector {parsed['collector'][:40]!r}; "
                                 f"expected one of {', '.join(sorted(engine.COLLECTORS))}") from None
    try:
        module.validate(parsed)
        name = db.validate_host_name(parsed["host"]["name"])
        when = uploads.normalise_collected_at(parsed["collected_at"])
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    raw = {**parsed, "collected_at": when}
    bench = _need_bench(module.BENCHMARK)
    try:
        results = engine.evaluate(raw, bench)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    except Exception:
        log.exception("Evaluating an upload failed")
        raise HTTPException(400, "Collector output could not be evaluated") from None

    conn.commit()  # no transaction may be open when taking the write lock
    conn.execute("BEGIN IMMEDIATE")
    try:
        created = False
        if host is not None:
            target = db.get_host(conn, host["id"])
            if target is None:
                raise HTTPException(404, "host not found")
            if name.lower() != target["name"].lower():
                raise HTTPException(409, f"This file is from host {name!r}, not {target['name']!r}. "
                                         "Upload it to the host it came from.")
        else:
            target = db.find_host(conn, name)
        if target is None:
            host_id = db.add_host(conn, name, module.COLLECTOR, module.BENCHMARK, commit=False)
            created = True
        else:
            if target["os"] != module.COLLECTOR or target["benchmark_id"] != module.BENCHMARK:
                raise HTTPException(
                    409, f"Host {target['name']!r} is registered as {target['os']} "
                         f"({target['benchmark_id']}); this file is from a {module.COLLECTOR} "
                         f"collector ({module.BENCHMARK}). Use a different host name or remove "
                         "the existing host first.")
            host_id = target["id"]
        newest = _latest_scan(conn, host_id)
        out_of_order = newest is not None and when < newest["collected_at"]
        scan_id = db.add_scan(conn, host_id, raw, bench, results=results, commit=False)
        recomputed = db.rebuild_next_alerts(conn, scan_id, commit=False) if out_of_order else None
        conn.commit()
    except BaseException:
        conn.rollback()
        raise

    n_alerts = conn.execute("SELECT COUNT(*) FROM alerts WHERE scan_id = ?", (scan_id,)).fetchone()[0]
    return {"scan_id": scan_id, "host_id": host_id, "host": name, "host_created": created,
            "collected_at": when, "benchmark": bench.benchmark_id, "release": bench.label,
            "privileged": raw.get("privileged") is True, "out_of_order": out_of_order, "alerts_recomputed_for_scan": recomputed,
            "alerts_raised": n_alerts, **_counts(conn, scan_id), "drift": _drift_out(conn, scan_id)}


@protected.post("/api/scans", status_code=201)
async def upload_scan(_w: Annotated[str, Writer], request: Request, conn: Conn):
    """Upload collector JSON; the host is matched by the name in the file or created."""
    data = await _read_body(request, config.max_upload_bytes())
    parsed = _parse_collector(data)
    return await run_in_threadpool(_ingest, conn, parsed, None)


@protected.post("/api/hosts/{host_id}/scans", status_code=201)
async def upload_host_scan(_w: Annotated[str, Writer], host: Host, request: Request, conn: Conn):
    """Upload collector JSON for an existing host."""
    data = await _read_body(request, config.max_upload_bytes())
    parsed = _parse_collector(data)
    return await run_in_threadpool(_ingest, conn, parsed, host)


# -- exports ----------------------------------------------------------------------------------

def _download(content: bytes | str, media_type: str, filename: str, csp: str | None = None) -> Response:
    body = content.encode("utf-8") if isinstance(content, str) else content
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    if csp:
        headers["Content-Security-Policy"] = csp
    return Response(body, media_type=media_type, headers=headers)


def _checklist(scan: dict, conn: sqlite3.Connection):
    host = db.get_host(conn, scan["host_id"])
    bench = _need_bench(scan["benchmark_id"])
    return host, exports.load_scan(conn, scan["id"]), bench


@protected.get("/api/scans/{scan_id}/export.ckl")
def export_ckl(scan: Scan, conn: Conn):
    host, loaded, bench = _checklist(scan, conn)
    return _download(exports.ckl(host, loaded, bench), "application/xml",
                     exports.safe_filename(host["name"], "ckl", stamp=scan["collected_at"]))


@protected.get("/api/scans/{scan_id}/export.cklb")
def export_cklb(scan: Scan, conn: Conn):
    host, loaded, bench = _checklist(scan, conn)
    return _download(exports.cklb(host, loaded, bench), "application/json",
                     exports.safe_filename(host["name"], "cklb", stamp=scan["collected_at"]))


@protected.get("/api/hosts/{host_id}/remediation")
def host_remediation(host: Host, conn: Conn):
    """Ansible playbook (Linux) or PowerShell script (Windows) for the host's open findings
    in its latest scan. Generated for review; STIGWatch never applies it."""
    latest = _latest_scan(conn, host["id"])
    if latest is None:
        raise HTTPException(404, "host has no scans")
    bench = _need_bench(latest["benchmark_id"])
    open_results = [r for r in db.scan_results(conn, latest["id"]) if r["status"] == "Open"]
    stamp = latest["collected_at"]
    if host["os"] == "windows":
        role = remediation.domain_role_of(db.get_raw(conn, latest["id"]))
        script = remediation.powershell_script(host, open_results, bench, domain_role=role)
        return _download(script, "text/plain; charset=utf-8",
                         exports.safe_filename(host["name"] + "-remediation", "ps1", stamp=stamp))
    playbook = remediation.ansible_playbook(host, open_results, bench)
    return _download(playbook, "text/yaml; charset=utf-8",
                     exports.safe_filename(host["name"] + "-remediation", "yml", stamp=stamp))


@protected.get("/api/reports/fleet.csv")
def report_fleet_csv(conn: Conn):
    return _download(exports.fleet_csv(conn), "text/csv; charset=utf-8", "stigwatch-fleet.csv")


@protected.get("/api/reports/fleet.html")
def report_fleet_html(conn: Conn):
    return _download(exports.fleet_report_html(conn), "text/html; charset=utf-8",
                     "stigwatch-fleet.html", csp=REPORT_CSP)


# Registered last so every @protected route above is included.
app.include_router(protected)
