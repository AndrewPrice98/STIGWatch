"""REST API: routes, auth, uploads, exports, hostile input."""

import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from conftest import TEST_PASSWORD, TEST_USER
from stigwatch import api, db, remediation

FIX = Path(__file__).parent / "fixtures"


def fixture(name):
    return json.loads((FIX / f"{name}.json").read_text(encoding="utf-8"))


def body(raw):
    return json.dumps(raw).encode()


@pytest.fixture
def client(db_file):
    with TestClient(api.app) as c:
        r = c.post("/api/auth/login", json={"username": TEST_USER, "password": TEST_PASSWORD})
        assert r.status_code == 200
        yield c


@pytest.fixture
def anon(db_file):
    with TestClient(api.app) as c:
        yield c


@pytest.fixture
def guest(db_file, monkeypatch):
    monkeypatch.setenv("STIGWATCH_GUEST", "1")
    with TestClient(api.app) as c:
        yield c


def upload(c, raw, **kw):
    return c.post("/api/scans", content=body(raw), headers={"content-type": "application/json"}, **kw)


# ---------------------------------------------------------------- docs, headers, auth

def test_health_headers_and_no_store(anon):
    r = anon.get("/api/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["cache-control"] == "no-store"


def test_docs_are_off_and_openapi_is_writer_only(anon, client, guest):
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert anon.get(path).status_code == 404
    assert client.get("/api/openapi.json").status_code == 200
    assert guest.get("/api/openapi.json").status_code == 403


def test_openapi_needs_login(anon):
    assert anon.get("/api/openapi.json").status_code == 401


def test_junk_ids_are_404(client):
    for path in ("/api/hosts/abc", "/api/hosts/99999", "/api/hosts/1;DROP", "/api/scans/0/results",
                 "/api/scans/x/drift", "/api/scans/1/export.ckl", "/api/hosts/1/remediation",
                 "/api/benchmarks/nope/coverage", "/api/benchmarks/..%2f..%2fetc/coverage"):
        assert client.get(path).status_code == 404, path


def test_unauthenticated_is_401(anon):
    assert anon.get("/api/fleet").status_code == 401
    assert anon.post("/api/hosts", json={"name": "a", "os": "linux"}).status_code == 401


def test_unhandled_error_is_json_500_with_headers(client, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("secret internals")
    monkeypatch.setattr(api.db, "list_hosts", boom)
    with TestClient(api.app, raise_server_exceptions=False) as c:
        c.cookies.update(client.cookies)
        r = c.get("/api/hosts")
    assert r.status_code == 500 and r.json() == {"detail": "Internal server error"}
    assert r.headers["x-content-type-options"] == "nosniff"


# ---------------------------------------------------------------- guest is read-only

def test_guest_403_on_every_write_and_nothing_is_stored(guest, db_file):
    """Guests are refused on every write route and nothing is stored. (JSON routes read their small,
    64 KiB-capped body before FastAPI resolves dependencies; uploads are refused before any read.)"""
    big = b"x" * 200_000
    cases = [("post", "/api/hosts", {"json": {"name": "a", "os": "linux"}}),
             ("post", "/api/scans", {"content": big}),
             ("post", "/api/scans", {"files": {"file": ("c.json", big)}}),
             ("post", "/api/hosts/1/scans", {"content": big}),
             ("put", "/api/hosts/1/rules/UBTU-22-211015/comment", {"json": {"text": "x"}})]
    for method, path, kw in cases:
        assert getattr(guest, method)(path, **kw).status_code == 403, path
    assert guest.get("/api/hosts").status_code == 200
    assert guest.get("/api/auth/me").json()["guest"] is True
    c = db.connect(db_file)
    assert db.list_hosts(c) == []
    c.close()


# ---------------------------------------------------------------- upload limits

def test_upload_rejections(client, monkeypatch):
    def mp(data):
        return client.post("/api/scans", files={"file": ("c.json", data)})

    assert mp(b"\x00\x01binary").status_code == 415
    assert mp(b"\xff\xfe not utf8").status_code == 415
    assert mp(b"").status_code == 400
    assert mp(b"{not json").status_code == 400
    assert mp(b"[1,2,3]").status_code == 400
    r = mp(b'{"collector":"mystery","version":1}')
    assert r.status_code == 400 and "Unknown collector" in r.json()["detail"]
    assert mp(b'{"collector":["x"]}').status_code == 400
    assert mp(b'{"a":"' + b"x" * 70_000 + b'"}').status_code == 413
    r = client.post("/api/scans", content=b"<x/>", headers={"content-type": "text/xml"})
    assert r.status_code == 415
    r = client.post("/api/scans", data={"other": "1"}, files={"nofile": ("a", b"x")})
    assert r.status_code == 400
    monkeypatch.setenv("STIGWATCH_MAX_UPLOAD_MB", "1")
    r = client.post("/api/scans", content=b"x" * (1024 * 1024 + 70_000),
                    headers={"content-type": "application/json"})
    assert r.status_code == 413
    assert r.headers["x-content-type-options"] == "nosniff"
    # no Content-Length (chunked): the cap still holds
    r = client.post("/api/scans", content=(b"y" * 65536 for _ in range(40)),
                    headers={"content-type": "application/json"})
    assert r.status_code == 413


def test_collected_at_is_strict_and_normalised(client):
    raw = fixture("linux-compliant")
    for bad in ("2026-11-09", "2026-11-09T14:02:11", "yesterday", "", 5, None, "2026-13-09T14:02:11Z",
                "2999-01-01T00:00:00Z", "1999-01-01T00:00:00Z", "2026-11-09 14:02:11Z"):
        assert upload(client, {**raw, "collected_at": bad}).status_code == 400, bad
    r = upload(client, {**raw, "collected_at": "2026-11-09T16:02:11+02:00"})
    assert r.status_code == 201 and r.json()["collected_at"] == "2026-11-09T14:02:11Z"
    r = upload(client, {**raw, "collected_at": "2026-11-09T14:02:12.250Z"})
    assert r.json()["collected_at"] == "2026-11-09T14:02:12Z"
    scan = client.get(f"/api/scans/{r.json()['scan_id']}/results").json()["scan"]
    assert scan["collected_at"] == "2026-11-09T14:02:12Z"


# ---------------------------------------------------------------- hostile upload

HOSTILE_NAMES = ["../../etc/passwd", "a/b", "a\\b", "a\nb", "a\r\nSet-Cookie: x=1", "x" * 5000,
                 "<script>alert(1)</script>", "{{ 7*7 }}", "a b", "", " ", "=cmd|' /C calc'!A0",
                 "host‮", "a;rm -rf /", "$(id)", "a\x00b", "-lead", ".lead"]


def test_hostile_hostname_upload(client, db_file):
    raw = fixture("linux-compliant")
    for name in HOSTILE_NAMES:
        r = upload(client, {**raw, "host": {**raw["host"], "name": name}})
        assert r.status_code == 400, repr(name[:30])
        assert "host" in r.json()["detail"]
    c = db.connect(db_file)
    assert db.list_hosts(c) == [] and c.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 0
    c.close()
    for name in HOSTILE_NAMES:
        assert client.post("/api/hosts", json={"name": name, "os": "linux"}).status_code == 422


def test_hostile_content_is_stored_and_exported_safely(client):
    raw = fixture("linux-compliant")
    raw["host"]["os_release"] = 'Ubuntu\n]]><script>alert(1)</script>"&\x07‮=cmd|calc'
    raw["host"]["kernel"] = "=HYPERLINK(\"http://evil\")\r\n+1"
    raw["facts"]["hostile_extra"] = {"status": "ok", "value": {"a": [{"b": ["c"] * 3}] * 3}}
    r = upload(client, raw)
    assert r.status_code == 201, r.text
    sid, hid = r.json()["scan_id"], r.json()["host_id"]
    assert client.put(f"/api/hosts/{hid}/rules/UBTU-22-211015/comment",
                      json={"text": "</COMMENTS><script>x</script>\x07 =1+1"}).status_code == 200
    ckl = client.get(f"/api/scans/{sid}/export.ckl")
    assert ckl.status_code == 200
    ET.fromstring(ckl.content)                      # well-formed
    assert b"<script>" not in ckl.content
    assert json.loads(client.get(f"/api/scans/{sid}/export.cklb").content)["stigs"]
    csv = client.get("/api/reports/fleet.csv")
    html = client.get("/api/reports/fleet.html")
    assert csv.status_code == 200 and html.status_code == 200 and "<script" not in html.text
    for resp in (ckl, csv, html):
        assert resp.headers["content-disposition"].startswith('attachment; filename="')
    assert client.get(f"/api/hosts/{hid}/remediation").status_code == 200


def test_deeply_nested_json_is_refused(client):
    raw = fixture("linux-compliant")
    deep = cur = {}
    for _ in range(200):
        cur["n"] = {}
        cur = cur["n"]
    raw["facts"]["deep"] = {"status": "ok", "value": deep}
    r = upload(client, raw)
    assert r.status_code == 400 and "nested" in r.json()["detail"]
    r = client.post("/api/scans", content=b"[\n" * 100_000 + b"]\n" * 100_000,
                    headers={"content-type": "application/json"})
    assert r.status_code == 400


# ---------------------------------------------------------------- host reuse policy and ordering

def test_host_name_reuse_requires_same_fingerprint(client):
    lin = fixture("linux-compliant")
    assert upload(client, lin).status_code == 201
    win = fixture("windows-member-compliant")
    win["host"]["name"] = lin["host"]["name"].upper()          # same name, other case, other OS
    r = upload(client, win)
    assert r.status_code == 409 and "registered as linux" in r.json()["detail"]
    same = {**lin, "collected_at": "2026-11-09T20:00:00Z",
            "host": {**lin["host"], "name": lin["host"]["name"].upper()}}
    r = upload(client, same)                                    # same fingerprint, case-insensitive
    assert r.status_code == 201 and r.json()["host_created"] is False
    assert len(client.get("/api/hosts").json()) == 1


def test_upload_to_host_checks_name(client):
    h = client.post("/api/hosts", json={"name": "jammy-stig-01", "os": "linux"}).json()
    r = client.post(f"/api/hosts/{h['id']}/scans", content=body(fixture("linux-gui")),
                    headers={"content-type": "application/json"})
    assert r.status_code == 409 and "jammy-ws-12" in r.json()["detail"]
    r = client.post(f"/api/hosts/{h['id']}/scans", files={"file": ("a.json", body(fixture("linux-compliant")))})
    assert r.status_code == 201 and r.json()["host_id"] == h["id"]
    assert client.post("/api/hosts", json={"name": "JAMMY-STIG-01", "os": "linux"}).status_code == 409


def test_out_of_order_upload_recomputes_next_scans_alerts(client):
    good, bad = fixture("linux-compliant"), fixture("linux-noncompliant")
    bad["host"]["name"] = good["host"]["name"]
    a = upload(client, {**good, "collected_at": "2026-11-01T10:00:00Z"}).json()
    c = upload(client, {**bad, "collected_at": "2026-11-09T10:00:00Z"}).json()
    hid = a["host_id"]
    before = client.get("/api/alerts", params={"host_id": str(hid)}).json()
    assert before and all(x["scan_id"] == c["scan_id"] and x["prev_scan_id"] == a["scan_id"] for x in before)
    # an older scan that is already bad lands between the two: nothing regressed after it
    b = upload(client, {**bad, "collected_at": "2026-11-05T10:00:00Z"})
    assert b.status_code == 201 and b.json()["out_of_order"] is True
    assert b.json()["alerts_recomputed_for_scan"] == c["scan_id"]
    after = client.get("/api/alerts", params={"host_id": str(hid)}).json()
    assert after and all(x["scan_id"] == b.json()["scan_id"] for x in after)   # the regression is now at b
    d = client.get(f"/api/scans/{c['scan_id']}/drift").json()
    assert d["prev_scan_id"] == b.json()["scan_id"] and d["regressed"] == []


# ---------------------------------------------------------------- end to end on an empty DB

def test_end_to_end_empty_database(client):
    assert client.get("/api/hosts").json() == []
    f = client.get("/api/fleet").json()
    assert f["hosts"] == 0 and f["compliance"] is None and f["trend"] == []
    h = client.post("/api/hosts", json={"name": "jammy-stig-01", "os": "linux", "environment": "prod",
                                        "owner": "ops", "tags": ["a"]})
    assert h.status_code == 201 and h.json()["latest_scan"] is None
    hid = h.json()["id"]
    first = fixture("linux-compliant")
    r = upload(client, first)
    assert r.status_code == 201
    j = r.json()
    assert j["host_id"] == hid and j["host_created"] is False and j["drift"]["first_scan"] is True
    assert sum(j["status"].values()) == 191 and j["release"] == "V2R10"
    second = fixture("linux-noncompliant")
    second["host"]["name"] = first["host"]["name"]
    second["collected_at"] = "2026-11-09T20:00:00Z"
    j2 = upload(client, second).json()
    d = j2["drift"]
    assert d["first_scan"] is False and d["prev_scan_id"] == j["scan_id"]
    assert d["regressed"] and "newly_visible_cat1" in d
    assert j2["alerts_raised"] == len([x for x in d["regressed"] if x["cat"] == "CAT I"])
    res = client.get(f"/api/scans/{j2['scan_id']}/results").json()
    assert res["count"] == 191 and {"stig_id", "status", "cat", "title", "reason"} <= set(res["results"][0])
    only = client.get(f"/api/scans/{j2['scan_id']}/results", params={"status": "Open", "severity": "high"}).json()
    assert only["count"] and all(x["status"] == "Open" and x["cat"] == "CAT I" for x in only["results"])
    assert client.get(f"/api/scans/{j2['scan_id']}/results", params={"q": "ssh"}).json()["count"] > 0
    assert len(client.get(f"/api/hosts/{hid}/scans").json()) == 2
    detail = client.get(f"/api/hosts/{hid}").json()
    assert len(detail["trend"]) == 2 and detail["scan_count"] == 2
    assert client.get("/api/fleet").json()["hosts"] == 1
    assert client.get("/api/hosts", params={"has_cat1": "true"}).json()
    rule = d["regressed"][0]["stig_id"]
    rd = client.get(f"/api/hosts/{hid}/rules/{rule}").json()
    assert rd["history"][-1]["status"] == "Open" and rd["rule"]["fix_text"] and rd["evidence"] is not None
    assert client.put(f"/api/hosts/{hid}/rules/{rule}/comment", json={"text": "accepted risk"}).status_code == 200
    assert client.get(f"/api/hosts/{hid}/rules/{rule}").json()["comment"]["text"] == "accepted risk"
    ckl = client.get(f"/api/scans/{j2['scan_id']}/export.ckl")
    assert ckl.status_code == 200 and ckl.headers["content-disposition"].endswith('.ckl"')
    assert len(ET.fromstring(ckl.content).findall(".//VULN")) == 191
    rem = client.get(f"/api/hosts/{hid}/remediation")
    assert rem.status_code == 200 and rem.headers["content-disposition"].endswith('.yml"')
    assert "Review before applying" in rem.text


def test_windows_remediation_passes_domain_role(client, monkeypatch):
    seen = {}
    real = remediation.powershell_script

    def spy(host, opens, bench, domain_role=None):
        seen["role"] = domain_role
        return real(host, opens, bench, domain_role=domain_role)
    monkeypatch.setattr(api.remediation, "powershell_script", spy)
    dc = fixture("windows-dc")
    assert upload(client, dc).status_code == 201
    hid = client.get("/api/hosts").json()[0]["id"]
    r = client.get(f"/api/hosts/{hid}/remediation")
    assert r.status_code == 200 and r.headers["content-disposition"].endswith('.ps1"')
    assert seen["role"] == "dc" == remediation.domain_role_of(dc)
    assert "Review before applying" in r.text


def test_newly_visible_cat1_is_surfaced(client):
    full, blind = fixture("linux-noncompliant"), fixture("linux-unprivileged")
    blind["host"]["name"] = full["host"]["name"]
    upload(client, {**blind, "collected_at": "2026-11-08T10:00:00Z"})
    j = upload(client, {**full, "collected_at": "2026-11-09T10:00:00Z"}).json()
    d = client.get(f"/api/scans/{j['scan_id']}/drift").json()
    assert d["newly_visible_cat1"] == [x for x in d["newly_open"] if x["cat"] == "CAT I"]
    fleet = client.get("/api/fleet").json()
    assert len(fleet["newly_visible_cat1"]) == len(d["newly_visible_cat1"])


# ---------------------------------------------------------------- filters and injection

def test_filters_are_allow_listed_and_injection_is_inert(client):
    upload(client, fixture("linux-compliant"))
    upload(client, fixture("windows-member-compliant"))
    assert {h["os"] for h in client.get("/api/hosts", params={"os": "linux"}).json()} == {"linux"}
    assert client.get("/api/hosts", params={"os": "linux' OR 1=1--"}).status_code == 422
    assert client.get("/api/hosts", params={"has_cat1": "maybe"}).status_code == 422
    for payload in ("' OR 1=1 --", "\"; DROP TABLE hosts;--", "%", "_", "<script>"):
        assert client.get("/api/hosts", params={"q": payload}).status_code == 200
        assert client.get("/api/hosts", params={"environment": payload}).json() == []
    assert client.get("/api/hosts", params={"q": "x" * 101}).status_code == 422
    sid = client.get("/api/hosts").json()[0]["latest_scan"]["id"]
    for bad in ({"status": "Open' OR '1'='1"}, {"severity": "critical"}):
        assert client.get(f"/api/scans/{sid}/results", params=bad).status_code == 422
    assert client.get(f"/api/scans/{sid}/results", params={"q": "'; DROP TABLE results;--"}).json()["count"] == 0
    assert client.get("/api/alerts", params={"host_id": "1 OR 1=1"}).status_code == 404
    hosts = client.get("/api/hosts", params={"os": "linux"}).json()
    hid = hosts[0]["id"]
    for sid_bad in ("UBTU-22-211015'--", "..%2f..", "A" * 80):
        assert client.get(f"/api/hosts/{hid}/rules/{sid_bad}").status_code == 404
        assert client.put(f"/api/hosts/{hid}/rules/{sid_bad}/comment", json={"text": "x"}).status_code == 404
    assert client.put(f"/api/hosts/{hid}/rules/UBTU-22-999999/comment", json={"text": "x"}).status_code == 404
    assert client.put(f"/api/hosts/{hid}/rules/UBTU-22-211015/comment", json={"text": "x" * 5001}).status_code == 422
    assert client.post("/api/hosts", json={"name": "ok", "os": "freebsd"}).status_code == 422
    assert len(client.get("/api/hosts").json()) == 2


# ---------------------------------------------------------------- benchmarks, reports

def test_benchmarks_and_coverage(client):
    bl = client.get("/api/benchmarks").json()
    assert {b["id"] for b in bl} >= {"ubuntu-22.04", "windows-server-2022"}
    ub = next(b for b in bl if b["id"] == "ubuntu-22.04")
    assert ub["rules"] == 191 and ub["severity"] == {"CAT I": 16, "CAT II": 158, "CAT III": 17}
    cov = client.get("/api/benchmarks/ubuntu-22.04/coverage").json()
    assert len(cov["automated"]) + len(cov["manual"]) == 191 and cov["by_cat"]["CAT I"]["total"] == 16


def test_report_downloads(client):
    upload(client, fixture("linux-compliant"))
    html = client.get("/api/reports/fleet.html")
    assert html.headers["content-security-policy"] == "default-src 'none'; style-src 'unsafe-inline'; sandbox"
    assert html.headers["content-disposition"] == 'attachment; filename="stigwatch-fleet.html"'
    csv = client.get("/api/reports/fleet.csv")
    assert csv.text.startswith("host,os,") and "independent tool" in csv.text
    sid = client.get("/api/hosts").json()[0]["latest_scan"]["id"]
    cklb = client.get(f"/api/scans/{sid}/export.cklb")
    assert cklb.headers["content-disposition"].endswith('.cklb"') and cklb.json()["stigs"][0]["rules"]


# ---------------------------------------------------------------- demo mode

def test_demo_guest_lazy_seed_and_read_shapes(db_file, monkeypatch):
    monkeypatch.setenv("STIGWATCH_DEMO", "1")
    api._seeded.clear()
    with TestClient(api.app) as c:
        hosts = c.get("/api/hosts").json()
        assert len(hosts) == 14
        assert c.get("/api/health").json()["guest"] is True
        assert c.get("/api/fleet").json()["hosts"] == 14
        assert c.get("/api/alerts").status_code == 200
        assert set(hosts[0]) >= {"id", "name", "os", "open", "latest_scan", "compliance", "scan_count"}
        assert c.post("/api/hosts", json={"name": "z", "os": "linux"}).status_code == 403
        assert c.get("/api/openapi.json").status_code == 403
    # lifespan not run (serverless): the first request seeds a fresh database
    api._seeded.clear()
    monkeypatch.setenv("STIGWATCH_DB", str(db_file.parent / "second.db"))
    c2 = TestClient(api.app)         # no context manager: the lifespan hook does not run
    assert len(c2.get("/api/hosts").json()) == 14
    assert len(c2.get("/api/hosts").json()) == 14


# ---------------------------------------------------------------- request body caps

def test_login_body_is_capped_at_64k_but_uploads_keep_the_big_cap(client, anon):
    r = anon.post("/api/auth/login", content=b"x" * (1024 * 1024),
                  headers={"content-type": "application/json"})
    assert r.status_code == 413 and r.headers["x-content-type-options"] == "nosniff"
    r = anon.post("/api/auth/login", content=(b"y" * 8192 for _ in range(16)),   # chunked, 128 KB
                  headers={"content-type": "application/json"})
    assert r.status_code == 413
    # a sibling path does not get the upload cap
    assert client.post("/api/scans-extra", content=b"x" * (1024 * 1024)).status_code == 413
    assert client.post("/api/scans/x", content=b"x" * (1024 * 1024)).status_code == 413
    assert client.put("/api/hosts/1/rules/UBTU-22-211015/comment", content=b"x" * 100_000).status_code == 413
    # a valid upload larger than 64 KiB is accepted (pretty-printed: short lines), also with a slash
    raw = fixture("linux-compliant")
    raw["facts"]["padding"] = {"status": "ok", "value": ["row %d" % i for i in range(20000)]}
    big = json.dumps(raw, indent=1).encode()
    assert len(big) > 300_000
    r = client.post("/api/scans", content=big, headers={"content-type": "application/json"})
    assert r.status_code == 201
    raw["collected_at"] = "2026-11-09T20:00:00Z"
    r = client.post("/api/scans/", content=json.dumps(raw, indent=1).encode(),
                    headers={"content-type": "application/json"})
    assert r.status_code == 201
    hid = r.json()["host_id"]
    r = client.post(f"/api/hosts/{hid}/scans", files={"file": ("c.json", json.dumps(raw, indent=1))})
    assert r.status_code == 201


def test_413_does_not_read_the_body(anon):
    import asyncio
    reads = []

    async def run():
        sent = []

        async def receive():
            reads.append(1)
            return {"type": "http.request", "body": b"x", "more_body": True}

        async def send(m):
            sent.append(m)
        scope = {"type": "http", "method": "POST", "path": "/api/auth/login", "headers": [
            (b"content-length", str(50 * 1024 * 1024).encode())]}
        await api.BodyLimitMiddleware(lambda *a: None)(scope, receive, send)
        return sent
    sent = asyncio.run(run())
    assert sent[0]["status"] == 413 and not reads


def _count_seeds(monkeypatch, fail=False):
    calls = []

    def fake():
        calls.append(1)
        if fail:
            raise RuntimeError("disk full")
    monkeypatch.setattr(api.demo, "ensure_seeded", fake)
    return calls


def test_demo_seed_runs_once_per_database(db_file, monkeypatch):
    monkeypatch.setenv("STIGWATCH_DEMO", "1")
    api._seeded.clear()
    api._seed_failed_until.clear()
    calls = _count_seeds(monkeypatch)
    c = TestClient(api.app)
    for _ in range(6):
        assert c.get("/api/hosts").status_code == 200
    assert len(calls) == 1


def test_demo_seed_failure_is_cached_then_retried(db_file, monkeypatch):
    monkeypatch.setenv("STIGWATCH_DEMO", "1")
    api._seeded.clear()
    api._seed_failed_until.clear()
    calls = _count_seeds(monkeypatch, fail=True)
    clock = [1000.0]
    monkeypatch.setattr(api.time, "monotonic", lambda: clock[0])
    c = TestClient(api.app)
    for _ in range(5):
        r = c.get("/api/hosts")
        assert r.status_code == 503 and r.json() == {"detail": "Demo data is not available yet"}
        assert r.headers["retry-after"] == "60"
    assert len(calls) == 1                                  # one attempt within the TTL
    assert c.get("/api/health").status_code == 200          # non-data routes still work
    clock[0] += 61
    assert c.get("/api/hosts").status_code == 503
    assert len(calls) == 2                                  # retried after the TTL
    clock[0] += 61
    monkeypatch.setattr(api.demo, "ensure_seeded", lambda: calls.append(1))
    assert c.get("/api/hosts").status_code == 200 and len(calls) == 3


def test_scan_objects_expose_privileged(client):
    priv, unpriv = fixture("linux-compliant"), fixture("linux-unprivileged")
    assert priv.get("privileged") is True and unpriv.get("privileged") is False
    r = upload(client, {**priv, "collected_at": "2026-11-08T10:00:00Z"}).json()
    assert r["privileged"] is True
    unpriv["host"]["name"] = priv["host"]["name"]
    r2 = upload(client, {**unpriv, "collected_at": "2026-11-09T10:00:00Z"}).json()
    assert r2["privileged"] is False
    hid = r["host_id"]
    scans = client.get(f"/api/hosts/{hid}/scans").json()
    assert [s["privileged"] for s in scans] == [False, True]          # newest first
    assert client.get(f"/api/hosts/{hid}").json()["latest_scan"]["privileged"] is False
    res = client.get(f"/api/scans/{r['scan_id']}/results").json()
    assert res["scan"]["privileged"] is True
    # unknown is not "not privileged": missing, null and non-boolean values give null
    unknown = {k: v for k, v in priv.items() if k != "privileged"}
    assert upload(client, {**unknown, "collected_at": "2026-11-10T01:00:00Z"}).json()["privileged"] is None
    r3 = upload(client, {**priv, "collected_at": "2026-11-10T02:00:00Z", "privileged": None})
    assert r3.json()["privileged"] is None
    r4 = upload(client, {**priv, "collected_at": "2026-11-10T03:00:00Z", "privileged": "yes"})
    assert r4.status_code == 400                         # the collector envelope check refuses it
    shown = {s["id"]: s["privileged"] for s in client.get(f"/api/hosts/{hid}/scans").json()}
    assert shown[r["scan_id"]] is True and shown[r2["scan_id"]] is False and shown[r3.json()["scan_id"]] is None
    assert client.get(f"/api/hosts/{hid}").json()["latest_scan"]["privileged"] is None
    assert client.get(f"/api/scans/{r3.json()['scan_id']}/results").json()["scan"]["privileged"] is None
