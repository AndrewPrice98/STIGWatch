"""api/index.py, the Vercel entry point: it serves data routes, and the body cap still
recognises the scan upload paths (/api/scans...) when the request arrives through it."""

import importlib.util
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ENTRY = Path(__file__).resolve().parents[2] / "api" / "index.py"
UPLOAD_PATHS = ("/api/scans", "/api/scans/", "/api/hosts/1/scans")


def load_entrypoint(monkeypatch, tmp_path, **env):
    # setenv then delenv records the original so the entry point's os.environ defaults are undone.
    for name in ("STIGWATCH_DEMO", "STIGWATCH_TRUST_PROXY", "STIGWATCH_MAX_UPLOAD_MB"):
        monkeypatch.setenv(name, "x")
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("STIGWATCH_DB", str(tmp_path / "vercel.db"))  # /tmp does not exist on Windows
    monkeypatch.delenv("STIGWATCH_ADMIN_PASSWORD_HASH", raising=False)  # a deployment without an admin: guests only
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    spec = importlib.util.spec_from_file_location("vercel_entry", ENTRY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def entry(monkeypatch, tmp_path):
    return load_entrypoint(monkeypatch, tmp_path)


def test_entrypoint_serves_data_routes(entry):
    client = TestClient(entry.app)
    health = client.get("/api/health").json()
    assert health["demo"] is True and health["guest"] is True
    assert health["max_upload_mb"] == 4          # lowered below Vercel's 4.5 MB body limit
    hosts = client.get("/api/hosts")
    assert hosts.status_code == 200 and len(hosts.json()) == 14
    assert client.get("/api/benchmarks").status_code == 200


def test_upload_cap_is_never_above_the_platform_limit(monkeypatch, tmp_path):
    for requested, expected in (("50", "4"), ("2", "2"), ("junk", "4"), ("0", "1")):
        module = load_entrypoint(monkeypatch, tmp_path, STIGWATCH_MAX_UPLOAD_MB=requested)
        assert TestClient(module.app).get("/api/health").json()["max_upload_mb"] == int(expected)


@pytest.mark.parametrize("path", UPLOAD_PATHS)
def test_upload_paths_get_the_upload_cap_through_the_entrypoint(entry, path):
    client = TestClient(entry.app)
    # 200 KB is far over the 64 KiB JSON cap but under the 4 MB upload cap: not a 413.
    # (A guest cannot upload, so the app's own answer is 401/403.)
    small = client.post(path, content=b"x" * 200_000, headers={"Content-Type": "application/json"})
    assert small.status_code in (401, 403), small.text
    # Over the upload cap plus the multipart allowance: the app's own 413 JSON.
    big = client.post(path, content=b"x" * (5 * 1024 * 1024))
    assert big.status_code == 413 and "too large" in big.json()["detail"]
    assert "4 MB" in big.json()["detail"] or "MB" in big.json()["detail"]


def test_other_routes_keep_the_small_cap(entry):
    client = TestClient(entry.app)
    r = client.post("/api/auth/login", content=b"x" * 200_000, headers={"Content-Type": "application/json"})
    assert r.status_code == 413 and "KB" in r.json()["detail"]
