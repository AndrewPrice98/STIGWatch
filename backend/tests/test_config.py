"""Blank environment values count as unset, so .env.example can be copied verbatim."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from stigwatch import config
from stigwatch.api import app

REPO = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("value", ["", "   "])
def test_blank_values_fall_back_to_defaults(monkeypatch, value):
    for name in ("STIGWATCH_DB", "STIGWATCH_MAX_UPLOAD_MB", "STIGWATCH_SESSION_HOURS",
                 "STIGWATCH_DATA_DIR", "STIGWATCH_ADMIN_USER", "STIGWATCH_TRUSTED_PROXIES"):
        monkeypatch.setenv(name, value)
    assert config.db_path() == config.BACKEND_DIR / "data" / "stigwatch.db"
    assert config.max_upload_bytes() == 10 * 1024 * 1024
    assert config.session_hours() == 8.0
    assert config.data_dir() is None
    assert config.admin_user() == "admin"
    assert config.trusted_proxy_hops() == 0


@pytest.mark.parametrize("name, value", [("STIGWATCH_MAX_UPLOAD_MB", "junk"),
                                          ("STIGWATCH_MAX_UPLOAD_MB", "0"),
                                          ("STIGWATCH_SESSION_HOURS", "nan"),
                                          ("STIGWATCH_SESSION_HOURS", "-3")])
def test_malformed_numbers_fall_back(monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    assert config.max_upload_bytes() == 10 * 1024 * 1024
    assert config.session_hours() == 8.0


def test_real_values_still_win(monkeypatch, tmp_path):
    monkeypatch.setenv("STIGWATCH_DB", str(tmp_path / "x.db"))
    monkeypatch.setenv("STIGWATCH_MAX_UPLOAD_MB", "3")
    monkeypatch.setenv("STIGWATCH_SESSION_HOURS", "0.5")
    assert config.db_path() == tmp_path / "x.db"
    assert config.max_upload_bytes() == 3 * 1024 * 1024
    assert config.session_hours() == 0.5


def test_env_example_copied_verbatim_works(monkeypatch, tmp_path):
    """Load .env.example exactly as a user would copy it, then use the API."""
    env_file = tmp_path / ".env"
    env_file.write_text((REPO / ".env.example").read_text(encoding="utf-8"), encoding="utf-8")
    from stigwatch.auth import hash_password
    managed = ("STIGWATCH_DB", "STIGWATCH_MAX_UPLOAD_MB", "STIGWATCH_SESSION_HOURS", "STIGWATCH_DATA_DIR",
               "STIGWATCH_GUEST", "STIGWATCH_ADMIN_USER", "STIGWATCH_COOKIE_SECURE", "STIGWATCH_TRUST_PROXY")
    for name in managed:
        monkeypatch.delenv(name, raising=False)
    config.load_env_file(env_file)
    try:
        # The example leaves the admin credentials blank; the app must still answer.
        assert config.db_path().name == "stigwatch.db"
        monkeypatch.setenv("STIGWATCH_DB", str(tmp_path / "t.db"))  # keep the test off the real file
        monkeypatch.setenv("STIGWATCH_ADMIN_PASSWORD_HASH", hash_password("pw", iterations=1_000))
        monkeypatch.setenv("STIGWATCH_SECRET_KEY", "k" * 48)
        monkeypatch.setenv("STIGWATCH_COOKIE_SECURE", "false")  # TestClient talks plain http
        client = TestClient(app)
        health = client.get("/api/health")
        assert health.status_code == 200 and health.json()["max_upload_mb"] == 10
        login = client.post("/api/auth/login", json={"username": "admin", "password": "pw"})
        assert login.status_code == 200, login.text
        assert client.get("/api/hosts").status_code == 200
    finally:
        import os
        for name in managed:  # the loader wrote straight to os.environ
            os.environ.pop(name, None)


def test_blank_db_is_not_the_working_directory(monkeypatch, tmp_path):
    """Regression: STIGWATCH_DB= used to resolve to Path('') and every data route returned 500."""
    monkeypatch.setenv("STIGWATCH_DB", "")
    monkeypatch.chdir(tmp_path)
    assert config.db_path() != Path("")
