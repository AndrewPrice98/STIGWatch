"""Shared pytest fixtures: known admin credentials and a throwaway database."""

import pytest

from stigwatch.auth import hash_password, limiter

TEST_USER = "admin"
TEST_PASSWORD = "correct horse battery staple"
# Few iterations keep the suite fast; production hashes use auth.DEFAULT_ITERATIONS.
TEST_HASH = hash_password(TEST_PASSWORD, iterations=1_000)


@pytest.fixture(autouse=True)
def auth_env(monkeypatch):
    """Known admin credentials for every test, regardless of any local backend/.env."""
    monkeypatch.setenv("STIGWATCH_ADMIN_USER", TEST_USER)
    monkeypatch.setenv("STIGWATCH_ADMIN_PASSWORD_HASH", TEST_HASH)
    monkeypatch.setenv("STIGWATCH_SECRET_KEY", "test-secret-" + "x" * 40)
    monkeypatch.setenv("STIGWATCH_COOKIE_SECURE", "false")  # TestClient talks plain http
    monkeypatch.setenv("STIGWATCH_TRUST_PROXY", "false")
    monkeypatch.delenv("STIGWATCH_DEMO", raising=False)
    monkeypatch.delenv("STIGWATCH_GUEST", raising=False)
    limiter.reset()
    yield
    limiter.reset()


@pytest.fixture
def db_file(tmp_path, monkeypatch):
    path = tmp_path / "test.db"
    monkeypatch.setenv("STIGWATCH_DB", str(path))
    return path


@pytest.fixture
def conn(db_file):
    from stigwatch import db

    c = db.connect(db_file)
    yield c
    c.close()
