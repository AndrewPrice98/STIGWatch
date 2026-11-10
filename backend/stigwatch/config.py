"""Runtime configuration, read from environment variables.

Values are read through functions (not module constants) so tests can
override them with environment variables at any time.

For local development, variables can also live in backend/.env (git-ignored).
Real environment variables always win, so a hosting provider's settings
(for example Vercel project environment variables) take precedence.
"""

import os
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
REPO_DIR = BACKEND_DIR.parent
DEMO_FIXTURE = BACKEND_DIR / "data" / "demo_fixture.json"
ENV_FILE = BACKEND_DIR / ".env"


def load_env_file(path: Path = ENV_FILE) -> None:
    """Minimal .env loader: KEY=VALUE lines, '#' comments, optional quotes.
    Never overrides variables that are already set."""
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        os.environ.setdefault(key.strip(), value)


load_env_file()


def env_str(name: str, default: str = "") -> str:
    """An environment variable, with a blank or whitespace-only value treated as unset.
    A copied-but-unfilled line such as `STIGWATCH_DB=` must not override the default."""
    value = os.environ.get(name)
    if value is None or not value.strip():
        return default
    return value.strip()


def _number(name: str, default: float, minimum: float) -> float:
    """A positive number from the environment; unset, blank, malformed or too small -> default."""
    try:
        value = float(env_str(name, str(default)))
    except ValueError:
        return default
    if value != value or value < minimum:  # NaN or below the floor
        return default
    return value


def _flag(name: str, default: bool) -> bool:
    value = env_str(name)
    if not value:
        return default
    return value.lower() in ("1", "true", "yes", "on")


def db_path() -> Path:
    value = env_str("STIGWATCH_DB")
    return Path(value) if value else BACKEND_DIR / "data" / "stigwatch.db"


def max_upload_bytes() -> int:
    return int(_number("STIGWATCH_MAX_UPLOAD_MB", 10, 1)) * 1024 * 1024


# -- authentication --------------------------------------------------------------------

def admin_user() -> str:
    return env_str("STIGWATCH_ADMIN_USER", "admin")


def admin_password_hash() -> str:
    return env_str("STIGWATCH_ADMIN_PASSWORD_HASH")


def secret_key() -> str:
    """Key that signs session tokens. Must be long and random; rotating it logs everyone out."""
    return env_str("STIGWATCH_SECRET_KEY")


def session_hours() -> float:
    return _number("STIGWATCH_SESSION_HOURS", 8.0, 0.01)


def cookie_secure() -> bool:
    """Send the session cookie over HTTPS only. On by default (production); the local
    .env written by `create-admin` turns it off for plain-http development."""
    return _flag("STIGWATCH_COOKIE_SECURE", True)


def demo_mode() -> bool:
    """Hosted demo: data is seeded from the fictional demo organization."""
    return _flag("STIGWATCH_DEMO", False)


def guest_enabled() -> bool:
    """Anonymous read-only access. Defaults to on in demo mode, off everywhere else."""
    return _flag("STIGWATCH_GUEST", demo_mode())


def trusted_proxy_hops() -> int:
    """How many reverse proxies in front of the app append to X-Forwarded-For (0 = trust none,
    the default). STIGWATCH_TRUSTED_PROXIES sets the count; STIGWATCH_TRUST_PROXY=true is
    shorthand for one proxy. Clients can send any X-Forwarded-For they like, so the client
    address is taken from the right: the entry the outermost trusted proxy appended."""
    try:
        hops = int(env_str("STIGWATCH_TRUSTED_PROXIES", "0"))
    except ValueError:
        hops = 0
    if hops <= 0 and _flag("STIGWATCH_TRUST_PROXY", False):
        hops = 1
    return max(0, min(hops, 10))


def trust_proxy() -> bool:
    return trusted_proxy_hops() > 0


def data_dir() -> Path | None:
    """Where locally imported benchmarks live (STIGWATCH_DATA_DIR); None means ~/.stigwatch."""
    value = env_str("STIGWATCH_DATA_DIR")
    return Path(value) if value else None
