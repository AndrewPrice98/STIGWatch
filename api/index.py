"""Vercel entry point: serves the STIGWatch FastAPI app as a Python serverless function.

vercel.json rewrites every /api/* request here; FastAPI routes on the original path, so the
upload matcher in BodyLimitMiddleware still sees /api/scans (tests/test_entrypoint.py checks it).

Each function instance builds its own SQLite database in /tmp from backend/data/demo_fixture.json
(the fictional demo fleet), lazily: until it is ready the data routes answer 503 with Retry-After
and the dashboard retries. The hosted demo therefore resets whenever an instance is replaced.
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

# The admin variables (STIGWATCH_ADMIN_PASSWORD_HASH, STIGWATCH_SECRET_KEY) are optional here:
# without them visitors browse as a read-only guest and nobody can sign in.
# Serverless defaults; any of these can be overridden in Vercel's environment settings.
# A blank value counts as unset, as everywhere else.
for _name, _default in (("STIGWATCH_DB", "/tmp/stigwatch.db"),  # /tmp is the only writable path
                        ("STIGWATCH_DEMO", "true"),
                        ("STIGWATCH_TRUST_PROXY", "1")):  # Vercel sets X-Forwarded-For itself
    if not os.environ.get(_name, "").strip():
        os.environ[_name] = _default

# Vercel Functions reject request bodies over 4.5 MB before the app sees them
# (https://vercel.com/docs/functions/limitations#request-body-size). The upload cap plus the
# multipart allowance must stay under that, so it is never allowed above 4 MB here.
VERCEL_MAX_UPLOAD_MB = 4
try:
    _requested = int(os.environ.get("STIGWATCH_MAX_UPLOAD_MB", "").strip() or VERCEL_MAX_UPLOAD_MB)
except ValueError:
    _requested = VERCEL_MAX_UPLOAD_MB
os.environ["STIGWATCH_MAX_UPLOAD_MB"] = str(min(max(_requested, 1), VERCEL_MAX_UPLOAD_MB))

from stigwatch.api import app  # noqa: E402

__all__ = ["app"]
