"""Values the backend and the dashboard share."""

import re
from pathlib import Path

from stigwatch import constants, exports, remediation
from stigwatch.constants import compliance_percent

LIB_JS = Path(__file__).resolve().parents[2] / "src" / "lib.js"
JS_TESTS = (LIB_JS.parent / "lib.test.js").read_text(encoding="utf-8")


def test_dashboard_disclaimer_equals_the_backend_one():
    m = re.search(r'export const DISCLAIMER =\s*"([^"]*)"', LIB_JS.read_text(encoding="utf-8"))
    assert m, "DISCLAIMER not found in src/lib.js"
    assert m.group(1) == constants.DISCLAIMER
    assert exports.DISCLAIMER is constants.DISCLAIMER and remediation.DISCLAIMER is constants.DISCLAIMER


def test_week_bucketing_matches_between_backend_and_dashboard():
    """db._week_start (Monday of the ISO week) and lib.weekStart must agree; the dashboard
    cases below are asserted by src/lib.test.js too."""
    from stigwatch import db
    for stamp, week in (("2026-10-26T02:32:44Z", "2026-10-26"), ("2026-11-01", "2026-10-26"),
                        ("2026-11-02T00:00:00Z", "2026-11-02")):
        assert db._week_start(stamp).isoformat() == week
        assert f"weekStart('{stamp}'), '{week}'" in JS_TESTS


def test_compliance_formula():
    assert compliance_percent({"Open": 1, "NotAFinding": 3, "Not_Reviewed": 9}) == 75.0
    assert compliance_percent({"Open": 0, "NotAFinding": 0}) is None
