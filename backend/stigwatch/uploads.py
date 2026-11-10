"""Validation of uploaded collector files.

Byte-level checks (NUL bytes, UTF-8, line length), a strict ``collected_at`` parser, and a
nesting-depth limit. The envelope itself is checked by the collector modules
(``facts.linux.validate``, ``facts.windows.validate``); host names by ``db.validate_host_name``.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

# Collectors write pretty-printed JSON; a few values (for example a config file's text) are
# long single-line strings. 64 KiB per line is far above real output.
MAX_LINE_CHARS = 65536
MAX_DEPTH = 32
_TS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})")


class UploadError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def decode_json_upload(data: bytes, max_line: int = MAX_LINE_CHARS) -> str:
    """Text of an upload after the byte-level checks. NUL bytes and invalid UTF-8 give 415;
    a line over ``max_line`` characters gives 413."""
    if b"\x00" in data:
        raise UploadError(415, "File looks binary, expected a JSON text file")
    try:
        text = data.decode("utf-8-sig")  # strips a leading BOM
    except UnicodeDecodeError:
        raise UploadError(415, "File is not UTF-8 text") from None
    for n, line in enumerate(text.splitlines(), 1):
        if len(line) > max_line:
            raise UploadError(413, f"Line {n} is longer than the limit of {max_line} characters "
                                   f"({len(line)} found)")
    return text


def normalise_collected_at(value: Any, now: datetime | None = None) -> str:
    """``YYYY-MM-DDTHH:MM:SSZ`` in UTC from an ISO 8601 timestamp that carries an explicit
    UTC offset (``Z`` or ``+hh:mm``). Anything else raises ValueError: a date without a time
    or zone would sort wrongly against other scans and corrupt the drift order."""
    if not isinstance(value, str) or not _TS.fullmatch(value):
        raise ValueError("collected_at must be an ISO 8601 UTC timestamp such as "
                         "2026-11-09T14:02:11Z (with Z or an explicit offset)")
    try:
        when = datetime.fromisoformat(value)
    except ValueError:
        raise ValueError(f"collected_at {value!r} is not a valid date and time") from None
    when = when.astimezone(timezone.utc)
    now = now or datetime.now(timezone.utc)
    if when.year < 2000:
        raise ValueError("collected_at is before the year 2000")
    if when > now + timedelta(days=1):
        raise ValueError("collected_at is in the future")
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def check_depth(value: Any, limit: int = MAX_DEPTH) -> None:
    """Raise ValueError when JSON nests deeper than ``limit`` (iterative, no recursion)."""
    stack = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, dict):
            children = node.values()
        elif isinstance(node, list):
            children = node
        else:
            continue
        if depth > limit:
            raise ValueError(f"JSON is nested deeper than {limit} levels")
        stack.extend((c, depth + 1) for c in children)
