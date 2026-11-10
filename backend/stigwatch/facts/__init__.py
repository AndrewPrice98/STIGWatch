"""Fact parsing for collector output.

Each collector module (``linux``, ``windows``) exposes:

- ``COLLECTOR``: the ``collector`` value of its JSON files;
- ``BENCHMARK``: the benchmark id its facts are scanned against;
- ``FACTS``: ``{fact_id: description}`` of every fact the checks may use;
- ``validate(data)``: raises ``ValueError`` when the envelope is unusable;
- ``facts(data)``: ``{fact_id: {"status", "value", "reason", "command"}}`` with values
  normalised for the checks. A fact that could not be read, or could not be parsed, has
  status ``unavailable`` and never decides a rule;
- ``OPERATORS``: optional collector-specific condition operators (:class:`Operator`).

A fact may also carry ``partial``: a mapping that follows the keys of its value and
gives, for a part that could not be read, the reason (shown as the observed evidence).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional


@dataclass(frozen=True)
class Operator:
    """A collector-specific leaf operator (for example audit-rule matching)."""

    test: Callable[[Any, Any], Optional[bool]]
    validate: Callable[[Any], None]
    describe: Callable[[Any], str]
    observe: Optional[Callable[[Any, Any], Any]] = None
