#!/usr/bin/env python3
"""Small, JSON-safe evidence helpers shared by local adapters.

The scanner deliberately keeps evidence collection separate from answer
selection.  These helpers decode structured tool output and preserve the
analyzer/source chain while leaving the existing candidate state unchanged.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable

from ico_scan_core import FlagMatcher


@dataclass(frozen=True)
class EvidenceRecord:
    analyzer: str
    artifact: str
    value: str
    state: str = "candidate"
    triage: str = "candidate"
    source: str = ""
    parent: str | None = None
    transform_chain: tuple[str, ...] = ()
    metadata: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "analyzer": self.analyzer,
            "artifact": self.artifact,
            "value": self.value,
            "state": self.state,
            "triage": self.triage,
            "source": self.source,
            "parent": self.parent,
            "transform_chain": list(self.transform_chain),
            "metadata": dict(self.metadata),
        }


def _walk_strings(value: Any, *, max_items: int = 2048, max_length: int = 4096) -> Iterable[str]:
    seen = 0

    def walk(node: Any) -> Iterable[str]:
        nonlocal seen
        if seen >= max_items:
            return
        if isinstance(node, str):
            seen += 1
            yield node[:max_length]
            return
        if isinstance(node, dict):
            for key, item in node.items():
                if seen >= max_items:
                    break
                if isinstance(key, str):
                    seen += 1
                    yield key[:max_length]
                yield from walk(item)
            return
        if isinstance(node, (list, tuple)):
            for item in node:
                if seen >= max_items:
                    break
                yield from walk(item)

    yield from walk(value)


def structured_flag_hits(
    text: str,
    *,
    analyzer: str,
    source: str,
    max_bytes: int = 1_048_576,
) -> list[dict[str, object]]:
    """Parse JSON output when possible and scan decoded string values.

    Invalid JSON simply returns no structured hits; the caller still scans the
    raw output through the normal matcher.  No value is promoted beyond the
    matcher-provided candidate state.
    """

    view = text[:max_bytes]
    try:
        payload = json.loads(view)
    except (TypeError, ValueError, json.JSONDecodeError):
        return []
    matcher = FlagMatcher()
    hits: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for index, value in enumerate(_walk_strings(payload)):
        for hit in matcher.scan(value, source=f"{source}#json[{index}]", analyzer=analyzer):
            key = (str(hit.get("value", "")), str(hit.get("source", "")))
            if key in seen:
                continue
            seen.add(key)
            hit["structured"] = True
            hit["format"] = "json"
            hits.append(hit)
    return hits


def merge_evidence(records: Iterable[EvidenceRecord]) -> tuple[EvidenceRecord, ...]:
    """Stable value/source deduplication for reports and derived queues."""

    unique: dict[tuple[str, str, str, tuple[str, ...]], EvidenceRecord] = {}
    for record in records:
        key = (record.value, record.artifact, record.analyzer, record.transform_chain)
        unique.setdefault(key, record)
    return tuple(sorted(unique.values(), key=lambda item: (item.artifact, item.analyzer, item.value, item.transform_chain)))


__all__ = ["EvidenceRecord", "merge_evidence", "structured_flag_hits"]
