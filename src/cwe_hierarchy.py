"""Offline CWE parent traversal for weakness-based CME matching.

The relationship data is generated from MITRE CWE's canonical View-1000
``ChildOf`` relationships and intentionally kept separate from CME entries.
"""

import json
from functools import lru_cache
from pathlib import Path


_PARENT_DATA_PATH = Path(__file__).parent.parent / "data" / "cwe_parents.json"


@lru_cache(maxsize=1)
def _parents() -> dict[str, tuple[str, ...]]:
    with _PARENT_DATA_PATH.open() as parent_data:
        data = json.load(parent_data)
    return {
        cwe_id: tuple(parent_ids)
        for cwe_id, parent_ids in data.get("parents", {}).items()
    }


def ancestor_cwes(cwe_id: str) -> list[str]:
    """Return ``cwe_id`` followed by its unique ancestors, nearest first.

    The explicit CWE is always first, so callers can preserve exact matches as
    the most specific result. A visited set prevents malformed source data from
    introducing a cycle into a lookup.
    """
    result: list[str] = []
    seen: set[str] = set()
    pending = [cwe_id]
    parents = _parents()

    while pending:
        current = pending.pop(0)
        if current in seen:
            continue
        seen.add(current)
        result.append(current)
        pending.extend(parent for parent in parents.get(current, ()) if parent not in seen)

    return result
