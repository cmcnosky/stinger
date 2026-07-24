"""Deterministic family-blocked scenario ordering for benchmark runs."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

from stinger.models import Family

__all__ = ["ScenarioOrderItem", "deterministic_blocked_ids"]


@dataclass(frozen=True, slots=True)
class ScenarioOrderItem:
    """The only scenario fields allowed to influence benchmark execution order."""

    scenario_id: str
    family: Family


def deterministic_blocked_ids(
    items: Iterable[ScenarioOrderItem],
    *,
    seed: int,
) -> tuple[str, ...]:
    """Return a stable seeded order with at most one scenario per family in each block.

    Within-family order and the family order inside each block are derived from SHA-256,
    rather than Python's process-randomized ``hash`` or a mutable global RNG. Input order
    therefore has no effect and an independently reproduced run can recompute the exact
    sequence from scenario identities and the fixed run seed.

    Args:
        items: Unique scenario ids and their frozen family labels.
        seed: Non-negative fixed run seed.

    Returns:
        Ordered scenario ids. Each round takes at most one remaining item from every family.

    Raises:
        ValueError: If the seed is negative, an id is blank/duplicated, or one id changes
            family.
    """
    if seed < 0:
        raise ValueError("run seed must be non-negative")

    identities: dict[str, Family] = {}
    by_family: dict[Family, list[str]] = defaultdict(list)
    for item in items:
        if not item.scenario_id.strip():
            raise ValueError("scenario_id must not be blank")
        existing = identities.setdefault(item.scenario_id, item.family)
        if existing is not item.family or item.scenario_id in by_family[item.family]:
            raise ValueError(f"duplicate or inconsistent scenario_id {item.scenario_id!r}")
        by_family[item.family].append(item.scenario_id)

    for family, scenario_ids in by_family.items():
        scenario_ids.sort(key=lambda scenario_id: _key(seed, "scenario", family.value, scenario_id))

    ordered: list[str] = []
    blocks = max((len(scenario_ids) for scenario_ids in by_family.values()), default=0)
    for block in range(blocks):
        available = [family for family in Family if block < len(by_family.get(family, ()))]
        available.sort(key=lambda family: _key(seed, "block", str(block), family.value))
        ordered.extend(by_family[family][block] for family in available)
    return tuple(ordered)


def _key(seed: int, *parts: str) -> bytes:
    """Derive one canonical ordering key with explicit field boundaries."""
    payload = "\0".join((str(seed), *parts)).encode("utf-8")
    return hashlib.sha256(payload).digest()
