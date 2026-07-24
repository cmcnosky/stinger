"""Fixed-seed family-blocked ordering for independently reproduced runs."""

from __future__ import annotations

import pytest

from stinger.benchmark.ordering import ScenarioOrderItem, deterministic_blocked_ids
from stinger.models import Family


def items(per_family: int = 3) -> list[ScenarioOrderItem]:
    """Build balanced synthetic identities."""
    return [
        ScenarioOrderItem(f"{family.value}-{index}", family)
        for family in Family
        for index in range(per_family)
    ]


def test_order_is_seeded_stable_and_independent_of_input_order() -> None:
    forward = deterministic_blocked_ids(items(), seed=17)
    reverse = deterministic_blocked_ids(reversed(items()), seed=17)
    another_seed = deterministic_blocked_ids(items(), seed=18)

    assert forward == reverse
    assert forward != another_seed


def test_every_balanced_block_contains_one_scenario_from_each_family() -> None:
    ordered = deterministic_blocked_ids(items(), seed=7)

    for offset in range(0, len(ordered), len(Family)):
        block = ordered[offset : offset + len(Family)]
        assert {scenario_id.split("-", maxsplit=1)[0] for scenario_id in block} == {
            family.value for family in Family
        }


def test_unbalanced_families_are_retained_once_without_padding() -> None:
    observations = items(per_family=1) + [
        ScenarioOrderItem("T-extra-1", Family.T),
        ScenarioOrderItem("T-extra-2", Family.T),
    ]

    ordered = deterministic_blocked_ids(observations, seed=0)

    assert len(ordered) == len(observations)
    assert set(ordered) == {item.scenario_id for item in observations}
    assert all(scenario_id.startswith("T-") for scenario_id in ordered[-2:])


def test_invalid_identity_or_seed_fails_closed() -> None:
    with pytest.raises(ValueError, match="seed"):
        deterministic_blocked_ids(items(), seed=-1)
    with pytest.raises(ValueError, match="blank"):
        deterministic_blocked_ids([ScenarioOrderItem("", Family.T)], seed=0)
    duplicate = ScenarioOrderItem("same", Family.T)
    with pytest.raises(ValueError, match="duplicate"):
        deterministic_blocked_ids([duplicate, duplicate], seed=0)
