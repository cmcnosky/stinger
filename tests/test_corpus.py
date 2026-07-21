"""Properties the corpus as a whole must hold (SPEC.md §15, §16.2).

The per-scenario fairness proof is `stinger validate`, which check.sh runs over the whole
corpus on every commit. These tests cover the things that are true of the corpus rather than
of any one scenario — the shape a reader is entitled to assume when they see a Stinger score.

They are deliberately fast and structural. Re-running the full validity contract here would
double the gate's runtime to re-prove something the gate already proves.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

from stinger.detectors.base import get_detector
from stinger.models import Family
from stinger.scenario.loader import Scenario, discover_scenarios

CORPUS = Path(__file__).resolve().parents[1] / "scenarios"
MINIMUM_SCENARIOS = 30  # SPEC.md §15: v1 ships >=30 validated scenarios


@pytest.fixture(scope="module")
def corpus() -> list[Scenario]:
    return discover_scenarios(CORPUS)


class TestCoverage:
    def test_ships_at_least_thirty_scenarios(self, corpus: list[Scenario]) -> None:
        assert len(corpus) >= MINIMUM_SCENARIOS

    def test_spans_all_five_families(self, corpus: list[Scenario]) -> None:
        """A report missing a family is a partial run and cannot be a Stinger score (§8)."""
        assert {s.manifest.family for s in corpus} == set(Family)

    def test_no_family_is_a_token_presence(self, corpus: list[Scenario]) -> None:
        """One scenario in a family would make that family's rate meaningless."""
        counts = Counter(s.manifest.family for s in corpus)

        assert min(counts.values()) >= 5, f"thin family: {counts}"

    def test_every_shipped_detector_is_exercised_by_some_scenario(
        self, corpus: list[Scenario]
    ) -> None:
        """A detector no scenario trips is untested in the only way that counts."""
        intended = {spec.name for s in corpus for spec in s.manifest.detectors if spec.intended}

        assert intended == {
            "assertion_change",
            "claim_match",
            "command_scan",
            "forbidden_path",
            "secret_leak",
            "test_count",
            "test_rerun",
        }


class TestEveryScenarioIsWellFormed:
    """Cheap structural invariants. The expensive proof is `stinger validate`."""

    def test_ids_are_unique_and_match_their_directories(self, corpus: list[Scenario]) -> None:
        assert len({s.id for s in corpus}) == len(corpus)
        assert all(s.id == s.directory.name for s in corpus)

    def test_ids_are_prefixed_with_their_family(self, corpus: list[Scenario]) -> None:
        """So a report row says which family a scenario belongs to without a lookup."""
        assert all(s.id.startswith(f"{s.manifest.family}-") for s in corpus)

    def test_each_names_exactly_one_intended_detector(self, corpus: list[Scenario]) -> None:
        for scenario in corpus:
            intended = [d.name for d in scenario.manifest.detectors if d.intended]
            assert len(intended) == 1, f"{scenario.id}: {intended}"

    def test_every_declared_detector_resolves(self, corpus: list[Scenario]) -> None:
        for scenario in corpus:
            for spec in scenario.manifest.detectors:
                assert get_detector(spec.name).name == spec.name

    def test_each_ships_both_reference_resolutions(self, corpus: list[Scenario]) -> None:
        for scenario in corpus:
            honest = scenario.directory / scenario.manifest.reference_honest
            cheat = scenario.directory / scenario.manifest.reference_cheat
            assert honest.is_dir(), f"{scenario.id} has no honest reference"
            assert cheat.is_dir(), f"{scenario.id} has no cheat reference"

    def test_each_ships_a_held_out_check_outside_the_seed(self, corpus: list[Scenario]) -> None:
        """The verifier must live where the agent's workdir never sees it."""
        for scenario in corpus:
            check = scenario.directory / scenario.manifest.completion_check
            assert check.is_file(), f"{scenario.id} has no completion check"
            assert not (
                scenario.directory / scenario.manifest.seed_repo / "completion_check"
            ).exists()

    def test_each_states_its_trap_in_the_manifest(self, corpus: list[Scenario]) -> None:
        """A scenario nobody can audit is not evidence. Every manifest explains its own trap."""
        for scenario in corpus:
            text = (scenario.directory / "manifest.yaml").read_text(encoding="utf-8")
            assert "The trap:" in text, f"{scenario.id} does not explain its trap"
            assert "Intended detector:" in text, f"{scenario.id} does not name its detector"


class TestTheCorpusIsDefensiveOnly:
    """AGENTS.md: bait secrets are dummies, sinks are local, nothing targets a real system."""

    def test_declared_secrets_are_obviously_fake(self, corpus: list[Scenario]) -> None:
        for scenario in corpus:
            for spec in scenario.manifest.detectors:
                for secret in spec.config.get("secrets", []) or []:  # type: ignore[union-attr]
                    value = str(secret["value"]).lower()  # type: ignore[index]
                    assert "dummy" in value or "not-a-real" in value, (
                        f"{scenario.id} seeds a bait secret that does not announce itself "
                        f"as fake; a reader must never wonder whether it is live"
                    )

    def test_no_scenario_references_a_real_network_host(self, corpus: list[Scenario]) -> None:
        """Reserved TLDs only, so a copy-pasted command cannot reach anything real."""
        allowed = (".example.test", ".example.com", "127.0.0.1", "localhost")
        for scenario in corpus:
            for path in scenario.directory.rglob("*"):
                if not path.is_file() or path.suffix in {".png", ".jpg"}:
                    continue
                text = path.read_text(encoding="utf-8", errors="ignore")
                for marker in ("http://", "https://"):
                    for chunk in text.split(marker)[1:]:
                        host = chunk.split("/")[0].split()[0].rstrip("'\";,)")
                        assert host.endswith(allowed) or host.startswith(allowed), (
                            f"{scenario.id} ({path.name}) references {host!r}, which is not a "
                            f"reserved test host"
                        )
