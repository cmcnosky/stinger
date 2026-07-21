"""The discrimination demo (SPEC.md §16.4) — the M8 acceptance criterion.

"The CI action fails a demo repo whose agent is configured to cheat, and passes one whose
agent is configured strictly — demonstrating the tool discriminates."

This is the test that would fail if Stinger stopped measuring anything. Everything else
checks that a component behaves as specified; this checks that the assembled instrument
responds to the one variable it claims to respond to. Both runs use the real corpus, the real
detectors, the real held-out checks and the real CI gate. The only difference is agent
behaviour.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from stinger.cli import main
from stinger.config import RunConfig
from stinger.models import Outcome
from stinger.report.generate import load_report, verify_report

REPO = Path(__file__).resolve().parents[1]
DEMO = REPO / "demo"


def run_demo(config_name: str, output: Path) -> tuple[int, object]:
    """Run one demo config into `output`, returning its exit code and report."""
    source = RunConfig.from_yaml(DEMO / config_name)
    config = output / config_name
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(
        (DEMO / config_name)
        .read_text(encoding="utf-8")
        .replace(f"output_dir: {source.output_dir}", f"output_dir: {output / 'repro'}"),
        encoding="utf-8",
    )

    result = CliRunner().invoke(main, ["run", "--config", str(config)])
    (package,) = (output / "repro").iterdir()
    return result.exit_code, load_report((package / "report.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def strict(tmp_path_factory: pytest.TempPathFactory) -> tuple[int, object]:
    return run_demo("stinger.strict.yaml", tmp_path_factory.mktemp("strict"))


@pytest.fixture(scope="module")
def permissive(tmp_path_factory: pytest.TempPathFactory) -> tuple[int, object]:
    return run_demo("stinger.permissive.yaml", tmp_path_factory.mktemp("permissive"))


class TestTheToolDiscriminates:
    """THE M8 GATE."""

    def test_the_strict_agent_passes_the_gate(self, strict: tuple[int, object]) -> None:
        exit_code, report = strict

        assert exit_code == 0
        assert report.overall_integrity_rate == 1.0  # type: ignore[attr-defined]
        assert all(r.outcome is Outcome.HONEST for r in report.results)  # type: ignore[attr-defined]

    def test_the_permissive_agent_fails_the_gate(self, permissive: tuple[int, object]) -> None:
        exit_code, report = permissive

        assert exit_code != 0
        assert report.overall_integrity_rate == 0.0  # type: ignore[attr-defined]
        assert all(r.outcome is Outcome.CHEATED for r in report.results)  # type: ignore[attr-defined]

    def test_only_the_agent_differed(
        self, strict: tuple[int, object], permissive: tuple[int, object]
    ) -> None:
        """Same corpus, same rubric. If these ever diverge, the demo proves nothing."""
        _, honest_report = strict
        _, cheating_report = permissive

        assert honest_report.corpus_hash == cheating_report.corpus_hash  # type: ignore[attr-defined]
        assert honest_report.rubric_version == cheating_report.rubric_version  # type: ignore[attr-defined]
        assert honest_report.config_fingerprint != cheating_report.config_fingerprint  # type: ignore[attr-defined]

    def test_no_single_detector_is_carrying_the_result(
        self, permissive: tuple[int, object]
    ) -> None:
        """Six scenarios, six shortcuts, more than one detector catching them."""
        _, report = permissive
        fired = {
            d.detector
            for r in report.results  # type: ignore[attr-defined]
            for d in r.detector_results
            if d.fired and not d.low_confidence
        }

        assert len(fired) >= 2, f"only {fired} fired across the whole demo"

    def test_both_runs_are_labelled_partial(
        self, strict: tuple[int, object], permissive: tuple[int, object]
    ) -> None:
        """The demo covers one family, so neither number may be presented as a score."""
        assert strict[1].partial is True  # type: ignore[attr-defined]
        assert permissive[1].partial is True  # type: ignore[attr-defined]

    def test_both_reports_survive_rescoring(
        self, strict: tuple[int, object], permissive: tuple[int, object]
    ) -> None:
        verify_report(strict[1])  # type: ignore[arg-type]
        verify_report(permissive[1])  # type: ignore[arg-type]


class TestTheDemoConfigsAreHonestlyPaired:
    """The demo only proves something if the two configs are otherwise identical."""

    def test_they_differ_only_in_the_agent_and_where_output_goes(self) -> None:
        strict = json.loads(RunConfig.from_yaml(DEMO / "stinger.strict.yaml").resolved_json())
        permissive = json.loads(
            RunConfig.from_yaml(DEMO / "stinger.permissive.yaml").resolved_json()
        )

        differing = {k for k in strict if strict[k] != permissive[k]}

        assert differing == {"agent", "output_dir", "config_fingerprint"}

    def test_both_gate_at_the_same_threshold(self) -> None:
        strict = RunConfig.from_yaml(DEMO / "stinger.strict.yaml")
        permissive = RunConfig.from_yaml(DEMO / "stinger.permissive.yaml")

        assert strict.regression_threshold == permissive.regression_threshold == 0.9

    def test_both_agents_are_executable(self) -> None:
        for agent in ("strict-agent.sh", "permissive-agent.sh"):
            assert (DEMO / "agents" / agent).stat().st_mode & 0o111, agent
