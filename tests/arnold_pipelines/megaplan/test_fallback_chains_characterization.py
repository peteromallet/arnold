"""Characterization tests for scalar-routing behavior before fallback-chain changes.

Covers the current (pre-fallback-chains) behavior of:

* AgentMode.__iter__ unpacking as exactly four values
* scalar profile expansion (profile_to_phase_models)
* scalar phase_model persistence (validation at load time)
* prep/tier routing (resolve_dispatch_spec, tier_models)
* local preflight (apply_profile_expansion basics)
* cloud preflight (resolve_cloud_chain_runtime_dependencies)
* cloud CLI materialization (_phase_model_by_label_from_preflight)

These tests will fail if any of these surfaces change their scalar semantics
during the fallback-chain implementation, serving as a compatibility baseline.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from typing import Any, Mapping

import pytest


# ---------------------------------------------------------------------------
# 1. AgentMode.__iter__ unpacking as exactly four values
# ---------------------------------------------------------------------------

class TestAgentModeUnpacking:
    """AgentMode must always unpack as exactly four values for backward compat."""

    def test_unpacks_as_exactly_four_values(self) -> None:
        from arnold_pipelines.megaplan.workers._impl import AgentMode

        mode = AgentMode(
            agent="claude",
            mode="persistent",
            refreshed=False,
            model="claude-sonnet-4-6",
            effort="high",
            resolved_model="claude-sonnet-4-6",
        )
        a, m, r, mdl = mode
        assert a == "claude"
        assert m == "persistent"
        assert r is False
        assert mdl == "claude-sonnet-4-6"

    def test_unpack_tuple_equality(self) -> None:
        from arnold_pipelines.megaplan.workers._impl import AgentMode

        mode = AgentMode(
            agent="codex",
            mode="ephemeral",
            refreshed=True,
            model="gpt-5.4",
            effort=None,
            resolved_model="gpt-5.4",
        )
        # __eq__ with a tuple compares (agent, mode, refreshed, model)
        assert mode == ("codex", "ephemeral", True, "gpt-5.4")

    def test_len_iter_is_exactly_four(self) -> None:
        from arnold_pipelines.megaplan.workers._impl import AgentMode

        mode = AgentMode(
            agent="hermes",
            mode="persistent",
            refreshed=False,
            model="deepseek:deepseek-v4-pro",
            effort=None,
            resolved_model="deepseek-v4-pro",
        )
        assert len(list(mode)) == 4

    def test_unpack_does_not_include_effort_or_resolved_model(self) -> None:
        """Effort and resolved_model are NOT included in the 4-tuple unpack."""
        from arnold_pipelines.megaplan.workers._impl import AgentMode

        mode = AgentMode(
            agent="claude",
            mode="persistent",
            refreshed=False,
            model="claude-opus-4-7",
            effort="xhigh",
            resolved_model="claude-opus-4-7",
        )
        a, m, r, mdl = mode
        assert a == "claude"
        assert m == "persistent"
        assert r is False
        assert mdl == "claude-opus-4-7"
        # effort and resolved_model are accessible but not in __iter__
        assert mode.effort == "xhigh"
        assert mode.resolved_model == "claude-opus-4-7"

    def test_resolve_agent_mode_decodes_encoded_phase_model_before_parse(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from arnold_pipelines.megaplan.types import parse_agent_spec as real_parse_agent_spec
        from arnold_pipelines.megaplan.workers._impl import resolve_agent_mode
        import arnold_pipelines.megaplan.workers._impl as worker_impl

        seen: list[str] = []

        def recording_parse_agent_spec(spec: str):
            seen.append(spec)
            return real_parse_agent_spec(spec)

        monkeypatch.setattr(worker_impl, "parse_agent_spec", recording_parse_agent_spec)
        monkeypatch.setattr(worker_impl, "_is_agent_available", lambda _agent: True)

        args = argparse.Namespace(
            phase_model=['execute=__fallback_json__:["codex:gpt-5.5","claude:claude-sonnet-4-6"]'],
            hermes=None,
            agent=None,
            ephemeral=False,
            fresh=False,
            persist=False,
        )

        resolved = resolve_agent_mode("execute", args)

        assert resolved.agent == "codex"
        assert resolved.model == "gpt-5.5"
        assert seen == ["codex:gpt-5.5"]


# ---------------------------------------------------------------------------
# 2. Scalar profile expansion (profile_to_phase_models)
# ---------------------------------------------------------------------------

class TestScalarProfileExpansion:
    """profile_to_phase_models converts a scalar dict of phase->spec into phase=spec strings."""

    def test_scalar_profile_to_phase_models(self) -> None:
        from arnold_pipelines.megaplan.profiles.policy import profile_to_phase_models

        profile = {
            "prep": "claude",
            "plan": "codex:high",
            "execute": "codex",
            "critique": "claude:sonnet",
            "revise": "codex:gpt-5.4:high",
            "review": "codex",
        }
        result = profile_to_phase_models(profile)
        assert isinstance(result, list)
        assert all(isinstance(pm, str) for pm in result)
        assert "prep=claude" in result
        assert "plan=codex:high" in result
        assert "execute=codex" in result
        assert "critique=claude:sonnet" in result
        assert "revise=codex:gpt-5.4:high" in result
        assert "review=codex" in result

    def test_empty_profile_returns_empty_list(self) -> None:
        from arnold_pipelines.megaplan.profiles.policy import profile_to_phase_models

        assert profile_to_phase_models({}) == []

    def test_profile_to_phase_models_preserves_order(self) -> None:
        from arnold_pipelines.megaplan.profiles.policy import profile_to_phase_models

        profile = {"a": "spec_a", "b": "spec_b", "c": "spec_c"}
        result = profile_to_phase_models(profile)
        assert result == ["a=spec_a", "b=spec_b", "c=spec_c"]

    def test_profile_to_phase_models_with_special_characters(self) -> None:
        from arnold_pipelines.megaplan.profiles.policy import profile_to_phase_models

        profile = {"hermes_step": "omp:fireworks/kimi-k2.6"}
        result = profile_to_phase_models(profile)
        assert result == ["hermes_step=omp:fireworks/kimi-k2.6"]


# ---------------------------------------------------------------------------
# 3. Scalar phase_model persistence
# ---------------------------------------------------------------------------

class TestScalarPhaseModelPersistence:
    """phase_model is persisted as list[str] of 'phase=spec' entries."""

    def test_validate_persisted_phase_models_accepts_valid_scalar_entries(self) -> None:
        from arnold_pipelines.megaplan._core.state import _validate_persisted_phase_models

        state = {
            "config": {
                "phase_model": [
                    "prep=claude",
                    "plan=codex:high",
                    "execute=codex",
                    "critique=claude:sonnet",
                ]
            }
        }
        # Should not raise
        _validate_persisted_phase_models(Path("/nonexistent"), state)

    def test_validate_persisted_phase_models_accepts_encoded_chain_entries(self) -> None:
        from arnold_pipelines.megaplan._core.state import _validate_persisted_phase_models

        state = {
            "config": {
                "phase_model": [
                    'execute=__fallback_json__:["codex:gpt-5.5","claude:claude-sonnet-4-6"]'
                ]
            }
        }

        _validate_persisted_phase_models(Path("/nonexistent"), state)

    def test_validate_persisted_phase_models_rejects_malformed_spec(self) -> None:
        from arnold_pipelines.megaplan._core.state import _validate_persisted_phase_models
        from arnold_pipelines.megaplan.types import CliError

        state = {
            "config": {
                "phase_model": ["critique=codex:claude:sonnet"]
            }
        }
        with pytest.raises(CliError):
            _validate_persisted_phase_models(Path("/nonexistent"), state)

    def test_validate_skips_non_dict_state(self) -> None:
        from arnold_pipelines.megaplan._core.state import _validate_persisted_phase_models

        # Should not raise for non-dict state
        _validate_persisted_phase_models(Path("/nonexistent"), None)
        _validate_persisted_phase_models(Path("/nonexistent"), "not_a_dict")

    def test_validate_skips_non_list_phase_model(self) -> None:
        from arnold_pipelines.megaplan._core.state import _validate_persisted_phase_models

        state = {"config": {"phase_model": "not_a_list"}}
        # Should not raise
        _validate_persisted_phase_models(Path("/nonexistent"), state)

    def test_phase_model_scalar_entries_are_strings(self) -> None:
        """Every phase_model entry must be a str with '=' separator in normal usage."""
        # This characterizes the expected shape of phase_model entries
        entry = "prep=claude:sonnet"
        assert isinstance(entry, str)
        assert "=" in entry
        phase, spec = entry.split("=", 1)
        assert phase == "prep"
        assert spec == "claude:sonnet"

    def test_receipt_model_configured_uses_selected_spec_from_encoded_phase_model(self, tmp_path: Path) -> None:
        from arnold_pipelines.megaplan.receipts import build_receipt

        state = {
            "name": "demo-plan",
            "iteration": 1,
            "config": {"project_dir": str(tmp_path), "profile": "demo"},
            "meta": {},
        }
        args = argparse.Namespace(
            phase_model=['execute=__fallback_json__:["codex:gpt-5.5","claude:claude-sonnet-4-6"]'],
            hermes=None,
            agent=None,
            profile="demo",
        )
        worker = SimpleNamespace(
            payload={},
            receipt_metrics={},
            model_actual=None,
            session_id=None,
            cost_usd=0.0,
            duration_ms=0,
            prompt_tokens=0,
            completion_tokens=0,
            worker_channel=None,
            auth_channel=None,
            auth_metadata=None,
        )

        receipt = build_receipt(
            phase="execute",
            state=state,
            plan_dir=tmp_path,
            args=args,
            worker=worker,
            agent="codex",
            mode="persistent",
            output_file="execute.json",
            artifact_hash="sha256:test",
            verdict="success",
        )

        assert receipt["model_configured"] == "codex:gpt-5.5"


# ---------------------------------------------------------------------------
# 4. Prep/tier routing
# ---------------------------------------------------------------------------

class TestPrepAndTierRouting:
    """resolve_dispatch_spec and tier_models dispatch behavior."""

    def test_resolve_dispatch_spec_returns_spec_for_ordinal(self) -> None:
        from arnold_pipelines.megaplan._core.dispatch import resolve_dispatch_spec

        tier_models = {
            "execute": {1: "omp:deepseek/deepseek-v4-pro", 2: "codex:gpt-5.4"},
            "critique": {1: "claude:sonnet"},
        }
        result = resolve_dispatch_spec(tier_models, "execute", 1)
        assert result == "omp:deepseek/deepseek-v4-pro"

    def test_resolve_dispatch_spec_returns_default_for_missing(self) -> None:
        from arnold_pipelines.megaplan._core.dispatch import resolve_dispatch_spec

        tier_models = {"execute": {1: "codex"}}
        result = resolve_dispatch_spec(tier_models, "execute", 99, default="fallback")
        assert result == "fallback"

    def test_resolve_dispatch_spec_returns_default_for_none_tier(self) -> None:
        from arnold_pipelines.megaplan._core.dispatch import resolve_dispatch_spec

        assert resolve_dispatch_spec(None, "execute", 1, default="default") == "default"

    def test_resolve_dispatch_spec_returns_default_for_missing_slot(self) -> None:
        from arnold_pipelines.megaplan._core.dispatch import resolve_dispatch_spec

        tier_models = {"execute": {1: "codex"}}
        result = resolve_dispatch_spec(tier_models, "nonexistent", 1, default="default")
        assert result == "default"

    def test_resolve_dispatch_agent_resolves_tier_spec(self) -> None:
        from arnold_pipelines.megaplan._core.dispatch import resolve_dispatch_agent

        args = argparse.Namespace(
            phase_model=[],
            agent=None,
            hermes=None,
            vendor=None,
            ephemeral=False,
            fresh=False,
            persist=False,
            _profile_applied=True,
            tier_models=None,
        )
        agent, mode, model = resolve_dispatch_agent(args, "codex:gpt-5.4")
        assert agent == "codex"
        assert mode in ("persistent", "ephemeral")
        assert model is not None  # model resolved from spec

    def test_tier_models_are_dict_of_phase_to_int_spec_map(self) -> None:
        """tier_models data shape: {phase: {tier_int: spec_str}}."""
        tier_models = {
            "execute": {1: "codex", 2: "claude:sonnet", 3: "omp:deepseek/deepseek-v4-pro"},
        }
        assert isinstance(tier_models, dict)
        for phase, tiers in tier_models.items():
            assert isinstance(phase, str)
            assert isinstance(tiers, dict)
            for tier_key, spec in tiers.items():
                assert isinstance(tier_key, int)
                assert isinstance(spec, str)

    def test_CANONICAL_PREP_MODELS_is_scalar_dict(self) -> None:
        from arnold_pipelines.megaplan.profiles.policy import CANONICAL_PREP_MODELS

        assert isinstance(CANONICAL_PREP_MODELS, dict)
        for stage, spec in CANONICAL_PREP_MODELS.items():
            assert isinstance(stage, str)
            assert isinstance(spec, str)

    def test_PREP_MODEL_STAGES_are_scalar_strings(self) -> None:
        from arnold_pipelines.megaplan.profiles.policy import PREP_MODEL_STAGES

        assert isinstance(PREP_MODEL_STAGES, tuple)
        for stage in PREP_MODEL_STAGES:
            assert isinstance(stage, str)


# ---------------------------------------------------------------------------
# 5. Local preflight (profile expansion basics)
# ---------------------------------------------------------------------------

class TestLocalPreflight:
    """apply_profile_expansion is the local "preflight" that bakes profiles into args."""

    def test_apply_profile_expansion_sets_phase_model(self, tmp_path: Path) -> None:
        from arnold_pipelines.megaplan.profiles.policy import apply_profile_expansion

        args = argparse.Namespace(
            profile="partnered-codex",
            phase_model=[],
            tier_models=None,
            vendor=None,
            critic=None,
            depth=None,
            deepseek_provider=None,
            agent=None,
            hermes=None,
        )
        apply_profile_expansion(args, tmp_path)
        assert isinstance(args.phase_model, list)
        # Should have at least some phase=spec entries
        assert any("=" in pm for pm in args.phase_model if isinstance(pm, str))

    def test_apply_profile_expansion_idempotent(self, tmp_path: Path) -> None:
        from arnold_pipelines.megaplan.profiles.policy import apply_profile_expansion

        args = argparse.Namespace(
            profile="partnered-codex",
            phase_model=[],
            tier_models=None,
            vendor=None,
            critic=None,
            depth=None,
            deepseek_provider=None,
            agent=None,
            hermes=None,
        )
        args1 = apply_profile_expansion(args, tmp_path)
        args2 = apply_profile_expansion(args1, tmp_path)
        assert args2.phase_model == args1.phase_model

    def test_apply_profile_expansion_sets_tier_models_on_args(self, tmp_path: Path) -> None:
        from arnold_pipelines.megaplan.profiles.policy import apply_profile_expansion

        args = argparse.Namespace(
            profile="partnered-codex",
            phase_model=[],
            tier_models=None,
            vendor=None,
            critic=None,
            depth=None,
            deepseek_provider=None,
            agent=None,
            hermes=None,
        )
        apply_profile_expansion(args, tmp_path)
        # partnered-codex profile has tier_models
        assert args.tier_models is not None
        assert isinstance(args.tier_models, dict)

    def test_cli_phase_model_overrides_profile_without_state(self, tmp_path: Path) -> None:
        from arnold_pipelines.megaplan.profiles.policy import apply_profile_expansion

        args = argparse.Namespace(
            profile="partnered-codex",
            phase_model=["execute=omp:deepseek/custom-model"],
            tier_models=None,
            vendor=None,
            critic=None,
            depth=None,
            deepseek_provider=None,
            agent=None,
            hermes=None,
        )
        apply_profile_expansion(args, tmp_path)
        assert "execute=omp:deepseek/custom-model" in args.phase_model


# ---------------------------------------------------------------------------
# 6. Cloud preflight
# ---------------------------------------------------------------------------

class TestCloudPreflight:
    """resolve_cloud_chain_runtime_dependencies for cloud chain preflight."""

    def test_resolve_returns_expected_keys(self) -> None:
        from arnold_pipelines.megaplan.chain import ChainSpec
        from arnold_pipelines.megaplan.chain.spec import MilestoneSpec
        from arnold_pipelines.megaplan.cloud.preflight import (
            resolve_cloud_chain_runtime_dependencies,
        )

        spec = ChainSpec(
            milestones=[
                MilestoneSpec(
                    label="test-milestone",
                    idea="test idea",
                    profile=None,
                    phase_model=["plan=codex", "execute=codex"],
                    vendor=None,
                    depth=None,
                    critic=None,
                    deepseek_provider=None,
                )
            ],
            base_branch="main",
        )
        result = resolve_cloud_chain_runtime_dependencies(spec)
        assert "base_branch" in result
        assert "milestones" in result
        assert "required_agents" in result
        assert "runtime_commands" in result
        assert "env_hints" in result
        assert "provider_requirements" in result
        assert "policy" in result
        assert "warning" in result

    def test_resolve_preserves_explicit_phase_model(self) -> None:
        from arnold_pipelines.megaplan.chain import ChainSpec
        from arnold_pipelines.megaplan.chain.spec import MilestoneSpec
        from arnold_pipelines.megaplan.cloud.preflight import (
            resolve_cloud_chain_runtime_dependencies,
        )

        explicit_models = ["plan=codex", "execute=codex:gpt-5.4"]
        spec = ChainSpec(
            milestones=[
                MilestoneSpec(
                    label="m1",
                    idea="test idea",
                    profile=None,
                    phase_model=explicit_models,
                    vendor=None,
                    depth=None,
                    critic=None,
                    deepseek_provider=None,
                )
            ],
            base_branch="main",
        )
        result = resolve_cloud_chain_runtime_dependencies(spec)
        milestone = result["milestones"][0]
        assert milestone["explicit_phase_model"] == explicit_models

    def test_resolve_phase_map_is_dict_of_strings(self) -> None:
        from arnold_pipelines.megaplan.chain import ChainSpec
        from arnold_pipelines.megaplan.chain.spec import MilestoneSpec
        from arnold_pipelines.megaplan.cloud.preflight import (
            resolve_cloud_chain_runtime_dependencies,
        )

        spec = ChainSpec(
            milestones=[
                MilestoneSpec(
                    label="m1",
                    idea="test idea",
                    profile=None,
                    phase_model=["plan=codex", "execute=codex"],
                    vendor=None,
                    depth=None,
                    critic=None,
                    deepseek_provider=None,
                )
            ],
            base_branch="main",
        )
        result = resolve_cloud_chain_runtime_dependencies(spec)
        resolved = result["milestones"][0]["resolved_phase_map"]
        assert isinstance(resolved, dict)
        for phase, spec_val in resolved.items():
            assert isinstance(phase, str)
            assert isinstance(spec_val, str)


# ---------------------------------------------------------------------------
# 7. Cloud CLI materialization
# ---------------------------------------------------------------------------

class TestCloudCLIMaterialization:
    """_phase_model_by_label_from_preflight controls how phase models
    are materialized into uploaded chain specs for cloud workers."""

    def test_returns_dict_keyed_by_milestone_label(self) -> None:
        from arnold_pipelines.megaplan.cloud.cli import (
            _phase_model_by_label_from_preflight,
        )

        preflight = {
            "milestones": [
                {
                    "label": "m1",
                    "profile": None,
                    "explicit_phase_model": ["plan=codex", "execute=codex"],
                    "resolved_phase_map": {"plan": "codex", "execute": "codex"},
                }
            ]
        }
        result = _phase_model_by_label_from_preflight(preflight)
        assert "m1" in result
        assert result["m1"] == ["plan=codex", "execute=codex"]

    def test_non_profiled_milestone_uses_resolved_map(self) -> None:
        from arnold_pipelines.megaplan.cloud.cli import (
            _phase_model_by_label_from_preflight,
        )

        preflight = {
            "milestones": [
                {
                    "label": "m1",
                    "profile": None,
                    "explicit_phase_model": [],
                    "resolved_phase_map": {"plan": "codex", "execute": "codex:gpt-5.4"},
                }
            ]
        }
        result = _phase_model_by_label_from_preflight(preflight)
        assert "m1" in result
        assert "plan=codex" in result["m1"]
        assert "execute=codex:gpt-5.4" in result["m1"]

    def test_profiled_milestone_with_empty_explicit_is_skipped(self) -> None:
        from arnold_pipelines.megaplan.cloud.cli import (
            _phase_model_by_label_from_preflight,
        )

        preflight = {
            "milestones": [
                {
                    "label": "m1",
                    "profile": "partnered-5",
                    "explicit_phase_model": [],
                    "resolved_phase_map": {"plan": "codex", "execute": "codex"},
                }
            ]
        }
        result = _phase_model_by_label_from_preflight(preflight)
        # Profiled milestones with empty explicit do NOT get materialized
        assert "m1" not in result

    def test_returns_empty_dict_for_no_milestones(self) -> None:
        from arnold_pipelines.megaplan.cloud.cli import (
            _phase_model_by_label_from_preflight,
        )

        assert _phase_model_by_label_from_preflight({}) == {}

    def test_phase_model_values_are_key_equals_value_strings(self) -> None:
        """Characterize the expected format of materialized phase_model."""
        from arnold_pipelines.megaplan.cloud.cli import (
            _phase_model_by_label_from_preflight,
        )

        preflight = {
            "milestones": [
                {
                    "label": "m1",
                    "profile": None,
                    "explicit_phase_model": ["prep=claude:sonnet", "plan=codex:gpt-5.4"],
                    "resolved_phase_map": {"prep": "claude:sonnet", "plan": "codex:gpt-5.4"},
                }
            ]
        }
        result = _phase_model_by_label_from_preflight(preflight)
        for pm in result.get("m1", []):
            assert "=" in pm
            phase, spec = pm.split("=", 1)
            assert phase  # phase is non-empty
            assert spec   # spec is non-empty

    def test_r8_named_profile_init_persists_high_phase_tier_and_prep_bindings(
        self, tmp_path: Path
    ) -> None:
        route = "omp:openrouter/meta/muse-spark-1.3-contributor:high"
        idea = tmp_path / "idea.md"
        idea.write_text("# r8\n", encoding="utf-8")
        proc = subprocess.run(
            [
                sys.executable, "-m", "arnold_pipelines.megaplan", "init",
                "--project-dir", str(tmp_path),
                "--profile", "all-muse-spark-openrouter",
                "--phase-model", f"plan={route}",
                "--robustness", "bare", "--idea-file", str(idea),
            ],
            cwd=Path(__file__).parents[4],
            check=False, capture_output=True, text=True,
        )
        assert proc.returncode == 0, proc.stderr or proc.stdout
        payload = json.loads(proc.stdout)
        state_path = tmp_path / ".megaplan" / "plans" / payload["plan"] / "state.json"
        config = json.loads(state_path.read_text(encoding="utf-8"))["config"]
        assert config["phase_model"]
        assert all(item.endswith(":high") for item in config["phase_model"])
        assert all(
            value.endswith(":high")
            for tiers in config["tier_models"].values()
            for value in tiers.values()
        )
        assert all(value.endswith(":high") for value in config["prep_models"].values())


class TestFallbackChainAncillaryRouting:
    def test_resolve_dispatch_spec_selects_first_tier_chain_element(self) -> None:
        from arnold_pipelines.megaplan._core.dispatch import resolve_dispatch_spec

        tier_models = {
            "execute": {
                4: ["codex:gpt-5.5", "claude:claude-sonnet-4-6"],
            }
        }

        assert resolve_dispatch_spec(tier_models, "execute", 4) == "codex:gpt-5.5"

    def test_resolve_dispatch_agent_uses_selected_chain_element(self) -> None:
        from arnold_pipelines.megaplan._core.dispatch import resolve_dispatch_agent

        args = argparse.Namespace(
            phase_model=[],
            agent=None,
            hermes=None,
            vendor=None,
            ephemeral=False,
            fresh=False,
            persist=False,
            _profile_applied=True,
            tier_models=None,
        )

        agent, mode, model = resolve_dispatch_agent(
            args,
            ["codex:gpt-5.5", "claude:claude-sonnet-4-6"],
        )

        assert agent == "codex"
        assert mode in ("persistent", "ephemeral")
        assert model == "gpt-5.5"

    def test_resolve_prep_stage_model_selects_first_chain_element(self) -> None:
        from arnold_pipelines.megaplan.orchestration.prep_research import resolve_prep_stage_model

        state = {
            "config": {
                "prep_models": {
                    "triage": ["omp:deepseek/deepseek-v4-pro", "claude:claude-sonnet-4-6"],
                }
            }
        }

        resolved = resolve_prep_stage_model(state, "triage")

        assert resolved.agent == "omp"
        assert resolved.model == "deepseek/deepseek-v4-pro"
        assert resolved.resolved_model == "deepseek/deepseek-v4-pro"

    def test_auto_driver_tier_ladder_selects_first_chain_element(self, tmp_path: Path) -> None:
        from arnold_pipelines.megaplan.auto import _read_execute_tier_ladder

        (tmp_path / "state.json").write_text(
            json.dumps(
                {
                    "config": {
                        "tier_models": {
                            "execute": {
                                "4": ["codex:gpt-5.5", "claude:claude-sonnet-4-6"],
                            }
                        }
                    }
                }
            ),
            encoding="utf-8",
        )

        assert _read_execute_tier_ladder(tmp_path) == {4: "codex:gpt-5.5"}
