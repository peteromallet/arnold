from __future__ import annotations

from argparse import Namespace
from pathlib import Path

import pytest

from arnold_pipelines.megaplan.fallback_chains import (
    configured_fallback_chain_for_phase,
    encode_phase_model_value,
    is_encoded_fallback_specs,
)
from arnold_pipelines.megaplan.profiles.policy import (
    _profile_has_premium_slots,
    _validate_named_profile_invariants,
    _validate_resolved_profile_invariants,
    apply_available_model_floor,
    apply_critic_rewrite,
    apply_deepseek_provider_rewrite,
    apply_depth_rewrite,
    apply_profile_expansion,
    apply_vendor_rewrite,
    profile_to_phase_models,
)
from arnold_pipelines.megaplan.types import CliError


# ---------------------------------------------------------------------------
# Chain-aware scalar preservation: apply_vendor_rewrite
# ---------------------------------------------------------------------------


class TestVendorRewriteScalarPreservation:
    """apply_vendor_rewrite preserves scalar-vs-list shape and order."""

    def test_scalar_stays_scalar(self) -> None:
        profile = {"plan": "codex:gpt-5.4", "execute": "claude:sonnet"}
        result = apply_vendor_rewrite(profile, "claude")
        assert isinstance(result["plan"], str)
        assert isinstance(result["execute"], str)
        # codex → claude via swap; claude stays claude
        assert "claude" in result["plan"]
        assert "claude" in result["execute"]

    def test_list_stays_list_with_order_preserved(self) -> None:
        profile = {"plan": ["codex:gpt-5.4", "claude:sonnet", "omp:deepseek/deepseek-v4-pro"]}
        result = apply_vendor_rewrite(profile, "claude")
        assert isinstance(result["plan"], list)
        assert len(result["plan"]) == 3
        # First element (codex) swapped to claude; second stays claude; third OMP unchanged
        assert result["plan"][0] != "codex:gpt-5.4"
        assert result["plan"][1] == "claude:sonnet"
        assert result["plan"][2] == "omp:deepseek/deepseek-v4-pro"

    def test_mixed_scalar_and_list_phases(self) -> None:
        profile = {
            "prep": "claude",
            "plan": ["codex:high", "omp:deepseek/deepseek-v4-pro"],
            "execute": "codex",
        }
        result = apply_vendor_rewrite(profile, "claude")
        assert isinstance(result["prep"], str)
        assert isinstance(result["plan"], list)
        assert isinstance(result["execute"], str)
        assert len(result["plan"]) == 2

    def test_tier_models_list_preserves_shape(self) -> None:
        profile = {"execute": "codex"}
        tier_models = {"execute": {1: ["codex:gpt-5.4", "omp:deepseek/deepseek-v4-pro"]}}
        result = apply_vendor_rewrite(profile, "claude", tier_models=tier_models)
        assert isinstance(result["execute"], str)
        tm = tier_models["execute"][1]
        assert isinstance(tm, list)
        assert len(tm) == 2
        assert tm[1] == "omp:deepseek/deepseek-v4-pro"

    def test_prep_models_list_preserves_shape(self) -> None:
        profile = {"prep": "claude"}
        prep_models = {"triage": ["omp:deepseek/deepseek-v4-pro", "claude:sonnet"]}
        apply_vendor_rewrite(profile, "claude", prep_models=prep_models)
        assert isinstance(prep_models["triage"], list)
        assert len(prep_models["triage"]) == 2


# ---------------------------------------------------------------------------
# Chain-aware scalar preservation: apply_critic_rewrite
# ---------------------------------------------------------------------------


class TestCriticRewriteScalarPreservation:
    """apply_critic_rewrite preserves scalar-vs-list shape and order."""

    def test_kimi_scalar_replaced_by_scalar(self) -> None:
        profile = {"critique": "codex", "review": "claude:sonnet"}
        result = apply_critic_rewrite(profile, "kimi", vendor="codex")
        assert isinstance(result["critique"], str)
        assert isinstance(result["review"], str)
        assert "kimi" in result["critique"]
        assert "kimi" in result["review"]

    def test_kimi_list_replaced_by_scalar(self) -> None:
        """kimi critic replaces the entire spec with a scalar KIMI_SPEC."""
        profile = {
            "critique": ["codex:high", "omp:deepseek/deepseek-v4-pro"],
            "review": "claude",
        }
        result = apply_critic_rewrite(profile, "kimi", vendor="codex")
        # kimi overwrites both phases with the scalar KIMI_SPEC
        assert isinstance(result["critique"], str)
        assert isinstance(result["review"], str)
        assert "kimi" in result["critique"]
        assert "kimi" in result["review"]

    def test_cross_scalar_preserves_scalar(self) -> None:
        # Use specs without explicit model pins to avoid vendor_swap_model_conflict
        profile = {"critique": "codex", "review": "codex"}
        result = apply_critic_rewrite(profile, "cross", vendor="codex")
        assert isinstance(result["critique"], str)
        assert isinstance(result["review"], str)

    def test_cross_list_maps_over_each_element(self) -> None:
        profile = {
            "critique": ["codex", "omp:deepseek/deepseek-v4-pro"],
            "review": "codex",
        }
        result = apply_critic_rewrite(profile, "cross", vendor="codex")
        assert isinstance(result["critique"], list)
        assert len(result["critique"]) == 2
        # codex premium → swapped to claude; OMP non-premium → unchanged
        assert result["critique"][1] == "omp:deepseek/deepseek-v4-pro"


# ---------------------------------------------------------------------------
# Chain-aware scalar preservation: apply_depth_rewrite
# ---------------------------------------------------------------------------


class TestDepthRewriteScalarPreservation:
    """apply_depth_rewrite preserves scalar-vs-list shape and order."""

    def test_scalar_stays_scalar_in_depth_author_phase(self) -> None:
        profile = {"plan": "codex:high"}
        result = apply_depth_rewrite(profile, "max")
        assert isinstance(result["plan"], str)
        assert "max" in result["plan"]

    def test_list_stays_list_with_depth_applied_to_each(self) -> None:
        profile = {"plan": ["codex:high", "claude:medium", "omp:deepseek/deepseek-v4-pro"]}
        result = apply_depth_rewrite(profile, "max")
        assert isinstance(result["plan"], list)
        assert len(result["plan"]) == 3
        # premium agents get depth appended; OMP (non-premium) unchanged
        assert "max" in result["plan"][0]
        assert "max" in result["plan"][1]
        assert result["plan"][2] == "omp:deepseek/deepseek-v4-pro"

    def test_non_depth_author_phase_unchanged(self) -> None:
        profile = {"execute": ["codex:gpt-5.4", "claude:sonnet"]}
        result = apply_depth_rewrite(profile, "max")
        # execute is not in DEPTH_AUTHOR_PHASES
        assert result["execute"] == ["codex:gpt-5.4", "claude:sonnet"]

    def test_tier_models_list_preserves_order(self) -> None:
        profile = {"execute": "codex"}
        tier_models = {"plan": {1: ["codex:high", "omp:deepseek/deepseek-v4-pro"]}}
        apply_depth_rewrite(profile, "xhigh", tier_models=tier_models)
        tm = tier_models["plan"][1]
        assert isinstance(tm, list)
        assert len(tm) == 2
        assert tm[1] == "omp:deepseek/deepseek-v4-pro"


# ---------------------------------------------------------------------------
# Chain-aware scalar preservation: apply_deepseek_provider_rewrite
# ---------------------------------------------------------------------------


class TestDeepseekProviderRewriteScalarPreservation:
    """apply_deepseek_provider_rewrite preserves scalar-vs-list shape and order."""

    def test_scalar_stays_scalar(self) -> None:
        from arnold_pipelines.megaplan.profiles.policy import FIREWORKS_DEEPSEEK_V4_PRO_SPEC

        profile = {"execute": FIREWORKS_DEEPSEEK_V4_PRO_SPEC}
        result = apply_deepseek_provider_rewrite(profile, "direct")
        assert isinstance(result["execute"], str)

    def test_list_stays_list(self) -> None:
        from arnold_pipelines.megaplan.profiles.policy import FIREWORKS_DEEPSEEK_V4_PRO_SPEC

        profile = {"execute": [FIREWORKS_DEEPSEEK_V4_PRO_SPEC, "codex:gpt-5.4"]}
        result = apply_deepseek_provider_rewrite(profile, "direct")
        assert isinstance(result["execute"], list)
        assert len(result["execute"]) == 2
        # codex spec unchanged (not a fireworks deepseek spec)
        assert result["execute"][1] == "codex:gpt-5.4"

    def test_tier_models_list_preserves_shape(self) -> None:
        from arnold_pipelines.megaplan.profiles.policy import FIREWORKS_DEEPSEEK_V4_PRO_SPEC

        profile = {"execute": "codex"}
        tier_models = {"execute": {1: [FIREWORKS_DEEPSEEK_V4_PRO_SPEC, "codex:gpt-5.4"]}}
        apply_deepseek_provider_rewrite(profile, "direct", tier_models=tier_models)
        tm = tier_models["execute"][1]
        assert isinstance(tm, list)
        assert len(tm) == 2


# ---------------------------------------------------------------------------
# Chain-aware scalar preservation: apply_available_model_floor
# ---------------------------------------------------------------------------


class TestAvailableModelFloorScalarPreservation:
    """apply_available_model_floor preserves scalar-vs-list shape and order."""

    def test_scalar_stays_scalar_when_no_degradation(self, monkeypatch) -> None:
        profile = {"execute": "omp:deepseek/deepseek-v4-pro"}
        result = apply_available_model_floor(profile)
        assert isinstance(result["execute"], str)
        assert result["execute"] == "omp:deepseek/deepseek-v4-pro"

    def test_list_stays_list_with_order_preserved(self) -> None:
        profile = {"execute": ["omp:deepseek/deepseek-v4-pro", "codex:gpt-5.4"]}
        result = apply_available_model_floor(profile)
        assert isinstance(result["execute"], list)
        assert len(result["execute"]) == 2
        # order is preserved
        assert result["execute"][0] == "omp:deepseek/deepseek-v4-pro"
        assert result["execute"][1] == "codex:gpt-5.4"

    def test_tier_models_list_preserves_shape(self) -> None:
        profile = {"execute": "codex"}
        tier_models = {"execute": {1: ["omp:deepseek/deepseek-v4-pro", "codex:gpt-5.4"]}}
        apply_available_model_floor(profile, tier_models=tier_models)
        tm = tier_models["execute"][1]
        assert isinstance(tm, list)
        assert len(tm) == 2


# ---------------------------------------------------------------------------
# Chain-aware invariant checks
# ---------------------------------------------------------------------------


class TestResolvedProfileInvariantsChainAware:
    """_validate_resolved_profile_invariants scans every element in chains."""

    def test_scalar_premium_placeholder_detected(self) -> None:
        with pytest.raises(CliError, match="premium"):
            _validate_resolved_profile_invariants("test", {"plan": "premium"})

    def test_list_premium_placeholder_detected(self) -> None:
        with pytest.raises(CliError, match="premium"):
            _validate_resolved_profile_invariants("test", {"plan": ["codex", "premium"]})

    def test_list_element_index_in_error(self) -> None:
        with pytest.raises(CliError) as exc_info:
            _validate_resolved_profile_invariants("test", {"plan": ["codex", "premium"]})
        error_msg = str(exc_info.value)
        assert "plan" in error_msg
        assert "premium" in error_msg

    def test_all_elements_scanned_not_just_first(self) -> None:
        """Ensure the invariant check scans ALL elements, not just the first."""
        # First element is fine, second has premium placeholder
        with pytest.raises(CliError, match="premium"):
            _validate_resolved_profile_invariants("test", {"plan": ["codex", "premium"]})

    def test_no_premium_in_any_element_passes(self) -> None:
        _validate_resolved_profile_invariants("test", {"plan": ["codex", "claude:sonnet"]})

    def test_tier_models_list_with_premium_detected(self) -> None:
        with pytest.raises(CliError, match="premium"):
            _validate_resolved_profile_invariants(
                "test",
                {"plan": "codex"},
                tier_models={"execute": {1: ["codex", "premium"]}},
            )

    def test_prep_models_list_with_premium_detected(self) -> None:
        with pytest.raises(CliError, match="premium"):
            _validate_resolved_profile_invariants(
                "test",
                {"plan": "codex"},
                prep_models={"triage": ["omp:deepseek/deepseek-v4-pro", "premium"]},
            )


class TestNamedProfileInvariantsChainAware:
    """_validate_named_profile_invariants scans every element in chains."""

    def test_list_element_with_wrong_vendor_detected(self) -> None:
        with pytest.raises(CliError, match="expected codex"):
            _validate_named_profile_invariants(
                "partnered-codex",
                {"plan": ["codex", "claude:sonnet"]},
            )

    def test_list_all_correct_vendor_passes(self) -> None:
        _validate_named_profile_invariants(
            "partnered-codex",
            {"plan": ["codex:high", "codex:medium"]},
        )

    def test_tier_models_list_element_checked(self) -> None:
        with pytest.raises(CliError, match="expected codex"):
            _validate_named_profile_invariants(
                "partnered-codex",
                {"plan": "codex"},
                tier_models={"execute": {1: ["codex", "claude:sonnet"]}},
            )


class TestProfileHasPremiumSlotsChainAware:
    """_profile_has_premium_slots scans every chain element."""

    def test_scalar_premium_detected(self) -> None:
        assert _profile_has_premium_slots({"plan": "codex"}) is True

    def test_list_premium_detected(self) -> None:
        assert _profile_has_premium_slots({"plan": ["omp:deepseek/deepseek-v4-pro", "codex"]}) is True

    def test_list_no_premium_returns_false(self) -> None:
        assert _profile_has_premium_slots({"plan": ["omp:deepseek/deepseek-v4-pro"]}) is False

    def test_scalar_no_premium_returns_false(self) -> None:
        assert _profile_has_premium_slots({"plan": "omp:deepseek/deepseek-v4-pro"}) is False

    def test_premium_placeholder_detected_in_list(self) -> None:
        assert _profile_has_premium_slots({"plan": ["omp:deepseek/deepseek-v4-pro", "premium"]}) is True


# ---------------------------------------------------------------------------
# Chain-aware profile_to_phase_models
# ---------------------------------------------------------------------------


class TestProfileToPhaseModelsChainAware:
    """profile_to_phase_models encodes chains correctly."""

    def test_scalar_produces_phase_equals_spec(self) -> None:
        result = profile_to_phase_models({"plan": "codex:high"})
        assert result == ["plan=codex:high"]

    def test_list_produces_encoded_fallback_json(self) -> None:
        result = profile_to_phase_models({"plan": ["codex:high", "claude:sonnet"]})
        assert len(result) == 1
        assert result[0].startswith("plan=")
        value = result[0].split("=", 1)[1]
        assert is_encoded_fallback_specs(value)

    def test_single_element_list_encodes_as_scalar(self) -> None:
        """Single-element chains use the compact scalar form in phase_model."""
        result = profile_to_phase_models({"plan": ["codex:high"]})
        assert result == ["plan=codex:high"]

    def test_mixed_scalar_and_list_phases(self) -> None:
        result = profile_to_phase_models({
            "prep": "claude",
            "plan": ["codex:high", "claude:sonnet"],
            "execute": "codex",
        })
        assert len(result) == 3
        scalars = [pm for pm in result if not is_encoded_fallback_specs(pm.split("=", 1)[1])]
        encoded = [pm for pm in result if is_encoded_fallback_specs(pm.split("=", 1)[1])]
        assert len(scalars) == 2
        assert len(encoded) == 1

    def test_scalar_empty_profile(self) -> None:
        assert profile_to_phase_models({}) == []


def test_explicit_prep_phase_model_overrides_profile_prep_models(tmp_path: Path) -> None:
    args = Namespace(
        profile="partnered-5",
        phase_model=["prep=omp:moonshot/kimi-k2.7-code"],
        tier_models=None,
        vendor=None,
        critic=None,
        depth=None,
        deepseek_provider=None,
    )

    apply_profile_expansion(args, tmp_path)

    assert args.prep_models == {
        "triage": "omp:moonshot/kimi-k2.7-code",
        "fanout": "omp:moonshot/kimi-k2.7-code",
        "distill": "omp:moonshot/kimi-k2.7-code",
    }


def test_profile_expansion_with_phase_model_and_no_state_keeps_tier_models(tmp_path: Path) -> None:
    args = Namespace(
        profile="partnered-codex",
        phase_model=["execute=codex"],
        tier_models=None,
        vendor=None,
        critic=None,
        depth=None,
        deepseek_provider=None,
    )

    apply_profile_expansion(args, tmp_path)

    assert "execute=codex" in args.phase_model
    assert args.tier_models is not None
    assert "execute" not in args.tier_models
    assert "critique" in args.tier_models


def test_profile_expansion_without_cli_keeps_profile_execute_tier_models(tmp_path: Path) -> None:
    args = Namespace(
        profile="partnered-5",
        phase_model=[],
        tier_models=None,
        vendor=None,
        critic=None,
        depth=None,
        deepseek_provider=None,
    )

    apply_profile_expansion(args, tmp_path)

    execute_chain = configured_fallback_chain_for_phase(args.phase_model, "execute")
    assert execute_chain is not None
    assert execute_chain.specs == (
        "omp:deepseek/deepseek-v4-pro",
        "codex:gpt-5.6-sol:high",
    )
    assert args.tier_models is not None
    assert "execute" in args.tier_models
    assert args.tier_models["execute"][3] == "omp:deepseek/deepseek-v4-flash"
    assert "critique" in args.tier_models


def test_profile_expansion_execute_tiers_survive_profile_fallback_pin(tmp_path: Path) -> None:
    from arnold_pipelines.megaplan.handlers.execute import _extract_execute_tier_map

    args = Namespace(
        profile="partnered-5",
        phase_model=[],
        tier_models=None,
        vendor="codex",
        critic=None,
        depth="high",
        deepseek_provider=None,
    )

    apply_profile_expansion(args, tmp_path)

    execute_chain = configured_fallback_chain_for_phase(args.phase_model, "execute")
    assert execute_chain is not None
    assert execute_chain.specs == (
        "omp:deepseek/deepseek-v4-pro",
        "codex:gpt-5.6-sol:high",
    )
    tier_map = _extract_execute_tier_map(args.tier_models)
    assert tier_map is not None
    assert tier_map[1] == "omp:deepseek/deepseek-v4-flash"
    assert tier_map[3] == "omp:deepseek/deepseek-v4-flash"
    assert tier_map[5] == "omp:deepseek/deepseek-v4-flash"
    assert tier_map[9] == "omp:deepseek/deepseek-v4-pro"
    assert tier_map[10] == "omp:deepseek/deepseek-v4-pro"


def test_profile_expansion_with_persisted_execute_pin_keeps_execute_pinned_and_suppressed(
    tmp_path: Path,
) -> None:
    args = Namespace(
        profile="partnered-5",
        phase_model=[],
        tier_models=None,
        vendor=None,
        critic=None,
        depth=None,
        deepseek_provider=None,
    )
    state = {"config": {"phase_model": ["execute=codex:gpt-5.5"]}}

    apply_profile_expansion(args, tmp_path, state=state)

    assert "execute=codex:gpt-5.5" in args.phase_model
    assert args.tier_models is not None
    assert "execute" not in args.tier_models
    assert "critique" in args.tier_models


def test_profile_expansion_selects_first_explicit_prep_chain_for_stage_models(tmp_path: Path) -> None:
    encoded_prep = encode_phase_model_value(
        "prep",
        ["omp:moonshot/kimi-k2.7-code", "omp:deepseek/deepseek-v4-pro"],
    )
    args = Namespace(
        profile="partnered-5",
        phase_model=[encoded_prep],
        tier_models=None,
        vendor=None,
        critic=None,
        depth=None,
        deepseek_provider=None,
    )

    apply_profile_expansion(args, tmp_path)

    assert encoded_prep in args.phase_model
    assert args.prep_models == {
        "triage": "omp:moonshot/kimi-k2.7-code",
        "fanout": "omp:moonshot/kimi-k2.7-code",
        "distill": "omp:moonshot/kimi-k2.7-code",
    }


def test_all_muse_expansion_covers_every_nested_route_and_resolver_trace(
    tmp_path: Path,
) -> None:
    """The all-Muse profile must pin flat and nested routes alike.

    A flat ``prep`` phase does not control triage/fanout/distill, and an
    absent tier table leaves execute/critique complexity routing to defaults.
    Exercise the real profile expansion so both persisted route maps and the
    resolver trace prove that no canonical DeepSeek fallback was used.
    """
    muse = "omp:openrouter/meta/muse-spark-1.3-contributor"
    from arnold_pipelines.megaplan.profiles import (
        load_profile_metadata,
        load_profiles,
        _resolve_tier_models_with_inheritance,
    )

    profiles = load_profiles()
    metadata = load_profile_metadata()
    profile = profiles["all-muse-spark-openrouter"]
    assert len(profile) == 14
    assert set(profile.values()) == {muse}

    tier_models = _resolve_tier_models_with_inheritance(
        "all-muse-spark-openrouter",
        system_profiles=profiles,
        system_metadata=metadata,
        pipeline_local_profiles={},
        pipeline_local_metadata={},
    )
    assert set(tier_models) == {"execute", "critique"}
    assert set(tier_models["execute"]) == set(range(1, 11))
    assert set(tier_models["critique"]) == set(range(1, 11))
    assert all(
        isinstance(spec, str) and spec == muse
        for tiers in tier_models.values()
        for spec in tiers.values()
    )

    args = Namespace(
        profile="all-muse-spark-openrouter",
        phase_model=[],
        tier_models=None,
        vendor=None,
        critic=None,
        depth=None,
        deepseek_provider=None,
    )
    apply_profile_expansion(args, tmp_path)

    assert args.prep_models == {stage: muse for stage in ("triage", "fanout", "distill")}
    assert args.prep_model_resolver_trace["canonical_fallback_used"] == {
        "triage": False,
        "fanout": False,
        "distill": False,
    }
    assert args.tier_models == tier_models
    assert all(
        isinstance(spec, str) and spec == muse
        for value in args.tier_models.values()
        for spec in value.values()
    )
    assert all(
        entry.split("=", 1)[1] == muse
        for entry in args.phase_model
        if isinstance(entry, str) and "=" in entry
    )
