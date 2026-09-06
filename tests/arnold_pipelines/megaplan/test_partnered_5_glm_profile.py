from __future__ import annotations

from argparse import Namespace
from pathlib import Path
from typing import Any

from arnold_pipelines.megaplan.profiles import load_profile_metadata, load_profiles
from arnold_pipelines.megaplan.profiles.policy import apply_profile_expansion
from arnold_pipelines.megaplan._core.dispatch import resolve_dispatch_spec


GLM_SPEC = "omp:zai/glm-5.2"
FIREWORKS_GLM_SPEC = "omp:fireworks/glm-5.2"
FINALIZE_SPEC = "codex:gpt-5.6-sol:high"
FORBIDDEN_GPT_TOKENS = ("codex", "openai", "gpt")


def _is_gpt_spec(spec: str) -> bool:
    lowered = spec.lower()
    return any(token in lowered for token in FORBIDDEN_GPT_TOKENS)


def _replace_gpt_specs(value: Any) -> Any:
    if isinstance(value, str):
        return GLM_SPEC if _is_gpt_spec(value) else value
    if isinstance(value, list):
        return [_replace_gpt_specs(item) for item in value]
    if isinstance(value, dict):
        return {key: _replace_gpt_specs(item) for key, item in value.items()}
    return value


def _flatten_specs(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [spec for item in value for spec in _flatten_specs(item)]
    if isinstance(value, dict):
        return [spec for item in value.values() for spec in _flatten_specs(item)]
    return []


def _replace_phase_model_gpt_specs(entries: list[str]) -> list[str]:
    replaced: list[str] = []
    for entry in entries:
        phase, spec = entry.split("=", 1)
        replaced.append(f"{phase}={_replace_gpt_specs(spec)}")
    return replaced


def _expected_glm_profile(base: dict[str, Any]) -> dict[str, Any]:
    # The canonical GLM profile is an explicit OMP policy, not a mechanical
    # provider rewrite of the partnered-5 fallback lists.  Only finalize keeps
    # its deliberate Codex premium route; prep/critique remain DeepSeek and
    # every other phase is routed to the OMP GLM provider.
    expected = {phase: GLM_SPEC for phase in base}
    expected["prep"] = "omp:deepseek/deepseek-v4-pro"
    expected["critique"] = "omp:deepseek/deepseek-v4-pro"
    expected["finalize"] = FINALIZE_SPEC
    return expected


def _expected_glm_critique_tiers() -> dict[int, Any]:
    return {
        1: "omp:deepseek/deepseek-v4-flash",
        2: "omp:deepseek/deepseek-v4-pro",
        3: "omp:deepseek/deepseek-v4-pro",
        4: [GLM_SPEC, FIREWORKS_GLM_SPEC, GLM_SPEC],
        5: GLM_SPEC,
    }


def _profile_args(profile: str) -> Namespace:
    return Namespace(
        profile=profile,
        phase_model=[],
        tier_models=None,
        vendor=None,
        critic=None,
        depth=None,
        deepseek_provider=None,
    )


def test_partnered_5_glm_preserves_phase_shape_with_finalize_as_only_gpt_route(
    tmp_path: Path,
) -> None:
    profiles = load_profiles(project_dir=tmp_path)
    metadata = load_profile_metadata(project_dir=tmp_path)

    base = profiles["partnered-5"]
    glm = profiles["partnered-5-glm"]
    base_metadata = metadata["partnered-5"]
    glm_metadata = metadata["partnered-5-glm"]

    expected = _expected_glm_profile(base)
    assert glm == expected
    assert glm_metadata["adaptive_critique"] == base_metadata["adaptive_critique"]
    assert glm_metadata["tier_models"]["critique"] == _expected_glm_critique_tiers()


def test_partnered_5_glm_resolution_contains_only_finalize_gpt_route(
    tmp_path: Path,
) -> None:
    args = _profile_args("partnered-5-glm")

    apply_profile_expansion(args, tmp_path)

    resolved_specs = [
        *_flatten_specs(args.phase_model),
        *_flatten_specs(args.tier_models),
        *_flatten_specs(args.prep_models),
    ]
    assert resolved_specs
    gpt_specs = [spec for spec in resolved_specs if _is_gpt_spec(spec)]
    assert gpt_specs == [f"finalize={FINALIZE_SPEC}"]
    assert GLM_SPEC in resolved_specs


def test_partnered_5_glm_preserves_non_gpt_phase_and_critique_routes(
    tmp_path: Path,
) -> None:
    base_args = _profile_args("partnered-5")
    glm_args = _profile_args("partnered-5-glm")

    apply_profile_expansion(base_args, tmp_path)
    apply_profile_expansion(glm_args, tmp_path)

    expected_phase_models = [
        f"{phase}={spec}"
        for phase, spec in _expected_glm_profile(load_profiles(project_dir=tmp_path)["partnered-5"]).items()
    ]
    assert glm_args.phase_model == expected_phase_models
    assert glm_args.tier_models["critique"] == _expected_glm_critique_tiers()
    assert glm_args.prep_models == _replace_gpt_specs(base_args.prep_models)


def test_partnered_5_glm_all_resolved_execute_tiers_are_glm_family(
    tmp_path: Path,
) -> None:
    args = _profile_args("partnered-5-glm")

    apply_profile_expansion(args, tmp_path)

    assert "execute=omp:zai/glm-5.2" in args.phase_model
    execute_tiers = args.tier_models["execute"]
    assert set(execute_tiers) == set(range(1, 11))
    for tier in range(1, 11):
        resolved = _flatten_specs(execute_tiers[tier])
        assert resolved == [GLM_SPEC, FIREWORKS_GLM_SPEC, GLM_SPEC]
        assert resolve_dispatch_spec(args.tier_models, "execute", tier) == GLM_SPEC
        assert all("glm" in spec.lower() for spec in resolved)
        assert all("deepseek" not in spec.lower() for spec in resolved)
        assert all(not _is_gpt_spec(spec) for spec in resolved)
