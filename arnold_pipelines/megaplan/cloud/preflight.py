"""Pure cloud-chain preflight helpers.

These helpers do not contact a provider. They resolve chain milestone routing
with the same profile/phase_model expansion used by runtime workers, then
translate the resolved agents into runtime commands and environment hints that
cloud launchers can validate before starting a remote chain.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from arnold_pipelines.megaplan.chain import ChainSpec
from arnold_pipelines.megaplan.fallback_chains import FallbackSpecChain, decode_phase_model_value
from arnold_pipelines.megaplan.profiles import (
    CONTINUATION_RUNTIME_MODEL_SPEC,
    CONTINUATION_RUNTIME_PROFILE,
    DEFAULT_AGENT_ROUTING,
    apply_profile_expansion,
    effective_premium_vendor,
    resolve_continuation_runtime_model,
)
from arnold_pipelines.megaplan.types import (
    CliError,
    format_agent_spec,
    is_premium_placeholder_spec,
    parse_agent_spec,
    resolve_premium_placeholder_spec,
)
from arnold_pipelines.megaplan.workers.omp import validate_omp_catalog_model


AGENTS_DEFAULT_WARNING = (
    "cloud.yaml agents.default does not override explicit chain profile or "
    "phase_model routing; resolved chain phase maps are shown below."
)


_COMMANDS_BY_AGENT: dict[str, tuple[str, ...]] = {
    "claude": ("claude",),
    "shannon": ("claude",),
    "codex": ("codex", "tmux"),
}

_ENV_HINTS_BY_AGENT: dict[str, tuple[str, ...]] = {
    "claude": ("ANTHROPIC_API_KEY",),
    "shannon": ("ANTHROPIC_API_KEY",),
    "codex": ("OPENAI_API_KEY",),
}

# Keep cloud launch diagnostics in lock-step with the runtime omp worker.  A
# missing hint here used to make ``cloud preflight`` report a clean bill of
# health even though the omp worker would later construct a session with an
# empty credential.  Mirrors ``workers.omp._OMP_CREDENTIAL_ENV``; the z.ai
# route reads ZAI_API_KEY (with ZHIPU_API_KEY accepted as a legacy alias).
_ENV_HINTS_BY_OMP_PROVIDER: dict[str, tuple[str, ...]] = {
    "deepseek": ("DEEPSEEK_API_KEY",),
    "fireworks": ("FIREWORKS_API_KEY",),
    "zai": ("ZAI_API_KEY", "ZHIPU_API_KEY"),
    "moonshot": ("MOONSHOT_API_KEY", "KIMI_API_KEY"),
    "kimi-code": ("KIMI_API_KEY",),
    "openrouter": ("OPENROUTER_API_KEY",),
    "xai": ("XAI_API_KEY",),
    "anthropic": ("ANTHROPIC_OAUTH_TOKEN", "ANTHROPIC_API_KEY"),
    # omp-native credential routes: omp resolves credentials from its own
    # store (OAuth in omp's agent.db, command-backed models.yml keys) — the
    # Arnold env preflight must not gate them.
    "openai-codex": (),
    "grok": (),
}


def _expanded_phase_models(
    *,
    profile: str | None,
    phase_model: list[str],
    project_dir: Path | None,
    vendor: str | None = None,
    depth: str | None = None,
    critic: str | None = None,
    deepseek_provider: str | None = None,
) -> list[str]:
    args = argparse.Namespace(
        profile=profile,
        phase_model=list(phase_model),
        vendor=vendor,
        critic=critic,
        depth=depth,
        deepseek_provider=deepseek_provider,
        agent=None,
        _profile_applied=False,
    )
    apply_profile_expansion(args, project_dir)
    return list(args.phase_model or [])


def _resolved_phase_chains(
    phase_models: list[str],
    fallback_routing: dict[str, str],
) -> tuple[dict[str, FallbackSpecChain], dict[str, str]]:
    overrides: dict[str, FallbackSpecChain] = {}
    explicit_entries: dict[str, str] = {}
    for entry in phase_models:
        if "=" not in entry:
            continue
        phase, chain = decode_phase_model_value(entry)
        if phase not in overrides:
            overrides[phase] = chain
            explicit_entries[phase] = entry
    return (
        {
            phase: overrides.get(phase, FallbackSpecChain.from_value(fallback, path=f"fallback.{phase}"))
            for phase, fallback in fallback_routing.items()
        },
        explicit_entries,
    )


def _resolved_phase_map(
    resolved_phase_chains: dict[str, FallbackSpecChain],
) -> dict[str, str]:
    return {
        phase: chain.selected()
        for phase, chain in resolved_phase_chains.items()
    }


def _concrete_fallback_routing(
    *,
    vendor: str | None,
    depth: str | None,
    critic: str | None,
    cloud_default_agent: str | None,
) -> dict[str, str]:
    del depth, critic
    if cloud_default_agent:
        return {phase: cloud_default_agent for phase in DEFAULT_AGENT_ROUTING}

    args = argparse.Namespace(vendor=vendor)
    effective_vendor = effective_premium_vendor(args, {})
    return {
        phase: (
            format_agent_spec(resolve_premium_placeholder_spec(spec, effective_vendor))
            if is_premium_placeholder_spec(spec)
            else spec
        )
        for phase, spec in DEFAULT_AGENT_ROUTING.items()
    }


def _provider_requirements(agent: str, model: str | None) -> list[dict[str, Any]]:
    if agent != "omp":
        return []
    provider: str | None = None
    model_name = model
    if model:
        if agent == "omp":
            # omp spec grammar: ``omp:<provider>/<modelId>``.
            if model.startswith("omp:"):
                model = model[len("omp:"):]
            provider, _, model_name = model.partition("/")
        elif ":" in model:
            provider, model_name = model.split(":", 1)
    return [
        {
            "agent": "omp",
            "provider": provider,
            "model": model_name,
            "env_hints": list(_ENV_HINTS_BY_OMP_PROVIDER.get(provider or "", ())),
        }
    ]


def resolve_cloud_chain_runtime_dependencies(
    chain_spec: ChainSpec,
    *,
    project_dir: Path | None = None,
    cloud_default_agent: str | None = None,
) -> dict[str, Any]:
    """Return JSON-serializable runtime dependency details for a chain spec."""

    milestone_summaries: list[dict[str, Any]] = []
    required_agents: set[str] = set()
    runtime_commands: set[str] = set()
    env_hints: set[str] = set()
    provider_requirements: list[dict[str, Any]] = []
    # A closed Muse route is a property of the fully expanded model closure,
    # not of a profile spelling.  Keep this independent of the canonical
    # profile-name binding so explicit project aliases can still be proved.
    all_milestones_resolve_to_continuation_muse = bool(chain_spec.milestones)
    continuation_profile_used = any(
        milestone.profile == CONTINUATION_RUNTIME_PROFILE
        for milestone in chain_spec.milestones
    )
    continuation_model = (
        resolve_continuation_runtime_model(project_dir)
        if continuation_profile_used
        else None
    )
    if continuation_profile_used and continuation_model is None:
        raise CliError(
            "runtime_model_binding_mismatch",
            "continuation profile requires a project directory with its "
            "canonical model binding",
        )
    for milestone in chain_spec.milestones:
        fallback_routing = _concrete_fallback_routing(
            vendor=milestone.vendor,
            depth=milestone.depth,
            critic=milestone.critic,
            cloud_default_agent=cloud_default_agent,
        )
        expanded_phase_models = _expanded_phase_models(
            profile=milestone.profile,
            phase_model=milestone.phase_model,
            project_dir=project_dir,
            vendor=milestone.vendor,
            depth=milestone.depth,
            critic=milestone.critic,
            deepseek_provider=milestone.deepseek_provider,
        )
        resolved_phase_chains, explicit_phase_entries = _resolved_phase_chains(
            expanded_phase_models,
            fallback_routing,
        )
        resolved = _resolved_phase_map(resolved_phase_chains)
        if not resolved_phase_chains or any(
            tuple(chain.specs) != (CONTINUATION_RUNTIME_MODEL_SPEC,)
            for chain in resolved_phase_chains.values()
        ):
            all_milestones_resolve_to_continuation_muse = False
        if milestone.profile == CONTINUATION_RUNTIME_PROFILE:
            for phase, chain in resolved_phase_chains.items():
                if tuple(chain.specs) != (CONTINUATION_RUNTIME_MODEL_SPEC,):
                    raise CliError(
                        "runtime_model_binding_mismatch",
                        f"continuation milestone {milestone.label!r} phase {phase!r} "
                        "does not resolve to the canonical model without fallback",
                    )
        milestone_agents: set[str] = set()
        milestone_commands: set[str] = set()
        milestone_env_hints: set[str] = set()
        milestone_provider_requirements: list[dict[str, Any]] = []

        for chain in resolved_phase_chains.values():
            for spec in chain:
                parsed = parse_agent_spec(spec)
                if continuation_model is not None and parsed.agent == "omp":
                    provider, separator, model_id = str(parsed.model or "").partition("/")
                    if not separator:
                        raise CliError(
                            "runtime_model_binding_mismatch",
                            f"continuation OMP route {spec!r} lacks provider/model identity",
                        )
                    validate_omp_catalog_model(provider, model_id)
                milestone_agents.add(parsed.agent)
                required_agents.add(parsed.agent)
                for command in _COMMANDS_BY_AGENT.get(parsed.agent, ()):
                    milestone_commands.add(command)
                    runtime_commands.add(command)
                for env_name in _ENV_HINTS_BY_AGENT.get(parsed.agent, ()):
                    milestone_env_hints.add(env_name)
                    env_hints.add(env_name)
                requirements = _provider_requirements(parsed.agent, parsed.model)
                if requirements:
                    milestone_provider_requirements.extend(requirements)
                    provider_requirements.extend(requirements)
                    for requirement in requirements:
                        for env_name in requirement.get("env_hints", []):
                            if isinstance(env_name, str):
                                milestone_env_hints.add(env_name)
                                env_hints.add(env_name)

        milestone_summaries.append(
            {
                "label": milestone.label,
                "profile": milestone.profile,
                "explicit_phase_model": list(milestone.phase_model),
                "explicit_phase_model_by_phase": explicit_phase_entries,
                "resolved_phase_map": resolved,
                "resolved_phase_chains": {
                    phase: list(chain.specs)
                    for phase, chain in resolved_phase_chains.items()
                },
                "required_agents": sorted(milestone_agents),
                "runtime_commands": sorted(milestone_commands),
                "env_hints": sorted(milestone_env_hints),
                "provider_requirements": milestone_provider_requirements,
            }
        )

    # Policy fields from the chain spec
    policy = {
        "prerequisite_policy": chain_spec.prerequisite_policy,
        "validation_policy": chain_spec.validation_policy,
        "review_policy": dict(chain_spec.review_policy or {}),
    }

    result: dict[str, Any] = {
        "base_branch": chain_spec.base_branch,
        "cloud_default_agent": cloud_default_agent,
        "warning": AGENTS_DEFAULT_WARNING,
        "milestones": milestone_summaries,
        "required_agents": sorted(required_agents),
        "runtime_commands": sorted(runtime_commands),
        "env_hints": sorted(env_hints),
        "provider_requirements": provider_requirements,
        "policy": policy,
    }
    if continuation_model is not None or all_milestones_resolve_to_continuation_muse:
        runtime_binding_model = continuation_model or CONTINUATION_RUNTIME_MODEL_SPEC
        result["runtime_model_binding"] = {
            "profile": CONTINUATION_RUNTIME_PROFILE,
            "spec": runtime_binding_model,
            "backend": "omp",
            "provider": "openrouter",
            "model": "meta/muse-spark-1.3-contributor",
            "effort": "high",
            "roles": {
                role: {"spec": runtime_binding_model, "effort": "high"}
                for role in (
                    "phase",
                    "tiebreaker_researcher",
                    "tiebreaker_challenger",
                    "oracle",
                    "researcher",
                    "fixer",
                    "babysitter",
                )
            },
            "babysitter_enabled": False,
            "credential_env_hints": list(_ENV_HINTS_BY_OMP_PROVIDER["openrouter"]),
        }

    # When validation_policy is 'required', report a validation_environment
    # section with capability requirements so cloud launchers know what
    # tooling must be present.
    if chain_spec.validation_policy == "required":
        validation_commands: set[str] = set()
        # Collect validation-specific commands (any agent could run validation)
        for agent in required_agents:
            for command in _COMMANDS_BY_AGENT.get(agent, ()):
                validation_commands.add(command)
        result["validation_environment"] = {
            "required_commands": sorted(validation_commands),
            "env_hints": (
                sorted(env_hints)  # reuse the resolved env hints
                if env_hints
                else []
            ),
            "note": (
                "validation_policy='required' — the cloud environment must "
                "provide these commands and env vars for validation phases."
            ),
        }

    return result
