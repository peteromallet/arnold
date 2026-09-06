"""Explicit routing choices for the watchdog babysitter.

The omp/DeepSeek path is the default.  A temporary, explicit
environment toggle is the only way to select the Codex recovery path; an
unknown value fails closed instead of silently choosing a provider.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

ROUTING_ENV = "ARNOLD_BABYSITTER_ROUTING"
CODEX_MODEL_ENV = "ARNOLD_BABYSITTER_CODEX_MODEL"
CODEX_INVESTIGATOR_MODEL_ENV = "ARNOLD_BABYSITTER_CODEX_INVESTIGATOR_MODEL"
OMP_MODEL_ENV = "ARNOLD_BABYSITTER_OMP_MODEL"
# These two values are written by the manifest-bound chain launcher.  They are
# deliberately separate: the chain profile is authoritative workload
# identity, while the closed profile is an explicit opt-in for the resident
# fixer.  A session name is only a label and must never select a model.
CHAIN_PROFILE_ENV = "ARNOLD_BABYSITTER_CHAIN_PROFILE"
CLOSED_PROFILE_ENV = "ARNOLD_BABYSITTER_CLOSED_PROFILE"

OMP_ROUTING = "omp"
CODEX_ROUTING = "codex"
OMP_CONTROLLER_MODEL = "omp:deepseek/deepseek-v4-flash"
CODEX_CONTROLLER_MODEL = "codex:gpt-5.6-luna"
CONTINUATION_MUSE_PROFILE = "all-muse-spark-openrouter"
CONTINUATION_MUSE_SUCCESSOR_PROFILE = "all-muse-spark-1-3-contributor"
CONTINUATION_MUSE_PROFILES = frozenset(
    {CONTINUATION_MUSE_PROFILE, CONTINUATION_MUSE_SUCCESSOR_PROFILE}
)
CONTINUATION_MUSE_MODEL = "omp:openrouter/meta/muse-spark-1.3-contributor"
CONTINUATION_MUSE_THINKING = "high"
_CONTINUATION_MUSE_INPUT_THINKING = frozenset(
    {"auto", "off", "minimal", "low", "medium", "high", "xhigh", "max"}
)
CONTINUATION_FIXER_ROLES = (
    "controller",
    "researcher",
    "swarm",
    "investigator",
    "implementer",
    "reviewer",
    "xhard",
    "oracle",
    "recommendation",
    "recommender",
)


@dataclass(frozen=True)
class BabysitterRouting:
    """Resolved controller and evidence-investigator route."""

    mode: str
    controller_backend: str
    controller_model: str
    investigator_backend: str
    investigator_model: str
    thinking: str | None = None

    def as_dict(self) -> dict[str, object]:
        payload = {
            "mode": self.mode,
            "controller_backend": self.controller_backend,
            "controller_model": self.controller_model,
            "investigator_backend": self.investigator_backend,
            "investigator_model": self.investigator_model,
        }
        if self.thinking is not None:
            payload["thinking"] = self.thinking
            payload["role_models"] = {
                role: self.controller_model for role in CONTINUATION_FIXER_ROLES
            }
        return payload

    @property
    def closed(self) -> bool:
        return self.mode == "continuation-muse"


def _codex_model(value: str, *, variable: str) -> str:
    model = value.strip() or CODEX_CONTROLLER_MODEL
    if model.startswith("codex:"):
        model = model[len("codex:"):]
    if not model.startswith("gpt-5.6-"):
        raise ValueError(
            f"{variable} must select an explicit Codex GPT-5.6 model, got {value!r}"
        )
    return f"codex:{model}"

def resolve_babysitter_routing(
    env: Mapping[str, str] | None = None,
    *,
    session: str | None = None,
    require_explicit_model: bool = False,
    chain_profile: str | None = None,
    closed_profile: str | None = None,
    manifest_identity: Mapping[str, object] | None = None,
    project_dir: Path | str | None = None,
) -> BabysitterRouting:
    """Resolve routing from authoritative profile identity and closed config.

    ``session`` is intentionally not consulted for model selection.  Session
    names are operator-facing labels and are forgeable (and generations
    change them).  A continuation route requires both the chain's authoritative
    profile and an explicit closed-fixer declaration.  If either declaration
    is present but inconsistent, fail closed instead of falling through to the
    resident default.
    """

    values = os.environ if env is None else env
    if project_dir is not None:
        from arnold_pipelines.megaplan.profiles import resolve_continuation_runtime_model

        canonical_model = resolve_continuation_runtime_model(Path(project_dir))
        if canonical_model is not None:
            selected = str(values.get(ROUTING_ENV, "")).strip().lower()
            if selected and selected not in {OMP_ROUTING, "default", "legacy"}:
                raise ValueError(
                    f"continuation canonical model rejects {ROUTING_ENV}={selected!r}"
                )
            configured_model = str(values.get(OMP_MODEL_ENV, "")).strip()
            if configured_model and configured_model != canonical_model:
                raise ValueError(
                    f"{OMP_MODEL_ENV} conflicts with the continuation canonical model"
                )
            return BabysitterRouting(
                mode=OMP_ROUTING,
                controller_backend=OMP_ROUTING,
                controller_model=canonical_model,
                investigator_backend=OMP_ROUTING,
                investigator_model=canonical_model,
            )
    session_value = str(session or values.get("ARNOLD_BABYSITTER_SESSION", "")).strip()
    manifest_profile = ""
    if manifest_identity is not None:
        manifest_profile = str(
            manifest_identity.get("chain_profile")
            or manifest_identity.get("profile")
            or ""
        ).strip()
    declared_profiles = [
        item
        for item in (chain_profile, manifest_profile)
        if item is not None and str(item).strip()
    ]
    if len({str(item).strip() for item in declared_profiles}) > 1:
        raise ValueError("manifest and chain profile identities disagree")
    authoritative_profile = str(
        chain_profile
        if chain_profile is not None
        else manifest_profile or values.get(CHAIN_PROFILE_ENV, "")
    ).strip()
    requested_closed_profile = str(
        closed_profile if closed_profile is not None else values.get(CLOSED_PROFILE_ENV, "")
    ).strip()
    if requested_closed_profile and requested_closed_profile not in CONTINUATION_MUSE_PROFILES:
        raise ValueError(
            f"{CLOSED_PROFILE_ENV} must be {CONTINUATION_MUSE_PROFILE!r}; "
            f"got {requested_closed_profile!r}"
        )
    if authoritative_profile and authoritative_profile not in CONTINUATION_MUSE_PROFILES:
        if requested_closed_profile:
            raise ValueError(
                f"closed fixer profile {requested_closed_profile!r} contradicts "
                f"authoritative chain profile {authoritative_profile!r}"
            )
    if requested_closed_profile and not authoritative_profile:
        raise ValueError(
            f"{CLOSED_PROFILE_ENV} requires authoritative {CHAIN_PROFILE_ENV}"
        )
    continuation_route = authoritative_profile in CONTINUATION_MUSE_PROFILES
    if continuation_route and requested_closed_profile not in CONTINUATION_MUSE_PROFILES:
        raise ValueError(
            f"{session_value or 'continuation chain'} requires explicit "
            f"{CLOSED_PROFILE_ENV}={CONTINUATION_MUSE_PROFILE!r}"
        )
    if continuation_route:
        requested_closed_model = str(values.get("ARNOLD_BABYSITTER_MODEL", "")).strip()
        if require_explicit_model and not requested_closed_model:
            raise ValueError(
                f"{session_value or 'continuation chain'} requires explicit {CONTINUATION_MUSE_MODEL}:high "
                "for resident fixer registration"
            )
        selected = str(values.get(ROUTING_ENV, "")).strip().lower()
        if selected and selected not in {OMP_ROUTING, "default", "legacy"}:
            raise ValueError(
                f"{session_value or 'continuation chain'} is closed to Muse routing; {ROUTING_ENV}="
                f"{selected!r} is not permitted"
            )
        for variable in (
            OMP_MODEL_ENV,
            "ARNOLD_BABYSITTER_MODEL",
            CODEX_MODEL_ENV,
            CODEX_INVESTIGATOR_MODEL_ENV,
        ):
            requested = str(values.get(variable, "")).strip()
            if requested and requested != CONTINUATION_MUSE_MODEL:
                prefix, separator, suffix = requested.rpartition(":")
                if (
                    prefix != CONTINUATION_MUSE_MODEL
                    or not separator
                    or suffix not in _CONTINUATION_MUSE_INPUT_THINKING
                ):
                    raise ValueError(
                        f"{session_value or 'continuation chain'} is closed to Muse routing; {variable}="
                        f"{requested!r} is not permitted"
                    )
        return BabysitterRouting(
            mode="continuation-muse",
            controller_backend=OMP_ROUTING,
            controller_model=CONTINUATION_MUSE_MODEL,
            investigator_backend=OMP_ROUTING,
            investigator_model=CONTINUATION_MUSE_MODEL,
            thinking=CONTINUATION_MUSE_THINKING,
        )
    requested_routing = str(values.get(ROUTING_ENV, "")).strip().lower()
    selected = requested_routing or OMP_ROUTING
    if selected in {OMP_ROUTING, "default", "legacy"}:
        # ``legacy`` remains accepted as a back-compat alias for the omp route.
        configured_model = str(values.get(OMP_MODEL_ENV, "")).strip() or OMP_CONTROLLER_MODEL
        if not requested_routing or requested_routing in {"default", "legacy"}:
            return BabysitterRouting(
                mode="legacy",
                controller_backend="hermes",
                controller_model=configured_model,
                investigator_backend="hermes",
                investigator_model=configured_model,
            )
        return BabysitterRouting(
            mode=OMP_ROUTING,
            controller_backend="omp",
            controller_model=configured_model,
            investigator_backend="omp",
            investigator_model=configured_model,
        )
    if selected != CODEX_ROUTING:
        raise ValueError(
            f"{ROUTING_ENV} must be unset, 'omp', or 'codex'; got {selected!r}"
        )
    controller = _codex_model(
        str(values.get(CODEX_MODEL_ENV, CODEX_CONTROLLER_MODEL)),
        variable=CODEX_MODEL_ENV,
    )
    investigator = _codex_model(
        str(values.get(CODEX_INVESTIGATOR_MODEL_ENV, controller)),
        variable=CODEX_INVESTIGATOR_MODEL_ENV,
    )
    return BabysitterRouting(
        mode=CODEX_ROUTING,
        controller_backend="codex",
        controller_model=controller,
        investigator_backend="codex",
        investigator_model=investigator,
    )


def cli_model(model: str) -> str:
    """Return the provider-free model name required by the Codex CLI."""

    return model[len("codex:"):] if model.startswith("codex:") else model
