"""Wire-format agent contracts — pure, megaplan-free.

Defines the canonical types shared across every agent dispatch path:

* ``AgentSpec`` / ``parse_agent_spec`` / ``format_agent_spec`` — agent spec wire format.
* ``AgentMode`` — resolved agent mode carrying agent, mode, model, effort.
* ``AgentRequest`` / ``AgentResult`` — request/response carriers.
* ``TokenUsage`` / ``CostUsage`` / ``ResultProvenance`` — telemetry value objects.
* ``FanoutUnit`` / ``FanoutResult`` / ``scatter_agent_units`` — fan-out primitives.

No imports from arnold.pipelines.megaplan.
"""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol, runtime_checkable

# ---------------------------------------------------------------------------
# Agent spec parsing constants
# ---------------------------------------------------------------------------

# Premium agent vendors that support model:effort three-part specs.
_PREMIUM_VENDORS: frozenset[str] = frozenset({"claude", "codex"})

# Symbolic premium placeholder agent.
PREMIUM_AGENT = "premium"

_VALID_CLAUDE_SPEC_EFFORTS: frozenset[str] = frozenset(
    {"minimal", "low", "medium", "high", "xhigh", "max"}
)
_VALID_CODEX_SPEC_EFFORTS: frozenset[str] = frozenset(
    {"minimal", "low", "medium", "high", "xhigh", "max"}
)
_VALID_PREMIUM_EFFORTS: dict[str, frozenset[str]] = {
    "claude": _VALID_CLAUDE_SPEC_EFFORTS,
    "codex": _VALID_CODEX_SPEC_EFFORTS,
}
_PREMIUM_EFFORT_TOKENS: frozenset[str] = (
    _VALID_CLAUDE_SPEC_EFFORTS | _VALID_CODEX_SPEC_EFFORTS
)

# omp (the omp RPC worker) spec grammar: ``omp:<provider>/<modelId>`` with an
# optional Arnold-side effort suffix ``:<effort>``.  The effort suffix is
# stored separately on AgentSpec and becomes the RPC ``--thinking`` level;
# the double-colon form (a second colon inside the model slot) is never valid.
_OMP_EFFORT_TOKENS: frozenset[str] = frozenset(
    {"off", "minimal", "low", "medium", "high", "xhigh", "max", "auto"}
)


def _parse_omp_agent_spec(spec: str, rest: str) -> "AgentSpec":
    if ":" in rest:
        model, effort = rest.split(":", 1)
        if not effort:
            effort = None
    else:
        model, effort = rest, None
    if not model or "/" not in model or model.startswith("/") or model.endswith("/"):
        raise ValueError(
            f"Invalid omp agent spec {spec!r}: expected "
            "'omp:<provider>/<modelId>[:<effort>]'; the double-colon form "
            "is never valid"
        )
    if effort is not None and effort not in _OMP_EFFORT_TOKENS:
        raise ValueError(
            f"Invalid omp agent spec {spec!r}: effort token {effort!r} is not "
            f"a valid omp thinking level ({', '.join(sorted(_OMP_EFFORT_TOKENS))})"
        )
    return AgentSpec(agent="omp", model=model, effort=effort)


def _is_claude_model_name(name: str) -> bool:
    lowered = name.lower()
    return (
        "claude" in lowered
        or "sonnet" in lowered
        or "opus" in lowered
        or "haiku" in lowered
    )


def _is_codex_model_name(name: str) -> bool:
    lowered = name.lower()
    return lowered.startswith("gpt-5") or "/gpt-5" in lowered or "codex" in lowered


_PREMIUM_MODEL_PREDICATES = {
    "claude": _is_claude_model_name,
    "codex": _is_codex_model_name,
}


def _validate_premium_spec(agent: str, model: str | None, effort: str | None, spec: str) -> None:
    valid_efforts = _VALID_PREMIUM_EFFORTS[agent]
    model_ok = _PREMIUM_MODEL_PREDICATES[agent]
    if effort is not None and effort not in valid_efforts:
        raise ValueError(
            f"Invalid {agent} agent spec {spec!r}: effort token {effort!r} is not a "
            f"valid {agent} effort ({', '.join(sorted(valid_efforts))})."
        )
    if model is not None and not model_ok(model):
        raise ValueError(
            f"Invalid {agent} agent spec {spec!r}: {model!r} is neither a valid "
            f"{agent} effort ({', '.join(sorted(valid_efforts))}) nor a recognised "
            f"{agent} model."
        )


def _validate_premium_placeholder_spec(
    spec: str,
    *,
    model: str | None,
    effort: str | None,
) -> None:
    if model is not None:
        raise ValueError(
            f"Invalid premium agent spec {spec!r}: symbolic premium specs do not "
            "accept model pins; use 'premium' or 'premium:<effort>'."
        )
    if effort is not None and effort not in _PREMIUM_EFFORT_TOKENS:
        raise ValueError(
            f"Invalid premium agent spec {spec!r}: effort token {effort!r} is not valid."
        )


# ---------------------------------------------------------------------------
# AgentSpec
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AgentSpec:
    """Parsed representation of an agent spec string."""

    agent: str
    model: str | None = None
    effort: str | None = None

    def __iter__(self):
        """Backward compat: ``agent, model = spec`` ignores effort."""
        return iter((self.agent, self.model))

    def __eq__(self, other):
        if isinstance(other, AgentSpec):
            return (
                self.agent == other.agent
                and self.model == other.model
                and self.effort == other.effort
            )
        if isinstance(other, tuple):
            return (self.agent, self.model) == other
        return NotImplemented

    def __hash__(self):
        return hash((self.agent, self.model, self.effort))

    def __repr__(self):
        parts = [f"agent={self.agent!r}"]
        if self.model is not None:
            parts.append(f"model={self.model!r}")
        if self.effort is not None:
            parts.append(f"effort={self.effort!r}")
        return f"AgentSpec({', '.join(parts)})"


def parse_agent_spec(spec: str) -> AgentSpec:
    """Parse an agent spec string into an :class:`AgentSpec`.

    Spec syntax ::

        <agent>[:<model>][:<effort>]

    For **claude** and **codex** (premium agents), the first post-colon
    token is checked against reserved effort tokens; if it matches, the
    spec is treated as the legacy effort-only shape.  Otherwise it is
    treated as a model name, with an optional second ``:<effort>``
    segment.

    For **omp**, the entire string after the first colon is the model —
    slashes and provider path separators in the model name are preserved
    unchanged.

    Examples
    --------

    >>> parse_agent_spec("claude")
    AgentSpec(agent='claude', model=None, effort=None)
    >>> parse_agent_spec("claude:low")
    AgentSpec(agent='claude', model=None, effort='low')
    >>> parse_agent_spec("claude:sonnet-4.6:medium")
    AgentSpec(agent='claude', model='sonnet-4.6', effort='medium')
    >>> parse_agent_spec("codex:gpt-5.3-codex:high")
    AgentSpec(agent='codex', model='gpt-5.3-codex', effort='high')
    >>> parse_agent_spec("omp:fireworks/accounts/foo")
    AgentSpec(agent='omp', model='fireworks/accounts/foo', effort=None)
    """
    if ":" not in spec:
        return AgentSpec(agent=spec)

    agent, rest = spec.split(":", 1)

    if agent == PREMIUM_AGENT:
        if ":" in rest:
            model, effort = rest.split(":", 1)
            if not effort:
                effort = None
            _validate_premium_placeholder_spec(spec, model=model, effort=effort)
            return AgentSpec(agent=agent, model=model, effort=effort)
        if rest in _PREMIUM_EFFORT_TOKENS:
            _validate_premium_placeholder_spec(spec, model=None, effort=rest)
            return AgentSpec(agent=agent, effort=rest)
        _validate_premium_placeholder_spec(spec, model=rest, effort=None)

    if agent == "omp":
        return _parse_omp_agent_spec(spec, rest)

    if agent not in _PREMIUM_VENDORS:
        return AgentSpec(agent=agent, model=rest)

    if rest in _PREMIUM_EFFORT_TOKENS:
        _validate_premium_spec(agent, None, rest, spec)
        return AgentSpec(agent=agent, effort=rest)

    if ":" in rest:
        model, effort = rest.split(":", 1)
        if not effort:
            effort = None
        _validate_premium_spec(agent, model, effort, spec)
        return AgentSpec(agent=agent, model=model, effort=effort)

    _validate_premium_spec(agent, rest, None, spec)
    return AgentSpec(agent=agent, model=rest)


def format_agent_spec(spec: AgentSpec) -> str:
    """Format an :class:`AgentSpec` back to its canonical string form.

    >>> format_agent_spec(AgentSpec("claude"))
    'claude'
    >>> format_agent_spec(AgentSpec("claude", effort="low"))
    'claude:low'
    >>> format_agent_spec(AgentSpec("codex", model="gpt-5.3-codex", effort="high"))
    'codex:gpt-5.3-codex:high'
    >>> format_agent_spec(AgentSpec("omp", model="fireworks/accounts/foo"))
    'omp:fireworks/accounts/foo'
    """
    if spec.model is not None:
        base = f"{spec.agent}:{spec.model}"
    elif spec.effort is not None:
        base = f"{spec.agent}:{spec.effort}"
    else:
        base = spec.agent

    if spec.model is not None and spec.effort is not None:
        base = f"{base}:{spec.effort}"

    return base


# ---------------------------------------------------------------------------
# AgentMode
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AgentMode:
    """Resolved agent mode returned by resolve_agent_mode."""

    agent: str
    mode: str
    refreshed: bool
    model: str | None = None
    effort: str | None = None
    resolved_model: str | None = None

    def __iter__(self):
        """Backward-compat: unpack as (agent, mode, refreshed, model)."""
        return iter((self.agent, self.mode, self.refreshed, self.model))

    def __eq__(self, other):
        if isinstance(other, AgentMode):
            return (
                self.agent == other.agent
                and self.mode == other.mode
                and self.refreshed == other.refreshed
                and self.model == other.model
                and self.effort == other.effort
                and self.resolved_model == other.resolved_model
            )
        if isinstance(other, tuple):
            return (self.agent, self.mode, self.refreshed, self.model) == other
        return NotImplemented

    def __hash__(self):
        return hash(
            (self.agent, self.mode, self.refreshed, self.model, self.effort, self.resolved_model)
        )

    def __repr__(self):
        return (
            f"AgentMode(agent={self.agent!r}, mode={self.mode!r}, "
            f"refreshed={self.refreshed}, model={self.model!r}, "
            f"effort={self.effort!r}, resolved_model={self.resolved_model!r})"
        )


# ---------------------------------------------------------------------------
# Contract types (request/result/telemetry)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TokenUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


@dataclass(frozen=True, slots=True)
class CostUsage:
    cost_usd: float = 0.0


@dataclass(frozen=True, slots=True)
class ResultProvenance:
    agent: str | None = None
    mode: str | None = None
    model: str | None = None
    resolved_model: str | None = None
    effort: str | None = None
    session_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AgentRequest:
    agent: str
    mode: str
    model: str | None = None
    resolved_model: str | None = None
    effort: str | None = None
    spec: AgentSpec | None = None
    read_only: bool = True
    prompt: str | None = None
    system_prompt: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    timeout_seconds: float | None = None
    provenance: ResultProvenance | None = None
    attestation: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AgentResult:
    payload: dict[str, Any]
    raw_output: str
    duration_ms: int
    cost_usd: float
    session_id: str | None = None
    trace_output: str | None = None
    rendered_prompt: str | None = None
    model_actual: str | None = None
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    shannon_plan: dict[str, Any] | None = None
    rate_limit: dict[str, Any] | None = None
    provenance: ResultProvenance | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Transitional fallback: callers that still stash rate-limit state in
        # metadata (older workers, serialized envelopes) should still see it on
        # the direct field.
        if self.rate_limit is None:
            meta_value = self.metadata.get("rate_limit")
            if isinstance(meta_value, dict):
                object.__setattr__(self, "rate_limit", meta_value)

    @property
    def tokens(self) -> TokenUsage:
        return TokenUsage(
            prompt_tokens=self.prompt_tokens,
            completion_tokens=self.completion_tokens,
            total_tokens=self.total_tokens,
        )

    @property
    def cost(self) -> CostUsage:
        return CostUsage(cost_usd=self.cost_usd)


@dataclass(frozen=True, slots=True)
class FanoutUnit:
    request: AgentRequest
    key: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class FanoutResult:
    results: tuple[AgentResult, ...]
    cost_usd: float = 0.0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class AgentDispatcher(Protocol):
    def dispatch(self, request: AgentRequest) -> AgentResult: ...


_DispatchesAgentRequests = AgentDispatcher


def _fanout_result_from_results(results: list[AgentResult]) -> FanoutResult:
    return FanoutResult(
        results=tuple(results),
        cost_usd=sum(r.cost_usd for r in results),
        prompt_tokens=sum(r.prompt_tokens for r in results),
        completion_tokens=sum(r.completion_tokens for r in results),
        total_tokens=sum(r.total_tokens for r in results),
    )


def scatter_agent_units(
    *,
    units: list[FanoutUnit],
    dispatcher: _DispatchesAgentRequests,
    max_concurrent: int | None = None,
    on_unit_error: Callable[[int, FanoutUnit, Exception], AgentResult] | None = None,
) -> FanoutResult:
    """Dispatch agent units through an injected local dispatcher."""
    if not units:
        return FanoutResult(results=())
    if max_concurrent is not None and max_concurrent <= 0:
        raise ValueError("max_concurrent must be positive")

    concurrency = min(max_concurrent or len(units), len(units))
    results: list[AgentResult | None] = [None] * len(units)

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        future_to_index: dict[Future[AgentResult], int] = {
            executor.submit(dispatcher.dispatch, unit.request): index
            for index, unit in enumerate(units)
        }
        for future in as_completed(future_to_index):
            index = future_to_index[future]
            try:
                result = future.result()
            except Exception as exc:
                if on_unit_error is None:
                    raise
                result = on_unit_error(index, units[index], exc)
            results[index] = result

    ordered_results: list[AgentResult] = []
    for result in results:
        if result is None:
            raise RuntimeError("agent fan-out did not return all unit results")
        ordered_results.append(result)
    return _fanout_result_from_results(ordered_results)


__all__ = [
    "AgentDispatcher",
    "AgentMode",
    "AgentRequest",
    "AgentResult",
    "AgentSpec",
    "CostUsage",
    "FanoutResult",
    "FanoutUnit",
    "PREMIUM_AGENT",
    "ResultProvenance",
    "TokenUsage",
    "format_agent_spec",
    "parse_agent_spec",
    "scatter_agent_units",
]
