"""omp RPC worker for megaplan — runs phases through the omp coding agent.

The omp worker replaces the legacy in-process agent path with the pinned
``omp_rpc.RpcClient``.  Every phase runs in a fresh, stateless RPC session (one
``bun ... --mode rpc`` child per attempt); omp continuation/session-resume is
never used because Python owns the hot context.

Structured output uses the codex local-strict mechanism:

* a ``capture_recovery.output_path`` is allocated up front;
* a ``response_enforcement_attestation`` binds the canonical schema hash;
* the model receives a host tool (``write_phase_output``) that writes the
  phase payload to that path;
* ``model_seam.capture_step_output`` reads and validates the file;
* ``_extract_json_candidates_from_raw`` is used ONLY as a recovery fallback;
* prose contamination, markdown-only payloads, truncation, and unknown
  schema-owned fields are rejected by the local-strict audit.

Error handling implements the B2 matrix: launch failure, EOF/malformed frames,
timeout, SIGTERM/SIGKILL, provider 429/5xx, authentication, quota, unsupported
model, context overflow, tool failure, missing final text, malformed payload,
and schema failure.  Only availability/infrastructure failures are retryable;
retries are bounded, attempt-idempotent (a fresh stateless session per
attempt), and refuse to replay execute after side effects have landed
(``ExecuteFallbackUnsafe`` semantics).

Usage/cost accounting aggregates ``usage`` on each ``AssistantMessage`` exactly
once per RPC attempt and reconciles against derived ``get_session_stats``
before emitting Arnold ledger receipts.
"""

from __future__ import annotations
import contextvars
import hashlib
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from arnold_pipelines.megaplan._core import (
    creative_form_id,
    get_effective,
    read_json,
    schemas_root,
)
from arnold_pipelines.megaplan.model_seam import (
    ModelStructuralAuditError,
    ModelTier,
    capture_step_output,
    render_prompt_for_dispatch,
)
from arnold_pipelines.megaplan.prompts._projection import check_prompt_size
from arnold_pipelines.megaplan.provider_response import (
    compile_response_contract,
    persist_response_enforcement_attestation,
)
from arnold_pipelines.megaplan.schemas import SCHEMAS, get_execution_schema_key
from arnold_pipelines.megaplan.types import CliError, MOCK_ENV_VAR, PlanState
from arnold_pipelines.megaplan.workers._impl import (
    STEP_CAPTURE_SCHEMA_FILENAMES,
    STEP_SCHEMA_FILENAMES,
    WorkerResult,
    _check_mock_safe,
    mock_worker_output,
    resolve_work_dir,
)
from arnold_pipelines.megaplan.workers._mock_payloads import _EXECUTE_STEPS
from arnold.execution.step_invocation import StepInvocation

OMP_WORKER_CHANNEL = "omp_rpc"
OMP_AGENT = "omp"
_OMP_ADMISSION_ACTIVE: contextvars.ContextVar[bool] = contextvars.ContextVar("omp_admission_active", default=False)
# Spec prefix kept as a constant so rejection prose never spells the
# forbidden double-colon form literally.
_OMP_SPEC_PREFIX = "omp:"

# ────────────────────────────────────────────────────────────────────────
# Frozen B1 provider contract (verified against oh-my-pi catalog + RPC client)
# ────────────────────────────────────────────────────────────────────────

# Canonical catalog model per provider route.  ``deepseek`` accepts either of
# its two catalog rows; every other route has exactly one canonical model.
# Every row below was verified present in the omp catalog
# (oh-my-pi/packages/catalog/src/models.json) during B1/B4.
_OMP_CATALOG_MODELS: dict[str, tuple[str, ...]] = {
    "deepseek": ("deepseek/deepseek-v4-pro", "deepseek/deepseek-v4-flash"),
    "fireworks": (
        "fireworks/kimi-k2.7-code",
        "fireworks/glm-5.2",
        "fireworks/kimi-k2.6",
    ),
    "zai": ("zai/glm-5.2", "zai/glm-5.1"),
    "moonshot": ("moonshot/kimi-k2.7-code",),
    "kimi-code": ("kimi-code/kimi-for-coding",),
    "openrouter": (
        "openrouter/stealth/ox-alpha",
        "openrouter/openai/gpt-5.5",
        "openrouter/deepseek/deepseek-chat",
        "openrouter/deepseek/deepseek-r1",
        "openrouter/z-ai/glm-5.1",
        "openrouter/z-ai/glm-5.3-flash",
        "openrouter/meta/muse-spark-1.2-contributor",
        "openrouter/meta/muse-spark-1.3-contributor",
    ),
    "xai": ("xai/grok-4-fast-non-reasoning",),
    # omp-native credential routes: omp resolves credentials from its own
    # store (ChatGPT-subscription OAuth; the grok CLI-proxy OIDC token) —
    # no Arnold env vars required.
    "openai-codex": (
        "openai-codex/gpt-5.6-sol",
        "openai-codex/gpt-5.5",
        "openai-codex/gpt-5.4",
    ),
    "grok": ("grok/grok-4.6", "grok/grok-4.5"),
    "anthropic": ("anthropic/claude-opus-4-8",),
}

# Credential env var per provider (B1 table).  Multiple names are tried in
# order; the first present variable wins.
# Routes whose credentials omp resolves from its own store (OAuth in omp's
# agent.db, command-backed models.yml keys) — the Arnold env preflight must
# not gate them.
_OMP_NATIVE_CREDENTIAL_ROUTES: frozenset[str] = frozenset(
    {"openai-codex", "grok", "kimi-code"}
)


_OMP_CREDENTIAL_ENV: dict[str, tuple[str, ...]] = {
    "deepseek": ("DEEPSEEK_API_KEY",),
    "fireworks": ("FIREWORKS_API_KEY",),
    "zai": ("ZAI_API_KEY", "ZHIPU_API_KEY"),
    "moonshot": ("MOONSHOT_API_KEY", "KIMI_API_KEY"),
    "kimi-code": ("KIMI_API_KEY",),
    "openrouter": ("OPENROUTER_API_KEY",),
    "xai": ("XAI_API_KEY",),
    "anthropic": ("ANTHROPIC_OAUTH_TOKEN", "ANTHROPIC_API_KEY"),
}

# Valid RPC thinking levels (omp_rpc.protocol.ThinkingLevel).
_OMP_THINKING_LEVELS = frozenset(
    {"off", "minimal", "low", "medium", "high", "xhigh", "max"}
)
# CLI-level ``auto`` leaves the RPC client unset (omp's own default applies).
_AUTO_THINKING = "auto"
_MUSE_SPARK_1_3_MODEL = "muse-spark-1.3-contributor"


def _omp_model_thinking_ladder(provider: str | None, model_id: str | None) -> tuple[str, ...] | None:
    """Return the wire-exact thinking ladder for an omp route.

    Mirrors oh-my-pi ``model-thinking.ts`` per-model maps exactly:

    * Kimi K3 and DeepSeek V4 Flash: ``low/high/max``;
    * GLM-5.2 on z.ai (and DeepSeek V4 Pro): ``high/max``;
    * OpenRouter's DeepSeek route: ``high`` only;
    * GLM-5.2 resellers (Fireworks et al.): ``minimal..max`` verbatim;
    * GPT-5.6+/Anthropic adaptive: five tiers ``low..max`` with real xhigh;
    * xAI non-reasoning models: ``off`` only.
    """
    mid = (model_id or "").lower()
    provider = (provider or "").lower()
    if provider == "openrouter":
        if _MUSE_SPARK_1_3_MODEL in mid:
            # The closed continuation profile pins Muse Spark 1.3 to the
            # requested high reasoning tier.  The adapter still normalizes
            # every caller-supplied tier through this singleton ladder, so
            # ambient ``off``/``auto`` values cannot bypass the contract.
            return ("high",)
        if "deepseek" in mid:
            return ("high",)
        if "glm" in mid:
            # OpenRouter rejects ``max`` for GLM — xhigh IS its top tier.
            return ("low", "medium", "high", "xhigh")
        if "gpt-5" in mid or "claude" in mid:
            return ("low", "medium", "high", "xhigh", "max")
        return ("high",)
    if "glm" in mid:
        if provider == "zai":
            return ("high", "max")
        # Resellers pass the lower tiers verbatim and expose the genuine max.
        return ("minimal", "low", "medium", "high", "max")
    if "kimi" in mid:
        return ("low", "high", "max")
    if "deepseek" in mid:
        if "flash" in mid:
            return ("low", "high", "max")
        return ("high", "max")
    if provider == "openai-codex":
        # OpenAI Codex subscription models: gpt-5.6-sol supports low..max with
        # real xhigh; gpt-5.4/5.5 cap at xhigh.
        if "5.6" in mid:
            return ("low", "medium", "high", "xhigh", "max")
        return ("low", "medium", "high", "xhigh")
    if provider == "grok":
        # Custom grok CLI-proxy route: grok-4.6/4.5 accept low..xhigh.
        return ("low", "medium", "high", "xhigh")
    if provider == "xai":
        return ("off",)
    if provider == "anthropic":
        return ("off", "minimal", "low", "medium", "high", "xhigh", "max")
    return None


def omp_thinking_level(
    effort: str | None,
    provider: str | None,
    model_id: str | None,
) -> str | None:
    """Map an Arnold effort suffix to a typed RPC thinking level.

    ``None``/``auto`` leave the RPC client unset (omp default), except for
    Muse Spark 1.3 on OpenRouter, whose closed continuation contract requires
    explicit ``high``.  ``off`` disables thinking for ordinary routes; Muse
    1.3 is pinned to ``high`` and all caller levels normalize to it.  Levels
    outside the per-model ladder are clamped to the nearest accepted tier.
    Fireworks maps ``minimal`` to provider ``none`` (thinking off).
    """
    if not effort or effort == _AUTO_THINKING:
        ladder = _omp_model_thinking_ladder(provider, model_id)
        return ladder[0] if ladder == ("high",) else None
    if effort not in _OMP_THINKING_LEVELS:
        # Unknown Arnold-side token: do not invent a wire level.
        return None
    if effort == "off":
        ladder = _omp_model_thinking_ladder(provider, model_id)
        if ladder == ("high",):
            return "high"
        return "off"
    if provider == "fireworks" and effort == "minimal":
        # Fireworks host map: minimal → provider ``none`` (thinking off).
        return "off"
    ladder = _omp_model_thinking_ladder(provider, model_id)
    if ladder is None:
        return effort
    if effort in ladder:
        return effort
    # Clamp to the nearest accepted tier (OpenRouter → high, zai → high/max…).
    if effort in {"minimal", "low"}:
        return ladder[0]
    if effort in {"medium", "high"}:
        return "high" if "high" in ladder else ladder[-1]
    # xhigh/max → top tier.
    return ladder[-1]

# Retryable failure classes (availability/infrastructure only).  Everything
# else — auth, quota, unsupported model, context overflow, tool, malformed
# payload, schema, side effects — is hard or execute-blocked.
_OMP_RETRYABLE_CODES = frozenset(
    {
        "launch_failure",
        "connection_error",
        "worker_timeout",
        "worker_stall",
        "service_unavailable",
        "internal_error",
        "crash",
    }
)

_OMP_MAX_ATTEMPTS = int(os.getenv("MEGAPLAN_OMP_MAX_ATTEMPTS", "3") or "3")

# Provider stderr tokens used to classify RPC-command/provider failures into
# the canonical CliError codes (mirrors fallback_chains token maps).
_AUTH_TOKENS = frozenset(
    {
        "auth",
        "authentication",
        "unauthorized",
        "forbidden",
        "invalid_api_key",
        "invalid_auth",
        "permission_denied",
        "401",
        "403",
    }
)
_QUOTA_TOKENS = frozenset(
    {
        "quota",
        "billing",
        "insufficient_credits",
        "credit_balance",
        "payment_required",
        "402",
    }
)
_RATE_LIMIT_TOKENS = frozenset(
    {"rate_limit", "rate_limited", "throttled", "retry_after", "429"}
)
_UNSUPPORTED_MODEL_TOKENS = frozenset(
    {"unsupported_model", "model_not_found", "unknown_model", "no_such_model"}
)
_CONTEXT_WINDOW_TOKENS = frozenset(
    {
        "context_length",
        "context_window",
        "token_limit",
        "too_many_tokens",
        "maximum context",
    }
)
_AVAILABILITY_TOKENS = frozenset(
    {
        "availability",
        "connection_error",
        "network",
        "timeout",
        "timed_out",
        "service_unavailable",
        "unavailable",
        "overloaded",
        "502",
        "503",
        "504",
    }
)
_INFRASTRUCTURE_TOKENS = frozenset(
    {
        "infrastructure",
        "internal_error",
        "crash",
        "launch_failure",
        "worker_stall",
        "eof",
        "protocol",
        "broken pipe",
        "brokenpipe",
    }
)


# ────────────────────────────────────────────────────────────────────────
# Spec grammar
# ────────────────────────────────────────────────────────────────────────

def parse_omp_spec(spec: str | None) -> tuple[str, str]:
    """Parse ``omp:<provider>/<modelId>`` into ``(provider, model_id)``.

    Refuses the double-colon shape (a second colon inside the model slot): the
    only Arnold omp grammar is ``omp:provider/modelId`` (an effort suffix is
    carried separately and becomes the RPC thinking level).
    """
    if not spec or not str(spec).strip():
        raise CliError(
            "unsupported_model",
            "omp worker requires an explicit 'omp:<provider>/<modelId>' model",
        )
    text = str(spec).strip()
    if text == OMP_AGENT:
        raise CliError(
            "unsupported_model",
            "bare 'omp' agent requires an 'omp:<provider>/<modelId>' model",
        )
    if text.startswith(_OMP_SPEC_PREFIX):
        rest = text[len(_OMP_SPEC_PREFIX):]
        if ":" in rest:
            raise CliError(
                "invalid_spec",
                f"invalid omp spec {text!r}: use 'omp:<provider>/<modelId>', "
                "never the double-colon form",
            )
        provider, sep, model_id = rest.partition("/")
        if not sep or not provider.strip() or not model_id.strip():
            raise CliError(
                "invalid_spec",
                f"invalid omp spec {text!r}: expected 'omp:<provider>/<modelId>'",
            )
        return provider.strip(), model_id.strip()
    # A bare catalog model (e.g. ``deepseek/deepseek-v4-pro``) without the
    # ``omp:`` transport prefix is accepted for transitional callers; the
    # canonical form remains ``omp:...``.
    provider, sep, model_id = text.partition("/")
    if sep and provider.strip() and model_id.strip():
        return provider.strip(), model_id.strip()
    raise CliError(
        "invalid_spec",
        f"invalid omp spec {text!r}: expected 'omp:<provider>/<modelId>'",
    )


def format_omp_spec(provider: str, model_id: str) -> str:
    """Return the canonical ``omp:<provider>/<modelId>`` spec string."""
    return f"{OMP_AGENT}:{provider}/{model_id}"


def validate_omp_catalog_model(provider: str, model_id: str) -> str:
    """Validate a route against the frozen B1 catalog table.

    Returns the canonical catalog model id for the route.  Raises a hard
    ``unsupported_model`` CliError for unknown providers or non-canonical ids.
    """
    candidates = _OMP_CATALOG_MODELS.get(provider)
    if not candidates:
        raise CliError(
            "unsupported_model",
            f"omp provider {provider!r} is not in the frozen B1 contract "
            f"(known: {sorted(_OMP_CATALOG_MODELS)})",
        )
    canonical = f"{provider}/{model_id}"
    for candidate in candidates:
        if candidate == canonical:
            return candidate
    raise CliError(
        "unsupported_model",
        f"omp model {canonical!r} is not a canonical catalog row for "
        f"{provider!r} (canonical: {list(candidates)})",
    )


def _verify_omp_session_binding(
    client: Any, *, provider: str, model_id: str, thinking: str | None
) -> None:
    """Fail closed unless RPC readback matches requested model and effort."""
    if not hasattr(client, "get_state"):
        raise CliError(
            "runtime_model_mismatch",
            "omp RPC client cannot read back effective model/thinking state",
        )
    try:
        state = client.get_state()
    except Exception as exc:
        raise CliError(
            "runtime_model_mismatch",
            "omp RPC state readback failed while verifying model/thinking",
        ) from exc

    def _field(name: str) -> Any:
        if isinstance(state, Mapping):
            return state.get(name)
        return getattr(state, name, None)

    effective_model = _field("model")
    effective_provider = getattr(effective_model, "provider", None)
    effective_id = getattr(effective_model, "id", None)
    if isinstance(effective_model, Mapping):
        effective_provider = effective_model.get("provider")
        effective_id = effective_model.get("id") or effective_model.get("model")
    if effective_provider != provider or effective_id != model_id:
        raise CliError(
            "runtime_model_mismatch",
            "omp RPC effective model differs from requested catalog identity",
            extra={
                "requested_provider": provider,
                "requested_model": model_id,
                "effective_provider": effective_provider,
                "effective_model": effective_id,
            },
        )
    if thinking is not None and _field("thinking_level") != thinking:
        raise CliError(
            "thinking_verification",
            "omp RPC effective thinking level differs from requested effort",
            extra={"requested": thinking, "effective": _field("thinking_level")},
        )


# RPC client seam (tests inject deterministic fakes here)
# ────────────────────────────────────────────────────────────────────────

_OmpClientFactory = Callable[..., Any]
_client_factory: _OmpClientFactory | None = None


def set_omp_client_factory(factory: _OmpClientFactory | None) -> None:
    """Install (or clear) the RpcClient factory used by :func:`run_omp_step`.

    Tests inject deterministic fake RPC clients through this seam; production
    keeps the pinned ``omp_rpc.RpcClient``.
    """
    global _client_factory
    _client_factory = factory


def _bounded_memory_client_class(base: type) -> type:
    """Return an ``RpcClient`` subclass that does not retain the streamed
    prompt event history in supervisor memory.

    A megaplan phase runs as ONE long agent turn. The stock client retains
    every raw streamed event (tool results, file reads, message updates) for
    the whole turn — count-bounded only, so a long phase grew the chain-start
    supervisor to multi-GB RSS and OOM-killed the 16 GiB container
    (occurrence 8e4028a81152, 2026-08-27: 102MB → 13.5GB in ~40 min).
    Megaplan consumes only the terminal assistant text and the canonical
    session messages, so this subclass retains a constant-size terminal
    ``agent_end`` marker instead and rebuilds the turn from the
    authoritative ``get_messages()`` snapshot. Event listeners keep
    receiving every parsed event: listener dispatch happens in the reader
    loop, independent of ``_append_event`` retention (pinned omp_rpc
    ca1411b598273702c2e67cd127d44a2c52e48aac).
    """
    cached = _BOUNDED_MEMORY_CLIENT_CACHE.get(id(base))
    if cached is not None:
        return cached

    from omp_rpc.client import PromptTurn, _clone_json_object
    from omp_rpc.protocol import assistant_text

    class _NoPromptEventRetentionClient(base):  # type: ignore[misc,valid-type]
        def _append_event(self, payload: dict[str, Any]) -> None:
            if payload.get("type") != "agent_end":
                # Do not retain streamed events; the reader loop still
                # dispatches every parsed event to listeners.
                return
            marker: dict[str, Any] = {
                "type": "agent_end",
                "isTerminal": payload.get("isTerminal", True),
                "messages": [],
            }
            with self._event_condition:
                self._events.append(_clone_json_object(marker))
                self._event_condition.notify_all()

        def _build_prompt_turn(self, events: tuple[Any, ...]) -> Any:
            messages = self.get_messages()
            assistant_message: dict[str, Any] | None = None
            for message in reversed(messages):
                if isinstance(message, dict) and message.get("role") == "assistant":
                    assistant_message = message
                    break
            return PromptTurn(
                events=(),
                messages=messages,
                assistant_message=assistant_message,
                assistant_text=assistant_text(assistant_message)
                if assistant_message is not None
                else None,
            )

    _BOUNDED_MEMORY_CLIENT_CACHE[id(base)] = _NoPromptEventRetentionClient
    return _NoPromptEventRetentionClient


_BOUNDED_MEMORY_CLIENT_CACHE: dict[int, type] = {}


def _import_rpc_client() -> Any:
    try:
        from omp_rpc import RpcClient
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise CliError(
            "launch_failure",
            "omp_rpc package is not installed; install the pinned "
            "python/omp-rpc distribution",
        ) from exc
    return _bounded_memory_client_class(RpcClient)


def _build_client(
    *,
    provider: str,
    model_id: str,
    cwd: Path,
    thinking: str | None,
    tools: Sequence[str] | None,
    custom_tools: Sequence[Any],
    env: Mapping[str, str],
    timeout: float,
) -> Any:
    """Construct a fresh stateless RPC client for one attempt."""
    factory = _client_factory
    if factory is not None:
        return factory(
            provider=provider,
            model=model_id,
            cwd=str(cwd),
            thinking=thinking,
            tools=tools,
            custom_tools=custom_tools,
            env=dict(env),
            startup_timeout=timeout,
            request_timeout=min(timeout, 60.0),
            # Long megaplan phases stream many events (tool calls, updates);
            # the RPC client default (10k) is too small and aborts the turn.
            max_event_history=200_000,
        )
    rpc_client = _import_rpc_client()
    return rpc_client(
        executable="omp",
        provider=provider,
        model=model_id,
        cwd=str(cwd),
        thinking=thinking,
        tools=list(tools) if tools is not None else None,
        custom_tools=list(custom_tools),
        no_session=True,
        no_skills=True,
        env=dict(env),
        startup_timeout=timeout,
        request_timeout=min(timeout, 60.0),
        max_event_history=200_000,
    )


# ────────────────────────────────────────────────────────────────────────
# Structured-output host tool
# ────────────────────────────────────────────────────────────────────────

_WRITE_OUTPUT_TOOL_NAME = "write_phase_output"


def _write_phase_output_tool(output_path: Path) -> Any:
    """Build the host tool that writes the phase payload to ``output_path``."""
    try:
        from omp_rpc.host_tools import host_tool
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise CliError(
            "launch_failure",
            "omp_rpc host_tools module is unavailable",
        ) from exc

    def _execute(params: Mapping[str, Any], _ctx: Any) -> Any:
        payload = params.get("payload")
        if not isinstance(payload, str) or not payload.strip():
            return {
                "content": [
                    {
                        "type": "text",
                        "text": (
                            "error: payload must be a non-empty string "
                            "containing the exact JSON object"
                        ),
                    }
                ],
                "details": {"isError": True},
            }
        # The payload parameter accepts arbitrary text; enforce the JSON
        # contract here so a model that writes prose/markdown gets an
        # in-loop correction instead of silently poisoning the capture file.
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError as exc:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": (
                            "error: payload is not valid JSON "
                            f"({exc}). Retry with payload set to exactly one "
                            "JSON object (no Markdown fences, no prose)."
                        ),
                    }
                ],
                "details": {"isError": True, "json_error": str(exc)},
            }
        if not isinstance(parsed, Mapping):
            return {
                "content": [
                    {
                        "type": "text",
                        "text": (
                            "error: payload must be exactly one JSON object, "
                            f"got {type(parsed).__name__}"
                        ),
                    }
                ],
                "details": {"isError": True},
            }
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(payload, encoding="utf-8")
        except OSError as exc:
            return {
                "content": [
                    {"type": "text", "text": f"error: cannot write output: {exc}"}
                ],
                "details": {"isError": True},
            }
        return {
            "content": [
                {
                    "type": "text",
                    "text": f"wrote phase output to {output_path}",
                }
            ],
            "details": {"bytes": len(payload.encode("utf-8"))},
        }

    return host_tool(
        name=_WRITE_OUTPUT_TOOL_NAME,
        description=(
            "Write the complete phase output payload to the designated output "
            "file. Call ONCE at the end of the turn with the full, final JSON "
            "object (matching the supplied canonical schema) as the payload "
            "string. Do not use this tool for intermediate work."
        ),
        parameters={
            "type": "object",
            "properties": {
                "payload": {
                    "type": "string",
                    "description": (
                        "The exact JSON object string matching the canonical "
                        "schema. No Markdown fences, no prose wrapper."
                    ),
                }
            },
            "required": ["payload"],
        },
        execute=_execute,
    )


# ────────────────────────────────────────────────────────────────────────
# Failure classification
# ────────────────────────────────────────────────────────────────────────

def _provider_token_hits(text: str) -> frozenset[str]:
    lowered = (text or "").lower()
    hits: set[str] = set()
    for token in (
        _AUTH_TOKENS
        | _QUOTA_TOKENS
        | _RATE_LIMIT_TOKENS
        | _UNSUPPORTED_MODEL_TOKENS
        | _CONTEXT_WINDOW_TOKENS
        | _AVAILABILITY_TOKENS
        | _INFRASTRUCTURE_TOKENS
    ):
        if token in lowered:
            hits.add(token)
    return frozenset(hits)


def classify_omp_failure(
    error: BaseException,
    *,
    stderr_text: str,
    model: str | None,
) -> tuple[str, str]:
    """Map an RPC/process failure onto a canonical CliError ``(code, message)``.

    Retryable classes are exactly ``_OMP_RETRYABLE_CODES``; every other code is
    hard (or execute-blocked by the caller).
    """
    from omp_rpc import (
        RpcConcurrencyError,
        RpcProcessExitError,
        RpcProtocolError,
        RpcTimeoutError,
    )

    if isinstance(error, RpcTimeoutError):
        return (
            "worker_timeout",
            f"omp RPC request timed out for model {model!r}: {error}",
        )
    if isinstance(error, RpcProtocolError):
        return (
            "connection_error",
            f"omp RPC protocol/transport failure for model {model!r}: {error}",
        )
    if isinstance(error, RpcProcessExitError):
        detail = getattr(error, "exit_code", None)
        return (
            "crash" if detail not in (None, 0) else "connection_error",
            f"omp RPC child exited ({detail}) for model {model!r}: {error}",
        )
    if isinstance(error, RpcConcurrencyError):
        return (
            "worker_error",
            f"omp RPC concurrency failure for model {model!r}: {error}",
        )

    text = f"{error}\n{stderr_text}"
    hits = _provider_token_hits(text)
    if hits & _AUTH_TOKENS:
        return (
            "authentication",
            f"omp provider authentication failed for model {model!r}: {error}",
        )
    if hits & _QUOTA_TOKENS:
        return (
            "quota_exhausted",
            f"omp provider quota exhausted for model {model!r}: {error}",
        )
    if hits & _RATE_LIMIT_TOKENS:
        return (
            "rate_limit",
            f"omp provider rate-limited for model {model!r}: {error}",
        )
    if hits & _UNSUPPORTED_MODEL_TOKENS:
        return (
            "unsupported_model",
            f"omp provider rejected model {model!r}: {error}",
        )
    if hits & _CONTEXT_WINDOW_TOKENS:
        return (
            "context_length_exceeded",
            f"omp provider context overflow for model {model!r}: {error}",
        )
    if hits & _AVAILABILITY_TOKENS:
        return (
            "service_unavailable",
            f"omp provider unavailable for model {model!r}: {error}",
        )
    if hits & _INFRASTRUCTURE_TOKENS:
        return (
            "internal_error",
            f"omp RPC infrastructure failure for model {model!r}: {error}",
        )
    return (
        "worker_error",
        f"omp worker failed for model {model!r}: {error}",
    )


def _raise_provider_error_from_turn(
    turn: Any,
    *,
    model: str,
) -> None:
    """Surface a provider failure embedded in the prompt turn (if any)."""
    assistant = getattr(turn, "assistant_message", None)
    if isinstance(assistant, Mapping):
        error_message = assistant.get("errorMessage")
        stop_reason = assistant.get("stopReason")
        if error_message is None and stop_reason == "error":
            error_message = (
                f"omp provider stopped with an error for model {model!r}"
            )
        if error_message is not None:
            code, message = classify_omp_failure(
                RuntimeError(str(error_message)),
                stderr_text=str(error_message),
                model=model,
            )
            if code != "worker_error":
                raise CliError(
                    code, message, extra={"raw_output": str(error_message)}
                )


# ────────────────────────────────────────────────────────────────────────
# Usage aggregation and cost reconciliation
# ────────────────────────────────────────────────────────────────────────

@dataclass
class OmpUsage:
    """Exactly-once per-attempt usage aggregate."""

    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    total_tokens: int = 0
    cost_usd: float = 0.0
    cost_pricing: str | None = None
    provider: str | None = None
    model: str | None = None
    attempt_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    messages_counted: int = 0
    reconciled_delta: dict[str, int] = field(default_factory=dict)


def _usage_bucket(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def aggregate_usage_from_messages(
    messages: Sequence[Any],
    *,
    provider: str | None,
    model: str | None,
    attempt_id: str,
) -> OmpUsage:
    """Aggregate ``usage`` on each assistant message exactly once."""
    usage = OmpUsage(provider=provider, model=model, attempt_id=attempt_id)
    for message in messages:
        role = message.get("role") if isinstance(message, Mapping) else getattr(message, "role", None)
        if role != "assistant":
            continue
        msg_usage = (
            message.get("usage")
            if isinstance(message, Mapping)
            else getattr(message, "usage", None)
        )
        if not isinstance(msg_usage, Mapping):
            continue
        usage.input_tokens += _usage_bucket(msg_usage.get("input"))
        usage.output_tokens += _usage_bucket(msg_usage.get("output"))
        usage.cache_read_tokens += _usage_bucket(msg_usage.get("cacheRead"))
        usage.cache_write_tokens += _usage_bucket(msg_usage.get("cacheWrite"))
        usage.total_tokens += _usage_bucket(
            msg_usage.get("totalTokens")
            or (
                msg_usage.get("input", 0)
                + msg_usage.get("output", 0)
                + msg_usage.get("cacheRead", 0)
                + msg_usage.get("cacheWrite", 0)
            )
        )
        cost = msg_usage.get("cost")
        if isinstance(cost, Mapping):
            total = cost.get("total")
            if total is not None:
                usage.cost_usd += float(total or 0.0)
                usage.cost_pricing = "omp_usage_cost"
        usage.messages_counted += 1
    return usage


def reconcile_usage_with_session_stats(
    usage: OmpUsage,
    stats: Any,
) -> OmpUsage:
    """Reconcile per-message aggregates against derived ``get_session_stats``.

    Mirrors the codex delta-from-cumulative exactly-once pattern: the
    authoritative source is ``usage`` on each ``AssistantMessage``; when the
    derived session stats exceed the per-message sum (usage the provider did
    not surface per message), the delta is attributed to this attempt and
    recorded so ledger receipts stay exact.
    """
    if stats is None:
        return usage
    tokens = getattr(stats, "tokens", None) or {}
    if not isinstance(tokens, Mapping):
        return usage
    buckets = {
        "input_tokens": tokens.get("input", 0),
        "output_tokens": tokens.get("output", 0),
        "cache_read_tokens": tokens.get("cache_read", 0),
        "cache_write_tokens": tokens.get("cache_write", 0),
        "total_tokens": tokens.get("total", 0),
    }
    for field_name, stat_value in buckets.items():
        stat_value = _usage_bucket(stat_value)
        current = getattr(usage, field_name)
        if stat_value > current:
            usage.reconciled_delta[field_name] = stat_value - current
            setattr(usage, field_name, stat_value)
    if not usage.cost_pricing:
        stat_cost = getattr(stats, "cost", None)
        if stat_cost is not None:
            usage.cost_usd = float(stat_cost or 0.0)
            usage.cost_pricing = "omp_session_stats_cost"
    return usage


# ────────────────────────────────────────────────────────────────────────
# Observability emitters
# ────────────────────────────────────────────────────────────────────────

def _emit_llm_start(
    plan_dir: Path,
    step: str,
    model: str | None,
    prompt_hash: str | None,
    attempt_id: str,
) -> str:
    call_transaction_id = uuid.uuid4().hex
    try:
        from arnold_pipelines.megaplan.observability.events import emit, EventKind

        provider = (model or "").split("/", 1)[0] if model else None
        emit(
            EventKind.LLM_CALL_START,
            plan_dir=plan_dir,
            phase=step,
            payload={
                "provider": provider,
                "model": model,
                "prompt_hash": prompt_hash,
                "streaming": True,
                "request_id": None,
                "call_transaction_id": call_transaction_id,
                "attempt_id": attempt_id,
            },
        )
    except Exception:
        pass
    return call_transaction_id


def _emit_llm_end(
    plan_dir: Path,
    step: str,
    usage: OmpUsage,
    call_transaction_id: str | None,
) -> None:
    try:
        from arnold_pipelines.megaplan.observability.events import emit, EventKind

        emit(
            EventKind.LLM_CALL_END,
            plan_dir=plan_dir,
            phase=step,
            payload={
                "tokens_in": usage.input_tokens,
                "tokens_out": usage.output_tokens,
                "cache_read_tokens": usage.cache_read_tokens,
                "cache_write_tokens": usage.cache_write_tokens,
                "request_id": None,
                "model": usage.model,
                "call_transaction_id": call_transaction_id,
                "attempt_id": usage.attempt_id,
            },
        )
    except Exception:
        pass


def _emit_llm_error(
    plan_dir: Path,
    step: str,
    error_message: str,
    retry_after_s: float | None = None,
) -> None:
    try:
        from arnold_pipelines.megaplan.observability.events import emit, EventKind

        error_code = "unknown"
        if "429" in error_message:
            error_code = "429"
        elif "timeout" in error_message.lower():
            error_code = "timeout"
        elif "context" in error_message.lower():
            error_code = "context_length_exceeded"
        elif "rate" in error_message.lower():
            error_code = "rate_limit"
        emit(
            EventKind.LLM_CALL_ERROR,
            plan_dir=plan_dir,
            phase=step,
            payload={
                "provider_error_code": error_code,
                "retry_after_s": retry_after_s or 0,
                "message": error_message[:500],
            },
        )
    except Exception:
        pass


def _emit_cost_recorded(
    plan_dir: Path,
    step: str,
    usage: OmpUsage,
    model: str | None,
) -> None:
    try:
        from arnold_pipelines.megaplan.observability.events import emit, EventKind

        emit(
            EventKind.COST_RECORDED,
            plan_dir=plan_dir,
            phase=step,
            payload={
                "request_id": None,
                "cost_usd": float(usage.cost_usd),
                "provider": usage.provider,
                "model": model or usage.model,
                "attempt_id": usage.attempt_id,
            },
        )
    except Exception:
        pass


# ────────────────────────────────────────────────────────────────────────
# Worktree mutation guard (execute replay protection)
# ────────────────────────────────────────────────────────────────────────

def _worktree_mutation_fingerprint(work_dir: Path) -> str | None:
    """Return a content-aware fingerprint of the worktree's mutable state.

    ``None`` when git is unavailable or the directory is not a repository
    (the guard then cannot prove mutation and is skipped — the caller decides
    whether that is acceptable).

    ``git status --porcelain`` alone is insufficient: modifying an already-
    dirty file leaves the status text unchanged, so an unsafe execute retry
    could slip through. Hash the diff of tracked modifications plus the
    contents of untracked files so any content change moves the fingerprint.
    """
    try:
        import subprocess

        digest = hashlib.sha256()
        status = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=str(work_dir),
            capture_output=True,
            text=True,
            timeout=30,
        )
        if status.returncode != 0:
            return None
        digest.update(status.stdout.encode("utf-8", "replace"))
        diff = subprocess.run(
            ["git", "diff", "--binary"],
            cwd=str(work_dir),
            capture_output=True,
            text=True,
            timeout=60,
        )
        if diff.returncode != 0:
            return None
        digest.update(diff.stdout.encode("utf-8", "replace"))
        staged = subprocess.run(
            ["git", "diff", "--cached", "--binary"],
            cwd=str(work_dir),
            capture_output=True,
            text=True,
            timeout=60,
        )
        if staged.returncode != 0:
            return None
        digest.update(staged.stdout.encode("utf-8", "replace"))
        for line in status.stdout.splitlines():
            # Untracked entries read "?? path" — include their contents.
            if not line.startswith("??"):
                continue
            rel = line[3:].strip().strip('"')
            path = Path(work_dir) / rel
            if path.is_file():
                try:
                    digest.update(path.read_bytes())
                except OSError:
                    continue
        return digest.hexdigest()
    except Exception:
        return None


def _reject_unknown_schema_fields(
    payload: Mapping[str, Any],
    strict_schema: Mapping[str, Any],
    step: str,
) -> None:
    """Reject unknown schema-owned fields in the exact output payload.

    The model_seam normalizer silently drops undeclared fields before its
    audit, so the local-strict omp worker validates the *exact* parsed file
    against ``additionalProperties: false`` up front.  Any field the canonical
    schema does not own fails the step.
    """
    from arnold.pipeline.contract_validation import validate_payload_against_schema

    result = validate_payload_against_schema(payload, strict_schema)
    if result.ok:
        return
    extra_props = [
        diagnostic
        for diagnostic in result.diagnostics
        if diagnostic.code == "additional_property"
    ]
    if extra_props:
        fields = ", ".join(
            diagnostic.payload_pointer for diagnostic in extra_props
        )
        raise ModelStructuralAuditError(
            f"omp output for step {step!r} carries unknown schema-owned "
            f"fields: {fields}"
        )
    details = "; ".join(
        f"{diagnostic.code} at {diagnostic.payload_pointer or '/'}: "
        f"{diagnostic.message}"
        for diagnostic in result.diagnostics
    )
    raise ModelStructuralAuditError(details)


# ────────────────────────────────────────────────────────────────────────
# Prompt helpers
# ────────────────────────────────────────────────────────────────────────

def _resolve_omp_schema(step: str, state: PlanState, root: Path) -> dict[str, Any]:
    plan_mode = state["config"].get("mode", "code")
    schema_name = (
        get_execution_schema_key(plan_mode, form=creative_form_id(state))
        if step == "execute"
        else STEP_CAPTURE_SCHEMA_FILENAMES.get(step, STEP_SCHEMA_FILENAMES[step])
    )
    schema = SCHEMAS.get(schema_name) or read_json(schemas_root(root) / schema_name)
    if not isinstance(schema, dict):
        raise CliError(
            "schema_error",
            f"no capture schema found for omp step {step!r} ({schema_name})",
        )
    return schema


def _omp_timeout_for_step(step: str) -> float:
    # The canonical timeout is worker_timeout_seconds (default 7200).  The
    # legacy MEGAPLAN_OMP_TIMEOUT_S override is still accepted for migration;
    # everything else uses the configured policy.
    try:
        value = float(os.getenv("MEGAPLAN_OMP_TIMEOUT_S", ""))
        if value > 0:
            return value
    except (TypeError, ValueError):
        pass
    return float(get_effective("execution", "worker_timeout_seconds"))


def _prompt_phase_tools(step: str, read_only: bool) -> tuple[str, ...] | None:
    """Phase toolset for the omp child.

    Execute gets the default full toolset (bash + file tools + …); read-only
    phases get only the read tool plus the structured-output host tool —
    built-in edit/write on a read-only phase could mutate the repository
    outside the execute mutation guard. Other non-execute phases keep
    read/edit/write for legitimate plan-file work.
    """
    if step in _EXECUTE_STEPS:
        return None  # default full toolset
    if read_only:
        return ("read",)
    return ("read", "edit", "write")


def _local_strict_prompt_suffix() -> str:
    return (
        "\n\nResponse enforcement: produce the complete phase output as "
        "exactly one JSON object matching the supplied canonical schema. "
        "Call the write_phase_output tool once at the end with that JSON "
        "object as its payload argument. Do NOT put the JSON in your text "
        "response and do NOT use Markdown fences. The output file is the "
        "only output that matters."
    )


# ────────────────────────────────────────────────────────────────────────
# Main entry
# ────────────────────────────────────────────────────────────────────────
def _run_omp_with_admission(
    step: str,
    state: PlanState,
    plan_dir: Path,
    *,
    root: Path,
    fresh: bool,
    model: str | None,
    effort: str | None,
    prompt_override: str | None,
    output_path: Path | None,
    worker_options: dict[str, Any] | None,
    read_only: bool,
    prompt_kwargs: dict[str, Any] | None,
    wbc_dispatch: Any = None,
) -> Any:
    if wbc_dispatch is None:
        raise CliError(
            "wbc_dispatch_required",
            "production OMP dispatch requires the canonical WBC adapter before admission",
        )
    from arnold_pipelines.megaplan.cloud.runtime_attestation import (
        configured_seed_path,
        require_production_worker_dispatch_runtime,
        validated_configured_worker_runtime_expectation,
    )
    from arnold_pipelines.megaplan.cloud.runtime_provenance import runtime_provenance
    from arnold_pipelines.megaplan.cloud.worker_dispatch import (
        AdmissionRefusal,
        SchedulingCondition,
        WorkerAdmissionRequest,
        dispatch_with_admission,
        production_provider_probe_executor,
    )
    from arnold_pipelines.megaplan.types import parse_agent_spec

    options = worker_options or {}
    raw_spec = model or ""
    provider, model_id = parse_omp_spec(raw_spec)
    selected_spec = format_omp_spec(provider, model_id)
    expected_root, expected_revision = (
        validated_configured_worker_runtime_expectation()
    )
    provenance = runtime_provenance(
        expected_root=expected_root,
        expected_revision=expected_revision,
    )
    seed_path = configured_seed_path()
    manifest_path = os.environ.get("ARNOLD_RUNTIME_MANIFEST", "")
    seed_identity = hashlib.sha256(seed_path.read_bytes()).hexdigest() if seed_path and seed_path.is_file() else ""
    manifest_identity = hashlib.sha256(Path(manifest_path).read_bytes()).hexdigest() if manifest_path and Path(manifest_path).is_file() else ""
    logical_id = str((state.get("meta") or {}).get("current_invocation_id") or uuid.uuid4())
    configured_specs = tuple(options.get("configured_fallback_specs") or (selected_spec,))
    request = WorkerAdmissionRequest(
        plan_id=plan_dir.name,
        phase=step,
        dispatch_family_id=str(options.get("dispatch_family_id") or logical_id),
        logical_dispatch_id=logical_id,
        physical_door_id="workers.omp.run_omp_step",
        configured_spec=selected_spec,
        selected_spec=selected_spec,
        source_revision=str(provenance.get("source_revision") or ""),
        runtime_vector=provenance,
        manifest_identity=manifest_identity,
        seed_identity=seed_identity,
        dependency_interpreter_identity=str(Path(os.sys.executable).resolve()),
        prompt_or_phase_input_identity=str(options.get("prompt_or_phase_input_identity") or hashlib.sha256(f"{step}:{prompt_override or ''}".encode()).hexdigest()),
        configured_fallback_chain_identity=str(options.get("configured_fallback_chain_identity") or ""),
        configured_fallback_specs=configured_specs,
        authorized_route_identity=selected_spec,
        projection_key=str(options.get("projection_key") or f"{plan_dir.name}:{step}"),
        timeout_budget_s=float(options.get("timeout_budget_s") or 3600.0),
        production_intent=True,
        ledger_root=root,
        admission_attempt=int(options.get("admission_attempt") or 1),
    )
    token = _OMP_ADMISSION_ACTIVE.set(True)
    transport_worker: WorkerResult | None = None
    try:
        def launch(context: Any) -> WorkerResult:
            nonlocal transport_worker
            admitted = getattr(context, "selected_spec", None) or selected_spec
            parse_agent_spec(admitted)
            parse_omp_spec(admitted)
            def final_launch(_start: Any = None) -> WorkerResult:
                return run_omp_step(
                    step, state, plan_dir, root=root, fresh=fresh, model=admitted,
                    effort=effort, prompt_override=prompt_override, output_path=output_path,
                    worker_options=worker_options, read_only=read_only,
                    prompt_kwargs=prompt_kwargs,
                )
            result = wbc_dispatch.run(final_launch).worker_result
            if isinstance(result, WorkerResult):
                # Keep the legacy worker available for the historical caller
                # while the shared seam returns its canonical typed outcome.
                transport_worker = result
            return result

        probe_executor = production_provider_probe_executor()
        result = dispatch_with_admission(
            request, launch, gate=require_production_worker_dispatch_runtime,
            return_worker=False,
            probe_executor=probe_executor, child_launch=launch,
        )
    finally:
        _OMP_ADMISSION_ACTIVE.reset(token)
    if isinstance(result, AdmissionRefusal):
        raise CliError(result.code, result.reason, extra=result.to_dict())
    if isinstance(result, SchedulingCondition):
        raise CliError("scheduling_condition", result.reason, extra=result.to_dict())
    from arnold_pipelines.megaplan.orchestration.phase_result import DispatchOutcome
    if isinstance(result, DispatchOutcome) and result.kind == "unresolved_launch":
        # Keep the canonical typed hold visible to downstream consumers while
        # retaining the historical exception boundary for OMP callers.
        raise CliError(
            "scheduling_condition",
            "canonical OMP launch remains unresolved",
            extra={"reason": "unresolved_launch", "dispatch_outcome": result.to_dict()},
        )
    if isinstance(result, DispatchOutcome):
        # Typed ordinary/provider/disposition terminals are already canonical
        # results from the shared dispatch seam.  Preserve them losslessly so
        # callers can consume the durable identity and provider context.
        if result.kind == "success" and transport_worker is not None:
            metadata = dict(transport_worker.auth_metadata or {})
            metadata["dispatch_outcome"] = result.to_dict()
            transport_worker.auth_metadata = metadata
            return transport_worker
        return result
    if not isinstance(result, WorkerResult):
        raise CliError("internal_error", "canonical OMP dispatch returned an invalid worker result")
    return result


def run_omp_step(
    step: str,
    state: PlanState,
    plan_dir: Path,
    *,
    root: Path,
    fresh: bool = True,
    model: str | None = None,
    effort: str | None = None,
    prompt_override: str | None = None,
    output_path: Path | None = None,
    worker_options: dict[str, Any] | None = None,
    read_only: bool = False,
    free_text: bool = False,
    prompt_kwargs: dict[str, Any] | None = None,
    wbc_dispatch: Any = None,
) -> Any:
    """Run a megaplan phase through a fresh stateless omp RPC session.

    Structured output is enforced locally (local-strict): the model writes the
    phase payload to ``capture_recovery.output_path`` via the
    ``write_phase_output`` host tool, and ``model_seam.capture_step_output``
    reads/validates the file.  Retries are bounded and attempt-idempotent;
    execute never replays after side effects.
    """
    if (
        not _OMP_ADMISSION_ACTIVE.get()
        and (
            os.environ.get("ARNOLD_RUNTIME_MANIFEST")
            or os.environ.get("MEGAPLAN_RUNTIME_LAUNCH_SEED")
            or (worker_options or {}).get("production_intent")
        )
    ):
        return _run_omp_with_admission(
            step, state, plan_dir, root=root, fresh=fresh, model=model, effort=effort,
            prompt_override=prompt_override, output_path=output_path,
            worker_options=worker_options, read_only=read_only,
            prompt_kwargs=prompt_kwargs, wbc_dispatch=wbc_dispatch,
        )
    if os.getenv(MOCK_ENV_VAR) == "1":
        _check_mock_safe()
        return mock_worker_output(
            step,
            state,
            plan_dir,
            prompt_override=prompt_override,
            prompt_kwargs=prompt_kwargs,
        )

    # ── Resolve the omp route from the frozen B1 contract ─────────────
    raw_model = model
    provider, model_id = parse_omp_spec(raw_model)
    catalog_model = validate_omp_catalog_model(provider, model_id)
    _, model_id = parse_omp_spec(catalog_model)
    thinking = omp_thinking_level(effort, provider, model_id)

    work_dir = resolve_work_dir(state)
    schema = _resolve_omp_schema(step, state, root)
    # Local-strict capture schema: the model may only emit fields the
    # canonical schema owns.  ``additionalProperties: false`` makes the
    # exact-JSON pre-validation below reject unknown schema-owned fields.
    import copy as _copy

    strict_capture_schema = _copy.deepcopy(schema)
    # Runtime dialect for the omp AUDIT path: convert oneOf to anyOf (at
    # least one branch) only. Deliberately NOT the full codex strict-mode
    # conversion: its required-promotion makes absent optional keys (e.g.
    # `area` for catalog lenses, `why`) fail the audit on valid output -
    # models legitimately omit branch-specific keys. Field-level semantics
    # are still validated inside each matched branch.
    def _runtime_dialect(node):
        if isinstance(node, dict):
            node = {k: _runtime_dialect(v) for k, v in node.items()}
            if "oneOf" in node and "anyOf" not in node:
                node["anyOf"] = node.pop("oneOf")
            return node
        if isinstance(node, list):
            return [_runtime_dialect(item) for item in node]
        return node
    strict_capture_schema = _runtime_dialect(strict_capture_schema)
    strict_capture_schema["additionalProperties"] = False
    normalized_options = dict(worker_options or {})
    explicit_output_path = output_path
    if explicit_output_path is None and normalized_options.get("output_path"):
        explicit_output_path = Path(str(normalized_options["output_path"]))
    output_path = explicit_output_path or (
        plan_dir / f"{step}_omp_output.json"
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # ── Response contract (local strict — omp cannot enforce the schema) ──
    response_contract = compile_response_contract(
        schema,
        provider="omp",
        model=catalog_model,
        phase=step,
        provider_schema_available=False,
    )
    persist_response_enforcement_attestation(plan_dir, response_contract.attestation)
    response_attestation = response_contract.attestation.to_json()

    rendered_prompt = render_prompt_for_dispatch(
        "omp",
        step,
        state,
        plan_dir,
        root=root,
        worker=OMP_WORKER_CHANNEL,
        # The model seam's budget classifier rejects provider-prefixed
        # names (``anthropic/...``, ``fireworks/...``); the bare catalog
        # model id is provider-neutral and classifies by family.
        model=model_id,
        normalized_model=model_id,
        tier=ModelTier.ENFORCED,
        schema=schema,
        prompt_override=prompt_override,
        **(prompt_kwargs or {}),
    )
    prompt = rendered_prompt.prompt
    seed_text = ""
    if not free_text:
        # Seed the output file with a JSON template so the model's job is
        # concrete (read template -> fill -> write via the tool), and prepend
        # + append an unmissable output contract.
        try:
            if not output_path.exists() or not output_path.read_text(
                encoding="utf-8", errors="replace"
            ).strip():
                from arnold_pipelines.megaplan.workers._payload import (
                    _build_output_template,
                )

                output_path.parent.mkdir(parents=True, exist_ok=True)
                seed_text = _build_output_template(step, schema)
                output_path.write_text(seed_text, encoding="utf-8")
        except Exception:
            pass
        contract = (
            "\n\nOUTPUT CONTRACT (mandatory):\n"
            f"1. The output file is {output_path}. It currently contains an "
            "empty JSON template.\n"
            "2. Read the template file, then call the write_phase_output tool "
            "ONCE with the COMPLETE final JSON object as its payload argument.\n"
            "3. Your text response must be a brief confirmation only - never "
            "the JSON itself.\n"
            "4. Do not use Markdown fences anywhere.\n"
        )
        prompt = contract + "\n\n" + prompt + contract
    try:
        check_prompt_size(prompt, phase=step)
    except CliError:
        raise

    timeout_seconds = _omp_timeout_for_step(step)
    toolset = _prompt_phase_tools(step, read_only)
    prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()[:16]
    started = time.monotonic()

    # Credentials: the RPC child inherits the Arnold process env; validate the
    # frozen credential presence up front so a missing key fails closed before
    # launch (mirrors the legacy provider-credential validation).  At least one
    # alias variable per route must be set (e.g. ANTHROPIC_OAUTH_TOKEN OR
    # ANTHROPIC_API_KEY; MOONSHOT_API_KEY OR KIMI_API_KEY).
    alias_names = _OMP_CREDENTIAL_ENV.get(provider, ())
    if (
        provider not in _OMP_NATIVE_CREDENTIAL_ROUTES
        and not any(os.environ.get(name) for name in alias_names)
    ):
        # Native routes (openai-codex OAuth, grok CLI-proxy token, tokenless
        # Kimi Code OAuth) resolve credentials omp-side; env routes need at
        # least one key.
        raise CliError(
            "authentication",
            f"omp provider {provider!r} requires one of "
            f"{alias_names} but none is set",
        )

    attempt_index = 0
    attempted_specs: list[str] = []
    failed_attempt_reasons: list[str] = []
    last_error: CliError | None = None
    # Execute-shaped phases are mutating and v1 forbids replay: a provider
    # outage must return to the authoritative outer door, which raises the
    # typed ExecuteFallbackUnsafe before any second client/RPC attempt.  Keep
    # bounded retries for read-only phases only.
    max_attempts = 1 if step in _EXECUTE_STEPS else max(1, _OMP_MAX_ATTEMPTS)

    while True:
        attempt_index += 1
        attempt_id = uuid.uuid4().hex
        attempted_specs.append(format_omp_spec(provider, model_id))
        client = None
        try:
            if seed_text:
                # Reset the structured-output file to the seed template at the
                # start of EVERY attempt: a stale file written by a previous
                # attempt that then timed out must not be accepted by the next
                # attempt without the model actually calling the host tool.
                try:
                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    output_path.write_text(seed_text, encoding="utf-8")
                except OSError:
                    pass
            if step in _EXECUTE_STEPS:
                mutation_before = _worktree_mutation_fingerprint(work_dir)
            else:
                mutation_before = None
            client = _build_client(
                provider=provider,
                model_id=model_id,
                cwd=work_dir,
                thinking=thinking,
                tools=toolset,
                custom_tools=[_write_phase_output_tool(output_path)],
                env=os.environ,
                timeout=timeout_seconds,
            )
            client.start()
            try:
                # Bound the bun host's context growth during long streaming
                # turns (occurrence 1ac805e5eef9: frontier-phase workers
                # accumulated multi-GB RSS and were cgroup-OOM-killed under
                # the 8 GiB ceiling).  Auto-compaction summarises old context
                # instead of buffering unbounded thinking/tool deltas.
                client.set_auto_compaction(True)
            except Exception as exc:
                # The pinned RpcClient supports it; fakes may not.  Never
                # fail a launch over a best-effort memory lever, but make
                # a missing lever observable instead of a silent pass.
                logging.getLogger(__name__).warning(
                    "set_auto_compaction unavailable (%s); "
                    "continuing without context compaction",
                    exc,
                )
            try:
                client.set_model(provider, model_id)
            except Exception:
                # Some fakes/providers resolve the model at launch; tolerate
                # set_model being unsupported only when the client already
                # reports the requested model.
                try:
                    client.get_state()
                except Exception:
                    raise
            if thinking is not None:
                try:
                    client.set_thinking_level(thinking)
                except Exception as exc:
                    raise CliError(
                        "thinking_verification",
                        "omp RPC could not apply the requested thinking level",
                    ) from exc
            _verify_omp_session_binding(
                client,
                provider=provider,
                model_id=model_id,
                thinking=thinking,
            )

            call_transaction_id = _emit_llm_start(
                plan_dir,
                step,
                catalog_model,
                prompt_hash,
                attempt_id,
            )

            turn = client.prompt_and_wait(
                prompt,
                timeout=timeout_seconds,
            )
            _raise_provider_error_from_turn(turn, model=catalog_model)

            try:
                final_text = turn.require_assistant_text()
            except Exception as exc:
                raise CliError(
                    "worker_parse_error",
                    f"omp worker produced no final text for step '{step}' "
                    f"(attempt {attempt_index})",
                    extra={"raw_output": ""},
                ) from exc
            if not final_text.strip():
                raise CliError(
                    "worker_parse_error",
                    f"omp worker returned no final text for step '{step}' "
                    f"(attempt {attempt_index})",
                    extra={"raw_output": ""},
                )

            raw = final_text
            output_raw = ""
            if output_path.exists():
                output_raw = output_path.read_text(
                    encoding="utf-8", errors="replace"
                )
            # The seeded template is not model output: if the file still
            # holds the seed byte-for-byte, the model never wrote a valid
            # payload (rejected attempts leave the seed untouched) and the
            # final text is the only candidate.
            if output_raw.strip() and output_raw != seed_text:
                raw = output_raw

            try:
                exact_payload = json.loads(raw)
            except json.JSONDecodeError as error:
                raise CliError(
                    "parse_error",
                    f"omp output for step '{step}' is not a single exact JSON "
                    f"object (prose, markdown fences, or truncation)",
                    extra={"raw_output": raw},
                ) from error
            if not isinstance(exact_payload, Mapping):
                raise CliError(
                    "parse_error",
                    f"omp output for step '{step}' must be exactly one JSON "
                    f"object",
                    extra={"raw_output": raw},
                )
            # Apply the harness payload normalizers (critique severity_hint
            # enum mapping, execute bookkeeping-field strip, plan criterion
            # flattening) BEFORE the strict audit so known flexible fields
            # normalize instead of failing the enum/unknown-field gates.
            from arnold_pipelines.megaplan.workers._payload import (
                clean_parsed_payload,
            )

            clean_parsed_payload(exact_payload, schema, step)
            try:
                _reject_unknown_schema_fields(
                    exact_payload, strict_capture_schema, step
                )
            except ModelStructuralAuditError as error:
                raise CliError(
                    "worker_structural_audit_failed",
                    str(error),
                    extra={"raw_output": raw},
                ) from error

            try:
                capture_outcome = capture_step_output(
                    StepInvocation(
                        kind="model",
                        metadata={
                            "tier": ModelTier.ENFORCED.value,
                            "worker": OMP_WORKER_CHANNEL,
                            "model": model_id,
                            "normalized_model": model_id,
                            "validation_step": step,
                            "compatibility_validation_step": step,
                            "schema": schema,
                            "capture_schema": strict_capture_schema,
                            "response_enforcement_attestation": response_attestation,
                            "capture_recovery": {
                                "step": step,
                                "plan_dir": str(plan_dir),
                                "output_path": str(output_path),
                                "prefer_output_file": True,
                            },
                        },
                    ),
                    raw,
                )
                payload = dict(capture_outcome.legacy_payload)
            except json.JSONDecodeError as error:
                raise CliError(
                    "parse_error",
                    f"omp output for step '{step}' is not a single exact JSON "
                    f"object (prose, markdown fences, or truncation)",
                    extra={"raw_output": raw},
                ) from error
            except (CliError, ModelStructuralAuditError) as error:
                if isinstance(error, CliError):
                    raise
                raise CliError(
                    "worker_structural_audit_failed",
                    str(error),
                    extra={"raw_output": raw},
                ) from error

            # ── Exactly-once usage + reconciliation ────────────────────
            messages = client.get_messages()
            usage = aggregate_usage_from_messages(
                messages,
                provider=provider,
                model=catalog_model,
                attempt_id=attempt_id,
            )
            try:
                stats = client.get_session_stats()
            except Exception:
                stats = None
            usage = reconcile_usage_with_session_stats(usage, stats)
            _emit_llm_end(plan_dir, step, usage, call_transaction_id)
            _emit_cost_recorded(plan_dir, step, usage, catalog_model)

            elapsed_ms = int((time.monotonic() - started) * 1000)
            auth_metadata = {
                "worker_channel": OMP_WORKER_CHANNEL,
                "auth_channel": provider,
                "provider": provider,
                "resolved_model": catalog_model,
                "attempt_id": attempt_id,
                "usage_reconciliation": (
                    "per_message_exact"
                    if not usage.reconciled_delta
                    else "session_stats_delta_applied"
                ),
            }
            return WorkerResult(
                payload=payload,
                raw_output=raw,
                duration_ms=elapsed_ms,
                cost_usd=float(usage.cost_usd),
                session_id=f"omp-stateless:{attempt_id}",
                rendered_prompt=prompt,
                model_actual=catalog_model,
                model_evidence="omp_rpc_turn_context",
                prompt_tokens=usage.input_tokens,
                completion_tokens=usage.output_tokens,
                total_tokens=usage.total_tokens,
                cost_pricing=usage.cost_pricing,
                worker_channel=auth_metadata["worker_channel"],
                auth_channel=auth_metadata["auth_channel"],
                auth_metadata=auth_metadata,
                configured_specs=tuple(attempted_specs),
                attempt_index=attempt_index,
                attempted_specs=tuple(attempted_specs),
                failed_attempt_reasons=tuple(failed_attempt_reasons),
                response_enforcement_attestation=response_attestation,
            )
        except CliError as error:
            failed_attempt_reasons.append(error.code)
            _emit_llm_error(
                plan_dir,
                step,
                str(error.message),
            )
            last_error = error
            retryable = error.code in _OMP_RETRYABLE_CODES
            if not retryable or attempt_index >= max_attempts:
                if step in _EXECUTE_STEPS and retryable:
                    from arnold_pipelines.megaplan.fallback_chains import (
                        ExecuteFallbackUnsafe,
                    )

                    # Execute-shaped phases are single-attempt doors.  A
                    # retryable outage that would otherwise advance the
                    # local OMP loop is surfaced as the typed refusal
                    # before another RPC/client/worker side effect.
                    raise ExecuteFallbackUnsafe(
                        phase=step,
                        configured_specs=attempted_specs,
                        attempted_index=0,
                    ) from error
                raise
            # Execute replay guard: if the failed attempt landed any file
            # changes, a retry would replay side effects — fail hard instead.
            if step in _EXECUTE_STEPS and mutation_before is not None:
                mutation_after = _worktree_mutation_fingerprint(work_dir)
                if mutation_after != mutation_before:
                    from arnold_pipelines.megaplan.fallback_chains import (
                        ExecuteFallbackUnsafe,
                    )

                    # The attempted spec (index 0) produced side effects;
                    # automatic fallback to any further spec is refused.
                    raise ExecuteFallbackUnsafe(
                        phase=step,
                        configured_specs=attempted_specs,
                        attempted_index=0,
                    ) from error
            delay = 2.0 ** attempt_index
            print(
                f"[omp-worker] retryable {error.code} on attempt "
                f"{attempt_index}/{max_attempts} for step '{step}'; "
                f"retrying in {delay:.0f}s",
                flush=True,
            )
            time.sleep(delay)
            continue
        except Exception as error:
            code, message = classify_omp_failure(
                error,
                stderr_text=getattr(client, "stderr", "") if client is not None else "",
                model=catalog_model,
            )
            failed_attempt_reasons.append(code)
            _emit_llm_error(plan_dir, step, message)
            last_error = CliError(
                code,
                message,
                extra={"raw_output": message},
            )
            retryable = code in _OMP_RETRYABLE_CODES
            if not retryable or attempt_index >= max_attempts:
                if step in _EXECUTE_STEPS and retryable:
                    from arnold_pipelines.megaplan.fallback_chains import (
                        ExecuteFallbackUnsafe,
                    )

                    # Keep exception classification identical for native
                    # RPC exceptions and typed CliError responses: an
                    # execute retry is unsafe even when no mutation was
                    # observed, because a second provider call is itself
                    # an unowned side effect.
                    raise ExecuteFallbackUnsafe(
                        phase=step,
                        configured_specs=attempted_specs,
                        attempted_index=0,
                    ) from last_error
                raise last_error
            if step in _EXECUTE_STEPS and mutation_before is not None:
                mutation_after = _worktree_mutation_fingerprint(work_dir)
                if mutation_after != mutation_before:
                    from arnold_pipelines.megaplan.fallback_chains import (
                        ExecuteFallbackUnsafe,
                    )

                    raise ExecuteFallbackUnsafe(
                        phase=step,
                        configured_specs=attempted_specs,
                        attempted_index=0,
                    ) from error
            delay = 2.0 ** attempt_index
            print(
                f"[omp-worker] retryable {code} on attempt "
                f"{attempt_index}/{max_attempts} for step '{step}'; "
                f"retrying in {delay:.0f}s",
                flush=True,
            )
            time.sleep(delay)
            continue
        finally:
            if client is not None:
                try:
                    client.stop()
                except Exception:
                    pass

    # Unreachable: the loop either returns or raises.
    raise last_error  # pragma: no cover


__all__ = [
    "OMP_WORKER_CHANNEL",
    "OMP_AGENT",
    "OmpUsage",
    "aggregate_usage_from_messages",
    "classify_omp_failure",
    "format_omp_spec",
    "omp_thinking_level",
    "parse_omp_spec",
    "reconcile_usage_with_session_stats",
    "run_omp_step",
    "set_omp_client_factory",
    "validate_omp_catalog_model",
]
