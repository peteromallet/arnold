"""Resident-owned provider-neutral delegated-agent lifecycle tracking."""

from __future__ import annotations

import asyncio
import argparse
from collections.abc import Awaitable, Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import logging
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Literal

from agentbox.redaction import redact_text
from arnold.agent.contracts import AgentSpec, format_agent_spec, parse_agent_spec
from agentbox.onboarding import detect as agentbox_detect
from arnold.agent.routing import ManagedAgentRoute, resolve_managed_agent_route
from arnold.runtime.durable_ops import (
    FileBackedDurableOpsStore,
    LaunchDispatchRejected,
    LaunchEnvelope,
    LaunchResult as DurableLaunchResult,
    ResourceType,
    TypedResource,
    launch_transaction,
    inspect_launch,
    read_only_capacity_observation,
    read_only_network_observation,
    run_launch_preflight,
)
from arnold_pipelines.megaplan.managed_agent import (
    ACTIVE_STATUSES as SHARED_ACTIVE_STATUSES,
    TERMINAL_STATUSES as SHARED_TERMINAL_STATUSES,
    MANAGED_AGENT_CUSTODIAN,
    MANAGED_AGENT_SCHEMA,
    _pid_live,
    is_managed_manifest,
    managed_run_roots,
    validate_automatic_managed_manifest,
    observed_status as shared_observed_status,
    _managed_worker_identity,
    _pid_start_ticks,
    certify_managed_worker_launch,
    signal_managed_process,
)
from arnold_pipelines.megaplan.runtime import key_pool
from .config import ResidentConfig
from .git_custody import (
    GitCustodyError,
    git_custody_projection,
    render_git_custody_contract,
    resolve_launch_git_custody,
    validate_git_custody_evidence,
)
from .delivery_status import (
    DELIVERY_STATUS_SCHEMA,
    build_delivery_attention,
    build_delivery_projection,
    delivery_policy_for_launch,
    infer_outcome_contract,
)
from .managed_child_custody import (
    emit_managed_child_custody_event,
    ensure_managed_child_custody_fields,
    managed_child_delivery_projection,
)
from .provenance import (
    DelegationProvenanceError,
    discord_origin_projection,
    environment_with_provenance,
    normalize_delegation_provenance,
    provenance_from_environment,
    stable_identity,
)
from .provider_runtime import (
    PROVIDER_TELEMETRY_SCHEMA,
    claude_tools_for,
    collect_provider_evidence,
    normalize_toolsets,
    provider_execution_contract,
    reserve_session_id,
    valid_session_id,
    write_normalized_events,
)
from .request_summary import (
    REQUEST_DESCRIPTION_MAX_CHARS,
    canonical_request_description,
    content_with_request_summary,
    current_request_summary_line,
    source_request_fallback_line,
)
from .reply_chain import reply_chain_projection
from .query_relationship import relationship_from_environment_or_project

LOGGER = logging.getLogger(__name__)
MANAGED_RUN_SCHEMA = MANAGED_AGENT_SCHEMA
MANAGED_RUN_KIND = "resident_delegated_agent"
MANAGED_RUN_CUSTODIAN = MANAGED_AGENT_CUSTODIAN
LEGACY_MANAGED_RUN_SCHEMA = "arnold-subagent-run-v1"
DEFAULT_MANAGED_RUN_ROOT = Path(".megaplan/plans/resident-subagents")
DEFAULT_DELEGATED_TASK_KIND = "routine"
DEFAULT_DELEGATED_DIFFICULTY = 4
DEFAULT_DELEGATED_WORK_INTENT = "auto"
DELEGATED_TASK_KINDS = (
    "routine",
    "lookup",
    "extraction",
    "mechanical",
    "coding",
    "debugging",
    "research",
    "root_cause",
    "architecture",
    "migration",
    "review",
    "autonomous",
)
DELEGATED_WORK_INTENTS = ("auto", "execution", "review", "speculative")
DELEGATED_MUTATION_CLAIMS = ("auto", "none", "git_backed")
DelegatedTaskKind = Literal[
    "routine",
    "lookup",
    "extraction",
    "mechanical",
    "coding",
    "debugging",
    "research",
    "root_cause",
    "architecture",
    "migration",
    "review",
    "autonomous",
]
DelegatedWorkIntent = Literal["auto", "execution", "review", "speculative"]
DelegatedMutationClaim = Literal["auto", "none", "git_backed"]
_BOUNDED_TASK_KINDS = frozenset({"lookup", "extraction", "mechanical"})
_HIGH_RISK_TASK_KINDS = frozenset(
    {"root_cause", "architecture", "migration", "review", "autonomous"}
)
_VALID_DELEGATED_EFFORTS = frozenset(
    {"minimal", "low", "medium", "high", "xhigh", "max"}
)
_NON_EXECUTION_TASK_KINDS = frozenset(
    {"lookup", "extraction", "research", "root_cause", "architecture", "review"}
)
_ACTIVE_STATUSES = SHARED_ACTIVE_STATUSES
_TERMINAL_STATUSES = SHARED_TERMINAL_STATUSES
# ``abandoned`` is a historical/control-plane terminal label rather than a
# valid managed-agent terminal outcome.  Accept it only while observing a
# predecessor so an older abandoned parent cannot leave a current successor
# queued forever.  The successor itself still terminalizes as ``failed``.
_DEPENDENCY_TERMINAL_STATUSES = _TERMINAL_STATUSES | {"abandoned"}
_CONTROL_TERMINAL_STATUSES = frozenset({"cancelled", "superseded"})
_DELIVERY_RETRY_BASE_S = 30
_DELIVERY_RETRY_MAX_S = 60 * 60
_DELIVERY_MAX_ATTEMPTS = 8
_MAX_COMPLETION_DELIVERY_CHARS = 7_600
QUEUE_SCHEMA = "arnold-resident-subagent-queue-v1"
QUEUE_REFERENCE_SCHEMA = "arnold-resident-subagent-reference-v1"
QUEUE_CROSS_REQUEST_AUTHORIZATION_SCHEMA = (
    "arnold-resident-cross-request-queue-authorization-v1"
)
QUEUE_TRIGGER_POLICY = "on_predecessor_success"
MAX_QUEUE_CHAIN_DEPTH = 32
MAX_QUEUE_PREDECESSORS = 8
MAX_QUEUE_ANCESTOR_RUNS = 256
MAX_QUEUE_PROMPT_CHARS = 16_000
MAX_QUEUE_HOT_CONTEXT_ROWS = 8
_QUEUE_RETRY_BASE_S = 5
_QUEUE_RETRY_MAX_S = 5 * 60
_QUEUE_MAX_LAUNCH_ATTEMPTS = 3
MAX_DELEGATED_TASK_CHARS = 32_000
MAX_DELEGATED_PROMPT_CHARS = 40_000
MAX_FOLLOWUP_MESSAGE_CHARS = 32_000
MAX_AGENT_DESCRIPTION_CHARS = 180
MAX_MODEL_SESSION_LOG_PREFIX_BYTES = 1024 * 1024
FOLLOWUP_SCHEMA = "arnold-resident-agent-followup-v1"
QUEUED_OWNER_MATERIAL_SCHEMA = "arnold-resident-queued-owner-material-v1"
AGGREGATION_SCHEMA = "arnold-resident-agent-aggregation-v1"
AGGREGATION_ROLES = frozenset({"synthesis_delivery_owner", "internal_contributor"})
COMPLETION_VERIFICATION_SCHEMA = "arnold-resident-completion-verification-v1"
DISCORD_FOLLOWUP_WINDOW = timedelta(minutes=15)
_RUN_ID_RE = re.compile(r"^subagent-[0-9]{8}-[0-9]{6}-[A-Za-z0-9]{8}$")
_RESIDENT_TURN_ID_RE = re.compile(r"^turn_[A-Za-z0-9]{12,64}$")
_FOLLOWUP_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_SYNTHESIS_GROUP_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$")
_CODEX_SESSION_RE = re.compile(
    r"(?im)^session id:\s*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\s*$"
)
_CODEX_JSON_SESSION_RE = re.compile(
    r'"(?:thread_id|session_id)"\s*:\s*"'
    r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"',
    re.IGNORECASE,
)
FINAL_SUMMARY_INSTRUCTION = (
    "Your FINAL response will be sent directly to the user as a Discord reply. "
    "Make it a concise, user-facing summary that stands on its own. State the outcome, "
    "the important changes or findings, verification performed, and any remaining operational "
    "caveat. Do not include internal handoff notes, ask a follow-up question, or merely say that "
    "work is complete. Never expose credentials or other secrets. Preserve and follow all "
    "task-specific instructions above."
)
DELEGATION_DELIVERY_INSTRUCTION_SCHEMA = (
    "arnold-resident-delegation-delivery-instruction-v1"
)
DELEGATION_DELIVERY_INSTRUCTION_HEADER = (
    "[Resident delegation execution/delivery instruction — canonical v1]"
)

# resident/ -> megaplan/ -> skills/subagent-launcher/
OMP_LAUNCHER_PATH = (
    Path(__file__).resolve().parent.parent / "skills" / "subagent-launcher" / "launch_omp_agent.py"
)
CLAUDE_LAUNCHER_PATH = (
    Path(__file__).resolve().parent.parent / "skills" / "subagent-launcher" / "launch_claude_agent.py"
)


@dataclass(frozen=True)
class SubagentResult:
    ok: bool
    final_text: str
    stderr: str
    returncode: int
    error: str | None = None
    run_id: str | None = None
    status: str | None = None
    manifest_path: str | None = None
    log_path: str | None = None
    result_path: str | None = None
    custody_evidence_path: str | None = None
    delivery_owner_run_id: str | None = None
    parent_owned_delivery: bool | None = None
    pid: int | None = None
    description: str | None = None


@dataclass(frozen=True)
class SubagentFollowupResult:
    """Durable acceptance evidence for one resident-managed follow-up."""

    ok: bool
    followup_id: str
    target_run_id: str
    parent_run_id: str
    lineage_root_run_id: str
    continuation_run_id: str | None
    status: str
    evidence_path: str
    message_path: str
    continuation_manifest_path: str | None
    model_session_id: str | None = None
    idempotent_replay: bool = False
    route: str = "session_continuation"
    delivery_owner_run_id: str | None = None


class SubagentFollowupError(ValueError):
    """A follow-up target or custody/session binding is unsafe or ambiguous."""


class SubagentQueueError(ValueError):
    """A queued successor contract is unsafe, invalid, or ambiguous."""


@dataclass(frozen=True)
class DiscordFollowupTarget:
    """One unambiguous managed lineage launched from an exact Discord source."""

    run_id: str
    lineage_root_run_id: str
    manifest_path: str
    launch_anchor: str
    launch_anchor_field: str


@dataclass(frozen=True)
class ManagedAgentDeliverySweepResult:
    scanned: int = 0
    delivered: int = 0
    retry_pending: int = 0
    skipped: int = 0
    failed: int = 0


@dataclass(frozen=True)
class ManagedAgentQueueSweepResult:
    """Durable reconciliation result for resident-managed successor queues."""

    scanned: int = 0
    waiting: int = 0
    launched: int = 0
    retry_pending: int = 0
    failed_closed: int = 0
    skipped: int = 0


@dataclass(frozen=True)
class ManagedCompletionTurnResult:
    """Durable output of the resident's independent completion-verification turn."""

    final_text: str
    verification_outcome: str
    turn_id: str | None = None
    outbound_message_id: str | None = None


class _ProviderAcceptanceEvidenceMissing(RuntimeError):
    """A send returned, but no durable Discord message identity was exposed."""


@dataclass(frozen=True)
class DelegatedTaskRoute:
    """Resolved GPT-5.6 route for one resident-managed task."""

    task_kind: DelegatedTaskKind
    difficulty: int
    model: str
    reasoning_effort: str
    route_class: str


def route_delegated_task(
    *,
    task_kind: DelegatedTaskKind = DEFAULT_DELEGATED_TASK_KIND,
    difficulty: int = DEFAULT_DELEGATED_DIFFICULTY,
) -> DelegatedTaskRoute:
    """Route resident delegation by task kind and D1-D10 difficulty.

    Luna is intentionally limited to bounded/mechanical D1-D3 work. Terra is
    the routine default. Ambiguous or high-risk kinds, and all D7-D10 work,
    use Sol/high. Explicit launch model/effort overrides are applied after
    this policy so existing callers retain their escape hatch.
    """

    if task_kind not in DELEGATED_TASK_KINDS:
        raise ValueError(
            f"task_kind must be one of {', '.join(DELEGATED_TASK_KINDS)}; got {task_kind!r}"
        )
    if isinstance(difficulty, bool) or not isinstance(difficulty, int) or not 1 <= difficulty <= 10:
        raise ValueError(f"difficulty must be an integer from 1 to 10; got {difficulty!r}")
    if task_kind in _HIGH_RISK_TASK_KINDS or difficulty >= 7:
        return DelegatedTaskRoute(
            task_kind=task_kind,
            difficulty=difficulty,
            model="gpt-5.6-sol",
            reasoning_effort="high",
            route_class="ambiguous_or_high_risk",
        )
    if task_kind in _BOUNDED_TASK_KINDS and difficulty <= 3:
        return DelegatedTaskRoute(
            task_kind=task_kind,
            difficulty=difficulty,
            model="gpt-5.6-luna",
            reasoning_effort="low",
            route_class="bounded_mechanical",
        )
    return DelegatedTaskRoute(
        task_kind=task_kind,
        difficulty=difficulty,
        model="gpt-5.6-terra",
        reasoning_effort="medium",
        route_class="routine",
    )


def resolve_delegated_work_intent(
    *,
    task_kind: DelegatedTaskKind,
    work_intent: DelegatedWorkIntent = DEFAULT_DELEGATED_WORK_INTENT,
) -> Literal["execution", "review", "speculative"]:
    """Resolve one explicit instruction mode for every managed child launch.

    The compatibility default is deliberately conservative for analysis-shaped
    task kinds. Resident execution normally arrives as routine, mechanical,
    coding, debugging, migration, or autonomous work. Callers can explicitly
    downgrade any task to review/speculative, but no caller can omit the final
    resolved mode from the launch prompt and manifest.
    """

    if task_kind not in DELEGATED_TASK_KINDS:
        raise ValueError(
            f"task_kind must be one of {', '.join(DELEGATED_TASK_KINDS)}; got {task_kind!r}"
        )
    if work_intent not in DELEGATED_WORK_INTENTS:
        raise ValueError(
            "work_intent must be one of "
            f"{', '.join(DELEGATED_WORK_INTENTS)}; got {work_intent!r}"
        )
    if work_intent != "auto":
        return work_intent
    return "review" if task_kind in _NON_EXECUTION_TASK_KINDS else "execution"


def resolve_delegated_mutation_claim(
    *,
    task_kind: DelegatedTaskKind,
    work_intent: Literal["execution", "review", "speculative"],
    mutation_claim: DelegatedMutationClaim = "auto",
) -> Literal["none", "git_backed"]:
    """Separate execution authority from the git effect a task actually claims.

    Bounded lookup/extraction/mechanical execution is result-producing work, not
    an implicit repository mutation.  Mutation-shaped execution remains strict
    by default, while an explicit claim lets callers truthfully classify an
    unusual task without weakening the completion gate for git-backed work.
    """

    if mutation_claim not in DELEGATED_MUTATION_CLAIMS:
        raise ValueError(
            "mutation_claim must be one of "
            f"{', '.join(DELEGATED_MUTATION_CLAIMS)}; got {mutation_claim!r}"
        )
    if work_intent != "execution":
        if mutation_claim == "git_backed":
            raise ValueError(
                "review/speculative work cannot claim an integrated git-backed mutation"
            )
        return "none"
    if task_kind not in _BOUNDED_TASK_KINDS:
        if mutation_claim == "none":
            raise ValueError(
                "mutation-shaped execution cannot opt out of strict git custody"
            )
        return "git_backed"
    return "git_backed" if mutation_claim == "git_backed" else "none"


def _delegation_delivery_instruction(
    work_intent: Literal["execution", "review", "speculative"],
    mutation_claim: Literal["none", "git_backed"],
) -> str:
    common = (
        "This instruction is appended by the resident launch boundary and does not expand the "
        "user's authority. Preserve the inherited immutable Discord/delegation provenance; never "
        "replace, reconstruct, or reinterpret its source envelope."
    )
    if work_intent == "execution" and mutation_claim == "git_backed":
        applicable = (
            "This is execution work: complete and proportionally verify the explicitly authorized "
            "implementation in an isolated worktree, then integrate it into the clearly identified "
            "target branch using the repository's non-destructive workflow. If the request is actually "
            "tentative/speculative, the target is materially ambiguous, or authorization does not cover "
            "an effect, keep the work isolated and report the exact gate instead. A local implementation "
            "does not authorize push, remote merge, deployment, restart, destructive cleanup, credential "
            "changes, or any other external effect unless the user or established policy explicitly "
            "authorizes that effect."
        )
    elif work_intent == "execution":
        applicable = (
            "This is authorized non-mutating execution: produce and verify the requested durable "
            "result without changing a repository, branch, worktree, service, or external system. "
            "Git commit/diff/clean-worktree custody is not applicable to successful completion. "
            "If the task actually requires a git-backed mutation, stop and report the contract "
            "mismatch instead of mutating under this claim."
        )
    elif work_intent == "review":
        applicable = (
            "This is review/analysis work: inspect and verify without mutating repositories, branches, "
            "services, external systems, or user-visible state. Findings may recommend execution, but "
            "must not implement, integrate, push, deploy, restart, or otherwise perform it unless a newer "
            "authorized instruction explicitly changes the task."
        )
    else:
        applicable = (
            "This is speculative/tentative work: do not integrate or perform external effects. Prefer "
            "read-only analysis; when a prototype is necessary, keep it on an isolated disposable branch, "
            "label it unintegrated, and report the target or authorization decision needed before delivery."
        )
    return (
        f"{DELEGATION_DELIVERY_INSTRUCTION_HEADER}\n"
        f"- schema: {DELEGATION_DELIVERY_INSTRUCTION_SCHEMA}\n"
        f"- resolved work intent: {work_intent}\n"
        f"- resolved mutation claim: {mutation_claim}\n"
        f"{applicable} {common}"
    )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def concise_agent_description(description: object, task: str) -> str:
    """Return one durable human-readable launch line.

    Callers should supply the purpose-built description. The deterministic
    fallback keeps legacy/direct callers compatible while ensuring every new
    manifest still has a useful description.
    """

    if isinstance(description, str):
        supplied = " ".join(redact_text(description).split())
        if len(supplied) > MAX_AGENT_DESCRIPTION_CHARS:
            raise ValueError(
                f"agent description exceeds {MAX_AGENT_DESCRIPTION_CHARS} characters"
            )
        if supplied:
            return supplied.rstrip(".") + "."
    # Compatibility callers may predate semantic descriptions.  Never turn a
    # truncated raw task into a fake summary; use an explicit generic fallback.
    return "Handle the delegated resident request."


def _request_ref(
    relationship: Mapping[str, Any] | None, key: str
) -> Mapping[str, Any] | None:
    value = relationship.get(key) if isinstance(relationship, Mapping) else None
    return value if isinstance(value, Mapping) else None


def _aggregation_key(
    provenance: Mapping[str, Any],
    *,
    synthesis_group: str | None,
    task_digest: str,
    description: str,
    request_id: str | None,
) -> str:
    current_source = str(
        provenance.get("source_record_id")
        or provenance.get("custody_id")
        or "not-applicable"
    )
    if synthesis_group:
        return stable_identity(
            "resident-synthesis-group",
            provenance.get("resident_conversation_id") or "not-applicable",
            current_source,
            synthesis_group,
        )
    return stable_identity(
        "resident-single-delivery",
        provenance.get("resident_conversation_id") or "not-applicable",
        current_source,
        task_digest,
        description,
        request_id or "",
    )


def _render_query_relationship(relationship: Mapping[str, Any] | None) -> str:
    if not isinstance(relationship, Mapping):
        return ""
    root = _request_ref(relationship, "root_request") or {}
    current = _request_ref(relationship, "current_request") or {}
    earlier = _request_ref(relationship, "earlier_request") or {}
    return (
        "[Query relationship and delivery ownership]\n"
        f"- classification: {relationship.get('classification') or 'independent'}\n"
        f"- root request source/message: {root.get('source_record_id') or 'n/a'} / "
        f"{root.get('discord_message_id') or 'n/a'}\n"
        f"- root semantic description: {root.get('description') or 'unavailable'}\n"
        f"- earlier request source/message: {earlier.get('source_record_id') or 'n/a'} / "
        f"{earlier.get('discord_message_id') or 'n/a'}\n"
        f"- current follow-up source/message: {current.get('source_record_id') or 'n/a'} / "
        f"{current.get('discord_message_id') or 'n/a'}\n"
        f"- current semantic description: {current.get('description') or 'unavailable'}\n"
        "The current/newer request is the sole delivery and aggregation target. Consolidate relevant "
        "earlier work into one reply; internal reviewers report through the synthesis owner and must "
        "not emit independent user-facing completions.\n"
    )


def _delivery_transition_now(fixed_now: datetime | None) -> datetime:
    """Timestamp a state transition, or preserve an injected deterministic clock."""

    return fixed_now or datetime.now(timezone.utc)


def _atomic_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _atomic_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    os.replace(temporary, path)


def _emit_managed_child_event(
    manifest_path: Path,
    manifest: Mapping[str, Any],
    *,
    event_kind: str,
    surface: str,
    evidence: str,
    at: str | None = None,
    details: Mapping[str, Any] | None = None,
) -> None:
    try:
        emit_managed_child_custody_event(
            manifest_path,
            manifest,
            event_kind=event_kind,
            surface=surface,
            evidence=evidence,
            at=at,
            details=details,
        )
    except Exception:
        LOGGER.exception(
            "Managed-child custody event emission failed run_id=%s surface=%s evidence=%s",
            manifest.get("run_id") or manifest_path.parent.name,
            surface,
            evidence,
        )


def _git_revision_without_process(root: Path) -> str | None:
    """Resolve HEAD without spawning git in the latency-sensitive launch path."""

    git_path = root / ".git"
    try:
        if git_path.is_file():
            marker = git_path.read_text(encoding="utf-8").strip()
            if not marker.startswith("gitdir:"):
                return None
            git_dir = Path(marker.split(":", 1)[1].strip())
            if not git_dir.is_absolute():
                git_dir = (root / git_dir).resolve()
        else:
            git_dir = git_path
        head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
        if re.fullmatch(r"[0-9a-fA-F]{40}", head):
            return head.lower()
        if not head.startswith("ref:"):
            return None
        ref = head.split(":", 1)[1].strip()
        candidates = [git_dir / ref]
        commondir_path = git_dir / "commondir"
        if commondir_path.is_file():
            common = Path(commondir_path.read_text(encoding="utf-8").strip())
            if not common.is_absolute():
                common = (git_dir / common).resolve()
            candidates.append(common / ref)
        for candidate in candidates:
            if candidate.is_file():
                revision = candidate.read_text(encoding="utf-8").strip()
                if re.fullmatch(r"[0-9a-fA-F]{40}", revision):
                    return revision.lower()
    except OSError:
        return None
    return None


def _delegated_context_directory(
    *,
    project_root: Path,
    provenance: Mapping[str, Any],
) -> dict[str, Any]:
    runtime_root = Path(__file__).resolve().parents[3]
    conversation_id = (
        str(provenance.get("resident_conversation_id") or "") or None
        if provenance.get("applicability") == "applicable"
        else None
    )
    store_root = str(os.environ.get("MEGAPLAN_RESIDENT_STORE_ROOT") or "").strip() or None
    base = "python -P -m arnold_pipelines.megaplan resident"
    store_arg = ' --store-root "$MEGAPLAN_RESIDENT_STORE_ROOT"' if store_root else ""
    return {
        "project_worktree": str(project_root),
        "resident_runtime_source": str(runtime_root),
        "resident_runtime_revision": _git_revision_without_process(runtime_root),
        "project_equals_runtime_source": project_root == runtime_root,
        "resident_conversation_id": conversation_id,
        "routes": {
            "context_root": f"{base} context --node root{store_arg}",
            "targeted_context": f"{base} context --node '<node_id>'{store_arg}",
            "context_search": (
                f"{base} context-search --scope '<scope>' --query '<query>'{store_arg}"
            ),
            "reply_ancestry": f"{base} read-reply-chain --cursor '<cursor>'{store_arg}",
        },
    }


def _render_delegated_context_directory(directory: Mapping[str, Any]) -> str:
    routes = directory.get("routes") if isinstance(directory.get("routes"), Mapping) else {}
    return (
        "[Delegated context directory]\n"
        "The full resident/cloud/conversation state is deliberately not embedded. Use these bounded "
        "routes only when the task needs more evidence.\n"
        f"- project worktree: {directory.get('project_worktree')}\n"
        f"- resident runtime source: {directory.get('resident_runtime_source')}\n"
        f"- resident runtime revision: {directory.get('resident_runtime_revision') or 'unknown'}\n"
        f"- project is runtime source: {directory.get('project_equals_runtime_source')}\n"
        f"- resident conversation: {directory.get('resident_conversation_id') or 'not applicable'}\n"
        f"- context root: {routes.get('context_root')}\n"
        f"- targeted node: {routes.get('targeted_context')}\n"
        f"- scoped search: {routes.get('context_search')}\n"
        f"- older reply ancestry: {routes.get('reply_ancestry')}\n"
        "The immutable Discord source envelope is inherited in the process environment. Never replace "
        "it with a recent-message guess. The project worktree may differ from the pinned resident runtime; "
        "inspect both before resident-code changes, preserve concurrent dirty work, and publish/deploy only "
        "after explicit tree/revision reconciliation.\n"
    )


def _delivery_prompt(
    task: str,
    timezone_name: str = "UTC",
    *,
    task_kind: DelegatedTaskKind = DEFAULT_DELEGATED_TASK_KIND,
    work_intent: DelegatedWorkIntent = DEFAULT_DELEGATED_WORK_INTENT,
    mutation_claim: DelegatedMutationClaim = "auto",
    context_directory: Mapping[str, Any] | None = None,
    query_relationship: Mapping[str, Any] | None = None,
    contributors: list[Mapping[str, Any]] | None = None,
    git_custody: Mapping[str, Any] | None = None,
) -> str:
    if DELEGATION_DELIVERY_INSTRUCTION_HEADER in task:
        raise ValueError(
            "delegated task contains the reserved resident delivery instruction marker"
        )
    resolved_work_intent = resolve_delegated_work_intent(
        task_kind=task_kind,
        work_intent=work_intent,
    )
    resolved_mutation_claim = resolve_delegated_mutation_claim(
        task_kind=task_kind,
        work_intent=resolved_work_intent,
        mutation_claim=mutation_claim,
    )
    delivery_instruction = _delegation_delivery_instruction(
        resolved_work_intent, resolved_mutation_claim
    )
    prompt = (
        f"{task.rstrip()}\n\n"
        f"{delivery_instruction}\n\n"
        "[Completion delivery contract]\n"
        "[User-time presentation rule]\n"
        f"Render absolute user-visible times in {timezone_name} with local date/time, timezone "
        "abbreviation, and numeric UTC offset. Keep stored/control-plane/evidence timestamps in "
        "UTC and keep relative durations relative.\n\n"
    )
    if context_directory is not None:
        prompt += _render_delegated_context_directory(context_directory) + "\n"
    if resolved_mutation_claim == "git_backed" and git_custody is not None:
        prompt += render_git_custody_contract(git_custody) + "\n"
    relationship_context = _render_query_relationship(query_relationship)
    if relationship_context:
        prompt += relationship_context + "\n"
    if contributors:
        prompt += (
            "[Internal contributor evidence to synthesize]\n"
            + json.dumps(contributors, sort_keys=True)
            + "\nWait for every listed contributor manifest to become terminal, then read and "
            "consolidate its durable result. They are evidence inputs, not independent "
            "user-facing delivery owners.\n\n"
        )
    prompt += f"{FINAL_SUMMARY_INSTRUCTION}\n"
    if len(prompt) > MAX_DELEGATED_PROMPT_CHARS:
        raise ValueError(
            f"delegated prompt exceeds {MAX_DELEGATED_PROMPT_CHARS} characters; "
            "put large evidence in durable files and provide bounded routes"
        )
    return prompt


_RESIDENT_MESSAGE_ID_RE = re.compile(r"^msg_[A-Za-z0-9]{8,64}$")
_RESIDENT_CONVERSATION_ID_RE = re.compile(r"^rconv_[A-Za-z0-9]{8,64}$")


def _is_discord_snowflake(value: object) -> bool:
    text = str(value or "").strip()
    return text.isascii() and text.isdigit() and 0 < len(text) <= 20 and int(text) > 0


def _resolve_resident_message_id(
    value: str,
    *,
    project_root: str | Path | None,
    conversation_id: str | None,
) -> tuple[str, str] | None:
    """Resolve an Arnold message record id to its durable Discord snowflake."""

    if not project_root or not _RESIDENT_MESSAGE_ID_RE.fullmatch(value):
        return None
    record_path = Path(project_root).resolve() / ".megaplan" / "resident" / "messages" / f"{value}.json"
    try:
        record = json.loads(record_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None
    if not isinstance(record, dict) or str(record.get("id") or "") != value:
        return None
    if str(record.get("direction") or "") != "inbound":
        return None
    if conversation_id and str(record.get("conversation_id") or "") != conversation_id:
        return None
    discord_message_id = str(record.get("discord_message_id") or "").strip()
    if not _is_discord_snowflake(discord_message_id):
        return None
    return discord_message_id, value


def _find_resident_source_record_id(
    *,
    project_root: str | Path | None,
    conversation_id: str | None,
    discord_message_id: str,
) -> str | None:
    """Find the one inbound source record matching an immutable Discord id."""

    if not project_root or not conversation_id or not _is_discord_snowflake(discord_message_id):
        return None
    messages_dir = Path(project_root).resolve() / ".megaplan" / "resident" / "messages"
    matches: list[str] = []
    for path in messages_dir.glob("msg_*.json"):
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            continue
        if not isinstance(record, dict):
            continue
        record_id = str(record.get("id") or "")
        if (
            _RESIDENT_MESSAGE_ID_RE.fullmatch(record_id)
            and str(record.get("direction") or "") == "inbound"
            and str(record.get("conversation_id") or "") == conversation_id
            and str(record.get("discord_message_id") or "") == discord_message_id
        ):
            matches.append(record_id)
    return matches[0] if len(matches) == 1 else None


def _discord_origin_from_resident_request(
    request_id: object,
    *,
    project_root: str | Path | None,
) -> dict[str, str | None] | None:
    """Recover safe Discord provenance from an inbound resident message id.

    Message content, author metadata, and idempotency material deliberately do
    not cross into the managed-run manifest.  Only transport routing fields
    needed to reply to the original inbound message are retained.
    """

    resident_message_id = str(request_id or "").strip()
    if not project_root or not _RESIDENT_MESSAGE_ID_RE.fullmatch(resident_message_id):
        return None
    resident_root = Path(project_root).resolve() / ".megaplan" / "resident"
    message_path = resident_root / "messages" / f"{resident_message_id}.json"
    try:
        message = json.loads(message_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None
    if not isinstance(message, dict):
        return None
    conversation_id = str(message.get("conversation_id") or "").strip()
    if (
        str(message.get("id") or "") != resident_message_id
        or str(message.get("direction") or "") != "inbound"
        or not _RESIDENT_CONVERSATION_ID_RE.fullmatch(conversation_id)
    ):
        return None
    discord_message_id = str(message.get("discord_message_id") or "").strip()
    if not _is_discord_snowflake(discord_message_id):
        return None

    conversation_path = resident_root / "resident_conversations" / f"{conversation_id}.json"
    try:
        conversation = json.loads(conversation_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None
    if not isinstance(conversation, dict):
        return None
    conversation_key = str(conversation.get("conversation_key") or "").strip()
    if (
        str(conversation.get("id") or "") != conversation_id
        or str(conversation.get("transport") or "") != "discord"
        or not conversation_key.startswith("discord:")
    ):
        return None

    origin: dict[str, str | None] = {
        "transport": "discord",
        "conversation_id": conversation_id,
        "conversation_key": conversation_key,
        "message_id": discord_message_id,
        "reply_to_message_id": discord_message_id,
        "guild_id": None,
        "channel_id": None,
        "thread_id": None,
        "dm_user_id": None,
        "reply_target_source_record_id": resident_message_id,
    }
    for key in ("guild_id", "channel_id", "thread_id", "dm_user_id"):
        raw = conversation.get(key)
        origin[key] = str(raw) if raw is not None and str(raw) else None
    return origin


def _discord_origin(
    value: Mapping[str, Any] | None,
    *,
    project_root: str | Path | None = None,
) -> dict[str, str | None] | None:
    if not isinstance(value, Mapping) or value.get("transport") != "discord":
        return None
    conversation_key = str(value.get("conversation_key") or "").strip()
    reply_to_message_id = str(
        value.get("reply_to_message_id")
        or value.get("discord_message_id")
        or value.get("message_id")
        or ""
    ).strip()
    if not conversation_key.startswith("discord:") or not reply_to_message_id:
        return None
    conversation_id = str(
        value.get("resident_conversation_id") or value.get("conversation_id") or ""
    ).strip() or None
    source_record_id: str | None = None
    if not _is_discord_snowflake(reply_to_message_id):
        resolved = _resolve_resident_message_id(
            reply_to_message_id,
            project_root=project_root,
            conversation_id=conversation_id,
        )
        if resolved is None:
            return None
        reply_to_message_id, source_record_id = resolved
    allowed = (
        "conversation_id",
        "conversation_key",
        "message_id",
        "reply_to_message_id",
        "guild_id",
        "channel_id",
        "thread_id",
        "dm_user_id",
    )
    origin: dict[str, str | None] = {"transport": "discord"}
    for key in allowed:
        raw = value.get(key)
        origin[key] = str(raw) if raw is not None and str(raw) else None
    origin["conversation_id"] = conversation_id
    origin["conversation_key"] = conversation_key
    origin["reply_to_message_id"] = reply_to_message_id
    message_id = str(
        origin.get("message_id") or value.get("discord_message_id") or ""
    ).strip()
    if _is_discord_snowflake(message_id):
        origin["message_id"] = message_id
    if not _is_discord_snowflake(message_id):
        if source_record_id and message_id == source_record_id:
            origin["message_id"] = reply_to_message_id
        elif message_id:
            resolved_message = _resolve_resident_message_id(
                message_id,
                project_root=project_root,
                conversation_id=conversation_id,
            )
            origin["message_id"] = resolved_message[0] if resolved_message else None
    if source_record_id:
        origin["reply_target_source_record_id"] = source_record_id
    else:
        stored_source = str(
            value.get("source_record_id")
            or value.get("reply_target_source_record_id")
            or ""
        ).strip()
        if _RESIDENT_MESSAGE_ID_RE.fullmatch(stored_source):
            resolved_source = _resolve_resident_message_id(
                stored_source,
                project_root=project_root,
                conversation_id=conversation_id,
            )
            if resolved_source is not None and resolved_source[0] == reply_to_message_id:
                origin["reply_target_source_record_id"] = stored_source
    if not origin.get("reply_target_source_record_id"):
        recovered_source = _find_resident_source_record_id(
            project_root=project_root,
            conversation_id=conversation_id,
            discord_message_id=reply_to_message_id,
        )
        if recovered_source:
            origin["reply_target_source_record_id"] = recovered_source
    return origin


def _standalone_schedule_discord_target(
    schedule_context: Mapping[str, Any] | None,
    provenance: Mapping[str, Any],
) -> dict[str, str] | None:
    """Resolve a schedule-owned plain DM without manufacturing reply custody."""

    if not isinstance(schedule_context, Mapping):
        return None
    delivery = schedule_context.get("delivery")
    if not isinstance(delivery, Mapping):
        return None
    if delivery.get("mode") != "standalone":
        return None
    route = str(delivery.get("route_ref") or "").strip()
    if not route.startswith("discord:dm:") or not route.removeprefix("discord:dm:").strip():
        raise DelegationProvenanceError(
            "standalone schedule delivery requires a valid Discord DM route"
        )
    if provenance.get("applicability") != "not_applicable":
        raise DelegationProvenanceError(
            "standalone schedule delivery requires explicitly not_applicable launch origin"
        )
    return {"transport": "discord", "conversation_key": route, "mode": "standalone"}


def _canonical_launch_provenance(
    value: Mapping[str, Any] | None,
    *,
    project_root: Path,
    request_id: str | None,
) -> dict[str, Any]:
    """Resolve every launch to one Discord envelope or explicit N/A custody."""

    inherited = provenance_from_environment(strict=True)
    candidate: Mapping[str, Any] | None = value
    if candidate is None:
        candidate = inherited
    elif inherited is not None and inherited.get("applicability") == "applicable":
        if candidate.get("applicability") == "not_applicable" or candidate.get("transport") in {
            "non_discord",
            "not_applicable",
        }:
            raise DelegationProvenanceError(
                "a Discord-origin child launch cannot discard inherited custody"
            )
        candidate = {**inherited, **dict(candidate)}
    if candidate is not None and candidate.get("applicability") == "ambiguous":
        raise DelegationProvenanceError("Discord launch provenance is ambiguous")
    if candidate is not None and (
        candidate.get("transport") == "discord" or candidate.get("applicability") == "applicable"
    ):
        origin = _discord_origin(candidate, project_root=project_root)
        if origin is None:
            raise DelegationProvenanceError(
                "Discord launch provenance requires one exact, resolvable reply target"
            )
        merged = {**dict(candidate), **origin}
        merged["resident_conversation_id"] = origin.get("conversation_id")
        merged["source_record_id"] = (
            origin.get("reply_target_source_record_id")
            or candidate.get("source_record_id")
            or candidate.get("reply_target_source_record_id")
        )
        merged["discord_message_id"] = origin.get("message_id")
        source_record_id = str(merged.get("source_record_id") or "")
        file_messages_dir = project_root / ".megaplan" / "resident" / "messages"
        if _RESIDENT_MESSAGE_ID_RE.fullmatch(source_record_id) and file_messages_dir.exists():
            resolved_source = _resolve_resident_message_id(
                source_record_id,
                project_root=project_root,
                conversation_id=str(origin.get("conversation_id") or "") or None,
            )
            if resolved_source is None or resolved_source[0] != origin.get("message_id"):
                raise DelegationProvenanceError(
                    "source_record_id does not match the original Discord message"
                )
        normalized = normalize_delegation_provenance(merged)
        if inherited is not None and inherited.get("applicability") == "applicable":
            for field in (
                "correlation_id",
                "custody_id",
                "resident_conversation_id",
                "source_record_id",
                "conversation_key",
                "discord_message_id",
                "reply_to_message_id",
                "guild_id",
                "channel_id",
                "thread_id",
                "dm_user_id",
            ):
                if normalized.get(field) != inherited.get(field):
                    raise DelegationProvenanceError(
                        f"child launch {field} conflicts with inherited Discord custody"
                    )
        return normalized
    if candidate is not None:
        # A resident message record is positive evidence of Discord origin.  It
        # must never be reclassified as not_applicable merely because a caller
        # supplied an explicit non-Discord envelope or because recovery failed.
        # VP todo ids use a different shape, preserving scheduled-launch
        # compatibility while making stale/malformed Discord custody fail closed.
        if _RESIDENT_MESSAGE_ID_RE.fullmatch(str(request_id or "")):
            recovered = _discord_origin_from_resident_request(
                request_id, project_root=project_root
            )
            if recovered is None:
                raise DelegationProvenanceError(
                    "Discord-origin request_id cannot be bound to durable custody"
                )
            return normalize_delegation_provenance(
                {
                    **recovered,
                    "applicability": "applicable",
                    "resident_conversation_id": recovered["conversation_id"],
                    "source_record_id": recovered["reply_target_source_record_id"],
                    "discord_message_id": recovered["message_id"],
                    "source_kind": "resident_request_recovery",
                }
            )
        return normalize_delegation_provenance(candidate)

    recovered = _discord_origin_from_resident_request(request_id, project_root=project_root)
    if recovered is not None:
        return normalize_delegation_provenance(
            {
                **recovered,
                "applicability": "applicable",
                "resident_conversation_id": recovered["conversation_id"],
                "source_record_id": recovered["reply_target_source_record_id"],
                "discord_message_id": recovered["message_id"],
                "source_kind": "resident_request_recovery",
            }
        )
    if _RESIDENT_MESSAGE_ID_RE.fullmatch(str(request_id or "")):
        raise DelegationProvenanceError(
            "Discord-origin request_id cannot be bound to durable custody"
        )
    return normalize_delegation_provenance(
        {
            "transport": "non_discord",
            "applicability": "not_applicable",
            "source_kind": "explicit_non_discord",
        }
    )


def _result_from_manifest(manifest_path: Path, payload: Mapping[str, Any]) -> SubagentResult:
    status = str(payload.get("status") or "unknown")
    delivery = managed_child_delivery_projection(payload)
    return SubagentResult(
        ok=status not in {"failed", "interrupted"},
        final_text="",
        stderr="",
        returncode=int(payload.get("returncode") or 0),
        run_id=str(payload.get("run_id") or manifest_path.parent.name),
        status=status,
        manifest_path=str(manifest_path),
        log_path=str(payload.get("log_path") or manifest_path.parent / "run.log"),
        result_path=str(payload.get("result_path") or manifest_path.parent / "result.md"),
        custody_evidence_path=str(payload.get("custody_evidence_path") or "") or None,
        delivery_owner_run_id=delivery.get("delivery_owner_run_id"),
        parent_owned_delivery=bool(delivery.get("parent_owned_delivery")),
        pid=payload.get("pid") if isinstance(payload.get("pid"), int) else None,
        description=str(payload.get("description") or "") or None,
    )


def _manifest_matches_operation(path: Path, operation_id: str) -> bool:
    """Read-only lookup used only to recover an admitted resident operation."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError):
        return False
    return isinstance(payload, Mapping) and str(payload.get("operation_id") or "") == operation_id


def _queued_manifest_replay(root: Path, launch_key: str) -> tuple[Path, dict[str, Any]] | None:
    """Recover a queued delivery projection before a physical door exists.

    Queued successors have no OperationRun yet and therefore cannot be
    replayed through the launch engine.  This lookup is limited to queued
    records; supervisor admission and every physical spawn still use the
    canonical operation store below.
    """

    for path in root.glob("*/manifest.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, TypeError, ValueError):
            continue
        if (
            isinstance(payload, Mapping)
            and payload.get("launch_idempotency_key") == launch_key
        ):
            return path, dict(payload)
    return None


def _manifest_aggregation_key(payload: Mapping[str, Any]) -> str | None:
    aggregation = payload.get("aggregation")
    if isinstance(aggregation, Mapping) and aggregation.get("key"):
        return str(aggregation["key"])
    # Legacy manifests did not declare an explicit synthesis group.  Never
    # retroactively collapse them merely because they share a request root.
    return None


def _transfer_aggregation_delivery_ownership(
    root: Path,
    *,
    aggregation_key: str,
    new_owner_run_id: str,
    at: str,
) -> None:
    """Make one newest run the synthesis/delivery owner for a logical query."""

    for path in root.glob("*/manifest.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, TypeError, ValueError):
            continue
        if not isinstance(payload, dict) or not _is_managed_manifest(payload):
            continue
        if _manifest_aggregation_key(payload) != aggregation_key:
            continue
        prior_run_id = str(payload.get("run_id") or path.parent.name)
        aggregation = dict(payload.get("aggregation") or {})
        aggregation.update(
            {
                "schema_version": AGGREGATION_SCHEMA,
                "key": aggregation_key,
                "role": "internal_contributor",
                "delivery_owner_run_id": new_owner_run_id,
                "superseded_at": at,
            }
        )
        payload["aggregation"] = aggregation
        delivery = payload.get("completion_delivery")
        execution_contract = payload.get("execution_contract")
        delivers_independently = (
            isinstance(execution_contract, Mapping)
            and execution_contract.get("delivery_policy") == "deliver_independently"
        )
        if isinstance(delivery, dict) and delivery.get("status") not in {
            "delivered",
            "failed",
            "not_applicable",
            "superseded",
            "suppressed",
            "unknown",
        } and not delivers_independently:
            delivery.update(
                {
                    "status": "superseded",
                    "superseded_at": at,
                    "superseded_by_run_id": new_owner_run_id,
                    "superseded_reason": "new_synthesis_delivery_owner_for_logical_request",
                    "updated_at": at,
                }
            )
            history = list(delivery.get("state_history") or [])
            history.append(
                {
                    "status": "superseded",
                    "at": at,
                    "evidence": "single_logical_request_delivery_owner_transferred",
                    "delivery_owner_run_id": new_owner_run_id,
                }
            )
            delivery["state_history"] = history[-20:]
            payload["completion_delivery"] = delivery
        _atomic_json(path, payload)
        _emit_managed_child_event(
            path,
            payload,
            event_kind="delivery_custody",
            surface="resident.subagent.aggregation",
            evidence="single_logical_request_delivery_owner_transferred",
            at=at,
            details={
                "prior_run_id": prior_run_id,
                "new_owner_run_id": new_owner_run_id,
                "delivery_projection": managed_child_delivery_projection(payload),
            },
        )


def _aggregation_contributor_refs(
    root: Path, *, aggregation_key: str
) -> list[dict[str, Any]]:
    """Return bounded durable inputs that the synthesis owner must consume."""

    contributors: list[dict[str, Any]] = []
    for path in sorted(root.glob("*/manifest.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, TypeError, ValueError):
            continue
        if (
            not isinstance(payload, dict)
            or not _is_managed_manifest(payload)
            or _manifest_aggregation_key(payload) != aggregation_key
        ):
            continue
        result_path = Path(str(payload.get("result_path") or "result.md"))
        if not result_path.is_absolute():
            result_path = path.parent / result_path
        contributors.append(
            {
                "run_id": str(payload.get("run_id") or path.parent.name),
                "description": str(payload.get("description") or ""),
                "status": str(payload.get("status") or "unknown"),
                "aggregation_role": str(
                    (payload.get("aggregation") or {}).get("role") or "unknown"
                ),
                "delivery_status": str(
                    (payload.get("completion_delivery") or {}).get("status")
                    or "not_applicable"
                ),
                "manifest_path": str(path.resolve()),
                "result_path": str(result_path.resolve()),
            }
        )
    return contributors[-20:]


def _read_managed_resident_manifest(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        raise SubagentFollowupError(f"cannot read managed run manifest: {path}") from exc
    if not isinstance(payload, dict) or not _is_managed_manifest(payload):
        raise SubagentFollowupError(f"target is not a resident-managed agent run: {path}")
    run_id = str(payload.get("run_id") or path.parent.name)
    if run_id != path.parent.name:
        raise SubagentFollowupError("managed run manifest identity does not match its directory")
    return payload


def _queue_artifact_path(
    manifest_path: Path,
    manifest: Mapping[str, Any],
    field: str,
    fallback: str,
) -> Path:
    raw = Path(str(manifest.get(field) or fallback))
    resolved = raw.resolve() if raw.is_absolute() else (manifest_path.parent / raw).resolve()
    try:
        resolved.relative_to(manifest_path.parent.resolve())
    except ValueError as exc:
        raise SubagentQueueError(
            f"predecessor {field} escapes its managed run directory"
        ) from exc
    if len(str(resolved)) > 4096:
        raise SubagentQueueError(f"predecessor {field} reference is too long")
    return resolved


def _queue_predecessor_references(
    manifest_path: Path, manifest: Mapping[str, Any]
) -> list[dict[str, Any]]:
    """Return typed, path-only predecessor references; never inline artifact bytes."""

    run_id = str(manifest.get("run_id") or manifest_path.parent.name)
    refs = []
    for artifact_type, field, fallback in (
        ("manifest", "manifest_path", "manifest.json"),
        ("result", "result_path", "result.md"),
        ("log", "full_log_path", str(manifest.get("log_path") or "run.log")),
    ):
        path = _queue_artifact_path(manifest_path, manifest, field, fallback)
        refs.append(
            {
                "schema_version": QUEUE_REFERENCE_SCHEMA,
                "run_id": run_id,
                "artifact_type": artifact_type,
                "path": str(path),
                "content_inlined": False,
            }
        )
    return refs


def _render_queue_references(
    *, predecessor_run_ids: Sequence[str], references: list[dict[str, Any]]
) -> str:
    lines = [
        "[Queued predecessor references — bounded typed refs only]",
        f"- schema: {QUEUE_REFERENCE_SCHEMA}",
        f"- predecessor_run_ids: {json.dumps(list(predecessor_run_ids))}",
        "- instruction: inspect only the artifacts needed for the authored prompt; full content is not embedded",
    ]
    for ref in references:
        lines.append(f"- {ref['artifact_type']}: {ref['path']}")
    return "\n".join(lines)


def _normalize_dependency_run_ids(
    *,
    depends_on_run_id: str | None,
    depends_on_run_ids: Sequence[str] | None,
) -> tuple[str, ...]:
    """Normalize the public singular/plural contract without silently merging it."""

    if depends_on_run_id is not None and depends_on_run_ids is not None:
        raise SubagentQueueError(
            "depends_on_run_id and depends_on_run_ids are mutually exclusive"
        )
    if depends_on_run_ids is None:
        raw: list[object] = [] if depends_on_run_id is None else [depends_on_run_id]
    else:
        if isinstance(depends_on_run_ids, (str, bytes)) or not isinstance(
            depends_on_run_ids, Sequence
        ):
            raise SubagentQueueError("depends_on_run_ids must be a list of run IDs")
        raw = list(depends_on_run_ids)
        if not raw:
            raise SubagentQueueError("depends_on_run_ids must not be empty")
    if len(raw) > MAX_QUEUE_PREDECESSORS:
        raise SubagentQueueError(
            f"depends_on_run_ids exceeds the maximum of {MAX_QUEUE_PREDECESSORS}"
        )
    normalized: list[str] = []
    for value in raw:
        if not isinstance(value, str) or not _RUN_ID_RE.fullmatch(value):
            raise SubagentQueueError("predecessor run_id is malformed")
        if value in normalized:
            raise SubagentQueueError(f"duplicate predecessor run_id: {value}")
        normalized.append(value)
    return tuple(normalized)


def _queue_predecessor_run_ids(queue: Mapping[str, Any]) -> tuple[str, ...]:
    """Read a committed dependency set, accepting legacy singular manifests."""

    singular = queue.get("predecessor_run_id")
    plural = queue.get("predecessor_run_ids")
    if plural is None:
        if not isinstance(singular, str) or not _RUN_ID_RE.fullmatch(singular):
            raise SubagentQueueError("queued predecessor run_id is malformed")
        return (singular,)
    if isinstance(plural, (str, bytes)) or not isinstance(plural, list) or not plural:
        raise SubagentQueueError("queued predecessor_run_ids must be a nonempty list")
    if len(plural) > MAX_QUEUE_PREDECESSORS:
        raise SubagentQueueError(
            f"queued predecessor set exceeds {MAX_QUEUE_PREDECESSORS}"
        )
    values: list[str] = []
    for value in plural:
        if not isinstance(value, str) or not _RUN_ID_RE.fullmatch(value):
            raise SubagentQueueError("queued predecessor run_id is malformed")
        if value in values:
            raise SubagentQueueError(f"duplicate queued predecessor run_id: {value}")
        values.append(value)
    if singular is not None and (len(values) != 1 or singular != values[0]):
        raise SubagentQueueError(
            "queued singular/plural predecessor fields are inconsistent"
        )
    return tuple(values)


def _queue_waiting_labels(predecessor_run_ids: Sequence[str]) -> tuple[str, str]:
    if len(predecessor_run_ids) == 1:
        return "waiting_predecessor", "waiting_for_predecessor"
    return "waiting_predecessors", "waiting_for_predecessors"


def _queue_provenance_identity(value: Mapping[str, Any]) -> tuple[object, ...]:
    return tuple(
        value.get(field)
        for field in (
            "applicability",
            "transport",
            "correlation_id",
            "custody_id",
            "resident_conversation_id",
            "source_record_id",
            "conversation_key",
            "discord_message_id",
            "reply_to_message_id",
            "guild_id",
            "channel_id",
            "thread_id",
            "dm_user_id",
        )
    )


def _queue_mapping_digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(dict(value), sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _queue_store_root(project_root: Path) -> Path:
    configured = str(os.environ.get("MEGAPLAN_RESIDENT_STORE_ROOT") or "").strip()
    return (
        Path(configured).resolve()
        if configured
        else project_root / ".megaplan" / "resident"
    )


def _authoritative_queue_request(
    project_root: Path, provenance: Mapping[str, Any]
) -> dict[str, str]:
    """Resolve one Discord envelope against its immutable inbound record."""

    normalized = normalize_delegation_provenance(provenance)
    if normalized.get("applicability") != "applicable":
        raise SubagentQueueError(
            "cross-request queue authorization requires Discord provenance"
        )
    source_record_id = str(normalized.get("source_record_id") or "")
    conversation_id = str(normalized.get("resident_conversation_id") or "")
    if not _RESIDENT_MESSAGE_ID_RE.fullmatch(source_record_id):
        raise SubagentQueueError(
            "cross-request queue authorization source record is malformed"
        )
    store_root = _queue_store_root(project_root)
    message_path = store_root / "messages" / f"{source_record_id}.json"
    try:
        raw = message_path.read_bytes()
        message = json.loads(raw)
    except (OSError, TypeError, ValueError) as exc:
        raise SubagentQueueError(
            "cross-request queue authorization source record is unavailable"
        ) from exc
    reply = message.get("discord_reply_provenance") if isinstance(message, dict) else None
    scope = reply.get("scope") if isinstance(reply, Mapping) else None
    author_id = str(reply.get("source_author_id") or "") if isinstance(reply, Mapping) else ""
    if (
        not isinstance(message, dict)
        or message.get("id") != source_record_id
        or message.get("direction") != "inbound"
        or message.get("conversation_id") != conversation_id
        or str(message.get("discord_message_id") or "")
        != str(normalized.get("discord_message_id") or "")
        or not isinstance(reply, Mapping)
        or reply.get("transport") != "discord"
        or str(reply.get("source_message_id") or "")
        != str(normalized.get("discord_message_id") or "")
        or str(reply.get("conversation_key") or "")
        != str(normalized.get("conversation_key") or "")
        or not _is_discord_snowflake(author_id)
        or not isinstance(scope, Mapping)
        or str(scope.get("channel_id") or "")
        != str(normalized.get("channel_id") or "")
        or str(scope.get("dm_user_id") or "")
        != str(normalized.get("dm_user_id") or "")
    ):
        raise SubagentQueueError(
            "cross-request queue authorization source record conflicts with provenance"
        )
    conversation_path = store_root / "resident_conversations" / f"{conversation_id}.json"
    try:
        conversation = json.loads(conversation_path.read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError) as exc:
        raise SubagentQueueError(
            "cross-request queue authorization conversation is unavailable"
        ) from exc
    if (
        not isinstance(conversation, dict)
        or conversation.get("id") != conversation_id
        or conversation.get("transport") != "discord"
        or conversation.get("conversation_key") != normalized.get("conversation_key")
    ):
        raise SubagentQueueError(
            "cross-request queue authorization conversation conflicts with provenance"
        )
    return {
        "source_record_id": source_record_id,
        "record_sha256": hashlib.sha256(raw).hexdigest(),
        "subject_sha256": hashlib.sha256(
            f"discord-subject\0{author_id}".encode("utf-8")
        ).hexdigest(),
    }


def _cross_request_queue_authorization(
    root: Path,
    *,
    project_root: Path,
    predecessor_run_id: str,
    predecessor: Mapping[str, Any],
    current_provenance: Mapping[str, Any],
    require_active_caller: bool,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Bind one exact dependency to a later same-subject request, fail closed."""

    predecessor_provenance = predecessor.get("launch_provenance")
    if not isinstance(predecessor_provenance, Mapping):
        raise SubagentQueueError("predecessor lacks immutable launch provenance")
    predecessor_provenance = normalize_delegation_provenance(predecessor_provenance)
    if (
        predecessor_provenance.get("applicability") != "applicable"
        or current_provenance.get("applicability") != "applicable"
    ):
        raise SubagentQueueError(
            "cross-request queue authorization requires two Discord envelopes"
        )
    if predecessor_provenance.get("resident_conversation_id") != current_provenance.get(
        "resident_conversation_id"
    ):
        raise SubagentQueueError(
            "cross-request queue authorization changed resident conversation"
        )
    current_request = _authoritative_queue_request(project_root, current_provenance)
    predecessor_request = _authoritative_queue_request(
        project_root, predecessor_provenance
    )
    if current_request["subject_sha256"] != predecessor_request["subject_sha256"]:
        raise SubagentQueueError(
            "cross-request queue authorization changed Discord subject"
        )

    caller_run_id = str(current_provenance.get("root_run_id") or "")
    if not _RUN_ID_RE.fullmatch(caller_run_id):
        return _resident_turn_queue_authorization(
            project_root=project_root,
            predecessor_run_id=predecessor_run_id,
            predecessor=predecessor,
            predecessor_provenance=predecessor_provenance,
            current_provenance=current_provenance,
            current_request=current_request,
            predecessor_request=predecessor_request,
            require_active_caller=require_active_caller,
        )
    caller_path = root / caller_run_id / "manifest.json"
    try:
        caller = _read_managed_resident_manifest(caller_path)
    except SubagentFollowupError as exc:
        raise SubagentQueueError(
            "cross-request queue authorization caller manifest is unavailable"
        ) from exc
    if require_active_caller and str(caller.get("status") or "") not in {
        "launching",
        "running",
    }:
        raise SubagentQueueError(
            "cross-request queue authorization caller is not active"
        )
    caller_provenance = caller.get("launch_provenance")
    if (
        not isinstance(caller_provenance, Mapping)
        or _queue_provenance_identity(
            normalize_delegation_provenance(caller_provenance)
        )
        != _queue_provenance_identity(current_provenance)
        or Path(str(caller.get("project_dir") or "")).resolve() != project_root
    ):
        raise SubagentQueueError(
            "cross-request queue authorization caller does not own current custody"
        )
    if caller.get("work_intent") != predecessor.get("work_intent"):
        raise SubagentQueueError(
            "cross-request queue authorization cannot broaden work intent"
        )
    prompt_path = Path(str(caller.get("prompt_path") or ""))
    if prompt_path.parent.resolve() != caller_path.parent.resolve():
        raise SubagentQueueError(
            "cross-request queue authorization caller prompt path is invalid"
        )
    try:
        caller_prompt = prompt_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SubagentQueueError(
            "cross-request queue authorization caller prompt is unavailable"
        ) from exc
    caller_prompt_sha256 = hashlib.sha256(caller_prompt.encode("utf-8")).hexdigest()
    if (
        caller_prompt_sha256 != caller.get("prompt_sha256")
        or re.search(
            rf"(?<![A-Za-z0-9]){re.escape(predecessor_run_id)}(?![A-Za-z0-9])",
            caller_prompt,
        )
        is None
    ):
        raise SubagentQueueError(
            "cross-request queue authorization does not explicitly name predecessor"
        )

    relationship = caller.get("query_relationship")
    current_source = str(current_provenance.get("source_record_id") or "")
    if not isinstance(relationship, Mapping):
        raise SubagentQueueError(
            "cross-request queue authorization lacks current query relationship"
        )
    for field in ("current_request", "delivery_owner", "aggregation_owner"):
        ref = relationship.get(field)
        if not isinstance(ref, Mapping) or ref.get("source_record_id") != current_source:
            raise SubagentQueueError(
                "cross-request queue authorization changed current delivery ownership"
            )
    if relationship.get("conversation_id") != current_provenance.get(
        "resident_conversation_id"
    ):
        raise SubagentQueueError(
            "cross-request queue authorization relationship changed conversation"
        )
    aggregation = caller.get("aggregation")
    delivery = caller.get("completion_delivery")
    reply_target = delivery.get("reply_target") if isinstance(delivery, Mapping) else None
    if (
        not isinstance(aggregation, Mapping)
        or aggregation.get("role") != "internal_contributor"
        or not aggregation.get("key")
        or not aggregation.get("synthesis_group")
        or aggregation.get("delivery_target_source_record_id") != current_source
        or not isinstance(delivery, Mapping)
        or delivery.get("status") not in {"suppressed", "superseded"}
        or not isinstance(reply_target, Mapping)
        or reply_target.get("source_record_id") != current_source
    ):
        raise SubagentQueueError(
            "cross-request queue authorization lacks conflict-free aggregation custody"
        )

    authorization = {
        "schema_version": QUEUE_CROSS_REQUEST_AUTHORIZATION_SCHEMA,
        "mode": "same_subject_same_conversation_explicit_predecessor",
        "predecessor_run_id": predecessor_run_id,
        "resident_conversation_id": current_provenance.get(
            "resident_conversation_id"
        ),
        "subject_sha256": current_request["subject_sha256"],
        "current_source_record_id": current_source,
        "current_source_record_sha256": current_request["record_sha256"],
        "predecessor_source_record_id": predecessor_request["source_record_id"],
        "predecessor_source_record_sha256": predecessor_request["record_sha256"],
        "caller_run_id": caller_run_id,
        "caller_task_sha256": caller.get("task_sha256"),
        "caller_prompt_sha256": caller_prompt_sha256,
        "caller_provenance_sha256": _queue_mapping_digest(current_provenance),
        "predecessor_provenance_sha256": _queue_mapping_digest(
            predecessor_provenance
        ),
        "query_relationship_sha256": _queue_mapping_digest(relationship),
        "aggregation_key": aggregation.get("key"),
        "synthesis_group": aggregation.get("synthesis_group"),
        "delivery_target_source_record_id": current_source,
    }
    return authorization, dict(aggregation), dict(relationship)


def _resident_turn_queue_authorization(
    *,
    project_root: Path,
    predecessor_run_id: str,
    predecessor: Mapping[str, Any],
    predecessor_provenance: Mapping[str, Any],
    current_provenance: Mapping[str, Any],
    current_request: Mapping[str, str],
    predecessor_request: Mapping[str, str],
    require_active_caller: bool,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Authorize a cross-request queue from its durable resident root turn.

    Root Discord turns are not managed subagents and therefore never have a
    ``root_run_id``.  Their immutable launch envelope does carry the resident
    turn id committed before tool execution.  Validate that turn and its exact
    inbound message rather than requiring an impossible subagent manifest.
    """

    turn_id = str(current_provenance.get("resident_turn_id") or "")
    if not _RESIDENT_TURN_ID_RE.fullmatch(turn_id):
        raise SubagentQueueError(
            "cross-request queue authorization lacks immutable caller root_run_id "
            "or resident_turn_id"
        )
    store_root = _queue_store_root(project_root)
    turn_path = store_root / "turns" / f"{turn_id}.json"
    try:
        turn_raw = turn_path.read_bytes()
        turn = json.loads(turn_raw)
    except (OSError, TypeError, ValueError) as exc:
        raise SubagentQueueError(
            "cross-request queue authorization caller turn is unavailable"
        ) from exc
    current_source = str(current_provenance.get("source_record_id") or "")
    triggered = turn.get("triggered_by_message_ids") if isinstance(turn, Mapping) else None
    if (
        not isinstance(turn, Mapping)
        or turn.get("id") != turn_id
        or not isinstance(triggered, list)
        or triggered != [current_source]
    ):
        raise SubagentQueueError(
            "cross-request queue authorization caller turn does not own current custody"
        )
    if require_active_caller and str(turn.get("status") or "") not in {
        "in_progress",
        "running",
    }:
        raise SubagentQueueError(
            "cross-request queue authorization caller turn is not active"
        )

    message_path = store_root / "messages" / f"{current_source}.json"
    try:
        message = json.loads(message_path.read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError) as exc:
        raise SubagentQueueError(
            "cross-request queue authorization source record is unavailable"
        ) from exc
    reply = message.get("discord_reply_provenance") if isinstance(message, Mapping) else None
    ancestors = reply.get("ancestors") if isinstance(reply, Mapping) else None
    reference_text = "\n".join(
        [str(message.get("content") or "")]
        + [
            str(row.get("content") or "")
            for row in (ancestors or [])
            if isinstance(row, Mapping) and row.get("status") == "available"
        ]
    )
    if re.search(
        rf"(?<![A-Za-z0-9]){re.escape(predecessor_run_id)}(?![A-Za-z0-9])",
        reference_text,
    ) is None:
        raise SubagentQueueError(
            "cross-request queue authorization does not explicitly name predecessor"
        )

    relationship = relationship_from_environment_or_project(
        current_source, project_root=project_root
    )
    if not isinstance(relationship, Mapping):
        raise SubagentQueueError(
            "cross-request queue authorization lacks current query relationship"
        )
    for field in ("current_request", "delivery_owner", "aggregation_owner"):
        ref = relationship.get(field)
        if not isinstance(ref, Mapping) or ref.get("source_record_id") != current_source:
            raise SubagentQueueError(
                "cross-request queue authorization changed current delivery ownership"
            )
    if relationship.get("conversation_id") != current_provenance.get(
        "resident_conversation_id"
    ):
        raise SubagentQueueError(
            "cross-request queue authorization relationship changed conversation"
        )
    if predecessor.get("work_intent") not in DELEGATED_WORK_INTENTS:
        raise SubagentQueueError(
            "cross-request queue authorization predecessor work intent is invalid"
        )

    aggregation_key = stable_identity(
        "resident-root-turn-successor", current_source, predecessor_run_id
    )
    synthesis_group = stable_identity(
        "resident-root-turn-synthesis", turn_id, predecessor_run_id
    )
    aggregation = {
        "schema_version": AGGREGATION_SCHEMA,
        "key": aggregation_key,
        "synthesis_group": synthesis_group,
        "role": "internal_contributor",
        "delivery_owner_run_id": None,
        "delivery_target_source_record_id": current_source,
        "contributors": [],
    }
    turn_authority = {
        "id": turn.get("id"),
        "triggered_by_message_ids": list(triggered),
        "prompt_snapshot": turn.get("prompt_snapshot"),
        "started_at": turn.get("started_at"),
    }
    authorization = {
        "schema_version": QUEUE_CROSS_REQUEST_AUTHORIZATION_SCHEMA,
        "mode": "same_subject_same_conversation_explicit_predecessor",
        "authorization_source": "resident_root_turn",
        "predecessor_run_id": predecessor_run_id,
        "resident_conversation_id": current_provenance.get(
            "resident_conversation_id"
        ),
        "subject_sha256": current_request["subject_sha256"],
        "current_source_record_id": current_source,
        "current_source_record_sha256": current_request["record_sha256"],
        "predecessor_source_record_id": predecessor_request["source_record_id"],
        "predecessor_source_record_sha256": predecessor_request["record_sha256"],
        "caller_turn_id": turn_id,
        "caller_turn_authority_sha256": _queue_mapping_digest(turn_authority),
        "caller_provenance_sha256": _queue_mapping_digest(current_provenance),
        "predecessor_provenance_sha256": _queue_mapping_digest(
            predecessor_provenance
        ),
        "query_relationship_sha256": _queue_mapping_digest(relationship),
        "aggregation_key": aggregation_key,
        "synthesis_group": synthesis_group,
        "delivery_target_source_record_id": current_source,
    }
    return authorization, aggregation, dict(relationship)


def _queue_has_conflicting_delivered_owner(
    root: Path, *, aggregation_key: str, successor_run_id: str
) -> bool:
    for path in root.glob("*/manifest.json"):
        try:
            row = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, TypeError, ValueError):
            continue
        if str(row.get("run_id") or path.parent.name) == successor_run_id:
            continue
        if _manifest_aggregation_key(row) != aggregation_key:
            continue
        aggregation = row.get("aggregation")
        delivery = row.get("completion_delivery")
        if (
            isinstance(aggregation, Mapping)
            and aggregation.get("role") == "synthesis_delivery_owner"
            and isinstance(delivery, Mapping)
            and delivery.get("status") == "delivered"
        ):
            return True
    return False


def _queue_ancestor_ids(
    root: Path, predecessor_run_ids: str | Sequence[str]
) -> list[str]:
    """Walk a dependency DAG and fail closed on cycles, depth, or breadth."""

    roots = (
        (predecessor_run_ids,)
        if isinstance(predecessor_run_ids, str)
        else tuple(predecessor_run_ids)
    )
    ancestors: list[str] = []
    visited: set[str] = set()
    active: set[str] = set()

    def visit(run_id: str, depth: int) -> None:
        if run_id in active:
            raise SubagentQueueError(f"queued dependency cycle detected at {run_id}")
        if run_id in visited:
            return
        if depth > MAX_QUEUE_CHAIN_DEPTH:
            raise SubagentQueueError(
                f"queued dependency depth exceeds {MAX_QUEUE_CHAIN_DEPTH}"
            )
        if len(ancestors) >= MAX_QUEUE_ANCESTOR_RUNS:
            raise SubagentQueueError(
                f"queued dependency ancestry exceeds {MAX_QUEUE_ANCESTOR_RUNS} runs"
            )
        active.add(run_id)
        visited.add(run_id)
        ancestors.append(run_id)
        path = root / run_id / "manifest.json"
        if not path.is_file():
            raise SubagentQueueError(f"queued predecessor manifest is missing: {run_id}")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, TypeError, ValueError) as exc:
            raise SubagentQueueError(
                f"queued predecessor manifest is unreadable: {run_id}"
            ) from exc
        queue = payload.get("queue")
        if isinstance(queue, Mapping):
            for dependency_run_id in _queue_predecessor_run_ids(queue):
                visit(dependency_run_id, depth + 1)
        active.remove(run_id)

    for predecessor_run_id in roots:
        visit(predecessor_run_id, 1)
    return ancestors


def _validate_queue_authorization(
    predecessor: Mapping[str, Any],
    successor: Mapping[str, Any],
    *,
    predecessor_run_id: str,
    manifest_path: Path,
) -> None:
    predecessor_provenance = predecessor.get("launch_provenance")
    successor_provenance = successor.get("launch_provenance")
    if not isinstance(predecessor_provenance, Mapping) or not isinstance(
        successor_provenance, Mapping
    ):
        raise SubagentQueueError("queued dependency lacks immutable launch provenance")
    same_request = _queue_provenance_identity(
        predecessor_provenance
    ) == _queue_provenance_identity(successor_provenance)
    for field in ("project_dir", "work_intent"):
        if predecessor.get(field) != successor.get(field):
            raise SubagentQueueError(
                f"queued successor cannot broaden predecessor {field} authorization"
            )
    predecessor_mutation = str(
        predecessor.get("mutation_claim")
        or resolve_delegated_mutation_claim(
            task_kind=str(predecessor.get("task_kind") or DEFAULT_DELEGATED_TASK_KIND),
            work_intent=str(predecessor.get("work_intent") or "execution"),
        )
    )
    successor_mutation = str(
        successor.get("mutation_claim")
        or resolve_delegated_mutation_claim(
            task_kind=str(successor.get("task_kind") or DEFAULT_DELEGATED_TASK_KIND),
            work_intent=str(successor.get("work_intent") or "execution"),
        )
    )
    if predecessor_mutation != successor_mutation:
        raise SubagentQueueError(
            "queued successor cannot broaden predecessor mutation_claim authorization"
        )
    predecessor_aggregation = predecessor.get("aggregation")
    successor_aggregation = successor.get("aggregation")
    if not isinstance(predecessor_aggregation, Mapping) or not isinstance(
        successor_aggregation, Mapping
    ):
        raise SubagentQueueError("queued dependency lacks aggregation custody")
    if same_request:
        if predecessor_aggregation.get("key") != successor_aggregation.get("key"):
            raise SubagentQueueError("queued successor changed logical delivery ownership")
        if successor_aggregation.get("role") not in AGGREGATION_ROLES:
            raise SubagentQueueError("queued successor has invalid aggregation role")
        return
    if successor_aggregation.get("role") != "synthesis_delivery_owner":
        raise SubagentQueueError(
            "cross-request queued successor must be the sole synthesis delivery owner"
        )
    queue = successor.get("queue")
    authorizations = (
        queue.get("cross_request_authorizations")
        if isinstance(queue, Mapping)
        else None
    )
    authorization = None
    if isinstance(authorizations, list):
        authorization = next(
            (
                item
                for item in authorizations
                if isinstance(item, Mapping)
                and item.get("predecessor_run_id") == predecessor_run_id
            ),
            None,
        )
    elif isinstance(queue, Mapping):
        authorization = queue.get("cross_request_authorization")
    if not isinstance(authorization, Mapping):
        raise SubagentQueueError("queued successor provenance differs from predecessor")
    recomputed, aggregation, relationship = _cross_request_queue_authorization(
        manifest_path.parent.parent,
        project_root=Path(str(successor.get("project_dir") or "")).resolve(),
        predecessor_run_id=predecessor_run_id,
        predecessor=predecessor,
        current_provenance=normalize_delegation_provenance(successor_provenance),
        require_active_caller=False,
    )
    if dict(authorization) != recomputed:
        raise SubagentQueueError("cross-request queue authorization evidence changed")
    if (
        successor.get("query_relationship") != relationship
        or successor_aggregation.get("key") != aggregation.get("key")
        or successor_aggregation.get("synthesis_group")
        != aggregation.get("synthesis_group")
        or successor_aggregation.get("delivery_target_source_record_id")
        != successor_provenance.get("source_record_id")
    ):
        raise SubagentQueueError(
            "cross-request queued successor changed current aggregation custody"
        )
    delivery = successor.get("completion_delivery")
    reply_target = delivery.get("reply_target") if isinstance(delivery, Mapping) else None
    if (
        not isinstance(reply_target, Mapping)
        or reply_target.get("source_record_id") != successor_provenance.get("source_record_id")
        or _queue_has_conflicting_delivered_owner(
            manifest_path.parent.parent,
            aggregation_key=str(successor_aggregation.get("key") or ""),
            successor_run_id=str(successor.get("run_id") or manifest_path.parent.name),
        )
    ):
        raise SubagentQueueError(
            "cross-request queued successor has a delivery ownership conflict"
        )


def _recover_idempotent_cross_request_queue(
    manifest_path: Path, manifest: dict[str, Any]
) -> dict[str, Any]:
    """Requeue one zero-attempt false terminal after its contract validates again."""

    queue = manifest.get("queue")
    delivery = manifest.get("completion_delivery")
    if (
        manifest.get("status") != "failed"
        or not isinstance(queue, dict)
        or queue.get("attention") != "invalid_dependency_contract"
        or int(queue.get("attempt_count") or 0) != 0
        or not (
            isinstance(queue.get("cross_request_authorization"), Mapping)
            or isinstance(queue.get("cross_request_authorizations"), list)
        )
        or not isinstance(delivery, Mapping)
        or delivery.get("status") != "pending"
    ):
        return manifest
    try:
        predecessor_run_ids, predecessors = _validated_queue_predecessors(
            manifest_path, manifest
        )
    except (SubagentFollowupError, SubagentQueueError, OSError, ValueError):
        return manifest

    recovered_at = _utc_now()
    predecessor_states = [
        _queue_predecessor_state(run_id, path, predecessor)
        for run_id, path, predecessor in predecessors
    ]
    waiting_state, waiting_attention = _queue_waiting_labels(predecessor_run_ids)
    for field in ("failed_at", "last_validation_error"):
        queue.pop(field, None)
    queue.update(
        {
            "state": waiting_state,
            "attention": waiting_attention,
            "predecessor_states": predecessor_states,
            "recovered_at": recovered_at,
            "recovery_reason": "idempotent_replay_revalidated_dependency_contract",
            "updated_at": recovered_at,
        }
    )
    if len(predecessor_states) == 1:
        queue["predecessor_status"] = predecessor_states[0]["status"]
    else:
        queue.pop("predecessor_status", None)
    for field in (
        "terminal_outcome",
        "finished_at",
        "error",
        "error_class",
    ):
        manifest.pop(field, None)
    manifest.update(
        {
            "status": "queued",
            "queue": queue,
            "updated_at": recovered_at,
        }
    )
    history = list(manifest.get("status_history") or [])
    history.append(
        {
            "status": "queued",
            "at": recovered_at,
            "evidence": "idempotent_replay_revalidated_dependency_contract",
        }
    )
    manifest["status_history"] = history[-100:]
    _atomic_json(manifest_path, manifest)
    return manifest


def _queue_result_is_valid(
    predecessor_path: Path, predecessor: Mapping[str, Any]
) -> tuple[bool, str | None]:
    if predecessor.get("status") != "completed":
        return False, "predecessor_not_completed"
    if predecessor.get("terminal_outcome") not in {None, "completed"}:
        return False, "predecessor_terminal_outcome_invalid"
    if int(predecessor.get("returncode") or 0) != 0:
        return False, "predecessor_returncode_nonzero"
    verification = predecessor.get("completion_verification")
    if isinstance(verification, Mapping) and (
        verification.get("status") != "success"
        or verification.get("classification")
        not in {
            "applicable_non_mutating_success",
            "git_backed_mutation_custody_verified",
            "legacy_lifecycle_success",
        }
    ):
        return False, "predecessor_completion_verification_invalid"
    try:
        result_path = _queue_artifact_path(
            predecessor_path, predecessor, "result_path", "result.md"
        )
        stat = result_path.stat()
    except (OSError, SubagentQueueError):
        return False, "predecessor_result_missing"
    if not result_path.is_file() or stat.st_size <= 0:
        return False, "predecessor_result_empty_or_invalid"
    return True, None


def _queue_predecessor_state(
    run_id: str, predecessor_path: Path, predecessor: Mapping[str, Any]
) -> dict[str, Any]:
    status = _normalized_queue_predecessor_status(predecessor)
    state: dict[str, Any] = {
        "run_id": run_id,
        "status": status,
        "result_state": "pending",
        "attention": "waiting_for_predecessor",
    }
    if status == "unknown":
        state.update(
            result_state="invalid", attention="predecessor_status_unknown"
        )
    elif status in {"cancelled", "superseded", "abandoned"}:
        state.update(result_state="not_applicable", attention=f"predecessor_{status}")
    elif status in {"failed", "interrupted"}:
        state.update(
            result_state="not_applicable", attention="predecessor_terminal_failure"
        )
    elif status == "completed":
        result_valid, result_error = _queue_result_is_valid(
            predecessor_path, predecessor
        )
        state.update(
            result_state="valid" if result_valid else "invalid",
            attention="ready" if result_valid else str(result_error),
        )
    return state


def _validated_queue_predecessors(
    manifest_path: Path, manifest: Mapping[str, Any]
) -> tuple[tuple[str, ...], list[tuple[str, Path, dict[str, Any]]]]:
    """Validate the immutable dependency contract and return ordered predecessors."""

    queue = manifest.get("queue")
    if not isinstance(queue, Mapping) or queue.get("schema_version") != QUEUE_SCHEMA:
        raise SubagentQueueError("invalid queue contract")
    predecessor_run_ids = _queue_predecessor_run_ids(queue)
    successor_run_id = str(manifest.get("run_id") or manifest_path.parent.name)
    if successor_run_id in predecessor_run_ids:
        raise SubagentQueueError("queued successor cannot depend on itself")
    ancestors = _queue_ancestor_ids(manifest_path.parent.parent, predecessor_run_ids)
    if successor_run_id in ancestors:
        raise SubagentQueueError("queued dependency cycle reaches successor")
    if queue.get("ancestor_run_ids") != ancestors:
        raise SubagentQueueError("queued dependency ancestry changed after commit")
    if queue.get("trigger_policy") != QUEUE_TRIGGER_POLICY:
        raise SubagentQueueError("queued trigger policy is unsupported")

    predecessors: list[tuple[str, Path, dict[str, Any]]] = []
    references: list[dict[str, Any]] = []
    cross_request_ids: list[str] = []
    for run_id in predecessor_run_ids:
        predecessor_path = manifest_path.parent.parent / run_id / "manifest.json"
        predecessor = _read_managed_resident_manifest(predecessor_path)
        references.extend(_queue_predecessor_references(predecessor_path, predecessor))
        predecessor_provenance = predecessor.get("launch_provenance")
        successor_provenance = manifest.get("launch_provenance")
        if not isinstance(predecessor_provenance, Mapping) or not isinstance(
            successor_provenance, Mapping
        ):
            raise SubagentQueueError("queued dependency lacks immutable launch provenance")
        if _queue_provenance_identity(
            normalize_delegation_provenance(predecessor_provenance)
        ) != _queue_provenance_identity(
            normalize_delegation_provenance(successor_provenance)
        ):
            cross_request_ids.append(run_id)
        _validate_queue_authorization(
            predecessor,
            manifest,
            predecessor_run_id=run_id,
            manifest_path=manifest_path,
        )
        predecessors.append((run_id, predecessor_path, predecessor))
    if queue.get("predecessor_references") != references:
        raise SubagentQueueError("queued predecessor references changed after commit")

    plural_authorizations = queue.get("cross_request_authorizations")
    singular_authorization = queue.get("cross_request_authorization")
    if plural_authorizations is not None and singular_authorization is not None:
        raise SubagentQueueError("queued cross-request authorization fields conflict")
    if plural_authorizations is not None:
        if not isinstance(plural_authorizations, list):
            raise SubagentQueueError("queued cross-request authorizations are malformed")
        authorization_ids = [
            item.get("predecessor_run_id") if isinstance(item, Mapping) else None
            for item in plural_authorizations
        ]
        if authorization_ids != cross_request_ids:
            raise SubagentQueueError("queued cross-request authorization set changed")
    elif singular_authorization is not None:
        if cross_request_ids != [
            singular_authorization.get("predecessor_run_id")
            if isinstance(singular_authorization, Mapping)
            else None
        ]:
            raise SubagentQueueError("queued cross-request authorization changed")
    elif cross_request_ids:
        raise SubagentQueueError("queued cross-request authorization is missing")
    return predecessor_run_ids, predecessors


def _find_managed_run(
    run_id: str,
    *,
    project_root: Path,
    workspace_root: str | Path | None,
) -> tuple[Path, dict[str, Any], tuple[Path, ...]]:
    if not _RUN_ID_RE.fullmatch(run_id):
        raise SubagentFollowupError("run_id is malformed")
    roots = tuple(
        sorted(
            _managed_run_roots(project_root=project_root, workspace_root=workspace_root),
            key=str,
        )
    )
    matches = [
        root / run_id / "manifest.json"
        for root in roots
        if (root / run_id / "manifest.json").is_file()
    ]
    if not matches:
        raise SubagentFollowupError(f"unknown resident-managed run_id: {run_id}")
    unique = {path.resolve() for path in matches}
    if len(unique) != 1:
        raise SubagentFollowupError(f"run_id has ambiguous workspace ownership: {run_id}")
    manifest_path = unique.pop()
    return manifest_path, _read_managed_resident_manifest(manifest_path), roots


def find_discord_followup_target(
    *,
    source_record_id: str,
    discord_message_id: str,
    resident_conversation_id: str,
    conversation_key: str,
    reply_received_at: datetime,
    project_root: str | Path,
    workspace_root: str | Path | None = "/workspace",
) -> DiscordFollowupTarget | None:
    """Find the sole recent lineage launched from an exact Discord message.

    The launch anchor is the managed supervisor's ``started_at`` timestamp,
    falling back to the pre-launch manifest ``created_at`` timestamp for legacy
    records.  A reply is eligible when its durable resident ``sent_at`` is on
    or after that anchor and no later than exactly 15 minutes after it.  More
    than one matching lineage, duplicated run ownership across roots, malformed
    provenance, or a non-UTC/unparseable timestamp fails closed.
    """

    received = reply_received_at
    if received.tzinfo is None:
        received = received.replace(tzinfo=timezone.utc)
    received = received.astimezone(timezone.utc)
    candidates: list[tuple[datetime, str, str, Path, str]] = []
    seen_run_paths: dict[str, Path] = {}
    for manifest_path in _managed_manifest_paths(
        project_root=project_root,
        workspace_root=workspace_root,
    ):
        try:
            manifest = _read_managed_resident_manifest(manifest_path)
            provenance = normalize_delegation_provenance(
                manifest.get("launch_provenance") or {}
            )
        except (SubagentFollowupError, DelegationProvenanceError):
            continue
        if provenance.get("applicability") != "applicable":
            continue
        if any(
            (
                provenance.get("source_record_id") != source_record_id,
                provenance.get("discord_message_id") != discord_message_id,
                provenance.get("reply_to_message_id") != discord_message_id,
                provenance.get("resident_conversation_id")
                != resident_conversation_id,
                provenance.get("conversation_key") != conversation_key,
            )
        ):
            continue
        run_id = str(manifest.get("run_id") or manifest_path.parent.name)
        resolved_path = manifest_path.resolve()
        prior_path = seen_run_paths.get(run_id)
        if prior_path is not None and prior_path != resolved_path:
            return None
        seen_run_paths[run_id] = resolved_path
        anchor_field = "started_at" if manifest.get("started_at") else "created_at"
        anchor = _parse_timestamp(manifest.get(anchor_field))
        if anchor is None:
            continue
        anchor = anchor.astimezone(timezone.utc)
        age = received - anchor
        if age < timedelta(0) or age > DISCORD_FOLLOWUP_WINDOW:
            continue
        candidates.append(
            (
                anchor,
                run_id,
                _lineage_root_id(manifest, manifest_path),
                resolved_path,
                anchor_field,
            )
        )
    if not candidates:
        return None
    lineages = {candidate[2] for candidate in candidates}
    if len(lineages) != 1:
        # A Discord reply contains no run selector. Guessing between two agent
        # conversations launched from one source would cross session custody.
        return None
    anchor, run_id, lineage_root_run_id, manifest_path, anchor_field = max(
        candidates, key=lambda item: (item[0], item[1])
    )
    return DiscordFollowupTarget(
        run_id=run_id,
        lineage_root_run_id=lineage_root_run_id,
        manifest_path=str(manifest_path),
        launch_anchor=anchor.isoformat(),
        launch_anchor_field=anchor_field,
    )


def _manifest_session_ids(
    manifest_path: Path,
    manifest: Mapping[str, Any],
    *,
    allow_multiple: bool = False,
) -> set[str]:
    found: set[str] = set()
    backend = str(manifest.get("backend") or "codex")
    model_session = manifest.get("model_session")
    if isinstance(model_session, Mapping):
        session_id = str(model_session.get("session_id") or "").strip().lower()
        if session_id:
            session_provider = str(model_session.get("provider") or backend)
            if session_provider != backend:
                raise SubagentFollowupError(
                    "managed run model session provider conflicts with its backend"
                )
            if not valid_session_id(backend, session_id):
                raise SubagentFollowupError("managed run has a malformed model session id")
            found.add(session_id)
    log_path = Path(str(manifest.get("log_path") or manifest_path.parent / "run.log"))
    log_text = _model_session_log_prefix(log_path)
    # Only the first CLI header/event owns this run. Later tool output may quote
    # another run's log verbatim and must not become session-ownership evidence.
    text_matches = _CODEX_SESSION_RE.findall(log_text)
    json_matches = _CODEX_JSON_SESSION_RE.findall(log_text)
    if text_matches:
        found.add(text_matches[0].lower())
    elif json_matches:
        found.add(json_matches[0].lower())
    if backend == "codex":
        raw_path = Path(
            str(manifest.get("provider_raw_output_path") or manifest_path.parent / "provider.raw.jsonl")
        )
        log_text += "\n" + _model_session_log_prefix(raw_path)
        # Only the first CLI header/event owns this run. Later tool output may
        # quote another run's log and must not become ownership evidence.
        text_matches = _CODEX_SESSION_RE.findall(log_text)
        json_matches = _CODEX_JSON_SESSION_RE.findall(log_text)
        if text_matches:
            found.add(text_matches[0].lower())
        elif json_matches:
            found.add(json_matches[0].lower())
    if len(found) > 1 and not allow_multiple:
        raise SubagentFollowupError("managed run exposes multiple model session ids")
    return found


def _model_session_log_prefix(log_path: Path) -> str:
    """Read only the authoritative opening portion of a managed worker log."""

    try:
        with log_path.open("rb") as handle:
            return handle.read(MAX_MODEL_SESSION_LOG_PREFIX_BYTES).decode(
                "utf-8", errors="replace"
            )
    except OSError:
        return ""


def _lineage_root_id(manifest: Mapping[str, Any], manifest_path: Path) -> str:
    return str(
        manifest.get("lineage_root_run_id")
        or manifest.get("root_run_id")
        or manifest.get("run_id")
        or manifest_path.parent.name
    )


def _lineage_manifests(
    root: Path, lineage_root_run_id: str
) -> dict[str, tuple[Path, dict[str, Any]]]:
    rows: dict[str, tuple[Path, dict[str, Any]]] = {}
    for path in root.glob("*/manifest.json"):
        try:
            payload = _read_managed_resident_manifest(path)
        except SubagentFollowupError:
            continue
        run_id = str(payload.get("run_id") or path.parent.name)
        claimed_root = _lineage_root_id(payload, path)
        if run_id == lineage_root_run_id or claimed_root == lineage_root_run_id:
            rows[run_id] = (path, payload)
    return rows


def _lineage_tip(
    rows: Mapping[str, tuple[Path, dict[str, Any]]],
) -> tuple[Path, dict[str, Any]]:
    parent_ids = {
        str(payload.get("parent_run_id"))
        for _, payload in rows.values()
        if payload.get("parent_run_id")
    }
    leaves = [entry for run_id, entry in rows.items() if run_id not in parent_ids]
    if len(leaves) != 1:
        raise SubagentFollowupError("managed model session lineage has ambiguous branch ownership")
    return leaves[0]


def _compatible_followup_provenance(
    target: Mapping[str, Any], caller: Mapping[str, Any]
) -> None:
    target_normalized = normalize_delegation_provenance(target)
    caller_normalized = normalize_delegation_provenance(caller)
    if target_normalized["applicability"] != caller_normalized["applicability"]:
        raise SubagentFollowupError("follow-up provenance transport conflicts with target custody")
    if target_normalized["applicability"] != "applicable":
        return
    for field in (
        "resident_conversation_id",
        "conversation_key",
        "guild_id",
        "channel_id",
        "thread_id",
        "dm_user_id",
    ):
        if target_normalized.get(field) != caller_normalized.get(field):
            raise SubagentFollowupError(
                f"follow-up provenance {field} conflicts with target session ownership"
            )


def _session_owner_lineage(
    provider: str,
    session_id: str,
    *,
    roots: tuple[Path, ...],
) -> str | None:
    owners: set[str] = set()
    for root in roots:
        for path in root.glob("*/manifest.json"):
            try:
                payload = _read_managed_resident_manifest(path)
            except SubagentFollowupError:
                continue
            try:
                ids = _manifest_session_ids(path, payload, allow_multiple=True)
            except SubagentFollowupError:
                # An unrelated malformed legacy record must not deny service.
                # If it contains the requested session identity, however, safe
                # ownership cannot be established and continuation fails closed.
                log_path = Path(str(payload.get("log_path") or path.parent / "run.log"))
                raw = json.dumps(payload, sort_keys=True) + _model_session_log_prefix(
                    log_path
                )
                if session_id in raw.lower():
                    raise SubagentFollowupError(
                        "model session id has ambiguous malformed ownership evidence"
                    )
                continue
            if session_id in ids and str(payload.get("backend") or "codex") == provider:
                if len(ids) > 1:
                    raise SubagentFollowupError(
                        "model session id appears in a multi-session managed run"
                    )
                owners.add(_lineage_root_id(payload, path))
    if len(owners) > 1:
        raise SubagentFollowupError("model session id has ambiguous managed-run ownership")
    return next(iter(owners), None)


def _followup_result(
    record: Mapping[str, Any], *, idempotent_replay: bool
) -> SubagentFollowupResult:
    return SubagentFollowupResult(
        ok=True,
        followup_id=str(record["followup_id"]),
        target_run_id=str(record["target_run_id"]),
        parent_run_id=str(record["parent_run_id"]),
        lineage_root_run_id=str(record["lineage_root_run_id"]),
        continuation_run_id=(
            str(record["continuation_run_id"])
            if record.get("continuation_run_id")
            else None
        ),
        status=str(record.get("status") or "continuation_started"),
        evidence_path=str(record["evidence_path"]),
        message_path=str(record["message_path"]),
        continuation_manifest_path=(
            str(record["continuation_manifest_path"])
            if record.get("continuation_manifest_path")
            else None
        ),
        model_session_id=(
            str(record["model_session_id"])
            if record.get("model_session_id")
            else None
        ),
        idempotent_replay=idempotent_replay,
        route=str(record.get("route") or "session_continuation"),
        delivery_owner_run_id=(
            str(record["delivery_owner_run_id"])
            if record.get("delivery_owner_run_id")
            else None
        ),
    )


def _existing_synthesis_owner(
    *,
    run_id: str,
    target: Mapping[str, Any],
    rows: Mapping[str, tuple[Path, dict[str, Any]]],
    target_provenance: Mapping[str, Any],
) -> tuple[Path, dict[str, Any]] | None:
    """Resolve the existing synthesis owner without changing ownership.

    A queued all-success successor is a control-plane owner, not a resumable
    model-session tip.  Once it is running, material may still be preserved in
    that same owner's durable inbox without interrupting it or launching a
    continuation.  Both routes require mutual proof of aggregation key,
    synthesis group, contributor edge, lineage, and immutable Discord custody.
    """

    target_aggregation = target.get("aggregation")
    if not isinstance(target_aggregation, Mapping):
        return None
    target_role = str(target_aggregation.get("role") or "")
    owner_run_id = str(target_aggregation.get("delivery_owner_run_id") or "")
    if target_role == "synthesis_delivery_owner":
        owner_run_id = run_id
    elif target_role != "internal_contributor":
        return None
    if not _RUN_ID_RE.fullmatch(owner_run_id) or owner_run_id not in rows:
        return None

    owner_path, owner = rows[owner_run_id]
    if str(owner.get("status") or "") not in {"queued", "running"}:
        return None
    owner_aggregation = owner.get("aggregation")
    queue = owner.get("queue")
    if not isinstance(owner_aggregation, Mapping) or not isinstance(queue, Mapping):
        return None
    if (
        owner_aggregation.get("role") != "synthesis_delivery_owner"
        or str(owner_aggregation.get("delivery_owner_run_id") or "") != owner_run_id
        or owner_aggregation.get("key") != target_aggregation.get("key")
        or owner_aggregation.get("synthesis_group")
        != target_aggregation.get("synthesis_group")
    ):
        raise SubagentFollowupError(
            "queued synthesis owner aggregation custody conflicts with target lineage"
        )
    predecessor_ids = queue.get("predecessor_run_ids")
    if not isinstance(predecessor_ids, list):
        predecessor_id = str(queue.get("predecessor_run_id") or "")
        predecessor_ids = [predecessor_id] if predecessor_id else []
    if run_id != owner_run_id and run_id not in predecessor_ids:
        raise SubagentFollowupError(
            "queued synthesis owner does not depend on the targeted contributor"
        )
    contributors = owner_aggregation.get("contributors")
    contributor_ids = {
        str(item.get("run_id") or "")
        for item in contributors
        if isinstance(item, Mapping)
    } if isinstance(contributors, list) else set()
    if run_id != owner_run_id and run_id not in contributor_ids:
        raise SubagentFollowupError(
            "queued synthesis owner lacks the targeted contributor receipt"
        )
    owner_provenance = owner.get("launch_provenance")
    if not isinstance(owner_provenance, Mapping):
        raise SubagentFollowupError("queued synthesis owner has no canonical provenance")
    _compatible_followup_provenance(target_provenance, owner_provenance)
    delivery = owner.get("completion_delivery")
    if isinstance(delivery, Mapping) and str(delivery.get("status") or "") in {
        "delivered",
        "failed",
        "superseded",
        "suppressed",
    }:
        raise SubagentFollowupError(
            "queued synthesis owner no longer has pending delivery custody"
        )
    return owner_path, owner


def _attach_synthesis_owner_material(
    *,
    target_run_id: str,
    lineage_root_run_id: str,
    owner_path: Path,
    owner: Mapping[str, Any],
    message: str,
    message_path: Path,
    evidence_path: Path,
    followup_id: str,
    selector: str,
    message_sha256: str,
    caller_provenance: Mapping[str, Any],
    caller_sha256: str,
    query_relationship: Mapping[str, Any] | None,
    existing: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Atomically bind new material to the existing delivery owner's inbox."""

    owner_run_id = str(owner.get("run_id") or owner_path.parent.name)
    lock_path = owner_path.parent / ".queue-transition.lock"
    with lock_path.open("a+b") as queue_handle:
        fcntl.flock(queue_handle.fileno(), fcntl.LOCK_EX)
        current = _read_managed_resident_manifest(owner_path)
        owner_status = str(current.get("status") or "")
        if owner_status not in {"queued", "running"}:
            raise SubagentFollowupError(
                "synthesis owner left the attachable state before material was committed"
            )
        route = (
            "queued_synthesis_owner"
            if owner_status == "queued"
            else "running_synthesis_owner_inbox"
        )
        aggregation = current.get("aggregation")
        queue = current.get("queue")
        if (
            not isinstance(aggregation, Mapping)
            or aggregation.get("role") != "synthesis_delivery_owner"
            or str(aggregation.get("delivery_owner_run_id") or "") != owner_run_id
            or not isinstance(queue, dict)
        ):
            raise SubagentFollowupError(
                "queued synthesis owner custody changed before material was committed"
            )

        if existing is not None:
            if (
                existing.get("route") != route
                or existing.get("delivery_owner_run_id") != owner_run_id
            ):
                raise SubagentFollowupError(
                    "existing follow-up receipt is not bound to this synthesis owner"
                )
            if existing.get("status") == "accepted":
                return dict(existing)

        prompt_path = Path(str(current.get("prompt_path") or "prompt.md"))
        if not prompt_path.is_absolute():
            prompt_path = owner_path.parent / prompt_path
        prompt_path = prompt_path.resolve()
        try:
            prompt_path.relative_to(owner_path.parent.resolve())
        except ValueError as exc:
            raise SubagentFollowupError(
                "queued synthesis owner prompt escapes its managed run directory"
            ) from exc
        try:
            prompt = prompt_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise SubagentFollowupError(
                "queued synthesis owner prompt is unavailable"
            ) from exc
        prompt_sha256_before = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        recorded_prompt_sha256 = str(current.get("prompt_sha256") or "")
        recovering_prepared = bool(
            existing is not None
            and existing.get("route") == route
            and existing.get("status") == "prepared"
            and existing.get("prompt_sha256_after") == prompt_sha256_before
        )
        if (
            recorded_prompt_sha256
            and recorded_prompt_sha256 != prompt_sha256_before
            and not recovering_prepared
        ):
            raise SubagentFollowupError(
                "queued synthesis owner prompt checksum changed before attachment"
            )

        material_header = (
            "[Synthesis-owner material — canonical follow-up]\n"
            f"- schema: {QUEUED_OWNER_MATERIAL_SCHEMA}\n"
            f"- receipt_id: {followup_id}\n"
            f"- source_target_run_id: {target_run_id}\n"
            f"- delivery_owner_run_id: {owner_run_id}\n"
            f"- message_sha256: {message_sha256}\n"
            "- instruction: consume this material during synthesis; preserve existing "
            "single-delivery ownership and predecessor gates\n\n"
        )
        material_block = material_header + message.rstrip() + "\n"
        if material_block not in prompt:
            updated_prompt = prompt.rstrip() + "\n\n" + material_block
        else:
            updated_prompt = prompt
        if len(updated_prompt) > MAX_DELEGATED_PROMPT_CHARS:
            raise SubagentFollowupError(
                "queued synthesis owner prompt would exceed the managed prompt limit"
            )
        prompt_sha256_after = hashlib.sha256(
            updated_prompt.encode("utf-8")
        ).hexdigest()
        accepted_at = str(
            (existing or {}).get("accepted_at") or _utc_now()
        )
        original_prompt_sha256 = str(
            (existing or {}).get("prompt_sha256_before") or prompt_sha256_before
        )
        record: dict[str, Any] = {
            "schema_version": FOLLOWUP_SCHEMA,
            "followup_id": followup_id,
            "target_run_id": target_run_id,
            "parent_run_id": owner_run_id,
            "lineage_root_run_id": lineage_root_run_id,
            "delivery_owner_run_id": owner_run_id,
            "route": route,
            "message_path": str(message_path),
            "message_sha256": message_sha256,
            "idempotency_key": selector,
            "requester_provenance": dict(caller_provenance),
            "requester_provenance_sha256": caller_sha256,
            "query_relationship": (
                dict(query_relationship)
                if isinstance(query_relationship, Mapping)
                else None
            ),
            "parent_status_at_acceptance": owner_status,
            "launch_visibility": (
                "included_before_worker_launch"
                if owner_status == "queued"
                else "durable_owner_inbox_requires_process_observation"
            ),
            "status": "prepared",
            "accepted_at": accepted_at,
            "updated_at": accepted_at,
            "evidence_path": str(evidence_path),
            "continuation_run_id": None,
            "continuation_manifest_path": None,
            "prompt_path": str(prompt_path),
            "prompt_sha256_before": original_prompt_sha256,
            "prompt_sha256_after": prompt_sha256_after,
            "state_history": [
                {
                    "status": "prepared",
                    "at": accepted_at,
                    "evidence": "synthesis_owner_material_prepared_under_queue_lock",
                }
            ],
        }
        _atomic_text(message_path, message.rstrip() + "\n")
        _atomic_json(evidence_path, record)
        if updated_prompt != prompt:
            _atomic_text(prompt_path, updated_prompt)

        inbound_material = list(queue.get("inbound_material") or [])
        receipt_ref = {
            "schema_version": QUEUED_OWNER_MATERIAL_SCHEMA,
            "followup_id": followup_id,
            "target_run_id": target_run_id,
            "message_path": str(message_path),
            "message_sha256": message_sha256,
            "evidence_path": str(evidence_path),
            "accepted_at": accepted_at,
        }
        matching = [
            item
            for item in inbound_material
            if isinstance(item, Mapping) and item.get("followup_id") == followup_id
        ]
        if matching and dict(matching[0]) != receipt_ref:
            raise SubagentFollowupError(
                "queued synthesis owner already has conflicting material receipt"
            )
        if not matching:
            inbound_material.append(receipt_ref)
        queue["inbound_material"] = inbound_material[-20:]
        queue["updated_at"] = accepted_at
        current["queue"] = queue
        current["prompt_sha256"] = prompt_sha256_after
        current["updated_at"] = accepted_at
        _atomic_json(owner_path, current)

        record["status"] = "accepted"
        record["state_history"] = list(record["state_history"]) + [
            {
                "status": "accepted",
                "at": accepted_at,
                "evidence": (
                    "material_bound_to_existing_queued_synthesis_owner_prompt"
                    if owner_status == "queued"
                    else "material_bound_to_existing_running_synthesis_owner_inbox"
                ),
                "delivery_owner_run_id": owner_run_id,
            }
        ]
        _atomic_json(evidence_path, record)
        return record


def _configured_timeout(value: object) -> float | None:
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    return float(value)


def _explicit_manifest_timeout(manifest: Mapping[str, Any]) -> float | None:
    policy = manifest.get("timeout_policy")
    if not isinstance(policy, Mapping):
        return None
    if policy.get("mode") != "explicit" or policy.get("source") not in {
        "trusted_cli", "verified_user_request"
    }:
        return None
    timeout_s = _configured_timeout(policy.get("timeout_s"))
    return timeout_s if timeout_s is not None and timeout_s > 0 else None


def _explicit_manifest_timeout_source(manifest: Mapping[str, Any]) -> str | None:
    if _explicit_manifest_timeout(manifest) is None:
        return None
    policy = manifest["timeout_policy"]
    return str(policy["source"])


def follow_up_managed_subagent(
    *,
    run_id: str,
    message: str,
    project_dir: str | Path | None = None,
    idempotency_key: str | None = None,
    workspace_root: str | Path | None = "/workspace",
    caller_provenance: Mapping[str, Any] | None = None,
    expected_target_source_record_id: str | None = None,
    expected_target_discord_message_id: str | None = None,
    query_relationship: Mapping[str, Any] | None = None,
    aggregation_role: str = "synthesis_delivery_owner",
    synthesis_group: str | None = None,
    require_live: bool = False,
) -> SubagentFollowupResult:
    """Durably append ``message`` to the unique persistent session lineage.

    A continuation supervisor is created for both active and terminal parents.
    An active parent is interrupted only through its exact manifest-bound
    resident supervisor, after a unique persistent session is proven; the
    continuation waits for that parent to become terminal before resuming the
    same session.  The caller's validated resident provenance is the
    continuation's provenance; target provenance is used only to authorize the
    same immutable conversation ownership. ``require_live`` narrows this to
    the interrupting active-parent path and rejects a target that stopped
    between command resolution and the locked continuation attachment.
    """

    if not isinstance(message, str) or not message.strip():
        raise SubagentFollowupError("follow-up message must not be empty")
    if len(message) > MAX_FOLLOWUP_MESSAGE_CHARS:
        raise SubagentFollowupError(
            f"follow-up message exceeds {MAX_FOLLOWUP_MESSAGE_CHARS} characters"
        )
    if idempotency_key is not None and not _FOLLOWUP_KEY_RE.fullmatch(idempotency_key):
        raise SubagentFollowupError("idempotency_key is malformed")
    if aggregation_role not in AGGREGATION_ROLES:
        raise SubagentFollowupError("follow-up aggregation_role is invalid")
    synthesis_group = str(synthesis_group or "").strip() or None
    if aggregation_role == "internal_contributor" and synthesis_group is None:
        raise SubagentFollowupError(
            "internal contributor follow-ups require synthesis_group"
        )
    if synthesis_group is not None and not _SYNTHESIS_GROUP_RE.fullmatch(synthesis_group):
        raise SubagentFollowupError("follow-up synthesis_group is malformed")
    inherited_provenance = (
        normalize_delegation_provenance(caller_provenance)
        if caller_provenance is not None
        else provenance_from_environment(strict=True)
    )
    if inherited_provenance is None:
        raise SubagentFollowupError(
            "resident follow-up requires inherited delegation provenance"
        )
    caller_provenance = inherited_provenance

    project_root = Path(project_dir or Path.cwd()).resolve()
    target_path, target, roots = _find_managed_run(
        run_id, project_root=project_root, workspace_root=workspace_root
    )
    target_provenance = target.get("launch_provenance")
    if not isinstance(target_provenance, Mapping):
        raise SubagentFollowupError("target run has no canonical launch provenance")
    try:
        _compatible_followup_provenance(target_provenance, caller_provenance)
        normalized_target_provenance = normalize_delegation_provenance(
            target_provenance
        )
    except DelegationProvenanceError as exc:
        raise SubagentFollowupError("target run provenance is malformed") from exc
    if (
        expected_target_source_record_id is not None
        and normalized_target_provenance.get("source_record_id")
        != expected_target_source_record_id
    ):
        raise SubagentFollowupError(
            "target run source custody changed after Discord reply matching"
        )
    if (
        expected_target_discord_message_id is not None
        and normalized_target_provenance.get("discord_message_id")
        != expected_target_discord_message_id
    ):
        raise SubagentFollowupError(
            "target run Discord message custody changed after reply matching"
        )

    lineage_root_run_id = _lineage_root_id(target, target_path)
    root = target_path.parent.parent
    followups_dir = root / lineage_root_run_id / "followups"
    followups_dir.mkdir(parents=True, exist_ok=True)
    message_sha256 = hashlib.sha256(message.encode("utf-8")).hexdigest()
    selector = idempotency_key or message_sha256
    caller_sha256 = hashlib.sha256(
        json.dumps(caller_provenance, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    followup_id = stable_identity(
        "followup",
        lineage_root_run_id,
        caller_provenance.get("custody_id") or caller_provenance.get("source_record_id"),
        selector,
    )
    evidence_path = followups_dir / f"{followup_id}.json"
    message_path = followups_dir / f"{followup_id}.md"

    with (root / ".followup.lock").open("a+b") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        existing: dict[str, Any] | None = None
        if evidence_path.is_file():
            try:
                loaded = json.loads(evidence_path.read_text(encoding="utf-8"))
            except (OSError, ValueError, TypeError) as exc:
                raise SubagentFollowupError("existing follow-up evidence is unreadable") from exc
            if not isinstance(loaded, dict):
                raise SubagentFollowupError("existing follow-up evidence is malformed")
            if (
                loaded.get("message_sha256") != message_sha256
                or loaded.get("requester_provenance_sha256") != caller_sha256
                or loaded.get("aggregation_role", "synthesis_delivery_owner")
                != aggregation_role
                or loaded.get("synthesis_group") != synthesis_group
            ):
                raise SubagentFollowupError(
                    "idempotency key is already bound to different follow-up content or custody"
                )
            existing = loaded
            if existing.get("continuation_run_id") or (
                existing.get("route") in {
                    "queued_synthesis_owner",
                    "running_synthesis_owner_inbox",
                }
                and existing.get("status") == "accepted"
                and existing.get("delivery_owner_run_id")
            ):
                return _followup_result(existing, idempotent_replay=True)

        rows = _lineage_manifests(root, lineage_root_run_id)
        if run_id not in rows:
            raise SubagentFollowupError("target run is not in its claimed lineage")
        for lineage_run_id, (_lineage_path, lineage_manifest) in rows.items():
            lineage_provenance = lineage_manifest.get("launch_provenance")
            if not isinstance(lineage_provenance, Mapping):
                raise SubagentFollowupError(
                    "managed model session lineage contains missing provenance"
                )
            try:
                _compatible_followup_provenance(
                    target_provenance, lineage_provenance
                )
            except DelegationProvenanceError as exc:
                raise SubagentFollowupError(
                    "managed model session lineage contains malformed provenance"
                ) from exc
            parent_id = str(lineage_manifest.get("parent_run_id") or "")
            if (
                lineage_run_id != lineage_root_run_id
                and (not parent_id or parent_id not in rows)
            ):
                raise SubagentFollowupError(
                    "managed model session lineage contains an orphaned continuation"
                )

        lineage_backends = {
            str(payload.get("backend") or "codex") for _, payload in rows.values()
        }
        if len(lineage_backends) != 1:
            raise SubagentFollowupError(
                "managed model session lineage crosses provider boundaries"
            )

        synthesis_owner = _existing_synthesis_owner(
            run_id=run_id,
            target=target,
            rows=rows,
            target_provenance=target_provenance,
        )
        if synthesis_owner is not None:
            owner_path, owner = synthesis_owner
            record = _attach_synthesis_owner_material(
                target_run_id=run_id,
                lineage_root_run_id=lineage_root_run_id,
                owner_path=owner_path,
                owner=owner,
                message=message,
                message_path=message_path,
                evidence_path=evidence_path,
                followup_id=followup_id,
                selector=selector,
                message_sha256=message_sha256,
                caller_provenance=caller_provenance,
                caller_sha256=caller_sha256,
                query_relationship=query_relationship,
                existing=existing,
            )
            return _followup_result(record, idempotent_replay=False)

        tip_path, tip = _lineage_tip(rows)
        parent_run_id = str(
            (existing or {}).get("parent_run_id")
            or tip.get("run_id")
            or tip_path.parent.name
        )
        if existing and parent_run_id not in rows:
            raise SubagentFollowupError("recorded follow-up parent is missing from lineage")
        if existing:
            tip_path, tip = rows[parent_run_id]

        parent_status = str(tip.get("status") or "unknown")
        parent_live = (
            parent_status in _ACTIVE_STATUSES
            and isinstance(tip.get("pid"), int)
            and _pid_matches_manifest(int(tip["pid"]), tip_path)
        )
        if parent_status in _ACTIVE_STATUSES and not parent_live:
            raise SubagentFollowupError(
                "target lineage tip claims an active state without a matching supervisor"
            )
        if require_live and not parent_live:
            raise SubagentFollowupError(
                f"target lineage tip is not live (status: {parent_status})"
            )
        if parent_status not in _ACTIVE_STATUSES and parent_status not in {
            "completed",
            "failed",
            "interrupted",
        }:
            raise SubagentFollowupError(
                f"target lineage tip has unsafe non-continuable status: {parent_status}"
            )

        parent_model_session = tip.get("model_session")
        if (
            not parent_live
            and isinstance(parent_model_session, Mapping)
            and str(parent_model_session.get("state") or "")
            in {"reserved_unconfirmed", "unavailable"}
        ):
            raise SubagentFollowupError(
                "terminal target provider session persistence is unconfirmed; "
                "exact continuation is unavailable"
            )

        parent_session_ids = _manifest_session_ids(tip_path, tip)
        model_session_id = next(iter(parent_session_ids), None)
        if model_session_id is None:
            raise SubagentFollowupError(
                f"{('active' if parent_live else 'terminal')} target has no uniquely "
                "recoverable persistent model session"
            )
        if model_session_id is not None:
            provider = str(tip.get("backend") or target.get("backend") or "codex")
            owner = _session_owner_lineage(provider, model_session_id, roots=roots)
            if owner is not None and owner != lineage_root_run_id:
                raise SubagentFollowupError("model session is owned by another managed-run lineage")

        if existing is None:
            accepted_at = _utc_now()
            record = {
                "schema_version": FOLLOWUP_SCHEMA,
                "followup_id": followup_id,
                "target_run_id": run_id,
                "parent_run_id": parent_run_id,
                "lineage_root_run_id": lineage_root_run_id,
                "message_path": str(message_path),
                "message_sha256": message_sha256,
                "idempotency_key": selector,
                "requester_provenance": caller_provenance,
                "requester_provenance_sha256": caller_sha256,
                "aggregation_role": aggregation_role,
                "synthesis_group": synthesis_group,
                "query_relationship": (
                    dict(query_relationship)
                    if isinstance(query_relationship, Mapping)
                    else None
                ),
                "parent_status_at_acceptance": parent_status,
                "status": "accepted",
                "accepted_at": accepted_at,
                "updated_at": accepted_at,
                "evidence_path": str(evidence_path),
                "state_history": [
                    {
                        "status": "accepted",
                        "at": accepted_at,
                        "evidence": "followup_message_and_custody_committed",
                    }
                ],
            }
            message_path.write_text(message + "\n", encoding="utf-8")
            _atomic_json(evidence_path, record)
            _emit_managed_child_event(
                tip_path,
                tip,
                event_kind="effect",
                surface="resident.subagent.followup",
                evidence="followup_message_and_custody_committed",
                at=accepted_at,
                details={
                    "followup_id": followup_id,
                    "evidence_path": str(evidence_path),
                    "message_path": str(message_path),
                    "requester_provenance_sha256": caller_sha256,
                },
            )
        else:
            record = existing

        provider = str(tip.get("backend") or target.get("backend") or "codex")
        provider_options = dict(
            tip.get("provider_options") or target.get("provider_options") or {}
        )
        try:
            continuation = launch_managed_subagent_detached(
                task=message,
                description=(
                    f"Follow up on {str(tip.get('description') or target.get('description')).rstrip('.')}"
                    if tip.get("description") or target.get("description")
                    else None
                ),
                project_dir=str(
                    tip.get("project_dir")
                    or target.get("project_dir")
                    or project_root
                ),
                model=str(tip.get("model") or target.get("model") or "gpt-5.6-terra"),
                model_spec=str(
                    tip.get("model_spec")
                    or target.get("model_spec")
                    or f"{provider}:{tip.get('model') or target.get('model')}"
                ),
                backend=provider,
                reasoning_effort=str(
                    tip.get("reasoning_effort") or target.get("reasoning_effort") or "medium"
                ),
                toolsets=str(provider_options.get("toolsets") or "file,web,terminal"),
                max_tokens=int(provider_options.get("max_tokens") or 65_536),
                provider_timeout_s=_explicit_manifest_timeout(tip),
                timeout_source=_explicit_manifest_timeout_source(tip),
                task_kind=str(tip.get("task_kind") or target.get("task_kind") or "routine"),
                work_intent=str(
                    tip.get("work_intent")
                    or target.get("work_intent")
                    or DEFAULT_DELEGATED_WORK_INTENT
                ),
                mutation_claim=str(
                    tip.get("mutation_claim")
                    or target.get("mutation_claim")
                    or "auto"
                ),
                difficulty=int(tip.get("difficulty") or target.get("difficulty") or 4),
                route_class="resident_followup_continuation",
                run_root=root,
                launch_origin=caller_provenance,
                parent_run_id=parent_run_id,
                lineage_root_run_id=lineage_root_run_id,
                continued_session_id=model_session_id,
                followup_id=followup_id,
                parent_manifest_path=tip_path,
                interrupt_parent=parent_live,
                query_relationship=query_relationship,
                aggregation_role=aggregation_role,
                synthesis_group=synthesis_group,
            )
        except Exception as exc:
            failed_at = _utc_now()
            record["status"] = "launch_failed"
            record["updated_at"] = failed_at
            record["error_class"] = exc.__class__.__name__
            record["state_history"] = list(record.get("state_history") or []) + [
                {
                    "status": "launch_failed",
                    "at": failed_at,
                    "evidence": "continuation_supervisor_launch_failed",
                }
            ]
            _atomic_json(evidence_path, record)
            raise

        started_at = _utc_now()
        record.update(
            {
                "status": "continuation_started",
                "updated_at": started_at,
                "continuation_run_id": continuation.run_id,
                "continuation_manifest_path": continuation.manifest_path,
                "model_session_id": model_session_id,
            }
        )
        record["state_history"] = list(record.get("state_history") or []) + [
            {
                "status": "continuation_started",
                "at": started_at,
                "evidence": (
                    "continuation_queued_to_interrupt_active_parent"
                    if parent_live
                    else "terminal_lineage_continuation_supervisor_started"
                ),
                "continuation_run_id": continuation.run_id,
            }
        ]
        _atomic_json(evidence_path, record)
        child_manifest = json.loads(
            Path(continuation.manifest_path).read_text(encoding="utf-8")
        )
        _emit_managed_child_event(
            Path(continuation.manifest_path),
            child_manifest,
            event_kind="effect",
            surface="resident.subagent.followup",
            evidence=(
                "continuation_queued_to_interrupt_active_parent"
                if parent_live
                else "terminal_lineage_continuation_supervisor_started"
            ),
            at=started_at,
            details={
                "followup_id": followup_id,
                "parent_run_id": parent_run_id,
                "target_run_id": run_id,
                "followup_evidence_path": str(evidence_path),
            },
        )
        return _followup_result(record, idempotent_replay=False)


class _ResidentLaunchUnresolved(RuntimeError):
    """The supervisor door ran, but canonical acceptance is still unknown."""

    def __init__(self, result: Any) -> None:
        self.result = result
        super().__init__(
            "resident supervisor launch remains unresolved: "
            f"{getattr(result, 'reason', 'unknown')}"
        )


def _resident_ops_store_root(manifest_path: Path) -> Path:
    """Return the durable store co-located with the resident run root."""

    return manifest_path.parent.parent / ".durable-ops"


def _resident_credentials_observation(manifest: Mapping[str, Any]) -> dict[str, Any]:
    """Prove the manifest's selected model route without exposing credentials."""
    backend = str(manifest.get("backend") or "").strip().lower()
    model = str(manifest.get("model_spec") or manifest.get("model") or "").strip()
    if backend in {"", "local", "shell", "process", "managed", "tmux", "auto"}:
        return {
            "status": "not_applicable",
            "identity": "credentialless_local",
            "transport": "local",
        }
    if backend == "omp":
        route = model if model.startswith("omp:") else f"omp:{model}" if model else "omp"
    else:
        route = f"{backend}:{model}" if model else backend
    try:
        parsed = parse_agent_spec(route)
    except (TypeError, ValueError):
        return {"status": "unknown", "identity": "unparseable_route", "transport": "local"}
    provider = parsed.agent.lower()
    if provider == "omp":
        provider = str(parsed.model or "").split("/", 1)[0].strip().lower()
    provider = {"codex": "openai-codex", "claude": "anthropic", "shannon": "anthropic"}.get(provider, provider)
    env_backed = {"deepseek", "openrouter", "xai", "anthropic", "zai", "moonshot", "fireworks"}
    if backend == "omp" and provider in env_backed:
        try:
            wired = bool(key_pool.has_keys(provider))
        except Exception:
            wired = False
        if wired:
            return {
                "status": "available",
                "identity": f"key_pool:{provider}",
                "transport": "local",
                "probe": "selected_key_pool",
            }
        return {
            "status": "unknown",
            "identity": f"key_pool:{provider}",
            "transport": "local",
            "reason": "selected_route_credentials_unproven",
        }
    try:
        scan = agentbox_detect.scan_providers()
        selected = next((item for item in scan.providers if item.id == provider), None)
    except Exception:
        selected = None
    if selected is not None and selected.status == agentbox_detect.READY:
        return {
            "status": "available",
            "identity": f"agentbox:{provider}",
            "transport": "local",
            "probe": "agentbox_read_only_scan",
        }
    return {
        "status": "unknown",
        "identity": provider or "unidentified_route",
        "transport": "local",
        "reason": "selected_route_credentials_unproven",
    }


def _resident_launch_preflight(
    manifest_path: Path,
    manifest: Mapping[str, Any],
    *,
    argv: Sequence[str],
    operation_id: str,
    request_id: str,
    store_root: Path,
) -> tuple[LaunchEnvelope, Any]:
    """Build the complete observation-only preflight for one supervisor door."""

    project_root = Path(str(manifest.get("project_dir") or Path.cwd())).resolve()
    source_revision = _git_revision_without_process(project_root)
    source_identity = source_revision or "unknown"
    run_id = str(manifest.get("run_id") or manifest_path.parent.name)
    launch_spec = {
        "command": list(argv),
        "cwd": str(Path(__file__).resolve().parents[3]),
        "metadata": {
            "run_id": run_id,
            "manifest_path": str(manifest_path.resolve()),
            "operation_id": operation_id,
        },
        "operation_type": "resident_managed_supervisor",
        "launch_intent": "resident_managed_supervisor",
        "process_resource_id": f"launch-process-session:{operation_id}:{request_id}",
        "expected_session_name": run_id,
        "runtime_vector": {
            "python": str(Path(sys.executable).resolve()),
            "source_revision": source_identity,
        },
        # Only immutable launch-contract facts participate in the preflight
        # identity.  Mutable status/PID/telemetry projections must not turn an
        # exact canonical replay into an envelope conflict.
        "manifest_identity": stable_identity(
            "resident-manifest",
            operation_id,
            run_id,
            manifest.get("launch_idempotency_key") or "",
        ),
        "process_session_identity": None,
    }
    custody_id = str(manifest.get("custody_id") or run_id)
    raw_capacity = read_only_capacity_observation(
        store_root.parent,
        output_bound_bytes=0,
        temp_path=store_root.parent,
    )
    capacity = {
        "status": raw_capacity.get("status", "unknown"),
        "disk": "observed" if raw_capacity.get("free_bytes") is not None else "unknown",
        "inode": "observed" if raw_capacity.get("free_inodes") is not None else "unknown",
        "output": "bounded" if raw_capacity.get("output_bound_proven") else "unknown",
        "temp": "observed" if raw_capacity.get("temp_free_bytes") is not None else "unknown",
        "mount": raw_capacity.get("mount"),
        "temp_mount": raw_capacity.get("temp_mount"),
    }
    observations = {
        "source": {
            "status": "current" if source_revision else "unknown",
            "revision": source_identity,
            "ref": "HEAD",
            "tree": source_identity,
        },
        "authority": {
            "status": "current",
            "grant": f"resident:{run_id}",
            "fence": f"resident:{run_id}",
            "decision": "resident_supervisor_launch",
        },
        "custody": {
            "status": "present",
            "custody_ref": custody_id,
            "wbc_ref": str(store_root.resolve()),
        },
        "credentials": {
            **_resident_credentials_observation(manifest),
        },
        "runtime": {
            "status": "ready",
            "interpreter": str(Path(sys.executable).resolve()),
            "import_root": str(Path(__file__).resolve().parents[3]),
            "source_revision": source_identity,
        },
        "command": {
            "status": "valid",
            "argv": list(argv),
            "cwd": str(Path(__file__).resolve().parents[3]),
            "env": {"ARNOLD_OPS_STORE_ROOT": str(store_root.resolve())},
        },
        "namespace": {
            "status": "ready",
            "name": f"resident-supervisor:{run_id}",
        },
        "collision": {
            "status": "clear",
            "name": f"resident-supervisor:{run_id}",
        },
        "capacity": capacity,
        "network": read_only_network_observation(transport="local", host="localhost"),
    }
    report = run_launch_preflight(launch_spec, observations)
    envelope = LaunchEnvelope(
        version=1,
        operation_id=operation_id,
        request_id=request_id,
        venue="resident",
        launch_spec=launch_spec,
        preflight_digest=report.preflight_digest,
    )
    return envelope, report


def _spawn_managed_supervisor(
    manifest_path: Path, manifest: Mapping[str, Any]
) -> tuple[subprocess.Popen[bytes] | None, dict[str, Any]]:
    """Admit and start exactly one resident supervisor through the canonical door."""

    argv = [
        sys.executable,
        "-m",
        "arnold_pipelines.megaplan.resident.subagent_worker",
        "--run-managed",
        str(manifest_path),
    ]
    run_id = str(manifest.get("run_id") or manifest_path.parent.name)
    operation_id = str(
        manifest.get("operation_id") or stable_identity("resident-launch-operation", run_id)
    )
    request_id = str(
        manifest.get("launch_request_id")
        or stable_identity("resident-launch-request", operation_id)
    )
    store_root = _resident_ops_store_root(manifest_path)
    store = FileBackedDurableOpsStore(store_root)
    # Keep launch identity in memory until the complete observation-only gate
    # passes.  Manifest publication is launch-side mutation and must not occur
    # on a rejected preflight.
    launch_manifest = dict(manifest)
    launch_manifest["operation_id"] = operation_id
    launch_manifest["launch_request_id"] = request_id
    launch_manifest["operation_store_root"] = str(store_root.resolve())
    manifest = launch_manifest
    envelope, preflight = _resident_launch_preflight(
        manifest_path,
        manifest,
        argv=argv,
        operation_id=operation_id,
        request_id=request_id,
        store_root=store_root,
    )
    physical_process: subprocess.Popen[bytes] | None = None

    def dispatch(candidate: LaunchEnvelope) -> subprocess.Popen[bytes]:
        nonlocal physical_process
        provenance = manifest.get("launch_provenance")
        worker_provenance = dict(provenance) if isinstance(provenance, Mapping) else {}
        if worker_provenance.get("applicability") == "applicable":
            worker_provenance["root_run_id"] = run_id
        log_path = _queue_artifact_path(
            manifest_path,
            manifest,
            "full_log_path",
            str(manifest.get("log_path") or "run.log"),
        )
        try:
            with log_path.open("ab") as log_handle:
                physical_process = subprocess.Popen(
                    argv,
                    cwd=str(Path(__file__).resolve().parents[3]),
                    stdin=subprocess.DEVNULL,
                    stdout=log_handle,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                    env={
                        **environment_with_provenance(worker_provenance),
                        "ARNOLD_CANONICAL_LAUNCH_ACTIVE": "1",
                        "ARNOLD_OPS_STORE_ROOT": str(store_root.resolve()),
                        "ARNOLD_LAUNCH_OPERATION_ID": candidate.operation_id,
                        "ARNOLD_LAUNCH_REQUEST_ID": candidate.request_id,
                        "ARNOLD_LAUNCH_ENVELOPE_DIGEST": candidate.digest,
                    },
                )
                return physical_process
        except OSError as exc:
            raise LaunchDispatchRejected(str(exc)) from exc

    def observe(
        process: subprocess.Popen[bytes], candidate: LaunchEnvelope
    ) -> Mapping[str, Any]:
        pid = int(process.pid)
        start_identity = _pid_start_ticks(pid)
        live = process.poll() is None and bool(start_identity) and _pid_live(pid)
        return {
            "operation_id": candidate.operation_id,
            "request_id": candidate.request_id,
            "envelope_digest": candidate.digest,
            "session_name": run_id,
            "process_session_identity": (
                f"pid:{pid}:start:{start_identity}" if start_identity else ""
            ),
            "pid": pid,
            "process_start_identity": start_identity,
            "liveness": "running" if live else "stopped",
        }

    def resource_factory(
        process: subprocess.Popen[bytes],
        observation: Mapping[str, Any],
        candidate: LaunchEnvelope,
    ) -> TypedResource:
        return TypedResource(
            id=f"launch-process-session:{candidate.operation_id}:{candidate.request_id}",
            operation_id=candidate.operation_id,
            resource_type=ResourceType.PROCESS_SESSION,
            name=str(observation["session_name"]),
            details={
                "provider": "resident-supervisor",
                "session_name": observation["session_name"],
                "pid": observation["pid"],
                "process_start_identity": observation["process_start_identity"],
                "process_session_identity": observation["process_session_identity"],
                "manifest_path": str(manifest_path.resolve()),
                "liveness": observation["liveness"],
            },
        )

    transaction = launch_transaction(
        envelope,
        store=store,
        preflight=preflight,
        dispatch=dispatch,
        observe=observe,
        resource_factory=resource_factory,
        operation_type="resident_managed_supervisor",
    )
    current = dict(manifest)
    current["operation_id"] = operation_id
    current["launch_request_id"] = request_id
    current["launch_envelope_digest"] = envelope.digest
    current["operation_store_root"] = str(store_root.resolve())
    if transaction.result is not DurableLaunchResult.ACCEPTED:
        current.setdefault("launch_outcome", transaction.result.value)
        current.setdefault("launch_reason", transaction.reason.value)
        _atomic_json(manifest_path, current)
        raise _ResidentLaunchUnresolved(transaction)

    accepted_resource = getattr(transaction.store_result, "process_resource", None)
    if accepted_resource is not None:
        details = dict(accepted_resource.details)
        current["pid"] = details.get("pid")
        current["supervisor_start_ticks"] = details.get("process_start_identity")
        current["started_at"] = current.get("started_at") or _utc_now()
    if transaction.reason.name == "REPLAY":
        current = json.loads(manifest_path.read_text(encoding="utf-8"))
        accepted_resource = next(
            (
                resource
                for resource in store.list_typed_resources(operation_id)
                if resource.resource_type is ResourceType.PROCESS_SESSION
            ),
            accepted_resource,
        )
        if accepted_resource is not None:
            details = dict(accepted_resource.details)
            current.setdefault("pid", details.get("pid"))
            current.setdefault("supervisor_start_ticks", details.get("process_start_identity"))
            current.setdefault("started_at", _utc_now())
    if current.get("status") == "launching":
        current["status"] = "running"
        current["updated_at"] = _utc_now()
        history = list(current.get("status_history") or [])
        history.append(
            {
                "status": "running",
                "at": current["updated_at"],
                "evidence": "resident_supervisor_canonical_acceptance",
            }
        )
        current["status_history"] = history[-100:]
    queue = current.get("queue")
    if isinstance(queue, dict):
        queue.update(
            {
                "state": "running",
                "attention": "none",
                "supervisor_started_at": current.get("started_at"),
                "updated_at": current.get("updated_at"),
            }
        )
        current["queue"] = queue
    current["launch_outcome"] = transaction.result.value
    current["launch_reason"] = transaction.reason.value
    _atomic_json(manifest_path, current)
    _emit_managed_child_event(
        manifest_path,
        current,
        event_kind="start",
        surface="resident.subagent.supervisor",
        evidence="resident_supervisor_canonical_acceptance",
        at=str(current.get("updated_at") or current.get("started_at") or _utc_now()),
        details={
            "supervisor_pid": current.get("pid"),
            "operation_id": operation_id,
            "request_id": request_id,
            "envelope_digest": envelope.digest,
        },
    )
    # The physical process handle belongs to the dispatch closure and is not
    # persisted in the canonical store.  Replays therefore return no handle,
    # while the exact PID remains available from the accepted resource.
    return (None if transaction.reason.name == "REPLAY" else physical_process), current


def launch_managed_subagent_detached(
    *,
    task: str,
    description: str | None = None,
    project_dir: str | None = None,
    model: str = "gpt-5.6-terra",
    model_spec: str | None = None,
    provider_probe: Mapping[str, Any] | None = None,
    backend: str = "codex",
    reasoning_effort: str = "medium",
    toolsets: str = "file,web,terminal",
    max_tokens: int = 65_536,
    provider_timeout_s: float | None = None,
    timeout_source: str | None = None,
    task_kind: DelegatedTaskKind = DEFAULT_DELEGATED_TASK_KIND,
    work_intent: DelegatedWorkIntent = DEFAULT_DELEGATED_WORK_INTENT,
    mutation_claim: DelegatedMutationClaim = "auto",
    difficulty: int = DEFAULT_DELEGATED_DIFFICULTY,
    route_class: str = "routine",
    run_root: str | Path = DEFAULT_MANAGED_RUN_ROOT,
    request_id: str | None = None,
    launch_origin: Mapping[str, Any] | None = None,
    retry_of_run_id: str | None = None,
    parent_run_id: str | None = None,
    lineage_root_run_id: str | None = None,
    continued_session_id: str | None = None,
    followup_id: str | None = None,
    parent_manifest_path: str | Path | None = None,
    interrupt_parent: bool = False,
    query_relationship: Mapping[str, Any] | None = None,
    aggregation_role: str = "synthesis_delivery_owner",
    synthesis_group: str | None = None,
    depends_on_run_id: str | None = None,
    depends_on_run_ids: Sequence[str] | None = None,
    queue_max_launch_attempts: int = _QUEUE_MAX_LAUNCH_ATTEMPTS,
    outcome_contract: str | None = None,
    outcome_key: str | None = None,
    delivery_suppression_override_reason: str | None = None,
    schedule_context: Mapping[str, Any] | None = None,
) -> SubagentResult:
    """Launch a durable, fully-permissioned provider worker managed by Arnold.

    The supervisor process owns the manifest transitions and durable output, so
    the Discord resident can return immediately without losing lifecycle state.
    """
    if backend not in {"omp", "codex", "claude"}:
        raise ValueError(f"unsupported durable managed-agent backend: {backend}")
    provider_contract = provider_execution_contract(
        backend=backend,
        toolsets=toolsets,
        max_tokens=max_tokens,
        timeout_s=provider_timeout_s,
        timeout_source=timeout_source,
    )
    normalized_toolsets = tuple(provider_contract["controls"]["toolsets"])
    toolsets = ",".join(normalized_toolsets)
    provider_session_id = continued_session_id or reserve_session_id(backend)
    if provider_session_id and not valid_session_id(backend, provider_session_id):
        raise ValueError(f"invalid {backend} managed-agent session id")
    if len(task) > MAX_DELEGATED_TASK_CHARS:
        raise ValueError(
            f"delegated task exceeds {MAX_DELEGATED_TASK_CHARS} characters; "
            "store large evidence durably and pass paths/routes"
        )
    if DELEGATION_DELIVERY_INSTRUCTION_HEADER in task:
        raise ValueError(
            "delegated task contains the reserved resident delivery instruction marker"
        )
    dependency_run_ids = _normalize_dependency_run_ids(
        depends_on_run_id=depends_on_run_id,
        depends_on_run_ids=depends_on_run_ids,
    )
    if dependency_run_ids and len(task) > MAX_QUEUE_PROMPT_CHARS:
        raise ValueError(
            f"queued successor prompt exceeds {MAX_QUEUE_PROMPT_CHARS} characters"
        )
    if not 1 <= queue_max_launch_attempts <= 10:
        raise ValueError("queue_max_launch_attempts must be between 1 and 10")
    project_root = Path(project_dir or Path.cwd()).resolve()
    requested_root = Path(run_root)
    root = (
        project_root / requested_root
        if not requested_root.is_absolute() and requested_root == DEFAULT_MANAGED_RUN_ROOT
        else requested_root.resolve()
    )
    predecessor_paths: list[Path] = []
    predecessors: list[dict[str, Any]] = []
    predecessor: dict[str, Any] | None = None
    predecessor_references: list[dict[str, Any]] = []
    cross_request_authorizations: list[dict[str, Any]] = []
    queue_aggregation_key: str | None = None
    current_provenance = _canonical_launch_provenance(
        launch_origin,
        project_root=project_root,
        request_id=request_id,
    )
    provenance = current_provenance
    requested_work_intent = work_intent
    requested_mutation_claim = mutation_claim
    if dependency_run_ids:
        for predecessor_run_id in dependency_run_ids:
            predecessor_path = root / predecessor_run_id / "manifest.json"
            if not predecessor_path.is_file():
                raise SubagentQueueError(
                    f"unknown predecessor run_id in project custody: {predecessor_run_id}"
                )
            try:
                current_predecessor = _read_managed_resident_manifest(predecessor_path)
            except SubagentFollowupError as exc:
                raise SubagentQueueError(str(exc)) from exc
            predecessor_project = Path(
                str(current_predecessor.get("project_dir") or "")
            ).resolve()
            if predecessor_project != project_root:
                raise SubagentQueueError(
                    "queued successor must inherit every predecessor project directory"
                )
            predecessor_paths.append(predecessor_path)
            predecessors.append(current_predecessor)
        predecessor = predecessors[0]
        predecessor_provenance = predecessor.get("launch_provenance")
        if not isinstance(predecessor_provenance, Mapping):
            raise SubagentQueueError("predecessor lacks immutable launch provenance")
        predecessor_provenance = normalize_delegation_provenance(predecessor_provenance)
        for current_predecessor in predecessors[1:]:
            candidate_provenance = current_predecessor.get("launch_provenance")
            if not isinstance(candidate_provenance, Mapping) or _queue_provenance_identity(
                normalize_delegation_provenance(candidate_provenance)
            ) != _queue_provenance_identity(predecessor_provenance):
                raise SubagentQueueError(
                    "all predecessors must share one immutable launch provenance"
                )
        same_request = _queue_provenance_identity(current_provenance) == (
            _queue_provenance_identity(predecessor_provenance)
        )
        if same_request:
            provenance = predecessor_provenance
            request_id = str(predecessor.get("request_id") or "") or None
        else:
            current_aggregation: dict[str, Any] | None = None
            current_relationship: dict[str, Any] | None = None
            for predecessor_run_id, current_predecessor in zip(
                dependency_run_ids, predecessors, strict=True
            ):
                authorization, aggregation, relationship = (
                    _cross_request_queue_authorization(
                        root,
                        project_root=project_root,
                        predecessor_run_id=predecessor_run_id,
                        predecessor=current_predecessor,
                        current_provenance=current_provenance,
                        require_active_caller=True,
                    )
                )
                if current_aggregation is not None and (
                    aggregation != current_aggregation
                    or relationship != current_relationship
                ):
                    raise SubagentQueueError(
                        "predecessors resolve to conflicting current delivery custody"
                    )
                cross_request_authorizations.append(authorization)
                current_aggregation = aggregation
                current_relationship = relationship
            assert current_aggregation is not None and current_relationship is not None
            provenance = current_provenance
            request_id = str(current_provenance.get("source_record_id") or "") or None
            query_relationship = current_relationship
            queue_aggregation_key = str(current_aggregation["key"])
            synthesis_group = str(current_aggregation["synthesis_group"])
        model = str(predecessor.get("model") or model)
        reasoning_effort = str(predecessor.get("reasoning_effort") or reasoning_effort)
        task_kind = str(predecessor.get("task_kind") or task_kind)
        predecessor_work_intent = str(
            predecessor.get("work_intent") or requested_work_intent
        )
        if any(
            str(item.get("work_intent") or predecessor_work_intent)
            != predecessor_work_intent
            for item in predecessors[1:]
        ):
            raise SubagentQueueError(
                "all predecessors must share one resolved work_intent"
            )
        if (
            requested_work_intent != "auto"
            and requested_work_intent != predecessor_work_intent
        ):
            raise SubagentQueueError(
                "queued successor must inherit predecessor work_intent; "
                f"requested {requested_work_intent!r}, predecessor has "
                f"{predecessor_work_intent!r}"
            )
        work_intent = predecessor_work_intent
        predecessor_mutation_claim = str(
            predecessor.get("mutation_claim")
            or resolve_delegated_mutation_claim(
                task_kind=task_kind,
                work_intent=resolve_delegated_work_intent(
                    task_kind=task_kind, work_intent=work_intent
                ),
            )
        )
        if any(
            str(item.get("mutation_claim") or predecessor_mutation_claim)
            != predecessor_mutation_claim
            for item in predecessors[1:]
        ):
            raise SubagentQueueError(
                "all predecessors must share one resolved mutation_claim"
            )
        if (
            requested_mutation_claim != "auto"
            and requested_mutation_claim != predecessor_mutation_claim
        ):
            raise SubagentQueueError(
                "queued successor must inherit predecessor mutation_claim; "
                f"requested {requested_mutation_claim!r}, predecessor has "
                f"{predecessor_mutation_claim!r}"
            )
        mutation_claim = predecessor_mutation_claim
        difficulty = int(predecessor.get("difficulty") or difficulty)
        route_class = (
            "queued_successor" if same_request else "queued_cross_request_successor"
        )
        if same_request:
            query_relationship = (
                dict(predecessor["query_relationship"])
                if isinstance(predecessor.get("query_relationship"), Mapping)
                else None
            )
        predecessor_aggregation = predecessor.get("aggregation")
        if not isinstance(predecessor_aggregation, Mapping) or not predecessor_aggregation.get(
            "key"
        ):
            raise SubagentQueueError("predecessor lacks logical aggregation custody")
        if same_request:
            synthesis_group = (
                str(predecessor_aggregation.get("synthesis_group") or "") or None
            )
            for item in predecessors[1:]:
                item_aggregation = item.get("aggregation")
                if (
                    not isinstance(item_aggregation, Mapping)
                    or item_aggregation.get("key") != predecessor_aggregation.get("key")
                    or item.get("query_relationship")
                    != predecessor.get("query_relationship")
                ):
                    raise SubagentQueueError(
                        "all predecessors must share logical aggregation custody"
                    )
        for predecessor_path, current_predecessor in zip(
            predecessor_paths, predecessors, strict=True
        ):
            predecessor_references.extend(
                _queue_predecessor_references(predecessor_path, current_predecessor)
            )
        _queue_ancestor_ids(root, dependency_run_ids)
    effective_task = task
    if dependency_run_ids:
        effective_task = (
            f"{task.rstrip()}\n\n"
            + _render_queue_references(
                predecessor_run_ids=dependency_run_ids,
                references=predecessor_references,
            )
        )
        if len(effective_task) > MAX_DELEGATED_TASK_CHARS:
            raise ValueError(
                "queued predecessor references exceed the bounded delegated prompt budget"
            )
    root.mkdir(parents=True, exist_ok=True)
    is_discord = provenance["applicability"] == "applicable"
    agent_description = concise_agent_description(description, task)
    resolved_work_intent = resolve_delegated_work_intent(
        task_kind=task_kind,
        work_intent=work_intent,
    )
    resolved_mutation_claim = resolve_delegated_mutation_claim(
        task_kind=task_kind,
        work_intent=resolved_work_intent,
        mutation_claim=mutation_claim,
    )
    if aggregation_role not in AGGREGATION_ROLES:
        raise ValueError(
            "aggregation_role must be synthesis_delivery_owner or internal_contributor"
        )
    synthesis_group = str(synthesis_group or "").strip() or None
    if synthesis_group is not None and not _SYNTHESIS_GROUP_RE.fullmatch(synthesis_group):
        raise ValueError("synthesis_group must be a stable 1..80 character identifier")
    if aggregation_role == "internal_contributor" and synthesis_group is None:
        raise ValueError("internal_contributor launches require an explicit synthesis_group")
    resolved_outcome_contract, outcome_contract_authority = infer_outcome_contract(
        task=task,
        description=agent_description,
        task_kind=task_kind,
        aggregation_role=aggregation_role,
        explicit=outcome_contract,
    )
    delivery_policy = delivery_policy_for_launch(
        aggregation_role=aggregation_role,
        outcome_contract=resolved_outcome_contract,
        suppression_override_reason=delivery_suppression_override_reason,
    )
    normalized_outcome_key = str(outcome_key or "").strip() or None
    if normalized_outcome_key is not None and len(normalized_outcome_key) > 160:
        raise ValueError("outcome_key exceeds 160 characters")
    if query_relationship is None and is_discord:
        query_relationship = relationship_from_environment_or_project(
            str(provenance.get("source_record_id") or "") or None,
            project_root=project_root,
        )
    if isinstance(query_relationship, Mapping):
        current_ref = _request_ref(query_relationship, "current_request") or {}
        if (
            str(current_ref.get("source_record_id") or "")
            != str(provenance.get("source_record_id") or "")
        ):
            raise DelegationProvenanceError(
                "query relationship current request conflicts with launch provenance"
            )
    origin = discord_origin_projection(provenance) if is_discord else None
    task_digest = hashlib.sha256(task.encode("utf-8")).hexdigest()
    relationship_digest = hashlib.sha256(
        json.dumps(
            dict(query_relationship) if isinstance(query_relationship, Mapping) else None,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    normalized_schedule_context = (
        json.loads(json.dumps(dict(schedule_context), sort_keys=True, default=str))
        if isinstance(schedule_context, Mapping)
        else None
    )
    if normalized_schedule_context is not None:
        if (
            normalized_schedule_context.get("schema_version")
            != "arnold-resident-schedule-occurrence-v1"
        ):
            raise ValueError(
                "schedule_context requires the resident schedule occurrence v1 schema"
            )
        if not normalized_schedule_context.get("occurrence_key"):
            raise ValueError("schedule_context requires an immutable occurrence_key")
        if len(json.dumps(normalized_schedule_context, sort_keys=True)) > 16_384:
            raise ValueError("schedule_context exceeds the bounded manifest allowance")
    schedule_context_digest = hashlib.sha256(
        json.dumps(
            normalized_schedule_context,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    standalone_delivery_target = _standalone_schedule_discord_target(
        normalized_schedule_context, provenance
    )
    # Discord launch identity is owned by the inbound source record.  A model
    # or compatibility caller may still provide request_id, but it cannot
    # sever custody or turn the same inbound request into duplicate workers.
    launch_selector = str(
        provenance["source_record_id"]
        if is_discord
        else request_id or stable_identity("task", task_digest)
    )
    dependency_identity = (
        dependency_run_ids[0]
        if len(dependency_run_ids) == 1
        else json.dumps(list(dependency_run_ids), separators=(",", ":"))
    )
    launch_key = stable_identity(
        "resident-launch",
        provenance.get("correlation_id") or "not-applicable",
        launch_selector,
        task_digest,
        resolved_work_intent,
        resolved_mutation_claim,
        agent_description,
        aggregation_role,
        synthesis_group or "",
        resolved_outcome_contract,
        normalized_outcome_key or "",
        str(delivery_suppression_override_reason or "").strip(),
        relationship_digest,
        backend,
        model_spec or f"{backend}:{model}",
        reasoning_effort,
        toolsets,
        str(max_tokens),
        str(provider_timeout_s),
        retry_of_run_id or "",
        parent_run_id or "",
        lineage_root_run_id or "",
        continued_session_id or "",
        followup_id or "",
        dependency_identity,
        schedule_context_digest,
    )
    canonical_operation_id = stable_identity("resident-launch-operation", launch_key)
    canonical_request_id = stable_identity("resident-launch-request", launch_key)
    launch_lock = root / ".launch.lock"
    launch_handle = launch_lock.open("a+b")
    fcntl.flock(launch_handle.fileno(), fcntl.LOCK_EX)
    if dependency_run_ids:
        queued_replay = _queued_manifest_replay(root, launch_key)
        if queued_replay is not None:
            existing_path, existing_manifest = queued_replay
            existing_manifest = _recover_idempotent_cross_request_queue(
                existing_path, existing_manifest
            )
            fcntl.flock(launch_handle.fileno(), fcntl.LOCK_UN)
            launch_handle.close()
            return _result_from_manifest(existing_path, existing_manifest)
    # Canonical operation replay is the launch deduplication authority.  The
    # resident manifest is only a delivery/work projection and cannot suppress
    # a physical door on its own.
    canonical_store = FileBackedDurableOpsStore(root / ".durable-ops")
    canonical_inspection = inspect_launch(
        canonical_operation_id,
        store=canonical_store,
    )
    if canonical_inspection.result is DurableLaunchResult.ACCEPTED:
        accepted_resource = next(
            (
                resource
                for resource in canonical_inspection.resources
                if resource.resource_type is ResourceType.PROCESS_SESSION
            ),
            None,
        )
        accepted_details = dict(accepted_resource.details) if accepted_resource else {}
        existing_path = Path(str(accepted_details.get("manifest_path") or ""))
        if existing_path.is_file():
            existing_manifest = json.loads(existing_path.read_text(encoding="utf-8"))
            fcntl.flock(launch_handle.fileno(), fcntl.LOCK_UN)
            launch_handle.close()
            return _result_from_manifest(existing_path, existing_manifest)
        fcntl.flock(launch_handle.fileno(), fcntl.LOCK_UN)
        launch_handle.close()
        return SubagentResult(
            ok=True,
            final_text="",
            stderr="",
            returncode=0,
            run_id=canonical_operation_id,
            status="running",
            pid=accepted_details.get("pid") if isinstance(accepted_details.get("pid"), int) else None,
            description=agent_description,
        )
    if canonical_inspection.operation is not None:
        # An admitted PENDING operation is commit-unknown.  Never manufacture
        # a second run directory or redispatch it from a manifest probe.
        pending_path = next(
            (
                path
                for path in root.glob("*/manifest.json")
                if _manifest_matches_operation(path, canonical_operation_id)
            ),
            None,
        )
        fcntl.flock(launch_handle.fileno(), fcntl.LOCK_UN)
        launch_handle.close()
        if pending_path is not None:
            return _result_from_manifest(
                pending_path,
                json.loads(pending_path.read_text(encoding="utf-8")),
            )
        return SubagentResult(
            ok=False,
            final_text="",
            stderr="",
            returncode=2,
            run_id=canonical_operation_id,
            status="launching",
            description=agent_description,
        )
    created_at = _utc_now()
    aggregation_key = (
        (
            queue_aggregation_key
            or str((predecessor.get("aggregation") or {})["key"])
        )
        if predecessor is not None
        else (
            _aggregation_key(
                provenance,
                synthesis_group=synthesis_group,
                task_digest=task_digest,
                description=agent_description,
                request_id=request_id,
            )
            if is_discord
            else stable_identity("resident-single-delivery", launch_key)
        )
    )
    contributors = (
        _aggregation_contributor_refs(root, aggregation_key=aggregation_key)
        if aggregation_role == "synthesis_delivery_owner"
        else []
    )
    if aggregation_role == "synthesis_delivery_owner" and any(
        contributor.get("aggregation_role") == "synthesis_delivery_owner"
        and contributor.get("delivery_status") == "delivered"
        for contributor in contributors
    ):
        fcntl.flock(launch_handle.fileno(), fcntl.LOCK_UN)
        launch_handle.close()
        raise ValueError("synthesis_group already has a delivered owner")
    run_id = f"subagent-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"
    run_dir = root / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    prompt_path = run_dir / "prompt.md"
    manifest_path = run_dir / "manifest.json"
    log_path = run_dir / "run.log"
    result_path = run_dir / "result.md"
    git_custody_evidence_path = run_dir / "git-custody-evidence.json"
    provider_raw_output_path = run_dir / "provider.raw"
    provider_metadata_path = run_dir / "provider-metadata.json"
    provider_events_path = run_dir / "events.jsonl"
    context_directory = _delegated_context_directory(
        project_root=project_root,
        provenance=provenance,
    )
    git_custody = (
        resolve_launch_git_custody(
            project_root=project_root,
            runtime_root=str(context_directory["resident_runtime_source"]),
            evidence_path=git_custody_evidence_path,
        )
        if resolved_mutation_claim == "git_backed"
        else None
    )
    prompt = _delivery_prompt(
        effective_task,
        str(provenance.get("timezone_name") or "UTC"),
        task_kind=task_kind,
        work_intent=resolved_work_intent,
        mutation_claim=resolved_mutation_claim,
        context_directory=context_directory,
        query_relationship=query_relationship,
        contributors=contributors,
        git_custody=git_custody,
    )
    prompt_path.write_text(prompt, encoding="utf-8")
    result_path.touch()
    log_path.touch()
    provider_raw_output_path.touch()
    provider_events_path.touch()
    if aggregation_role == "synthesis_delivery_owner":
        _transfer_aggregation_delivery_ownership(
            root,
            aggregation_key=aggregation_key,
            new_owner_run_id=run_id,
            at=created_at,
        )
    manifest: dict[str, object] = {
        "schema_version": MANAGED_RUN_SCHEMA,
        "run_kind": MANAGED_RUN_KIND,
        "custodian": MANAGED_RUN_CUSTODIAN,
        "run_id": run_id,
        "backend": backend,
        "model": model,
        "model_spec": model_spec or f"{backend}:{model}",
        "provider_route": {
            "backend": backend,
            "runtime_model": model,
            "model_spec": model_spec or f"{backend}:{model}",
        },
        "provider_probe": dict(provider_probe) if provider_probe is not None else None,
        "reasoning_effort": reasoning_effort,
        "provider_options": {
            "toolsets": toolsets,
            "max_tokens": max_tokens,
            "timeout_s": provider_timeout_s,
        },
        "timeout_policy": {
            "mode": "explicit" if provider_timeout_s is not None else "not_configured",
            "source": timeout_source,
            "timeout_s": provider_timeout_s,
        },
        "provider_contract": provider_contract,
        "task_kind": task_kind,
        "work_intent": resolved_work_intent,
        "mutation_claim": resolved_mutation_claim,
        "delegation_delivery_instruction": {
            "schema_version": DELEGATION_DELIVERY_INSTRUCTION_SCHEMA,
            "resolved_work_intent": resolved_work_intent,
            "resolved_mutation_claim": resolved_mutation_claim,
            "sha256": hashlib.sha256(
                _delegation_delivery_instruction(
                    resolved_work_intent, resolved_mutation_claim
                ).encode("utf-8")
            ).hexdigest(),
        },
        "description": agent_description,
        "difficulty": difficulty,
        "route_class": route_class,
        "sandbox": (
            "danger-full-access"
            if backend == "codex"
            else "provider-permission-policy"
            if backend == "claude"
            else "inherited-full-machine-access"
        ),
        "project_dir": str(project_root),
        "manifest_path": str(manifest_path),
        "prompt_path": str(prompt_path),
        "log_path": str(log_path),
        "full_log_path": str(log_path),
        "result_path": str(result_path),
        "provider_raw_output_path": str(provider_raw_output_path),
        "provider_metadata_path": str(provider_metadata_path),
        "provider_events_path": str(provider_events_path),
        "telemetry": {
            "schema_version": PROVIDER_TELEMETRY_SCHEMA,
            "status": "pending",
            "normalized_events_path": str(provider_events_path),
            "raw_output_path": str(provider_raw_output_path),
            "raw_stream_contract": provider_contract["capabilities"]["raw_stream"],
            "raw_streams_are_provider_specific": True,
        },
        "task_sha256": task_digest,
        "prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
        "context_directory": context_directory,
        "completion_verification_contract": {
            "schema_version": COMPLETION_VERIFICATION_SCHEMA,
            "applicability": "applicable",
            "result_requirement": "worker_exit_zero",
            "git_custody_requirement": (
                "strict" if resolved_mutation_claim == "git_backed" else "not_applicable"
            ),
            "basis": {
                "task_kind": task_kind,
                "work_intent": resolved_work_intent,
                "mutation_claim": resolved_mutation_claim,
            },
        },
        **({"git_custody": git_custody} if git_custody is not None else {}),
        "launch_idempotency_key": launch_key,
        "operation_id": canonical_operation_id,
        "launch_request_id": canonical_request_id,
        "schedule_occurrence": normalized_schedule_context,
        "correlation_id": provenance.get("correlation_id") or run_id,
        "custody_id": provenance.get("custody_id") or stable_identity("resident-custody", run_id),
        "launch_provenance": provenance,
        "query_relationship": dict(query_relationship) if isinstance(query_relationship, Mapping) else None,
        "aggregation": {
            "schema_version": AGGREGATION_SCHEMA,
            "key": aggregation_key,
            "synthesis_group": synthesis_group,
            "role": aggregation_role,
            "delivery_owner_run_id": (
                run_id if aggregation_role == "synthesis_delivery_owner" else None
            ),
            "delivery_target_source_record_id": provenance.get("source_record_id"),
            "contributors": contributors,
        },
        "status": "queued" if dependency_run_ids else "launching",
        "execution_contract": {
            "schema_version": DELIVERY_STATUS_SCHEMA,
            "outcome_contract": resolved_outcome_contract,
            "outcome_contract_authority": outcome_contract_authority,
            "outcome_key": normalized_outcome_key or task_digest,
            "delivery_policy": delivery_policy,
            "delivery_suppression_override_reason": (
                str(delivery_suppression_override_reason or "").strip() or None
            ),
        },
        "lifecycle": {
            "schema_version": DELIVERY_STATUS_SCHEMA,
            "work": {"status": "launching", "worker_completed": False},
            "delivery": {
                "status": "pending" if delivery_policy.startswith("deliver_") else "suppressed",
                "policy": delivery_policy,
            },
            "request": {"status": "in_progress", "request_delivered": False},
        },
        "status": "launching",
        "created_at": created_at,
        "updated_at": created_at,
        "status_history": [
            {
                "status": "queued" if dependency_run_ids else "launching",
                "at": created_at,
                "evidence": (
                    "successor_committed_waiting_for_predecessor_terminal_evidence"
                    if dependency_run_ids
                    else "manifest_committed_before_process_launch"
                ),
            }
        ],
    }
    if dependency_run_ids:
        predecessor_states = [
            _queue_predecessor_state(run_id, path, item)
            for run_id, path, item in zip(
                dependency_run_ids, predecessor_paths, predecessors, strict=True
            )
        ]
        waiting_state, waiting_attention = _queue_waiting_labels(dependency_run_ids)
        manifest["queue"] = {
            "schema_version": QUEUE_SCHEMA,
            "trigger_policy": QUEUE_TRIGGER_POLICY,
            "state": waiting_state,
            "predecessor_run_ids": list(dependency_run_ids),
            "successor_run_id": run_id,
            "authored_prompt": {
                "sha256": task_digest,
                "size_chars": len(task),
                "description": agent_description,
            },
            "predecessor_references": predecessor_references,
            "predecessor_states": predecessor_states,
            "ancestor_run_ids": _queue_ancestor_ids(root, dependency_run_ids),
            "attempt_count": 0,
            "max_launch_attempts": queue_max_launch_attempts,
            "created_at": created_at,
            "updated_at": created_at,
            "attention": waiting_attention,
        }
        if len(dependency_run_ids) == 1:
            manifest["queue"]["predecessor_run_id"] = dependency_run_ids[0]
            manifest["queue"]["predecessor_status"] = predecessor_states[0][
                "status"
            ]
        if cross_request_authorizations:
            if len(cross_request_authorizations) == 1:
                manifest["queue"]["cross_request_authorization"] = (
                    cross_request_authorizations[0]
                )
            else:
                manifest["queue"]["cross_request_authorizations"] = (
                    cross_request_authorizations
                )
        manifest["parent_run_id"] = dependency_run_ids[0]
        manifest["lineage_root_run_id"] = str(
            predecessor.get("lineage_root_run_id")
            or predecessor.get("run_id")
            or dependency_run_ids[0]
        )
        manifest["lineage_key"] = stable_identity(
            "resident-session-lineage", manifest["lineage_root_run_id"]
        )
    if retry_of_run_id:
        manifest["retry_of_run_id"] = retry_of_run_id
    if parent_run_id:
        manifest["parent_run_id"] = parent_run_id
    if lineage_root_run_id:
        manifest["lineage_root_run_id"] = lineage_root_run_id
        manifest["lineage_key"] = stable_identity(
            "resident-session-lineage", lineage_root_run_id
        )
    if followup_id:
        manifest["followup_id"] = followup_id
        manifest["run_mode"] = "session_continuation"
    if continued_session_id:
        manifest["continued_session_id"] = continued_session_id
    if provider_session_id:
        manifest["model_session"] = {
            "provider": backend,
            "session_id": provider_session_id,
            "lineage_root_run_id": lineage_root_run_id or run_id,
            "state": "continuing" if continued_session_id else "reserved",
            "persistence": "durable",
            "resume_semantics": "exact_session",
            "evidence": "resident_reserved_before_provider_process_start",
            "recorded_at": created_at,
        }
    if parent_manifest_path:
        manifest["parent_manifest_path"] = str(Path(parent_manifest_path).resolve())
        manifest["continuation_wait"] = {
            "status": "pending_parent_terminal",
            "parent_run_id": parent_run_id,
            "parent_manifest_path": str(Path(parent_manifest_path).resolve()),
            "committed_at": created_at,
        }
        if interrupt_parent:
            manifest["continuation_wait"]["interrupt_parent_on_session_ready"] = True
    if is_discord:
        manifest["request_id"] = provenance["source_record_id"]
        if request_id and request_id != provenance["source_record_id"]:
            manifest["caller_request_id"] = request_id
        manifest["resident_conversation_id"] = provenance["resident_conversation_id"]
        manifest["source_record_id"] = provenance["source_record_id"]
    elif request_id:
        manifest["request_id"] = request_id
    if origin is not None:
        manifest["discord_origin"] = origin
        manifest["completion_delivery"] = {
            "transport": "discord",
            "status": (
                "pending"
                if delivery_policy.startswith("deliver_")
                else "suppressed"
            ),
            "attempt_count": 0,
            "custody_id": manifest["custody_id"],
            "outbox_id": stable_identity("discord-outbox", run_id, origin["reply_to_message_id"]),
            "aggregation_key": aggregation_key,
            "aggregation_role": aggregation_role,
            "idempotency_key": f"resident-subagent-completion:{run_id}",
            "reply_target": {
                "conversation_key": origin["conversation_key"],
                "message_id": origin["reply_to_message_id"],
                "source_record_id": provenance["source_record_id"],
            },
            "state_history": [
                {
                    "status": (
                        "pending"
                        if delivery_policy.startswith("deliver_")
                        else "suppressed"
                    ),
                    "at": manifest["created_at"],
                    "evidence": (
                        "outbox_committed_before_launch"
                        if delivery_policy.startswith("deliver_")
                        else "intentional_delivery_suppression_recorded"
                    ),
                }
            ],
        }
    elif standalone_delivery_target is not None:
        manifest["discord_delivery_target"] = standalone_delivery_target
        manifest["completion_delivery"] = {
            "transport": "discord",
            "delivery_mode": "standalone",
            "status": (
                "pending" if delivery_policy.startswith("deliver_") else "suppressed"
            ),
            "attempt_count": 0,
            "custody_id": manifest["custody_id"],
            "outbox_id": stable_identity(
                "discord-outbox", run_id, standalone_delivery_target["conversation_key"]
            ),
            "aggregation_key": aggregation_key,
            "aggregation_role": aggregation_role,
            "idempotency_key": f"resident-subagent-completion:{run_id}",
            "destination": {
                "conversation_key": standalone_delivery_target["conversation_key"],
            },
            "state_history": [{
                "status": (
                    "pending" if delivery_policy.startswith("deliver_") else "suppressed"
                ),
                "at": manifest["created_at"],
                "evidence": (
                    "standalone_outbox_committed_before_launch"
                    if delivery_policy.startswith("deliver_")
                    else "intentional_delivery_suppression_recorded"
                ),
            }],
        }
    else:
        manifest["completion_delivery"] = {
            "transport": "non_discord",
            "status": "not_applicable",
            "attempt_count": 0,
            "custody_id": manifest["custody_id"],
            "evidence": "launch_provenance_explicitly_non_discord",
        }
    manifest["lifecycle"]["delivery"]["status"] = str(
        dict(manifest["completion_delivery"]).get("status") or "not_applicable"
    )
    custody_path = ensure_managed_child_custody_fields(manifest_path, manifest)
    _atomic_json(manifest_path, manifest)
    _emit_managed_child_event(
        manifest_path,
        manifest,
        event_kind="start",
        surface="resident.subagent.launch",
        evidence=(
            "successor_committed_waiting_for_predecessor_terminal_evidence"
            if dependency_run_ids
            else "manifest_committed_before_process_launch"
        ),
        at=created_at,
        details={
            "custody_evidence_path": str(custody_path),
            "queued": bool(dependency_run_ids),
            "git_custody": git_custody_projection(git_custody),
            "reply_chain_custody": reply_chain_projection(
                (query_relationship or {}).get("reply_chain_provenance")
                if isinstance(query_relationship, Mapping)
                else None
            ),
        },
    )
    if dependency_run_ids:
        for predecessor_path in predecessor_paths:
            linked_predecessor = json.loads(
                predecessor_path.read_text(encoding="utf-8")
            )
            links = dict(linked_predecessor.get("queue_links") or {})
            successor_ids = [
                str(value)
                for value in links.get("successor_run_ids", [])
                if str(value).strip() and str(value) != run_id
            ]
            successor_ids.append(run_id)
            links.update(
                {
                    "schema_version": QUEUE_SCHEMA,
                    "successor_run_ids": successor_ids[-20:],
                    "successor_omitted_count": max(0, len(successor_ids) - 20),
                    "updated_at": created_at,
                }
            )
            linked_predecessor["queue_links"] = links
            _atomic_json(predecessor_path, linked_predecessor)
        fcntl.flock(launch_handle.fileno(), fcntl.LOCK_UN)
        launch_handle.close()
        return SubagentResult(
            ok=True,
            final_text="",
            stderr="",
            returncode=0,
            run_id=run_id,
            status="queued",
            manifest_path=str(manifest_path),
            log_path=str(log_path),
            result_path=str(result_path),
            custody_evidence_path=str(manifest.get("custody_evidence_path") or "") or None,
            delivery_owner_run_id=(
                managed_child_delivery_projection(manifest).get("delivery_owner_run_id")
            ),
            parent_owned_delivery=bool(
                managed_child_delivery_projection(manifest).get("parent_owned_delivery")
            ),
            pid=None,
            description=agent_description,
        )
    # Once the manifest exists, concurrent/restarted callers can return its
    # durable identity without creating a second worker.  Process start is a
    # recoverable transition from this point onward.
    fcntl.flock(launch_handle.fileno(), fcntl.LOCK_UN)
    launch_handle.close()
    try:
        process, current = _spawn_managed_supervisor(manifest_path, manifest)
    except _ResidentLaunchUnresolved as exc:
        unresolved = json.loads(manifest_path.read_text(encoding="utf-8"))
        delivery = managed_child_delivery_projection(unresolved)
        return SubagentResult(
            ok=False,
            final_text="",
            stderr="",
            returncode=2,
            run_id=run_id,
            status="unknown",
            manifest_path=str(manifest_path),
            log_path=str(log_path),
            result_path=str(result_path),
            custody_evidence_path=str(unresolved.get("custody_evidence_path") or "") or None,
            delivery_owner_run_id=delivery.get("delivery_owner_run_id"),
            parent_owned_delivery=bool(delivery.get("parent_owned_delivery")),
            pid=None,
            description=agent_description,
        )
    status = str(current.get("status") or "running")
    delivery = managed_child_delivery_projection(current)
    return SubagentResult(
        ok=status not in {"failed", "interrupted"},
        final_text="",
        stderr="",
        returncode=int(current.get("returncode") or 0),
        run_id=run_id,
        status=status,
        manifest_path=str(manifest_path),
        log_path=str(log_path),
        result_path=str(result_path),
        custody_evidence_path=str(current.get("custody_evidence_path") or "") or None,
        delivery_owner_run_id=delivery.get("delivery_owner_run_id"),
        parent_owned_delivery=bool(delivery.get("parent_owned_delivery")),
        pid=(process.pid if process is not None else current.get("pid")),
        description=agent_description,
    )


def launch_codex_subagent_detached(**kwargs: Any) -> SubagentResult:
    """Compatibility wrapper for existing Codex-only callers and continuations."""

    requested_backend = str(kwargs.pop("backend", "codex"))
    if requested_backend != "codex":
        raise ValueError("launch_codex_subagent_detached only accepts backend='codex'")
    kwargs.setdefault("model_spec", f"codex:{kwargs.get('model', 'gpt-5.6-terra')}")
    return launch_managed_subagent_detached(backend="codex", **kwargs)


def _interrupt_parent_for_followup(
    *,
    parent_path: Path,
    continuation_manifest: Mapping[str, Any],
    session_id: str,
) -> str:
    """Request one exact resident supervisor to stop its active model turn.

    This is deliberately narrower than process-group or terminal cleanup: the
    PID must still execute the resident subagent supervisor with this exact
    manifest path.  Custody and delivery supersession are committed before the
    signal so a restart cannot publish a misleading terminal-failure reply for
    the interrupted turn.
    """

    with (parent_path.parent / ".followup-interrupt.lock").open("a+b") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        parent = _read_managed_resident_manifest(parent_path)
        parent_run_id = str(parent.get("run_id") or parent_path.parent.name)
        expected_parent = str(continuation_manifest.get("parent_run_id") or "")
        if parent_run_id != expected_parent:
            raise SubagentFollowupError("continuation parent identity changed")
        expected_lineage = str(
            continuation_manifest.get("lineage_root_run_id") or ""
        )
        if _lineage_root_id(parent, parent_path) != expected_lineage:
            raise SubagentFollowupError("continuation parent lineage ownership changed")
        status = str(parent.get("status") or "unknown")
        if status in {"completed", "failed", "interrupted"}:
            return "parent_already_terminal"
        if status not in _ACTIVE_STATUSES:
            raise SubagentFollowupError(
                f"continuation parent entered unsafe status: {status}"
            )
        session_ids = _manifest_session_ids(parent_path, parent)
        if session_ids != {session_id}:
            raise SubagentFollowupError(
                "active parent session evidence changed before interruption"
            )
        pid = parent.get("pid")
        if not isinstance(pid, int) or not _pid_matches_manifest(pid, parent_path):
            raise SubagentFollowupError(
                "continuation parent lost its resident-managed supervisor"
            )
        requested_at = _utc_now()
        interrupt = {
            "schema_version": "arnold-resident-followup-interrupt-v1",
            "status": "requested",
            "requested_at": requested_at,
            "followup_id": continuation_manifest.get("followup_id"),
            "continuation_run_id": continuation_manifest.get("run_id")
            or continuation_manifest.get("continuation_run_id"),
            "session_id": session_id,
            "signal": "SIGINT",
            "evidence": "exact_manifest_supervisor_identity_verified",
        }
        parent["followup_interrupt"] = interrupt
        delivery = parent.get("completion_delivery")
        if isinstance(delivery, dict) and delivery.get("status") != "delivered":
            delivery.update(
                {
                    "status": "superseded",
                    "superseded_at": requested_at,
                    "superseded_by_run_id": interrupt["continuation_run_id"],
                    "superseded_reason": "active_turn_interrupted_for_same_session_followup",
                    "updated_at": requested_at,
                }
            )
            history = list(delivery.get("state_history") or [])
            history.append(
                {
                    "status": "superseded",
                    "at": requested_at,
                    "evidence": "same_session_followup_interrupt_committed",
                    "continuation_run_id": interrupt["continuation_run_id"],
                }
            )
            delivery["state_history"] = history[-20:]
            parent["completion_delivery"] = delivery
        _atomic_json(parent_path, parent)
        try:
            signal_managed_process(
                parent_path,
                parent,
                pid,
                signal.SIGINT,
                cause_kind="terminate",
                ladder_step="term",
            )
        except ProcessLookupError:
            latest = _read_managed_resident_manifest(parent_path)
            if str(latest.get("status") or "") not in {
                "completed",
                "failed",
                "interrupted",
            }:
                raise SubagentFollowupError(
                    "managed supervisor exited before interruption was accepted"
                )
            return "parent_became_terminal"
        return "interrupt_requested"


def _await_continuation_parent(
    manifest_path: Path, manifest: dict[str, Any]
) -> tuple[dict[str, Any], str]:
    parent_path = Path(str(manifest.get("parent_manifest_path") or ""))
    parent_run_id = str(manifest.get("parent_run_id") or "")
    backend = str(manifest.get("backend") or "codex")
    if not parent_path.is_absolute() or parent_path.name != "manifest.json":
        raise SubagentFollowupError("continuation parent manifest path is malformed")
    interrupt_requested = False
    while True:
        parent = _read_managed_resident_manifest(parent_path)
        if str(parent.get("run_id") or parent_path.parent.name) != parent_run_id:
            raise SubagentFollowupError("continuation parent identity changed")
        if _lineage_root_id(parent, parent_path) != str(manifest.get("lineage_root_run_id") or ""):
            raise SubagentFollowupError("continuation parent lineage ownership changed")
        status = str(parent.get("status") or "unknown")
        if status in {"completed", "failed", "interrupted"}:
            ids = _manifest_session_ids(parent_path, parent)
            expected = str(manifest.get("continued_session_id") or "").strip().lower()
            if expected:
                ids.add(expected)
            if len(ids) != 1:
                raise SubagentFollowupError(
                    "continuation parent has no unique persistent model session"
                )
            session_id = next(iter(ids))
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["continued_session_id"] = session_id
            manifest["model_session"] = {
                "provider": backend,
                "session_id": session_id,
                "lineage_root_run_id": manifest.get("lineage_root_run_id"),
                "evidence": "validated_from_terminal_parent",
                "source_run_id": parent_run_id,
                "recorded_at": _utc_now(),
            }
            continuation_wait = dict(manifest.get("continuation_wait") or {})
            continuation_wait.update(
                {
                    "status": "parent_terminal",
                    "parent_status": status,
                    "resolved_at": _utc_now(),
                }
            )
            manifest["continuation_wait"] = continuation_wait
            _atomic_json(manifest_path, manifest)
            return manifest, session_id
        if status in {"cancelled", "superseded"}:
            raise SubagentFollowupError(
                f"continuation parent entered intentionally terminal status: {status}"
            )
        if status not in _ACTIVE_STATUSES:
            raise SubagentFollowupError(
                f"continuation parent entered unsafe status: {status}"
            )
        parent_pid = parent.get("pid")
        if not isinstance(parent_pid, int) or not _pid_matches_manifest(parent_pid, parent_path):
            raise SubagentFollowupError(
                "continuation parent lost its resident-managed supervisor"
            )
        continuation_wait = dict(manifest.get("continuation_wait") or {})
        if (
            continuation_wait.get("interrupt_parent_on_session_ready")
            and not interrupt_requested
        ):
            expected = str(manifest.get("continued_session_id") or "").strip().lower()
            if not expected:
                raise SubagentFollowupError(
                    "active continuation has no committed session identity"
                )
            disposition = _interrupt_parent_for_followup(
                parent_path=parent_path,
                continuation_manifest=manifest,
                session_id=expected,
            )
            interrupt_requested = True
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            continuation_wait = dict(manifest.get("continuation_wait") or {})
            continuation_wait.update(
                {
                    "status": disposition,
                    "interrupt_requested_at": _utc_now(),
                    "session_id": expected,
                }
            )
            manifest["continuation_wait"] = continuation_wait
            _atomic_json(manifest_path, manifest)
        time.sleep(1)


def _verify_managed_completion_contract(
    manifest_path: Path, manifest: Mapping[str, Any]
) -> dict[str, Any]:
    """Apply only the completion checks that the run's effect claim requires."""

    if not any(
        field in manifest
        for field in (
            "completion_verification_contract",
            "mutation_claim",
            "work_intent",
        )
    ):
        return {
            "schema_version": COMPLETION_VERIFICATION_SCHEMA,
            "status": "success",
            "classification": "legacy_lifecycle_success",
            "git_custody": "not_declared_by_legacy_manifest",
            "basis": {"manifest_contract": "legacy_pre_verification_contract"},
        }
    task_kind = str(manifest.get("task_kind") or DEFAULT_DELEGATED_TASK_KIND)
    work_intent = str(manifest.get("work_intent") or "execution")
    mutation_claim = str(
        manifest.get("mutation_claim")
        or resolve_delegated_mutation_claim(
            task_kind=task_kind,
            work_intent=work_intent,
        )
    )
    evidence_path = manifest_path.parent / "git-custody-evidence.json"
    if mutation_claim == "none":
        if evidence_path.exists():
            raise GitCustodyError(
                "non-mutating completion contract received a git-backed mutation claim; "
                "relaunch with mutation_claim='git_backed'"
            )
        return {
            "schema_version": COMPLETION_VERIFICATION_SCHEMA,
            "status": "success",
            "classification": "applicable_non_mutating_success",
            "git_custody": "not_applicable",
            "basis": {
                "task_kind": task_kind,
                "work_intent": work_intent,
                "mutation_claim": mutation_claim,
            },
        }
    custody = manifest.get("git_custody")
    if not isinstance(custody, Mapping):
        raise GitCustodyError("git-backed mutation is missing launch custody")
    verified = validate_git_custody_evidence(custody)
    return {
        "schema_version": COMPLETION_VERIFICATION_SCHEMA,
        "status": "success",
        "classification": "git_backed_mutation_custody_verified",
        "git_custody": "verified",
        "basis": {
            "task_kind": task_kind,
            "work_intent": work_intent,
            "mutation_claim": mutation_claim,
        },
        "evidence": verified,
    }


def _summarize_completed_session(manifest_path: Path) -> None:
    """Mandatory post-session hook: DeepSeek Flash writes the 2-sentence summary.

    Runs from the terminal path (success/failure/timeout/kill) and never breaks
    the run. Summary written to <project>/.megaplan/fixer-sessions/summaries/.
    """
    try:
        m = json.loads(manifest_path.read_text(encoding="utf-8"))
        run_dir = manifest_path.parent
        session_id = run_dir.name
        project = str(m.get("project_dir") or run_dir.parents[4])
        store = Path(project) / ".megaplan" / "fixer-sessions"
        from arnold_pipelines.megaplan.cloud.summarize_fixer_session import summarize
        summarize(run_dir, store, session_id)
    except Exception:
        LOGGER.exception("post-session summarizer failed run_id=%s", manifest_path.parent.name)


def _run_managed_manifest(manifest_path: Path) -> int:
    execution_handle = (manifest_path.parent / ".execution.lock").open("a+b")
    try:
        fcntl.flock(execution_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        execution_handle.close()
        # Another manifest-bound supervisor owns the only execution lease.
        return 0
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    # The parent resident process owns the physical supervisor admission.  A
    # just-started supervisor must wait for the parent's exact accepted tuple
    # before it can open the nested provider/session door; otherwise a fast
    # child could bypass accepted-only custody between Popen and the store
    # replacement.  This is observation-only and has no redispatch path.
    operation_id = str(manifest.get("operation_id") or "")
    operation_store_root = str(manifest.get("operation_store_root") or "")
    if operation_id and operation_store_root:
        canonical_store = FileBackedDurableOpsStore(operation_store_root)
        deadline = time.monotonic() + 5.0
        while True:
            inspection = inspect_launch(operation_id, store=canonical_store)
            if inspection.result is DurableLaunchResult.ACCEPTED:
                break
            if time.monotonic() >= deadline:
                fcntl.flock(execution_handle.fileno(), fcntl.LOCK_UN)
                execution_handle.close()
                return 2
            time.sleep(0.01)
    if str(manifest.get("status") or "") in _TERMINAL_STATUSES:
        fcntl.flock(execution_handle.fileno(), fcntl.LOCK_UN)
        execution_handle.close()
        return int(manifest.get("returncode") or 0)
    prompt = Path(str(manifest["prompt_path"])).read_text(encoding="utf-8")
    result_path = Path(str(manifest["result_path"]))
    raw_output_path = Path(
        str(manifest.get("provider_raw_output_path") or manifest_path.parent / "provider.raw")
    )
    metadata_path = Path(
        str(manifest.get("provider_metadata_path") or manifest_path.parent / "provider-metadata.json")
    )
    events_path = Path(
        str(manifest.get("provider_events_path") or manifest_path.parent / "events.jsonl")
    )
    raw_output_path.touch(exist_ok=True)
    events_path.touch(exist_ok=True)
    manifest.setdefault("log_path", str(manifest_path.parent / "run.log"))
    manifest.setdefault("provider_raw_output_path", str(raw_output_path))
    manifest.setdefault("provider_metadata_path", str(metadata_path))
    manifest.setdefault("provider_events_path", str(events_path))
    manifest.setdefault(
        "telemetry",
        {
            "schema_version": PROVIDER_TELEMETRY_SCHEMA,
            "status": "pending",
            "normalized_events_path": str(events_path),
            "raw_output_path": str(raw_output_path),
            "raw_streams_are_provider_specific": True,
        },
    )
    _atomic_json(manifest_path, manifest)
    worker: subprocess.Popen[bytes] | None = None
    raw_handle: Any = None
    session_id: str | None = None
    interrupted_signal: int | None = None
    backend = str(manifest.get("backend") or "codex")
    provider_permission_mode: str | None = None
    provider_options = dict(manifest.get("provider_options") or {})
    timeout_s = _explicit_manifest_timeout(manifest)

    def _cleanup_held(result: Any, *, reason: str, error: BaseException | None = None) -> int:
        """Retain custody when the worker signal door refuses cleanup.

        In particular, never convert an uncertified live child into a terminal
        failure merely because the supervisor timed out while trying to stop it.
        Orphan reconciliation can inspect this durable hold later.
        """
        held = {
            "classification": "cleanup_held",
            "reason": reason,
            "signal_result": result if isinstance(result, Mapping) else {"authorized": False},
            "recorded_at": _utc_now(),
        }
        if error is not None:
            held["error_class"] = error.__class__.__name__
            held["error_message"] = str(error)
        manifest["cleanup_hold"] = held
        manifest["error_class"] = "WorkerCleanupHeld"
        manifest["error_message"] = reason
        manifest["updated_at"] = held["recorded_at"]
        history = list(manifest.get("status_history") or [])
        history.append({"status": manifest.get("status", "running"), "at": held["recorded_at"], "evidence": "worker_cleanup_held"})
        manifest["status_history"] = history[-100:]
        _atomic_json(manifest_path, manifest)
        return 75

    def _interrupt(signum: int, _frame: object) -> None:
        nonlocal interrupted_signal
        interrupted_signal = signum
        raise KeyboardInterrupt

    prior_handlers = {
        signum: signal.signal(signum, _interrupt)
        for signum in (signal.SIGINT, signal.SIGTERM)
    }
    try:
        if manifest.get("run_mode") == "session_continuation":
            manifest, session_id = _await_continuation_parent(manifest_path, manifest)
        else:
            model_session = manifest.get("model_session")
            if isinstance(model_session, Mapping):
                session_id = str(model_session.get("session_id") or "") or None
            if session_id is None:
                session_id = reserve_session_id(backend)
                if session_id:
                    manifest["model_session"] = {
                        "provider": backend,
                        "session_id": session_id,
                        "lineage_root_run_id": manifest.get("lineage_root_run_id")
                        or manifest.get("run_id")
                        or manifest_path.parent.name,
                        "state": "reserved",
                        "persistence": "durable",
                        "resume_semantics": "exact_session",
                        "evidence": "legacy_manifest_session_reserved_by_worker",
                        "recorded_at": _utc_now(),
                    }
                    _atomic_json(manifest_path, manifest)

        if backend == "codex" and manifest.get("run_mode") == "session_continuation":
            argv = [
                "codex",
                "exec",
                "resume",
                "--json",
                "--skip-git-repo-check",
                "--dangerously-bypass-approvals-and-sandbox",
                "-m",
                str(manifest["model"]),
                "-c",
                f"model_reasoning_effort={manifest['reasoning_effort']}",
                "--output-last-message",
                str(result_path),
                session_id,
                prompt,
            ]
        elif backend == "codex":
            argv = [
                "codex",
                "exec",
                "--json",
                "--skip-git-repo-check",
                "--sandbox",
                "danger-full-access",
                "-m",
                str(manifest["model"]),
                "-c",
                f"model_reasoning_effort={manifest['reasoning_effort']}",
                "--output-last-message",
                str(result_path),
                prompt,
            ]
        elif backend == "omp":
            if not OMP_LAUNCHER_PATH.exists():
                raise FileNotFoundError(f"omp launcher not found: {OMP_LAUNCHER_PATH}")
            argv = [
                sys.executable,
                str(OMP_LAUNCHER_PATH),
                "--model",
                str(manifest["model"]),
                "--toolsets",
                str(provider_options.get("toolsets") or "file,web,terminal"),
                "--max-tokens",
                str(int(provider_options.get("max_tokens") or 65_536)),
                "--project-dir",
                str(manifest["project_dir"]),
                "--query-file",
                str(manifest["prompt_path"]),
                "--session-id",
                str(session_id),
                "--metadata-file",
                str(metadata_path),
            ]
            if manifest.get("run_mode") == "session_continuation":
                argv.append("--resume-session")
        elif backend == "claude":
            if not CLAUDE_LAUNCHER_PATH.exists():
                raise FileNotFoundError(f"Claude launcher not found: {CLAUDE_LAUNCHER_PATH}")
            toolsets = normalize_toolsets(str(provider_options.get("toolsets") or ""))
            argv = [
                sys.executable,
                str(CLAUDE_LAUNCHER_PATH),
                "--model",
                str(manifest["model"]),
                "--project-dir",
                str(manifest["project_dir"]),
                "--query-file",
                str(manifest["prompt_path"]),
                "--output-format",
                "stream-json",
                "--verbose",
                "--tools",
                claude_tools_for(toolsets),
            ]
            if timeout_s is not None:
                argv[argv.index("--output-format"):argv.index("--output-format")] = ["--timeout", str(timeout_s)]
            if manifest.get("run_mode") == "session_continuation":
                argv += ["--resume", str(session_id)]
            else:
                argv += ["--session-id", str(session_id)]
            if hasattr(os, "geteuid") and os.geteuid() == 0:
                provider_permission_mode = "auto"
                argv += ["--permission-mode", provider_permission_mode]
            else:
                provider_permission_mode = "bypassPermissions"
                argv.append("--dangerously-skip-permissions")
            effort = str(manifest.get("reasoning_effort") or "")
            if effort in {"low", "medium", "high", "xhigh", "max"}:
                argv += ["--effort", effort]
        else:
            raise ValueError(f"unsupported managed-agent backend in manifest: {backend}")
        launch_provenance = manifest.get("launch_provenance")
        worker_env = None
        if isinstance(launch_provenance, Mapping):
            worker_provenance = dict(launch_provenance)
            if worker_provenance.get("applicability") == "applicable":
                worker_provenance["root_run_id"] = str(
                    manifest.get("run_id") or manifest_path.parent.name
                )
            worker_env = environment_with_provenance(worker_provenance)
        if worker_env is None:
            worker_env = os.environ.copy()
        if backend == "omp":
            # The launcher is executed from the resident package, but its
            # process cwd is the target project.  Without an explicit runtime
            # root, the launcher's fallback discovery selects the
            # target checkout (or a stale global PYTHONPATH), so an editable
            # runtime patch is not actually the code the fixer imports.
            # Bind the provider process to the same approved runtime source
            # recorded in launch custody and make that identity observable to
            # every terminal command it delegates.
            context_directory = manifest.get("context_directory")
            runtime_root = (
                context_directory.get("resident_runtime_source")
                if isinstance(context_directory, Mapping)
                else None
            )
            if not runtime_root:
                launch_custody = manifest.get("git_custody")
                runtime_root = (
                    launch_custody.get("runtime_root")
                    if isinstance(launch_custody, Mapping)
                    else None
                )
            if runtime_root:
                runtime_root = str(Path(str(runtime_root)).expanduser().resolve())
                worker_env["ARNOLD_PATH"] = runtime_root
                prior_pythonpath = worker_env.get("PYTHONPATH", "")
                worker_env["PYTHONPATH"] = os.pathsep.join(
                    part for part in (runtime_root, prior_pythonpath) if part
                )
        if backend == "omp" and timeout_s is None:
            worker_env["ARNOLD_RESIDENT_UNBOUNDED_REQUEST"] = "1"
        if backend == "claude":
            worker_env["CLAUDE_CODE_MAX_OUTPUT_TOKENS"] = str(
                int(provider_options.get("max_tokens") or 65_536)
            )
        context_payload = manifest.get("worker_execution_context")
        if isinstance(context_payload, Mapping):
            worker_env["ARNOLD_WORKER_EXECUTION_CONTEXT"] = json.dumps(
                dict(context_payload), sort_keys=True, separators=(",", ":")
            )
        raw_handle = raw_output_path.open("wb")
        worker = subprocess.Popen(
            argv,
            cwd=str(manifest["project_dir"]),
            stdin=subprocess.DEVNULL,
            stdout=raw_handle,
            env=worker_env,
        )
        # Reload before updating so the supervisor PID written by the launch
        # process cannot be lost to a parent/child manifest race.
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        ensure_managed_child_custody_fields(manifest_path, manifest)
        canonical_door = os.environ.get("ARNOLD_CANONICAL_LAUNCH_ACTIVE") == "1"
        worker_started_at = _utc_now()
        if not canonical_door:
            manifest.update({"worker_started_at": worker_started_at, "worker_pid": worker.pid})
            manifest["worker_start_ticks"] = _pid_start_ticks(worker.pid)
            manifest["worker_identity"] = _managed_worker_identity(
                worker.pid, manifest["worker_start_ticks"]
            )
            manifest["worker_launch_certified"] = certify_managed_worker_launch(
                manifest_path,
                manifest,
                pid=worker.pid,
                worker_identity=manifest["worker_identity"],
                process_start_identity=str(manifest["worker_start_ticks"] or ""),
                started_at=worker_started_at,
            )
            manifest["session_dispatch"] = {
                "status": "accepted",
                "mode": (
                    "resume" if manifest.get("run_mode") == "session_continuation" else "new"
                ),
                "session_id": session_id,
                "accepted_at": worker_started_at,
                "evidence": (
                    f"{backend}_resume_process_started"
                    if manifest.get("run_mode") == "session_continuation"
                    else f"{backend}_session_process_started"
                ),
            }
            if provider_permission_mode is not None:
                manifest["session_dispatch"]["permission_mode"] = provider_permission_mode
            _atomic_json(manifest_path, manifest)
            _emit_managed_child_event(
                manifest_path,
                manifest,
                event_kind="effect",
                surface="resident.subagent_worker.dispatch",
                evidence=str(manifest["session_dispatch"]["evidence"]),
                at=worker_started_at,
                details={
                    "worker_pid": worker.pid,
                    "dispatch_mode": manifest["session_dispatch"]["mode"],
                    "session_id": session_id,
                },
            )
        try:
            returncode = worker.wait(timeout=timeout_s) if timeout_s is not None else worker.wait()
        except subprocess.TimeoutExpired:
            signal_result = signal_managed_process(
                manifest_path,
                manifest,
                worker.pid,
                signal.SIGTERM,
                cause_kind="timeout",
                ladder_step="term",
                worker=True,
                wait_fn=lambda: worker.wait(timeout=5),
                return_result=True,
            )
            state = signal_result.get("state") if isinstance(signal_result, Mapping) else None
            if state not in {"killed", "already_dead"}:
                return _cleanup_held(signal_result, reason="timeout cleanup was not authorized")
            if state == "killed" and worker.poll() is None:
                worker.wait()
            returncode = 124
        raw_handle.close()
        raw_handle = None

        # Preserve the byte-exact provider stdout separately, then copy it into
        # run.log with an explicit provider-specific envelope. Stderr already
        # streams directly to run.log through the resident supervisor.
        print(f"\n[managed-provider-raw begin backend={backend} path={raw_output_path}]", flush=True)
        try:
            with raw_output_path.open("rb") as source:
                while chunk := source.read(1024 * 1024):
                    binary_stdout = getattr(sys.stdout, "buffer", None)
                    if binary_stdout is not None:
                        binary_stdout.write(chunk)
                    else:
                        sys.stdout.write(chunk.decode("utf-8", errors="replace"))
            sys.stdout.flush()
        except OSError as exc:
            print(f"[managed-provider-raw unavailable: {exc.__class__.__name__}]", flush=True)
        print(f"\n[managed-provider-raw end backend={backend}]", flush=True)

        evidence = collect_provider_evidence(
            backend=backend,
            raw_output_path=raw_output_path,
            metadata_path=metadata_path,
            expected_session_id=session_id,
            returncode=returncode,
            diagnostics_path=Path(
                str(manifest.get("log_path") or manifest_path.parent / "run.log")
            ),
        )
        if backend == "codex":
            try:
                codex_final_text = result_path.read_text(
                    encoding="utf-8", errors="replace"
                ).strip()
            except OSError:
                codex_final_text = ""
            if codex_final_text:
                evidence = evidence.__class__(
                    session_id=evidence.session_id,
                    final_text=codex_final_text,
                    events=evidence.events,
                    usage=evidence.usage,
                    failure_category=(
                        None
                        if evidence.failure_category == "empty_result"
                        else evidence.failure_category
                    ),
                    failure_message=(
                        None
                        if evidence.failure_category == "empty_result"
                        else evidence.failure_message
                    ),
                )
        write_normalized_events(events_path, evidence.events)
        if backend in {"omp", "claude"} and evidence.final_text:
            _atomic_text(result_path, evidence.final_text.rstrip() + "\n")
        result_path.touch(exist_ok=True)
        if evidence.failure_category and returncode == 0:
            returncode = 1
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        control_status = str(manifest.get("status") or "")
        if control_status in _CONTROL_TERMINAL_STATUSES:
            # The manifest-bound controller is the terminal-state authority.
            # A worker exit racing an explicit cancel/supersede must never
            # rewrite that durable intent as a generic failure/completion.
            return int(manifest.get("returncode") or returncode or 0)
        observed_session_ids = _manifest_session_ids(manifest_path, manifest)
        if session_id:
            observed_session_ids.add(session_id)
        resolved_session_id = evidence.session_id
        if resolved_session_id is None and len(observed_session_ids) == 1:
            resolved_session_id = next(iter(observed_session_ids))
        if returncode == 0 and not resolved_session_id:
            provider_session_required = backend != "codex" or any(
                key in manifest
                for key in (
                    "provider_contract",
                    "provider_options",
                    "provider_route",
                    "model_session",
                )
            )
            if (
                manifest.get("schema_version") == MANAGED_RUN_SCHEMA
                and provider_session_required
            ):
                returncode = 1
                evidence = evidence.__class__(
                    session_id=None,
                    final_text=evidence.final_text,
                    events=evidence.events,
                    usage=evidence.usage,
                    failure_category="session_identity_missing",
                    failure_message="provider completed without a recoverable session identity",
                )
            else:
                manifest["model_session"] = {
                    "provider": backend,
                    "state": "unavailable",
                    "persistence": "unknown_legacy_record",
                    "resume_semantics": "unavailable",
                    "evidence": "legacy_manifest_did_not_capture_session_identity",
                    "recorded_at": _utc_now(),
                }
        if resolved_session_id:
            manifest["model_session"] = {
                "provider": backend,
                "session_id": resolved_session_id,
                "lineage_root_run_id": manifest.get("lineage_root_run_id")
                or manifest.get("run_id")
                or manifest_path.parent.name,
                "state": "persisted" if returncode == 0 else "reserved_unconfirmed",
                "persistence": "durable" if returncode == 0 else "requested_unconfirmed",
                "resume_semantics": "exact_session",
                "evidence": f"managed_{backend}_raw_stream_and_dispatch",
                "recorded_at": _utc_now(),
            }
        custody_error: str | None = None
        if returncode == 0:
            try:
                manifest["completion_verification"] = _verify_managed_completion_contract(
                    manifest_path, manifest
                )
                custody_evidence = manifest["completion_verification"].get("evidence")
                if isinstance(custody_evidence, Mapping):
                    manifest["git_custody_verification"] = dict(custody_evidence)
                    custody = manifest.get("git_custody")
                    details = {
                        "verification": manifest["git_custody_verification"],
                    }
                    if isinstance(custody, Mapping):
                        details["git_custody"] = git_custody_projection(custody)
                    _emit_managed_child_event(
                        manifest_path,
                        manifest,
                        event_kind="effect",
                        surface="resident.git_custody.verify",
                        evidence="git_custody_verified",
                        details=details,
                    )
            except (GitCustodyError, ValueError) as exc:
                custody_error = str(exc)
                returncode = 2
                manifest["completion_verification"] = {
                    "schema_version": COMPLETION_VERIFICATION_SCHEMA,
                    "status": "failed",
                    "classification": "completion_contract_failed_closed",
                    "error": custody_error,
                }
        telemetry = dict(manifest.get("telemetry") or {})
        telemetry.update(
            {
                "status": "captured",
                "normalized_event_count": len(evidence.events),
                "usage": dict(evidence.usage),
                "updated_at": _utc_now(),
            }
        )
        manifest["telemetry"] = telemetry
        manifest.update(
            {
                "status": "completed" if returncode == 0 else "failed",
                "returncode": returncode,
                "finished_at": _utc_now(),
                "terminal_outcome": "completed" if returncode == 0 else "failed",
            }
        )
        if custody_error is not None:
            manifest["error"] = "git custody verification failed"
            manifest["git_custody_error"] = custody_error
        if returncode != 0:
            category = evidence.failure_category or "provider_error"
            message = evidence.failure_message or f"provider exited with status {returncode}"
            if custody_error is None:
                manifest["error"] = f"managed {backend} worker failed: {category}"
            manifest["failure"] = {
                "category": category,
                "message": message,
                "returncode": returncode,
                "raw_output_path": str(raw_output_path),
                "log_path": str(manifest["log_path"]),
                "captured_at": manifest["finished_at"],
            }
        manifest["updated_at"] = manifest["finished_at"]
        history = list(manifest.get("status_history") or [])
        history.append(
            {
                "status": manifest["status"],
                "at": manifest["finished_at"],
                "evidence": f"managed_{backend}_worker_waited",
                "returncode": returncode,
                **({"git_custody_error": custody_error} if custody_error else {}),
            }
        )
        manifest["status_history"] = history[-100:]
        lifecycle = dict(manifest.get("lifecycle") or {})
        lifecycle.update(
            {
                "schema_version": DELIVERY_STATUS_SCHEMA,
                "work": {
                    "status": "worker_completed" if returncode == 0 else "worker_failed",
                    "worker_completed": returncode == 0,
                },
                "delivery": {
                    "status": str(dict(manifest.get("completion_delivery") or {}).get("status") or "not_applicable"),
                    "policy": dict(manifest.get("execution_contract") or {}).get("delivery_policy"),
                },
                "request": {
                    "status": "awaiting_delivery" if returncode == 0 else "request_blocked",
                    "request_delivered": False,
                },
            }
        )
        manifest["lifecycle"] = lifecycle
        _atomic_json(manifest_path, manifest)
        _emit_managed_child_event(
            manifest_path,
            manifest,
            event_kind="terminal",
            surface="resident.subagent_worker.terminal",
            evidence="managed_codex_worker_waited",
            at=str(manifest.get("finished_at") or _utc_now()),
            details={
                "returncode": returncode,
                "git_custody_error": custody_error,
            },
        )
        try:
            reconcile_managed_subagent_queues(
                project_root=str(manifest.get("project_dir") or manifest_path.parents[4]),
                workspace_root=None,
            )
        except Exception:
            LOGGER.exception(
                "Resident successor reconciliation failed after terminalization run_id=%s",
                manifest.get("run_id") or manifest_path.parent.name,
            )
        return returncode
    except BaseException as exc:
        if worker is not None and worker.poll() is None:
            signal_result = signal_managed_process(
                manifest_path,
                manifest,
                worker.pid,
                signal.SIGTERM,
                cause_kind="terminate",
                ladder_step="term",
                worker=True,
                wait_fn=lambda: worker.wait(timeout=5),
                return_result=True,
            )
            state = signal_result.get("state") if isinstance(signal_result, Mapping) else None
            if state not in {"killed", "already_dead"}:
                return _cleanup_held(signal_result, reason="exception cleanup was not authorized", error=exc)
            if state == "killed" and worker.poll() is None:
                worker.wait()
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        control_status = str(manifest.get("status") or "")
        if control_status in _CONTROL_TERMINAL_STATUSES:
            history = list(manifest.get("status_history") or [])
            history.append(
                {
                    "status": control_status,
                    "at": _utc_now(),
                    "evidence": "managed_codex_supervisor_acknowledged_control_terminal",
                }
            )
            manifest["status_history"] = history[-100:]
            manifest["updated_at"] = history[-1]["at"]
            _atomic_json(manifest_path, manifest)
            _emit_managed_child_event(
                manifest_path,
                manifest,
                event_kind="terminal",
                surface="resident.subagent_worker.terminal",
                evidence="managed_codex_supervisor_acknowledged_control_terminal",
                at=history[-1]["at"],
                details={"control_status": control_status},
            )
            return int(
                manifest.get("returncode")
                or (128 + interrupted_signal if interrupted_signal is not None else 1)
            )
        status = "interrupted" if interrupted_signal is not None else "failed"
        manifest.update(
            {
                "status": status,
                "error": f"managed {backend} worker failed",
                "error_class": exc.__class__.__name__,
                "error_message": str(exc),
                "finished_at": _utc_now(),
                "terminal_outcome": status,
            }
        )
        manifest["updated_at"] = manifest["finished_at"]
        dispatch = dict(manifest.get("session_dispatch") or {})
        if dispatch.get("status") != "accepted":
            dispatch.update(
                {
                    "status": "failed",
                    "failed_at": manifest["finished_at"],
                    "evidence": f"{backend}_process_not_accepted",
                    "error_class": exc.__class__.__name__,
                }
            )
            manifest["session_dispatch"] = dispatch
        history = list(manifest.get("status_history") or [])
        history.append(
            {
                "status": status,
                "at": manifest["finished_at"],
                "evidence": f"managed_{backend}_supervisor_exception",
            }
        )
        lifecycle = dict(manifest.get("lifecycle") or {})
        lifecycle.update(
            {
                "schema_version": DELIVERY_STATUS_SCHEMA,
                "work": {"status": f"worker_{status}", "worker_completed": False},
                "delivery": {
                    "status": str(dict(manifest.get("completion_delivery") or {}).get("status") or "not_applicable"),
                    "policy": dict(manifest.get("execution_contract") or {}).get("delivery_policy"),
                },
                "request": {"status": "request_blocked", "request_delivered": False},
            }
        )
        manifest["lifecycle"] = lifecycle
        telemetry = dict(manifest.get("telemetry") or {})
        telemetry.update(
            {
                "status": "failed",
                "error_class": exc.__class__.__name__,
                "updated_at": manifest["finished_at"],
            }
        )
        manifest["telemetry"] = telemetry
        manifest["status_history"] = history[-100:]
        if interrupted_signal is not None:
            manifest["signal"] = interrupted_signal
            manifest["returncode"] = 128 + interrupted_signal
        _atomic_json(manifest_path, manifest)
        _emit_managed_child_event(
            manifest_path,
            manifest,
            event_kind="terminal",
            surface="resident.subagent_worker.terminal",
            evidence=(
                "managed_codex_supervisor_exception"
                if interrupted_signal is None
                else "managed_codex_supervisor_interrupted"
            ),
            at=str(manifest.get("finished_at") or _utc_now()),
            details={
                "error_class": exc.__class__.__name__,
                "signal": interrupted_signal,
            },
        )
        try:
            reconcile_managed_subagent_queues(
                project_root=str(manifest.get("project_dir") or manifest_path.parents[4]),
                workspace_root=None,
            )
        except Exception:
            LOGGER.exception(
                "Resident successor reconciliation failed after failed terminalization run_id=%s",
                manifest.get("run_id") or manifest_path.parent.name,
            )
        if interrupted_signal is not None:
            return 128 + interrupted_signal
        return 1
    finally:
        try:
            _summarize_completed_session(manifest_path)
        except Exception:
            LOGGER.exception("post-session summarizer failed run_id=%s", manifest_path.parent.name)
        if raw_handle is not None:
            raw_handle.close()
        for signum, handler in prior_handlers.items():
            signal.signal(signum, handler)
        fcntl.flock(execution_handle.fileno(), fcntl.LOCK_UN)
        execution_handle.close()


def _run_codex_manifest(manifest_path: Path) -> int:
    """Compatibility entry point for historical Codex worker invocations."""

    return _run_managed_manifest(manifest_path)


def _pid_matches_manifest(pid: int, manifest_path: Path) -> bool:
    """Return true only when the live PID is this managed wrapper.

    Matching the manifest path avoids reporting an unrelated process after PID
    reuse. Non-Linux hosts simply report the persisted lifecycle state.
    """
    try:
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8")
    except (OSError, UnicodeError):
        return False
    return (
        "arnold_pipelines.megaplan.resident.subagent" in cmdline
        and str(manifest_path) in cmdline
    )


def _managed_run_roots(
    *,
    project_root: str | Path,
    workspace_root: str | Path | None,
) -> set[Path]:
    return managed_run_roots(project_root=project_root, workspace_root=workspace_root)


def _managed_manifest_paths(
    *,
    project_root: str | Path,
    workspace_root: str | Path | None,
) -> list[Path]:
    paths: list[Path] = []
    for root in sorted(_managed_run_roots(project_root=project_root, workspace_root=workspace_root)):
        if root.is_dir():
            paths.extend(sorted(root.glob("*/manifest.json")))
    return paths


def _is_managed_manifest(payload: Mapping[str, Any]) -> bool:
    return (
        is_managed_manifest(payload)
        and payload.get("run_kind") == MANAGED_RUN_KIND
    )


@contextmanager
def _delivery_lock(manifest_path: Path) -> Iterator[None]:
    """Serialize delivery claims across resident processes without locking a replaced inode."""

    lock_path = manifest_path.parent / ".completion-delivery.lock"
    with lock_path.open("a+b") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextmanager
def _queue_lock(manifest_path: Path) -> Iterator[None]:
    """Serialize one successor transition across terminal observers and restarts."""

    lock_path = manifest_path.parent / ".queue-transition.lock"
    with lock_path.open("a+b") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _queue_terminalize(
    manifest_path: Path,
    manifest: dict[str, Any],
    *,
    status: str,
    reason: str,
    predecessor_status: str,
    now: datetime,
    predecessor_run_id: str | None = None,
) -> None:
    queue = dict(manifest.get("queue") or {})
    queue.update(
        {
            "state": "dependency_failed",
            "attention": reason,
            "predecessor_status": predecessor_status,
            "failed_at": now.isoformat(),
            "updated_at": now.isoformat(),
        }
    )
    if predecessor_run_id:
        queue["failed_predecessor_run_id"] = predecessor_run_id
    manifest.update(
        {
            "status": status,
            "terminal_outcome": status,
            "finished_at": now.isoformat(),
            "updated_at": now.isoformat(),
            "error": "queued successor dependency failed closed",
            "error_class": "ResidentSubagentDependencyFailure",
            "queue": queue,
        }
    )
    history = list(manifest.get("status_history") or [])
    history.append(
        {
            "status": status,
            "at": now.isoformat(),
            "evidence": reason,
            "predecessor_status": predecessor_status,
        }
    )
    manifest["status_history"] = history[-100:]
    _atomic_json(manifest_path, manifest)


def _is_cross_revision_contract_rejection(manifest: Mapping[str, Any]) -> bool:
    """Recognize the one terminal state an older worker can falsely produce.

    Detached workers retain the Python code loaded when they were launched.  A
    worker from before cross-request queues existed can therefore reject a
    newer, valid authorization contract when it reconciles queues on exit.
    Recovery remains fail closed: only the exact pre-launch rejection shape is
    eligible, and the current runtime must subsequently validate the complete
    authorization contract before this terminal state is removed.
    """

    queue = manifest.get("queue")
    delivery = manifest.get("completion_delivery")
    authorization = (
        queue.get("cross_request_authorization") if isinstance(queue, Mapping) else None
    )
    authorizations = (
        queue.get("cross_request_authorizations") if isinstance(queue, Mapping) else None
    )
    authorization_shape_valid = bool(
        (
            isinstance(authorization, Mapping)
            and authorization.get("schema_version")
            == QUEUE_CROSS_REQUEST_AUTHORIZATION_SCHEMA
        )
        or (
            isinstance(authorizations, list)
            and bool(authorizations)
            and all(
                isinstance(item, Mapping)
                and item.get("schema_version")
                == QUEUE_CROSS_REQUEST_AUTHORIZATION_SCHEMA
                for item in authorizations
            )
        )
    )
    history = manifest.get("status_history")
    last_history = history[-1] if isinstance(history, list) and history else None
    return bool(
        manifest.get("status") == "failed"
        and manifest.get("terminal_outcome") == "failed"
        and manifest.get("error_class") == "ResidentSubagentDependencyFailure"
        and isinstance(queue, Mapping)
        and queue.get("schema_version") == QUEUE_SCHEMA
        and queue.get("state") == "dependency_failed"
        and queue.get("attention") == "invalid_dependency_contract"
        and queue.get("predecessor_status") == "unknown"
        and queue.get("attempt_count") in {None, 0, "0"}
        and isinstance(delivery, Mapping)
        and delivery.get("status") == "pending"
        and delivery.get("attempt_count") in {None, 0, "0"}
        and authorization_shape_valid
        and isinstance(last_history, Mapping)
        and last_history.get("status") == "failed"
        and last_history.get("evidence") == "invalid_dependency_contract"
    )


def _restore_cross_revision_queue(
    manifest: dict[str, Any],
    *,
    predecessor_run_ids: Sequence[str],
    predecessor_states: list[dict[str, Any]],
    now: datetime,
) -> None:
    """Restore a currently validated cross-request queue to pre-launch state."""

    queue = dict(manifest.get("queue") or {})
    waiting_state, _ = _queue_waiting_labels(predecessor_run_ids)
    queue.update(
        {
            "state": waiting_state,
            "attention": "dependency_contract_revalidated",
            "predecessor_states": predecessor_states,
            "revalidated_at": now.isoformat(),
            "updated_at": now.isoformat(),
        }
    )
    if len(predecessor_states) == 1:
        queue["predecessor_status"] = predecessor_states[0]["status"]
    else:
        queue.pop("predecessor_status", None)
    queue.pop("failed_at", None)
    manifest.update(
        {
            "status": "queued",
            "queue": queue,
            "updated_at": now.isoformat(),
        }
    )
    for field in ("terminal_outcome", "finished_at", "error", "error_class"):
        manifest.pop(field, None)
    history = list(manifest.get("status_history") or [])
    history.append(
        {
            "status": "queued",
            "at": now.isoformat(),
            "evidence": "valid_contract_recovered_after_stale_runtime_rejection",
            "predecessor_status": (
                predecessor_states[0]["status"]
                if len(predecessor_states) == 1
                else "multiple"
            ),
        }
    )
    manifest["status_history"] = history[-100:]


def _normalized_queue_predecessor_status(predecessor: Mapping[str, Any]) -> str:
    """Return a canonical managed status without inventing terminal success."""

    status = str(predecessor.get("status") or "").strip().casefold()
    if (
        status in _ACTIVE_STATUSES
        or status in _DEPENDENCY_TERMINAL_STATUSES
        or status == "queued"
    ):
        return status
    return "unknown"


def reconcile_managed_subagent_queues(
    *,
    project_root: str | Path = ".",
    workspace_root: str | Path | None = "/workspace",
    now: datetime | None = None,
) -> ManagedAgentQueueSweepResult:
    """Launch eligible successors once and fail closed on invalid dependencies.

    The queued manifest is the durable launch intent. A per-successor flock
    serializes observers, while the worker's execution lock prevents duplicate
    Codex execution if a supervisor launch is retried after an ambiguous crash.
    """

    observed_at = now or datetime.now(timezone.utc)
    scanned = waiting = launched = retry_pending = failed_closed = skipped = 0
    paths = _managed_manifest_paths(
        project_root=project_root, workspace_root=workspace_root
    )
    for manifest_path in paths:
        try:
            initial = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, TypeError, ValueError):
            continue
        if not isinstance(initial.get("queue"), Mapping):
            continue
        scanned += 1
        with _queue_lock(manifest_path):
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, TypeError, ValueError):
                failed_closed += 1
                continue
            status = str(manifest.get("status") or "")
            recovering_cross_revision = _is_cross_revision_contract_rejection(
                manifest
            )
            if status in _TERMINAL_STATUSES and not recovering_cross_revision:
                skipped += 1
                continue
            if status in {"launching", "running"}:
                pid = manifest.get("pid")
                if isinstance(pid, int) and _pid_matches_manifest(pid, manifest_path):
                    skipped += 1
                    continue
                session_dispatch = manifest.get("session_dispatch")
                if (
                    isinstance(session_dispatch, Mapping)
                    and session_dispatch.get("status") == "accepted"
                ):
                    _queue_terminalize(
                        manifest_path,
                        manifest,
                        status="failed",
                        reason="successor_execution_lost_supervisor_without_terminal_evidence",
                        predecessor_status="completed",
                        now=observed_at,
                    )
                    failed_closed += 1
                    continue
            queue = manifest.get("queue")
            if not isinstance(queue, dict) or queue.get("schema_version") != QUEUE_SCHEMA:
                _queue_terminalize(
                    manifest_path,
                    manifest,
                    status="failed",
                    reason="invalid_queue_contract",
                    predecessor_status="unknown",
                    now=observed_at,
                )
                failed_closed += 1
                continue
            try:
                predecessor_run_ids, predecessors = _validated_queue_predecessors(
                    manifest_path, manifest
                )
            except (SubagentFollowupError, SubagentQueueError, OSError, ValueError) as exc:
                observed_states: list[dict[str, Any]] = []
                try:
                    declared_ids = _queue_predecessor_run_ids(queue)
                    for declared_id in declared_ids:
                        declared_path = (
                            manifest_path.parent.parent
                            / declared_id
                            / "manifest.json"
                        )
                        declared_predecessor = _read_managed_resident_manifest(
                            declared_path
                        )
                        observed_states.append(
                            _queue_predecessor_state(
                                declared_id, declared_path, declared_predecessor
                            )
                        )
                except (SubagentFollowupError, SubagentQueueError, OSError, ValueError):
                    observed_states = []
                if observed_states:
                    queue["predecessor_states"] = observed_states
                    if len(observed_states) == 1:
                        queue["predecessor_status"] = observed_states[0]["status"]
                queue["last_validation_error"] = {
                    "error_class": exc.__class__.__name__,
                    "message": " ".join(redact_text(str(exc)).split())[:240],
                    "at": observed_at.isoformat(),
                }
                manifest["queue"] = queue
                if not recovering_cross_revision:
                    _queue_terminalize(
                        manifest_path,
                        manifest,
                        status="failed",
                        reason="invalid_dependency_contract",
                        predecessor_status=(
                            str(observed_states[0]["status"])
                            if len(observed_states) == 1
                            else "unknown"
                        ),
                        now=observed_at,
                    )
                failed_closed += 1
                continue
            predecessor_states = [
                _queue_predecessor_state(run_id, path, predecessor)
                for run_id, path, predecessor in predecessors
            ]
            queue["predecessor_states"] = predecessor_states
            if len(predecessor_states) == 1:
                queue["predecessor_status"] = predecessor_states[0]["status"]
            else:
                queue.pop("predecessor_status", None)
            manifest["queue"] = queue
            if recovering_cross_revision:
                _restore_cross_revision_queue(
                    manifest,
                    predecessor_run_ids=predecessor_run_ids,
                    predecessor_states=predecessor_states,
                    now=observed_at,
                )
                queue = dict(manifest["queue"])
            dependency_failure = next(
                (
                    state
                    for state in predecessor_states
                    if state["status"] == "unknown"
                    or state["status"] in _DEPENDENCY_TERMINAL_STATUSES
                    and (
                        state["status"] != "completed"
                        or state["result_state"] != "valid"
                    )
                ),
                None,
            )
            if dependency_failure is not None:
                failed_run_id = str(dependency_failure["run_id"])
                predecessor_status = str(dependency_failure["status"])
                reason = str(dependency_failure["attention"])
                propagated_status = (
                    predecessor_status
                    if predecessor_status in {"cancelled", "superseded"}
                    else "failed"
                )
                _queue_terminalize(
                    manifest_path,
                    manifest,
                    status=propagated_status,
                    reason=reason,
                    predecessor_status=predecessor_status,
                    predecessor_run_id=failed_run_id,
                    now=observed_at,
                )
                failed_closed += 1
                continue
            if any(
                state["status"] not in _DEPENDENCY_TERMINAL_STATUSES
                for state in predecessor_states
            ):
                waiting_state, waiting_attention = _queue_waiting_labels(
                    predecessor_run_ids
                )
                queue.update(
                    {
                        "state": waiting_state,
                        "attention": waiting_attention,
                        "predecessor_states": predecessor_states,
                        "updated_at": observed_at.isoformat(),
                    }
                )
                manifest["status"] = "queued"
                manifest["queue"] = queue
                manifest["updated_at"] = observed_at.isoformat()
                _atomic_json(manifest_path, manifest)
                waiting += 1
                continue
            next_attempt_at = _parse_timestamp(queue.get("next_attempt_at"))
            if next_attempt_at is not None and observed_at < next_attempt_at:
                queue["predecessor_states"] = predecessor_states
                queue["updated_at"] = observed_at.isoformat()
                manifest["queue"] = queue
                manifest["updated_at"] = observed_at.isoformat()
                _atomic_json(manifest_path, manifest)
                retry_pending += 1
                continue
            attempt = int(queue.get("attempt_count") or 0) + 1
            max_attempts = int(
                queue.get("max_launch_attempts") or _QUEUE_MAX_LAUNCH_ATTEMPTS
            )
            queue.update(
                {
                    "state": "launching",
                    "attention": "none",
                    "attempt_count": attempt,
                    "predecessor_states": predecessor_states,
                    "launch_claimed_at": observed_at.isoformat(),
                    "updated_at": observed_at.isoformat(),
                }
            )
            queue.pop("next_attempt_at", None)
            manifest["status"] = "launching"
            manifest["queue"] = queue
            manifest["updated_at"] = observed_at.isoformat()
            history = list(manifest.get("status_history") or [])
            history.append(
                {
                    "status": "launching",
                    "at": observed_at.isoformat(),
                    "evidence": "all_predecessors_terminal_success_and_results_validated",
                    "attempt": attempt,
                }
            )
            manifest["status_history"] = history[-100:]
            _atomic_json(manifest_path, manifest)
            try:
                _spawn_managed_supervisor(manifest_path, manifest)
            except _ResidentLaunchUnresolved as exc:
                # Canonical UNKNOWN is commit-unknown custody, not a queue
                # retry signal.  Preserve PENDING/ownerless canonical state
                # and wait for read-only inspection/reconciliation.
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                queue = dict(manifest.get("queue") or {})
                queue.update(
                    {
                        "state": "launch_unresolved",
                        "attention": "canonical_launch_unresolved",
                        "last_error_class": exc.__class__.__name__,
                        "updated_at": observed_at.isoformat(),
                    }
                )
                manifest["status"] = "launching"
                manifest["queue"] = queue
                manifest["updated_at"] = observed_at.isoformat()
                _atomic_json(manifest_path, manifest)
                continue
            except Exception as exc:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                queue = dict(manifest.get("queue") or {})
                if attempt >= max_attempts:
                    _queue_terminalize(
                        manifest_path,
                        manifest,
                        status="failed",
                        reason="successor_launch_retry_budget_exhausted",
                        predecessor_status="completed",
                        now=observed_at,
                    )
                    failed_closed += 1
                else:
                    delay = min(
                        _QUEUE_RETRY_MAX_S,
                        _QUEUE_RETRY_BASE_S * (2 ** max(0, attempt - 1)),
                    )
                    queue.update(
                        {
                            "state": "retry_pending",
                            "attention": "successor_launch_retry_pending",
                            "last_error_class": exc.__class__.__name__,
                            "next_attempt_at": (
                                observed_at + timedelta(seconds=delay)
                            ).isoformat(),
                            "updated_at": observed_at.isoformat(),
                        }
                    )
                    manifest["status"] = "queued"
                    manifest["queue"] = queue
                    manifest["updated_at"] = observed_at.isoformat()
                    _atomic_json(manifest_path, manifest)
                    retry_pending += 1
                continue
            launched += 1
    return ManagedAgentQueueSweepResult(
        scanned=scanned,
        waiting=waiting,
        launched=launched,
        retry_pending=retry_pending,
        failed_closed=failed_closed,
        skipped=skipped,
    )


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def _repair_manifest_delivery_provenance(manifest: dict[str, Any]) -> bool:
    """Backfill delivery provenance for manifests launched by stale residents."""

    changed = False
    existing_delivery = manifest.get("completion_delivery")
    if isinstance(existing_delivery, Mapping):
        provider_ids = [
            str(value)
            for value in existing_delivery.get("discord_message_ids", [])
            if str(value).strip()
        ]
        # Provider acceptance evidence is stronger than a later compatibility
        # migration.  Old delivered records may lack today's provenance schema,
        # but they must never be downgraded or redriven after Discord message
        # IDs and a delivered timestamp were durably persisted.
        if provider_ids and _parse_timestamp(existing_delivery.get("delivered_at")):
            if existing_delivery.get("status") != "delivered":
                delivery = dict(existing_delivery)
                diagnostic = {
                    key: delivery.pop(key)
                    for key in (
                        "last_error",
                        "last_error_class",
                        "last_error_category",
                        "migration_evidence",
                    )
                    if delivery.get(key) not in (None, "")
                }
                history = list(delivery.get("state_history") or [])
                history.append(
                    {
                        "status": "delivered",
                        "at": _utc_now(),
                        "evidence": "provider_message_ids_prevented_migration_redrive",
                    }
                )
                delivery.update(
                    {
                        "status": "delivered",
                        "migration_diagnostic": diagnostic,
                        "migration_evidence": (
                            "historical provider acceptance preserved; no redrive"
                        ),
                        "state_history": history[-20:],
                        "updated_at": _utc_now(),
                    }
                )
                manifest["completion_delivery"] = delivery
                return True
            return False
    project_root = str(manifest.get("project_dir") or "").strip() or None
    standalone_target = manifest.get("discord_delivery_target")
    if isinstance(standalone_target, Mapping):
        delivery = dict(manifest.get("completion_delivery") or {})
        provenance = manifest.get("launch_provenance")
        route = str(standalone_target.get("conversation_key") or "").strip()
        valid = (
            standalone_target.get("mode") == "standalone"
            and route.startswith("discord:dm:")
            and isinstance(provenance, Mapping)
            and provenance.get("applicability") == "not_applicable"
            and delivery.get("transport") == "discord"
            and delivery.get("delivery_mode") == "standalone"
            and not manifest.get("source_record_id")
            and not manifest.get("discord_origin")
            and not delivery.get("reply_target")
        )
        if valid:
            return False
        delivery.update({
            "status": "failed",
            "last_error": "Standalone Discord delivery custody is malformed",
            "last_error_class": "InvalidStandaloneDeliveryTarget",
            "last_error_category": "invalid_delivery_target",
            "updated_at": _utc_now(),
        })
        manifest["completion_delivery"] = delivery
        return True
    raw_origin = manifest.get("discord_origin")
    existing_provenance: dict[str, Any] | None = None
    if isinstance(manifest.get("launch_provenance"), Mapping):
        try:
            candidate_provenance = normalize_delegation_provenance(
                manifest["launch_provenance"]
            )
        except DelegationProvenanceError:
            candidate_provenance = None
        if candidate_provenance is not None and candidate_provenance.get("applicability") == "applicable":
            existing_provenance = candidate_provenance

    origin: dict[str, Any] | None
    if existing_provenance is not None:
        expected_origin = discord_origin_projection(existing_provenance)
        supplied_origin = _discord_origin(raw_origin, project_root=project_root)
        if raw_origin is not None and (
            supplied_origin is None
            or any(
                supplied_origin.get(field) != expected_origin.get(field)
                for field in (
                    "conversation_id",
                    "conversation_key",
                    "message_id",
                    "reply_to_message_id",
                    "guild_id",
                    "channel_id",
                    "thread_id",
                    "dm_user_id",
                )
            )
        ):
            delivery = dict(manifest.get("completion_delivery") or {})
            delivery.update(
                {
                    "transport": "discord",
                    "status": "failed",
                    "attempt_count": int(delivery.get("attempt_count") or 0),
                    "last_error": "Discord custody failed: compatibility origin conflicts with immutable launch provenance",
                    "last_error_class": "ProvenanceCustodyMismatch",
                    "last_error_category": "invalid_reply_target",
                    "updated_at": _utc_now(),
                }
            )
            manifest["completion_delivery"] = delivery
            return True
        origin = expected_origin
    else:
        origin = _discord_origin(raw_origin, project_root=project_root)
    if origin is None:
        origin = _discord_origin_from_resident_request(
            manifest.get("request_id"),
            project_root=project_root,
        )
    if origin is None:
        existing_provenance = manifest.get("launch_provenance")
        if (
            isinstance(existing_provenance, Mapping)
            and existing_provenance.get("applicability") == "applicable"
        ):
            delivery = dict(manifest.get("completion_delivery") or {})
            delivery.update(
                {
                    "transport": "discord",
                    "status": "failed",
                    "attempt_count": int(delivery.get("attempt_count") or 0),
                    "last_error": "Discord custody failed: durable launch provenance is no longer valid",
                    "last_error_class": "InvalidDelegationProvenance",
                    "last_error_category": "invalid_reply_target",
                    "migration_evidence": "reply target was not inferred from mutable state",
                    "updated_at": _utc_now(),
                }
            )
            manifest["completion_delivery"] = delivery
            return True
        if (
            isinstance(existing_provenance, Mapping)
            and existing_provenance.get("applicability") == "not_applicable"
        ):
            delivery = dict(manifest.get("completion_delivery") or {})
            if delivery.get("status") != "not_applicable":
                delivery.update(
                    {
                        "transport": "non_discord",
                        "status": "not_applicable",
                        "attempt_count": int(delivery.get("attempt_count") or 0),
                        "evidence": "launch_provenance_explicitly_non_discord",
                    }
                )
                manifest["completion_delivery"] = delivery
                return True
            return False
        discord_hint = (
            isinstance(raw_origin, Mapping) and raw_origin.get("transport") == "discord"
        ) or bool(_RESIDENT_MESSAGE_ID_RE.fullmatch(str(manifest.get("request_id") or "")))
        if discord_hint:
            delivery = dict(manifest.get("completion_delivery") or {})
            delivery.update(
                {
                    "transport": "discord",
                    "status": "unknown" if raw_origin is None else "failed",
                    "attempt_count": int(delivery.get("attempt_count") or 0),
                    "last_error": (
                        "Legacy Discord custody is unknown: source provenance cannot be recovered"
                        if raw_origin is None
                        else "Legacy Discord custody failed validation: reply target is malformed"
                    ),
                    "last_error_class": "UnrecoverableLegacyProvenance",
                    "last_error_category": "invalid_reply_target",
                    "migration_evidence": "no reply target inferred from mutable cursors or final text",
                    "updated_at": _utc_now(),
                }
            )
            manifest["completion_delivery"] = delivery
            return True
        if manifest.get("launch_provenance") is None:
            manifest["launch_provenance"] = normalize_delegation_provenance(
                {
                    "transport": "non_discord",
                    "applicability": "not_applicable",
                    "source_kind": "legacy_non_discord_backfill",
                }
            )
            manifest["completion_delivery"] = {
                "transport": "non_discord",
                "status": "not_applicable",
                "attempt_count": 0,
                "evidence": "legacy manifest had no Discord provenance hint",
            }
            return True
        return False
    if existing_provenance is not None:
        provenance = existing_provenance
    else:
        try:
            provenance = normalize_delegation_provenance(
                {
                    **origin,
                    "applicability": "applicable",
                    "resident_conversation_id": origin.get("conversation_id"),
                    "source_record_id": origin.get("reply_target_source_record_id"),
                    "discord_message_id": origin.get("message_id"),
                    "correlation_id": manifest.get("correlation_id"),
                    "custody_id": manifest.get("custody_id"),
                    "source_kind": "manifest_backfill",
                }
            )
        except DelegationProvenanceError:
            return False
    if manifest.get("discord_origin") != origin:
        manifest["discord_origin"] = discord_origin_projection(provenance)
        changed = True
    for key, value in (
        ("launch_provenance", provenance),
        ("correlation_id", provenance["correlation_id"]),
        ("custody_id", provenance["custody_id"]),
        ("resident_conversation_id", provenance["resident_conversation_id"]),
        ("source_record_id", provenance["source_record_id"]),
    ):
        if manifest.get(key) != value:
            manifest[key] = value
            changed = True
    if not isinstance(manifest.get("completion_delivery"), dict):
        run_id = str(manifest.get("run_id") or "legacy-run")
        manifest["completion_delivery"] = {
            "transport": "discord",
            "status": "pending",
            "attempt_count": 0,
            "provenance_recovered": True,
            "custody_id": provenance["custody_id"],
            "outbox_id": stable_identity(
                "discord-outbox", run_id, provenance["reply_to_message_id"]
            ),
            "idempotency_key": f"resident-subagent-completion:{run_id}",
            "reply_target": {
                "conversation_key": provenance["conversation_key"],
                "message_id": provenance["reply_to_message_id"],
                "source_record_id": provenance["source_record_id"],
            },
        }
        changed = True
    else:
        delivery = dict(manifest["completion_delivery"])
        run_id = str(manifest.get("run_id") or "legacy-run")
        stored_target = delivery.get("reply_target")
        expected_target = {
            "conversation_key": provenance["conversation_key"],
            "message_id": provenance["reply_to_message_id"],
            "source_record_id": provenance["source_record_id"],
        }
        if existing_provenance is not None and isinstance(stored_target, Mapping) and any(
            stored_target.get(key) != value for key, value in expected_target.items()
        ):
            delivery.update(
                {
                    "status": "failed",
                    "last_error": "Discord custody failed: outbox target conflicts with immutable launch provenance",
                    "last_error_class": "ProvenanceCustodyMismatch",
                    "last_error_category": "invalid_reply_target",
                    "updated_at": _utc_now(),
                }
            )
            manifest["completion_delivery"] = delivery
            return True
        additions = {
            "custody_id": provenance["custody_id"],
            "outbox_id": stable_identity(
                "discord-outbox", run_id, provenance["reply_to_message_id"]
            ),
            "idempotency_key": f"resident-subagent-completion:{run_id}",
            "reply_target": expected_target,
        }
        for key, value in additions.items():
            if delivery.get(key) != value:
                delivery[key] = value
                changed = True
        manifest["completion_delivery"] = delivery
    return changed


def _delivery_request_identity(manifest: Mapping[str, Any]) -> tuple[str, ...] | None:
    execution_contract = manifest.get("execution_contract")
    if (
        isinstance(execution_contract, Mapping)
        and execution_contract.get("delivery_policy") == "deliver_independently"
    ):
        return (
            "independent_result",
            str(manifest.get("run_id") or manifest.get("launch_idempotency_key") or "unknown"),
        )
    aggregation = manifest.get("aggregation")
    if isinstance(aggregation, Mapping) and aggregation.get("key"):
        return "aggregation_key", str(aggregation["key"])
    launch_key = str(manifest.get("launch_idempotency_key") or "").strip()
    if launch_key:
        return "launch_idempotency_key", launch_key
    request_id = str(manifest.get("request_id") or "").strip()
    if not request_id:
        return None
    origin = manifest.get("discord_origin")
    if not isinstance(origin, Mapping):
        return None
    conversation = str(origin.get("conversation_id") or origin.get("conversation_key") or "").strip()
    reply_target = str(origin.get("reply_to_message_id") or "").strip()
    if not conversation or not reply_target:
        return None
    return request_id, conversation, reply_target


def _newer_delivery_run(
    manifest_path: Path,
    manifest: Mapping[str, Any],
) -> str | None:
    """Return the newest sibling run for the same logical resident request."""

    identity = _delivery_request_identity(manifest)
    created_at = _parse_timestamp(manifest.get("created_at"))
    if identity is None or created_at is None:
        return None
    run_id = str(manifest.get("run_id") or manifest_path.parent.name)
    current_order = (created_at, run_id)
    newest: tuple[datetime, str] | None = None
    for sibling_path in manifest_path.parent.parent.glob("*/manifest.json"):
        if sibling_path == manifest_path:
            continue
        try:
            sibling = json.loads(sibling_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            continue
        if not isinstance(sibling, dict) or not _is_managed_manifest(sibling):
            continue
        _repair_manifest_delivery_provenance(sibling)
        if _delivery_request_identity(sibling) != identity:
            continue
        sibling_created_at = _parse_timestamp(sibling.get("created_at"))
        if sibling_created_at is None:
            continue
        sibling_run_id = str(sibling.get("run_id") or sibling_path.parent.name)
        candidate = (sibling_created_at, sibling_run_id)
        if candidate > current_order and (newest is None or candidate > newest):
            newest = candidate
    return newest[1] if newest is not None else None


def _completion_payload(
    manifest: Mapping[str, Any],
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    rendered = str(payload.get("content") or "").strip()
    relationship = manifest.get("query_relationship")
    if (
        isinstance(relationship, Mapping)
        and relationship.get("classification") == "follow_up"
    ):
        root = _request_ref(relationship, "root_request") or {}
        current = _request_ref(relationship, "current_request") or {}
        reference_line = (
            "Related Discord messages: root request "
            f"{root.get('discord_message_id') or root.get('source_record_id') or 'unknown'}; "
            "current follow-up and delivery target "
            f"{current.get('discord_message_id') or current.get('source_record_id') or 'unknown'}."
        )
        rendered = f"{reference_line}\n\n{rendered}" if rendered else reference_line
    rendered = rendered[:_MAX_COMPLETION_DELIVERY_CHARS]
    return {
        **dict(payload),
        "content": rendered,
        "content_sha256": hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
    }


def _delivery_claim(
    manifest_path: Path,
    *,
    now: datetime,
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """Claim one terminal delivery, persisting intent before the Discord call."""

    with _delivery_lock(manifest_path):
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return None
        if isinstance(manifest, dict):
            ensure_managed_child_custody_fields(manifest_path, manifest)
        if not isinstance(manifest, dict) or not _is_managed_manifest(manifest):
            return None
        provenance_changed = _repair_manifest_delivery_provenance(manifest)
        delivery = manifest.get("completion_delivery")
        origin = manifest.get("discord_origin")
        standalone_target = manifest.get("discord_delivery_target")
        is_standalone = (
            isinstance(standalone_target, Mapping)
            and standalone_target.get("mode") == "standalone"
        )
        if not isinstance(delivery, dict) or (
            not isinstance(origin, dict) and not is_standalone
        ):
            if provenance_changed:
                _atomic_json(manifest_path, manifest)
            return None
        # A completed provider send is terminal even when a legacy manifest
        # cannot satisfy today's launch-provenance schema. Persist any truthful
        # state repair above, but never revalidate it into a sendable/failure
        # state or redrive it.
        if delivery.get("status") == "delivered":
            if provenance_changed:
                _atomic_json(manifest_path, manifest)
            return None
        try:
            provenance = normalize_delegation_provenance(
                manifest.get("launch_provenance") or {},
            )
        except DelegationProvenanceError:
            delivery.update(
                {
                    "status": "failed",
                    "last_error": "Discord delivery failed: durable provenance is missing or ambiguous",
                    "last_error_class": "InvalidDelegationProvenance",
                    "last_error_category": "invalid_reply_target",
                    "updated_at": now.isoformat(),
                }
            )
            manifest["completion_delivery"] = delivery
            _atomic_json(manifest_path, manifest)
            return None
        if not is_standalone and provenance.get("source_record_id") != manifest.get("source_record_id"):
            delivery.update(
                {
                    "status": "failed",
                    "last_error": "Discord delivery failed: source-record custody mismatch",
                    "last_error_class": "InvalidDelegationProvenance",
                    "last_error_category": "invalid_reply_target",
                    "updated_at": now.isoformat(),
                }
            )
            manifest["completion_delivery"] = delivery
            _atomic_json(manifest_path, manifest)
            return None
        delivery_status = str(delivery.get("status") or "pending")
        if delivery_status in {
            "delivered",
            "failed",
            "not_applicable",
            "superseded",
            "suppressed",
            "unknown",
        }:
            if provenance_changed:
                _atomic_json(manifest_path, manifest)
            return None
        superseded_by = _newer_delivery_run(manifest_path, manifest)
        if superseded_by is not None:
            delivery.update(
                {
                    "status": "superseded",
                    "superseded_by_run_id": superseded_by,
                    "superseded_at": now.isoformat(),
                    "updated_at": now.isoformat(),
                }
            )
            manifest["completion_delivery"] = delivery
            _atomic_json(manifest_path, manifest)
            return None
        # A prior process can stop after Discord accepts the message but before
        # evidence is persisted. Record the ambiguity before using the stable
        # provider nonce for a duplicate-safe recovery attempt.
        if delivery_status == "sending" or delivery.get("claim_state") == "sending":
            history = list(delivery.get("state_history") or [])
            history.append(
                {
                    "status": "unknown",
                    "at": now.isoformat(),
                    "evidence": "process_restarted_with_inflight_provider_attempt",
                    "attempt_id": delivery.get("attempt_id"),
                }
            )
            delivery["state_history"] = history[-20:]
            delivery["last_unknown_at"] = now.isoformat()
        next_attempt_at = _parse_timestamp(delivery.get("next_attempt_at"))
        if next_attempt_at is not None and next_attempt_at > now:
            return None

        status = str(manifest.get("status") or "unknown")
        if status in _ACTIVE_STATUSES:
            pid = manifest.get("pid")
            if isinstance(pid, int) and _pid_matches_manifest(pid, manifest_path):
                return None
            status = "interrupted"
            manifest.update(
                {
                    "status": status,
                    "finished_at": manifest.get("finished_at") or now.isoformat(),
                    "lifecycle_error": "managed supervisor was no longer running",
                }
            )
        if status not in _TERMINAL_STATUSES:
            return None

        normalized_origin = (
            {
                "transport": "discord",
                "conversation_key": str(standalone_target["conversation_key"]),
                "delivery_mode": "standalone",
            }
            if is_standalone
            else _discord_origin(
                origin,
                project_root=str(manifest.get("project_dir") or "") or None,
            )
        )
        if normalized_origin is None:
            delivery.update(
                {
                    "status": "failed",
                    "last_error": "Discord delivery failed: invalid reply target",
                    "last_error_class": "InvalidDiscordOrigin",
                    "last_error_category": "invalid_reply_target",
                    "last_http_status": None,
                    "last_http_body_category": "not_applicable",
                    "updated_at": now.isoformat(),
                }
            )
            manifest["completion_delivery"] = delivery
            _atomic_json(manifest_path, manifest)
            return None
        if not is_standalone and normalized_origin != origin:
            manifest["discord_origin"] = normalized_origin

        outbox_payload = delivery.get("payload")
        if not isinstance(outbox_payload, Mapping):
            content, result_kind = _completion_message(manifest, manifest_path)
            from .timezone import localize_text_timestamps

            launch_provenance = dict(manifest.get("launch_provenance") or {})
            content = localize_text_timestamps(
                content,
                str(launch_provenance.get("timezone_name") or "UTC"),
            )
            delivery["payload"] = _completion_payload(manifest, {
                "content": content,
                "result_kind": result_kind,
                "materialized_at": now.isoformat(),
            })

        attempt = int(delivery.get("attempt_count") or 0) + 1
        if attempt > _DELIVERY_MAX_ATTEMPTS:
            delivery.update(
                {
                    "status": "failed",
                    "last_error": "Discord delivery failed: retry budget exhausted",
                    "last_error_class": "DeliveryRetryExhausted",
                    "last_error_category": "retry_exhausted",
                    "updated_at": now.isoformat(),
                }
            )
            manifest["completion_delivery"] = delivery
            _atomic_json(manifest_path, manifest)
            return None
        run_id = str(manifest.get("run_id") or manifest_path.parent.name)
        nonce = str(
            delivery.get("discord_nonce")
            or hashlib.sha256(f"resident-subagent-completion:{run_id}".encode("utf-8")).hexdigest()[:20]
        )
        delivery.update(
            {
                "status": "pending",
                "claim_state": "sending",
                "attempt_count": attempt,
                "last_attempt_at": now.isoformat(),
                "attempt_id": f"{run_id}:{attempt}",
                "discord_nonce": nonce,
            }
        )
        history = list(delivery.get("state_history") or [])
        history.append(
            {
                "status": "pending",
                "at": now.isoformat(),
                "evidence": "provider_attempt_claimed",
                "attempt_id": f"{run_id}:{attempt}",
            }
        )
        delivery["state_history"] = history[-20:]
        delivery.pop("next_attempt_at", None)
        manifest["completion_delivery"] = delivery
        _atomic_json(manifest_path, manifest)
        _emit_managed_child_event(
            manifest_path,
            manifest,
            event_kind="effect",
            surface="resident.subagent.delivery",
            evidence="provider_attempt_claimed",
            at=now.isoformat(),
            details={"attempt_id": delivery.get("attempt_id")},
        )
        return manifest, normalized_origin


def _completion_turn_claim(
    manifest_path: Path,
    *,
    now: datetime,
) -> dict[str, Any] | None:
    """Claim one terminal run for a normal resident verification turn.

    This claim shares the completion-delivery lock and lives in the canonical
    run manifest.  A completed claim is immutable; an in-flight claim is only
    reclaimable after the resident's normal stale-turn timeout window.
    """

    with _delivery_lock(manifest_path):
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return None
        if isinstance(manifest, dict):
            ensure_managed_child_custody_fields(manifest_path, manifest)
        if not _is_managed_manifest(manifest):
            return None
        provenance_changed = _repair_manifest_delivery_provenance(manifest)
        if str(manifest.get("status") or "") not in _TERMINAL_STATUSES:
            if provenance_changed:
                _atomic_json(manifest_path, manifest)
            return None
        delivery = manifest.get("completion_delivery")
        if not isinstance(delivery, Mapping) or delivery.get("transport") != "discord":
            if provenance_changed:
                _atomic_json(manifest_path, manifest)
            return None
        if str(delivery.get("status") or "") in {
            "delivered", "failed", "not_applicable", "superseded", "suppressed", "unknown"
        }:
            return None
        completion = dict(manifest.get("resident_completion_turn") or {})
        if completion.get("status") == "completed":
            return None
        next_attempt_at = _parse_timestamp(completion.get("next_attempt_at"))
        if next_attempt_at is not None and next_attempt_at > now:
            return None
        claimed_at = _parse_timestamp(completion.get("claimed_at"))
        if (
            completion.get("status") == "running"
            and claimed_at is not None
            and (now - claimed_at).total_seconds() < 300
        ):
            return None
        attempt = int(completion.get("attempt_count") or 0) + 1
        run_id = str(manifest.get("run_id") or manifest_path.parent.name)
        completion.update(
            {
                "schema_version": "arnold-resident-completion-turn-v1",
                "trigger_id": stable_identity("resident-completion-turn", run_id),
                "status": "running",
                "attempt_count": attempt,
                "claimed_at": now.isoformat(),
                "updated_at": now.isoformat(),
            }
        )
        completion.pop("next_attempt_at", None)
        manifest["resident_completion_turn"] = completion
        _atomic_json(manifest_path, manifest)
        _emit_managed_child_event(
            manifest_path,
            manifest,
            event_kind="effect",
            surface="resident.runtime.completion_turn",
            evidence="resident_completion_turn_claimed",
            at=now.isoformat(),
            details={"attempt_count": attempt},
        )
        return manifest


def _finish_completion_turn(
    manifest_path: Path,
    *,
    now: datetime,
    result: ManagedCompletionTurnResult,
) -> None:
    safe_text = result.final_text.strip()
    if not safe_text:
        safe_text = (
            "The verification outcome is unknown because the resident completion turn produced no "
            "user-facing verification summary; the delegated result is not being treated as proof."
        )
    with _delivery_lock(manifest_path):
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        ensure_managed_child_custody_fields(manifest_path, manifest)
        payload = _completion_payload(
            manifest,
            {
                "content": safe_text,
                "result_kind": "resident_verified_summary",
                "verification_outcome": result.verification_outcome,
                "resident_turn_id": result.turn_id,
                "materialized_at": now.isoformat(),
            },
        )
        safe_text = str(payload["content"])
        completion = dict(manifest.get("resident_completion_turn") or {})
        completion.update(
            {
                "status": "completed",
                "verification_outcome": result.verification_outcome,
                "resident_turn_id": result.turn_id,
                "outbound_message_id": result.outbound_message_id,
                "summary_sha256": hashlib.sha256(safe_text.encode("utf-8")).hexdigest(),
                "completed_at": now.isoformat(),
                "updated_at": now.isoformat(),
            }
        )
        manifest["resident_completion_turn"] = completion
        delivery = dict(manifest.get("completion_delivery") or {})
        delivery["payload"] = payload
        manifest["completion_delivery"] = delivery
        _atomic_json(manifest_path, manifest)
        _emit_managed_child_event(
            manifest_path,
            manifest,
            event_kind="effect",
            surface="resident.runtime.completion_turn",
            evidence="resident_completion_turn_completed",
            at=now.isoformat(),
            details={
                "verification_outcome": result.verification_outcome,
                "resident_turn_id": result.turn_id,
            },
        )


def record_completion_turn_id(manifest_path: Path, turn_id: str) -> None:
    """Fence the canonical resident turn identity before model execution begins."""

    with _delivery_lock(manifest_path):
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        ensure_managed_child_custody_fields(manifest_path, manifest)
        completion = dict(manifest.get("resident_completion_turn") or {})
        existing = str(completion.get("resident_turn_id") or "")
        if existing and existing != turn_id:
            raise RuntimeError("resident completion turn identity changed")
        completion["resident_turn_id"] = turn_id
        completion["updated_at"] = _utc_now()
        manifest["resident_completion_turn"] = completion
        _atomic_json(manifest_path, manifest)


def _retry_completion_turn(manifest_path: Path, *, now: datetime, exc: Exception) -> str:
    """Persist a bounded retry without ever falling back to the unverified result."""

    with _delivery_lock(manifest_path):
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        completion = dict(manifest.get("resident_completion_turn") or {})
        attempt = max(1, int(completion.get("attempt_count") or 1))
        if attempt >= _DELIVERY_MAX_ATTEMPTS:
            terminal_content, _ = _completion_message(manifest, manifest_path)
            content = (
                f"{terminal_content}\n\n"
                "The resident could not establish an independent verification turn after bounded "
                "retries. The verification outcome is unknown, and no delegated claim is being "
                "treated as proof; operator inspection is required."
            )
            payload = _completion_payload(
                manifest,
                {
                    "content": content,
                    "result_kind": "resident_verification_unavailable",
                    "verification_outcome": "unknown",
                    "materialized_at": now.isoformat(),
                },
            )
            content = str(payload["content"])
            completion.update(
                {
                    "status": "completed",
                    "verification_outcome": "unknown",
                    "last_error_class": exc.__class__.__name__,
                    "last_error": "resident completion verification retry budget exhausted",
                    "summary_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
                    "completed_at": now.isoformat(),
                    "updated_at": now.isoformat(),
                }
            )
            manifest["resident_completion_turn"] = completion
            delivery = dict(manifest.get("completion_delivery") or {})
            delivery["payload"] = payload
            manifest["completion_delivery"] = delivery
            _atomic_json(manifest_path, manifest)
            _emit_managed_child_event(
                manifest_path,
                manifest,
                event_kind="effect",
                surface="resident.runtime.completion_turn",
                evidence="resident_completion_verification_unavailable",
                at=now.isoformat(),
                details={"attempt_count": attempt},
            )
            return "unknown"
        delay_s = min(_DELIVERY_RETRY_MAX_S, _DELIVERY_RETRY_BASE_S * (2 ** min(attempt - 1, 7)))
        completion.update(
            {
                "status": "retry_pending",
                "last_error_class": exc.__class__.__name__,
                "last_error": "resident completion verification turn failed",
                "next_attempt_at": datetime.fromtimestamp(now.timestamp() + delay_s, timezone.utc).isoformat(),
                "updated_at": now.isoformat(),
            }
        )
        manifest["resident_completion_turn"] = completion
        _atomic_json(manifest_path, manifest)
        _emit_managed_child_event(
            manifest_path,
            manifest,
            event_kind="effect",
            surface="resident.runtime.completion_turn",
            evidence="resident_completion_turn_retry_pending",
            at=now.isoformat(),
            details={"attempt_count": attempt},
        )
        return "retry_pending"


def _dependency_failure_message(
    manifest: Mapping[str, Any], manifest_path: Path
) -> str | None:
    """Render a fail-closed terminal dependency summary from durable manifests.

    This is the no-model fallback.  It deliberately reports only artifact
    existence, never a predecessor's unverified claims as successful work.
    """

    queue = manifest.get("queue")
    if not isinstance(queue, Mapping) or queue.get("state") != "dependency_failed":
        return None
    run_id = str(manifest.get("run_id") or manifest_path.parent.name)
    predecessor_run_id = str(queue.get("failed_predecessor_run_id") or "unknown")
    predecessor_status = str(queue.get("predecessor_status") or "unknown")
    reason = str(queue.get("attention") or "terminal_dependency_failure")
    partial_result = False
    if predecessor_run_id != "unknown":
        predecessor_path = manifest_path.parent.parent / predecessor_run_id / "manifest.json"
        try:
            predecessor = _read_managed_resident_manifest(predecessor_path)
            result_path = _queue_artifact_path(
                predecessor_path, predecessor, "result_path", "result.md"
            )
            partial_result = result_path.is_file() and result_path.stat().st_size > 0
        except (OSError, SubagentQueueError, ValueError):
            partial_result = False
    partial_text = (
        "The predecessor left a non-empty partial result artifact, but that artifact was not "
        "accepted as successful evidence."
        if partial_result
        else "No usable predecessor result was accepted as successful evidence."
    )
    return (
        f"The synthesis/delivery owner {run_id} did not run because required predecessor "
        f"{predecessor_run_id} ended with status {predecessor_status} ({reason}). "
        f"{partial_text} Downstream synthesis was not performed. This is a truthful terminal "
        "dependency failure, not a successful completion."
    )


def _completion_message(manifest: Mapping[str, Any], manifest_path: Path) -> tuple[str, str]:
    run_id = str(manifest.get("run_id") or manifest_path.parent.name)
    status = str(manifest.get("status") or "unknown")
    result_path = Path(str(manifest.get("result_path") or "result.md"))
    if not result_path.is_absolute():
        result_path = manifest_path.parent / result_path
    if status == "completed":
        try:
            with result_path.open("r", encoding="utf-8", errors="replace") as handle:
                final_text = handle.read(_MAX_COMPLETION_DELIVERY_CHARS + 1).strip()
        except OSError:
            final_text = ""
        if final_text:
            from agentbox.redaction import redact_text

            safe_text = redact_text(final_text)
            if len(safe_text) > _MAX_COMPLETION_DELIVERY_CHARS:
                suffix = f"\n\n[Result truncated for Discord; durable run: {run_id}]"
                safe_text = safe_text[: _MAX_COMPLETION_DELIVERY_CHARS - len(suffix)].rstrip() + suffix
            return safe_text, "final_result"
        return (
            f"The managed subagent finished run {run_id}, but it produced no deliverable final "
            "message. The run is not being reported as a successful result.",
            "missing_result",
        )
    dependency_failure = _dependency_failure_message(manifest, manifest_path)
    if dependency_failure is not None:
        return dependency_failure, "terminal_dependency_failure"
    return (
        f"The managed subagent did not complete this request successfully (run {run_id}, "
        f"status: {status}). No successful final result was produced.",
        "terminal_failure",
    )


def _finish_delivery(
    manifest_path: Path,
    *,
    now: datetime,
    message_ids: list[str],
    result_kind: str,
    delivery_evidence: Mapping[str, Any] | None = None,
) -> None:
    with _delivery_lock(manifest_path):
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        ensure_managed_child_custody_fields(manifest_path, manifest)
        delivery = dict(manifest.get("completion_delivery") or {})
        target = dict(
            manifest.get("discord_origin")
            or manifest.get("discord_delivery_target")
            or {}
        )
        expected_conversation_key = str(target.get("conversation_key") or "")
        evidence = _normalized_discord_delivery_evidence(
            delivery_evidence,
            expected_conversation_key=expected_conversation_key,
            message_ids=message_ids,
        )
        history = list(delivery.get("state_history") or [])
        for rejection in evidence["provider_rejections"]:
            history.append(
                {
                    "status": "rejected",
                    "at": now.isoformat(),
                    "evidence": "provider_rejected_reply_or_thread_target",
                    "attempt_id": delivery.get("attempt_id"),
                    **rejection,
                }
            )
        history.append(
            {
                "status": "delivered",
                "at": now.isoformat(),
                "evidence": (
                    "provider_fallback_message_ids_persisted"
                    if evidence["delivery_mode"] == "fallback_plain"
                    else "provider_reply_message_ids_persisted"
                    if evidence["delivery_mode"] == "reply"
                    else "provider_plain_message_ids_persisted"
                ),
                "attempt_id": delivery.get("attempt_id"),
            }
        )
        delivery.update(
            {
                "status": "delivered",
                "delivered_at": now.isoformat(),
                "discord_message_ids": message_ids,
                "result_kind": result_kind,
                "delivery_evidence": evidence,
                "provider_outcome": "accepted",
                # Discord's returned message ids acknowledge provider
                # acceptance.  They are not evidence that a person saw a
                # notification or rendered message.
                "user_notification_visibility": "unknown",
                "updated_at": now.isoformat(),
                "state_history": history[-20:],
            }
        )
        delivery.pop("claim_state", None)
        manifest["completion_delivery"] = delivery
        aggregation = manifest.get("aggregation")
        role = (
            str(aggregation.get("role") or "synthesis_delivery_owner")
            if isinstance(aggregation, Mapping)
            else "synthesis_delivery_owner"
        )
        lifecycle = dict(manifest.get("lifecycle") or {})
        lifecycle.update(
            {
                "schema_version": DELIVERY_STATUS_SCHEMA,
                "work": {"status": "worker_completed", "worker_completed": True},
                "delivery": {
                    "status": "delivered",
                    "policy": dict(manifest.get("execution_contract") or {}).get("delivery_policy"),
                },
                "request": {
                    "status": (
                        "request_delivered"
                        if role == "synthesis_delivery_owner"
                        else "independent_result_delivered_request_open"
                    ),
                    "request_delivered": role == "synthesis_delivery_owner",
                },
            }
        )
        manifest["lifecycle"] = lifecycle
        _atomic_json(manifest_path, manifest)
        _emit_managed_child_event(
            manifest_path,
            manifest,
            event_kind="delivery_custody",
            surface="resident.subagent.delivery",
            evidence=str(history[-1]["evidence"]),
            at=now.isoformat(),
            details={
                "message_ids": message_ids,
                "result_kind": result_kind,
                "delivery_evidence": evidence,
            },
        )


def _normalized_discord_delivery_evidence(
    value: Mapping[str, Any] | None,
    *,
    expected_conversation_key: str,
    message_ids: list[str],
) -> dict[str, Any]:
    evidence = dict(value or {})
    recorded_conversation_key = str(
        evidence.get("authoritative_conversation_key") or expected_conversation_key
    )
    evidence_custody_valid = recorded_conversation_key == expected_conversation_key
    mode = str(evidence.get("delivery_mode") or "reply")
    if mode not in {"reply", "fallback_plain", "plain"}:
        mode = "reply"
    rejections: list[dict[str, object]] = []
    raw_rejections = evidence.get("provider_rejections")
    if isinstance(raw_rejections, (list, tuple)):
        for item in raw_rejections:
            if not isinstance(item, Mapping):
                continue
            rejections.append(
                {
                    "outcome": "rejected",
                    "scope": str(item.get("scope") or "unknown"),
                    "error_class": str(item.get("error_class") or "unknown"),
                    "http_status": item.get("http_status"),
                    "discord_error_code": item.get("discord_error_code"),
                }
            )
    return {
        "schema_version": "arnold-discord-delivery-evidence-v1",
        "authoritative_conversation_key": expected_conversation_key,
        "evidence_custody_valid": evidence_custody_valid,
        "delivery_mode": mode,
        "fallback_reason": (
            str(evidence.get("fallback_reason"))
            if evidence.get("fallback_reason")
            else None
        ),
        "provider_outcome": "accepted",
        "provider_message_ids": list(message_ids),
        "provider_rejections": rejections,
        "resolved_channel_id": (
            str(evidence.get("resolved_channel_id"))
            if evidence.get("resolved_channel_id") is not None
            else None
        ),
        "resolved_thread_id": (
            str(evidence.get("resolved_thread_id"))
            if evidence.get("resolved_thread_id") is not None
            else None
        ),
        "user_notification_visibility": "unknown",
    }


def _optional_http_status(exc: Exception) -> int | None:
    candidates = [getattr(exc, "status", None), getattr(exc, "status_code", None)]
    response = getattr(exc, "response", None)
    if response is not None:
        candidates.extend([getattr(response, "status", None), getattr(response, "status_code", None)])
    for candidate in candidates:
        try:
            status = int(candidate)
        except (TypeError, ValueError):
            continue
        if 100 <= status <= 599:
            return status
    return None


def _optional_discord_error_code(exc: Exception) -> int | None:
    try:
        code = int(getattr(exc, "code", None))
    except (TypeError, ValueError):
        return None
    return code if code > 0 else None


def _http_body_category(exc: Exception, *, http_status: int | None) -> str:
    body = getattr(exc, "text", None)
    if body is None:
        response = getattr(exc, "response", None)
        body = getattr(response, "text", None) if response is not None else None
    if isinstance(body, Mapping) or isinstance(body, (list, tuple)):
        return "json"
    if isinstance(body, bytes):
        return "binary" if body else "empty"
    if isinstance(body, str):
        stripped = body.strip()
        if not stripped:
            return "empty"
        if stripped[:1] in {"{", "["}:
            return "json"
        return "text"
    return "unavailable" if http_status is not None else "not_applicable"


def _delivery_error_evidence(exc: Exception) -> dict[str, object]:
    """Return actionable failure evidence without persisting remote response text."""

    status = _optional_http_status(exc)
    discord_code = _optional_discord_error_code(exc)
    detail = str(exc).lower()
    if isinstance(exc, _ProviderAcceptanceEvidenceMissing):
        category = "provider_acceptance_unknown"
    elif "reply target" in detail or "snowflake" in detail:
        category = "invalid_reply_target"
    elif status == 429:
        category = "rate_limited"
    elif status == 401:
        category = "unauthorized"
    elif status == 403:
        category = "forbidden"
    elif status == 404:
        category = "not_found"
    elif status is not None and status >= 500:
        category = "server_error"
    elif status is not None and status >= 400:
        category = "client_error"
    elif isinstance(exc, (TimeoutError, asyncio.TimeoutError)):
        category = "timeout"
    elif isinstance(exc, (ConnectionError, OSError)):
        category = "network_error"
    else:
        category = "runtime_error"
    body_category = _http_body_category(exc, http_status=status)
    qualifiers = []
    if status is not None:
        qualifiers.append(f"HTTP {status}")
    if discord_code is not None:
        qualifiers.append(f"Discord code {discord_code}")
    qualifiers.append(f"body={body_category}")
    summary = f"Discord delivery failed: {category} ({'; '.join(qualifiers)})"
    return {
        "last_error": summary,
        "last_error_class": exc.__class__.__name__,
        "last_error_category": category,
        "last_http_status": status,
        "last_discord_error_code": discord_code,
        "last_http_body_category": body_category,
    }


def _retry_delivery(
    manifest_path: Path,
    *,
    now: datetime,
    exc: Exception,
    delivery_evidence: Mapping[str, Any] | None = None,
) -> str:
    with _delivery_lock(manifest_path):
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        ensure_managed_child_custody_fields(manifest_path, manifest)
        delivery = dict(manifest.get("completion_delivery") or {})
        attempt = max(1, int(delivery.get("attempt_count") or 1))
        delay_s = min(_DELIVERY_RETRY_MAX_S, _DELIVERY_RETRY_BASE_S * (2 ** min(attempt - 1, 7)))
        next_attempt = now.timestamp() + delay_s
        evidence = _delivery_error_evidence(exc)
        history = list(delivery.get("error_history") or [])
        history.append(
            {
                "attempt_id": delivery.get("attempt_id"),
                "attempted_at": delivery.get("last_attempt_at") or now.isoformat(),
                **evidence,
            }
        )
        category = str(evidence["last_error_category"])
        ambiguous_outcome = category in {
            "provider_acceptance_unknown",
            "timeout",
            "network_error",
            "server_error",
        }
        provider_rejected = (
            category == "invalid_reply_target"
            or isinstance(evidence.get("last_http_status"), int)
            and 400 <= int(evidence["last_http_status"]) < 500
        )
        permanent = category in {
            "invalid_reply_target",
            "unauthorized",
            "forbidden",
            "not_found",
            "client_error",
        }
        exhausted = attempt >= _DELIVERY_MAX_ATTEMPTS
        status = "failed" if permanent or exhausted else "retry_pending"
        state_history = list(delivery.get("state_history") or [])
        if isinstance(delivery_evidence, Mapping):
            raw_rejections = delivery_evidence.get("provider_rejections")
            if isinstance(raw_rejections, (list, tuple)):
                for rejection in raw_rejections:
                    if not isinstance(rejection, Mapping):
                        continue
                    state_history.append(
                        {
                            "status": "rejected",
                            "at": now.isoformat(),
                            "evidence": "provider_rejected_reply_or_thread_target",
                            "attempt_id": delivery.get("attempt_id"),
                            "scope": str(rejection.get("scope") or "unknown"),
                            "error_class": str(
                                rejection.get("error_class") or "unknown"
                            ),
                            "http_status": rejection.get("http_status"),
                            "discord_error_code": rejection.get(
                                "discord_error_code"
                            ),
                        }
                    )
        if ambiguous_outcome:
            state_history.append(
                {
                    "status": "unknown",
                    "at": now.isoformat(),
                    "evidence": "provider_acceptance_outcome_unknown",
                    "attempt_id": delivery.get("attempt_id"),
                }
            )
        state_history.append(
            {
                "status": status,
                "at": now.isoformat(),
                "evidence": (
                    "permanent_provider_rejection"
                    if permanent
                    else "retry_budget_exhausted"
                    if exhausted
                    else "retryable_provider_failure"
                ),
                "attempt_id": delivery.get("attempt_id"),
            }
        )
        delivery.update(
            {
                "status": status,
                "updated_at": now.isoformat(),
                "error_history": history[-10:],
                "state_history": state_history[-20:],
                "provider_outcome": (
                    "unknown"
                    if ambiguous_outcome
                    else "rejected"
                    if provider_rejected
                    else "not_accepted"
                ),
                "user_notification_visibility": "unknown",
                **evidence,
            }
        )
        delivery.pop("claim_state", None)
        if status == "retry_pending":
            delivery["next_attempt_at"] = datetime.fromtimestamp(
                next_attempt, timezone.utc
            ).isoformat()
        else:
            delivery.pop("next_attempt_at", None)
        manifest["completion_delivery"] = delivery
        _atomic_json(manifest_path, manifest)
        _emit_managed_child_event(
            manifest_path,
            manifest,
            event_kind="delivery_custody",
            surface="resident.subagent.delivery",
            evidence=str(state_history[-1]["evidence"]),
            at=now.isoformat(),
            details={
                "attempt_id": delivery.get("attempt_id"),
                "delivery_evidence": delivery_evidence,
                "last_error_category": evidence["last_error_category"],
                "status": status,
            },
        )
        return status


async def sweep_managed_agent_deliveries(
    *,
    outbound: Any,
    project_root: str | Path = ".",
    workspace_root: str | Path | None = "/workspace",
    now: datetime | None = None,
    completion_turn_handler: Callable[
        [Path, Mapping[str, Any]], Awaitable[ManagedCompletionTurnResult]
    ] | None = None,
    delivery_effects: Any | None = None,
) -> ManagedAgentDeliverySweepResult:
    """Reply with terminal managed-agent results and persist retry-safe evidence.

    Step 13H: When *delivery_effects* is provided, completion sweep delivery
    is routed through the durable WBC delivery effects adapter with stable
    global-effect keys.  Real Discord stays action-off in M10 (SD3).
    """

    from .runtime import OutboundMessage

    fixed_now = now
    reconcile_managed_subagent_queues(
        project_root=project_root,
        workspace_root=workspace_root,
        now=fixed_now,
    )
    paths = _managed_manifest_paths(project_root=project_root, workspace_root=workspace_root)
    delivered = retry_pending = skipped = failed = 0
    for manifest_path in paths:
        if completion_turn_handler is not None:
            completion_claim = _completion_turn_claim(
                manifest_path, now=_delivery_transition_now(fixed_now)
            )
            if completion_claim is not None:
                try:
                    completion_result = await completion_turn_handler(
                        manifest_path, completion_claim
                    )
                except Exception as exc:
                    verification_disposition = _retry_completion_turn(
                        manifest_path,
                        now=_delivery_transition_now(fixed_now),
                        exc=exc,
                    )
                    retry_pending += int(verification_disposition == "retry_pending")
                    failed += int(verification_disposition == "unknown")
                    LOGGER.exception(
                        "Resident completion verification turn failed run_id=%s",
                        completion_claim.get("run_id") or manifest_path.parent.name,
                    )
                    continue
                _finish_completion_turn(
                    manifest_path,
                    now=_delivery_transition_now(fixed_now),
                    result=completion_result,
                )
            try:
                current = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, ValueError, TypeError):
                skipped += 1
                continue
            completion_state = current.get("resident_completion_turn")
            if (
                str(current.get("status") or "") in _TERMINAL_STATUSES
                and isinstance(current.get("completion_delivery"), Mapping)
                and current["completion_delivery"].get("transport") == "discord"
                and (
                    not isinstance(completion_state, Mapping)
                    or completion_state.get("status") != "completed"
                )
            ):
                skipped += 1
                continue
        try:
            before_payload = json.loads(manifest_path.read_text(encoding="utf-8"))
            before_delivery = before_payload.get("completion_delivery")
            before_status = (
                str(before_delivery.get("status") or "")
                if isinstance(before_delivery, Mapping)
                else ""
            )
        except (OSError, ValueError, TypeError):
            before_status = ""
        claim = _delivery_claim(
            manifest_path, now=_delivery_transition_now(fixed_now)
        )
        if claim is None:
            try:
                after_payload = json.loads(manifest_path.read_text(encoding="utf-8"))
                after_delivery = after_payload.get("completion_delivery")
                after_status = (
                    str(after_delivery.get("status") or "")
                    if isinstance(after_delivery, Mapping)
                    else ""
                )
            except (OSError, ValueError, TypeError):
                after_status = ""
            if after_status == "failed" and before_status != "failed":
                failed += 1
            else:
                skipped += 1
            continue
        manifest, origin = claim
        delivery = dict(manifest.get("completion_delivery") or {})
        payload = delivery.get("payload")
        if not isinstance(payload, Mapping):
            # New claims always materialize before returning. Treat an absent
            # payload as failed custody rather than re-reading mutable output.
            disposition = _retry_delivery(
                manifest_path,
                now=_delivery_transition_now(fixed_now),
                exc=RuntimeError("durable outbox payload missing"),
            )
            retry_pending += int(disposition == "retry_pending")
            failed += int(disposition == "failed")
            continue
        content = str(payload.get("content") or "")
        result_kind = str(payload.get("result_kind") or "missing_result")
        metadata: dict[str, Any] = {
            "managed_agent_run_id": manifest.get("run_id") or manifest_path.parent.name,
            "completion_delivery": True,
            "timezone_name": str(
                dict(manifest.get("launch_provenance") or {}).get("timezone_name") or "UTC"
            ),
            "discord_nonce": dict(manifest.get("completion_delivery") or {}).get("discord_nonce"),
            "notification_safety_context": {
                "project_dir": manifest.get("project_dir"),
                "notification_context": manifest.get("notification_context"),
                "launch_provenance": manifest.get("launch_provenance"),
            },
        }
        reply_to_message_id = str(origin.get("reply_to_message_id") or "").strip()
        if reply_to_message_id:
            metadata.update({
                "discord_reply_to_message_id": reply_to_message_id,
                # The originating resident turn added this marker after durable
                # custody. Terminal outbox delivery removes it after restart.
                "discord_processing_message_ids": [reply_to_message_id],
                "discord_processing_turn_id": str(
                    dict(manifest.get("launch_provenance") or {}).get("resident_turn_id") or ""
                ),
            })
        else:
            metadata["discord_delivery_evidence"] = {
                "delivery_mode": "plain",
                "authoritative_conversation_key": origin["conversation_key"],
            }
        # Fake outbound sinks remain usable for deterministic delivery tests,
        # while the production Discord boundary independently reclassifies
        # durable manifest context immediately before the network send.
        if str(getattr(outbound, "delivery_environment", "")).lower() == "production":
            from arnold_pipelines.megaplan.notification_safety import (
                classify_user_notification,
            )

            safety = classify_user_notification(
                payload=metadata["notification_safety_context"], env={}
            )
            if not safety.allowed:
                suppressed_at = _delivery_transition_now(fixed_now)
                delivery.update(
                    {
                        "status": "suppressed",
                        "claim_state": "suppressed",
                        "last_error": "",
                        "last_error_class": "",
                        "last_error_category": "test_execution_suppressed",
                        "suppression_reason": safety.reason,
                        "updated_at": suppressed_at.isoformat(),
                    }
                )
                history = list(delivery.get("state_history") or [])
                history.append(
                    {
                        "status": "suppressed",
                        "at": suppressed_at.isoformat(),
                        "evidence": "notification_safety_policy",
                        "reason": safety.reason,
                    }
                )
                delivery["state_history"] = history[-20:]
                manifest["completion_delivery"] = delivery
                _atomic_json(manifest_path, manifest)
                skipped += 1
                continue
        try:
            run_id = manifest.get("run_id") or manifest_path.parent.name
            effect_routed = False

            # Step 13H: route completion sweep delivery through WBC when configured.
            # If delivery_effects is provided directly or via the outbound sink,
            # the delivery is routed through durable global-effect keys.
            if delivery_effects is not None:
                try:
                    from arnold_pipelines.megaplan.resident.delivery_effects import (
                        DeliveryChannel,
                        DeliveryTarget,
                    )

                    sweep_target = DeliveryTarget(
                        channel=DeliveryChannel.RESIDENT,
                        parent_id=str(origin.get("conversation_key", "")),
                        target_id=f"resident-subagent-completion:{run_id}",
                        action="completion_sweep",
                    )
                    sweep_intent = {
                        "content": content,
                        "run_id": run_id,
                        "result_kind": result_kind,
                        "conversation_key": str(origin.get("conversation_key", "")),
                        "idempotency_key": f"resident-subagent-completion:{run_id}",
                    }
                    if isinstance(metadata, dict):
                        sweep_intent["metadata"] = dict(metadata)

                    async def _provider_apply(
                        _provider_idempotency_key: str,
                        _intent: dict[str, Any],
                    ) -> dict[str, Any]:
                        await outbound.send(
                            OutboundMessage(
                                conversation_key=str(origin["conversation_key"]),
                                content=content,
                                idempotency_key=f"resident-subagent-completion:{run_id}",
                                metadata=metadata,
                            )
                        )
                        return {
                            "delivered": True,
                            "message_ids": list(metadata.get("discord_message_ids") or []),
                        }

                    if getattr(outbound, "_delivery_effects", None) is delivery_effects:
                        await outbound.send(
                            OutboundMessage(
                                conversation_key=str(origin["conversation_key"]),
                                content=content,
                                idempotency_key=f"resident-subagent-completion:{run_id}",
                                metadata=metadata,
                            )
                        )
                        effect_routed = True
                        sweep_outcome = None
                    else:
                        sweep_outcome = await delivery_effects.deliver_async(
                            target=sweep_target,
                            intent_payload=sweep_intent,
                            apply_fn=_provider_apply,
                        )
                    if sweep_outcome is not None:
                        if not sweep_outcome.ok:
                            raise RuntimeError(
                                f"Completion sweep delivery blocked by WBC: {sweep_outcome.error}"
                            )
                        effect_routed = True
                        effect_message_ids = [
                            str(value)
                            for value in sweep_outcome.evidence.get("message_ids", [])
                            if str(value)
                        ]
                        metadata["discord_message_ids"] = effect_message_ids or [
                            f"effect:{sweep_outcome.glek}"
                        ]
                        metadata["delivery_effects_routed"] = True
                        metadata["delivery_glek"] = sweep_outcome.glek
                except Exception as delivery_route_exc:
                    raise RuntimeError("Completion sweep delivery routing unavailable") from delivery_route_exc

            if not effect_routed:
                await outbound.send(
                    OutboundMessage(
                        conversation_key=str(origin["conversation_key"]),
                        content=content,
                        idempotency_key=f"resident-subagent-completion:{run_id}",
                        metadata=metadata,
                    )
                )
        except Exception as exc:
            evidence = _delivery_error_evidence(exc)
            disposition = _retry_delivery(
                manifest_path,
                now=_delivery_transition_now(fixed_now),
                exc=exc,
                delivery_evidence=(
                    metadata.get("discord_delivery_evidence")
                    if isinstance(
                        metadata.get("discord_delivery_evidence"), Mapping
                    )
                    else None
                ),
            )
            if disposition == "retry_pending":
                retry_pending += 1
            else:
                failed += 1
            LOGGER.warning(
                "Managed agent completion delivery disposition=%s run_id=%s error_class=%s "
                "error_category=%s http_status=%s body_category=%s",
                disposition,
                manifest.get("run_id") or manifest_path.parent.name,
                exc.__class__.__name__,
                evidence["last_error_category"],
                evidence["last_http_status"],
                evidence["last_http_body_category"],
            )
            continue
        message_ids = [str(value) for value in metadata.get("discord_message_ids", []) if str(value)]
        if not message_ids:
            # A normal return is not by itself provider-acceptance evidence.
            # Keep the stable nonce and redrive through the normal retry path;
            # Discord can deduplicate an attempt that was accepted but whose
            # response was lost, while the manifest remains truthful meanwhile.
            disposition = _retry_delivery(
                manifest_path,
                now=_delivery_transition_now(fixed_now),
                exc=_ProviderAcceptanceEvidenceMissing(
                    "Discord send returned without provider message ids"
                ),
                delivery_evidence=(
                    metadata.get("discord_delivery_evidence")
                    if isinstance(
                        metadata.get("discord_delivery_evidence"), Mapping
                    )
                    else None
                ),
            )
            retry_pending += int(disposition == "retry_pending")
            failed += int(disposition == "failed")
            continue
        _finish_delivery(
            manifest_path,
            now=_delivery_transition_now(fixed_now),
            message_ids=message_ids,
            result_kind=result_kind,
            delivery_evidence=(
                metadata.get("discord_delivery_evidence")
                if isinstance(metadata.get("discord_delivery_evidence"), Mapping)
                else None
            ),
        )
        delivered += 1
    return ManagedAgentDeliverySweepResult(
        scanned=len(paths),
        delivered=delivered,
        retry_pending=retry_pending,
        skipped=skipped,
        failed=failed,
    )


def list_managed_resident_agents(
    *,
    project_root: str | Path = ".",
    workspace_root: str | Path | None = "/workspace",
    recent_limit: int = 10,
    queue_limit: int = MAX_QUEUE_HOT_CONTEXT_ROWS,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build the unified managed-agent view used by resident hot context.

    Automatic repair appears here only when the real worker crossed the shared
    supervisor.  Legacy resident manifests remain visible; untracked legacy
    repairs are intentionally not manufactured into this view.
    """
    roots = _managed_run_roots(project_root=project_root, workspace_root=workspace_root)

    manifest_index: dict[str, tuple[Path, Mapping[str, Any]]] = {}
    for root in sorted(roots):
        if not root.is_dir():
            continue
        for manifest_path in sorted(root.glob("*/manifest.json")):
            try:
                candidate = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, ValueError, TypeError):
                continue
            if not isinstance(candidate, dict):
                continue
            schema = candidate.get("schema_version")
            if schema != LEGACY_MANAGED_RUN_SCHEMA and not is_managed_manifest(candidate):
                continue
            if schema != LEGACY_MANAGED_RUN_SCHEMA and candidate.get("run_kind") != MANAGED_RUN_KIND:
                continue
            run_id = str(candidate.get("run_id") or manifest_path.parent.name)
            manifest_index.setdefault(run_id, (manifest_path, candidate))

    rows: list[dict[str, Any]] = []
    for root in sorted(roots):
        if not root.is_dir():
            continue
        for manifest_path in root.glob("*/manifest.json"):
            try:
                payload = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, ValueError, TypeError):
                continue
            schema = payload.get("schema_version")
            very_legacy = schema == LEGACY_MANAGED_RUN_SCHEMA
            if not very_legacy and not is_managed_manifest(payload):
                continue
            persisted_status = str(payload.get("status") or "unknown")
            pid = payload.get("pid")
            run_kind = str(payload.get("run_kind") or MANAGED_RUN_KIND)
            evidence_class = "canonical"
            if schema == MANAGED_RUN_SCHEMA:
                observed_status, live = shared_observed_status(payload, manifest_path)
                if run_kind.startswith("automatic_"):
                    try:
                        validate_automatic_managed_manifest(
                            payload,
                            manifest_path=manifest_path,
                        )
                    except (TypeError, ValueError):
                        evidence_class = "legacy_noncanonical"
                        observed_status = "noncanonical_legacy"
                        live = False
            else:
                evidence_class = "legacy_compatibility"
                process_matches = isinstance(pid, int) and _pid_matches_manifest(pid, manifest_path)
                live = persisted_status in _ACTIVE_STATUSES and process_matches
                observed_status = persisted_status
                if persisted_status in _ACTIVE_STATUSES and not process_matches:
                    observed_status = "interrupted"

            projection = build_delivery_projection(
                manifest=payload,
                manifest_path=manifest_path,
                observed_status=observed_status,
                manifest_index=manifest_index,
            )

            def artifact_path(field: str, fallback: str) -> str:
                raw = payload.get(field) or fallback
                path = Path(str(raw))
                if not path.is_absolute():
                    path = manifest_path.parent / path
                return str(path.resolve())

            rows.append(
                {
                    "run_id": payload.get("run_id") or manifest_path.parent.name,
                    "run_kind": run_kind,
                    "evidence_class": evidence_class,
                    "status": observed_status,
                    "persisted_status": persisted_status,
                    "live": live,
                    "pid": pid,
                    "backend": payload.get("backend"),
                    "model": payload.get("model"),
                    "reasoning_effort": payload.get("reasoning_effort"),
                    "task_kind": payload.get("task_kind"),
                    "description": payload.get("description"),
                    "difficulty": payload.get("difficulty"),
                    "route_class": payload.get("route_class"),
                    "request_id": payload.get("request_id"),
                    "caller_request_id": payload.get("caller_request_id"),
                    "correlation_id": payload.get("correlation_id"),
                    "custody_id": payload.get("custody_id"),
                    "source_record_id": payload.get("source_record_id"),
                    "task_sha256": payload.get("task_sha256"),
                    "task_excerpt": payload.get("task_excerpt"),
                    "project_dir": payload.get("project_dir"),
                    "created_at": payload.get("created_at"),
                    "started_at": payload.get("started_at"),
                    "finished_at": payload.get("finished_at"),
                    # A provider may persist this immutable measurement on the
                    # manifest.  Do not synthesize it from logs or limits.
                    "usage": payload.get("usage"),
                    "manifest_path": str(manifest_path.resolve()),
                    "full_log_path": artifact_path(
                        "full_log_path", str(payload.get("log_path") or "run.log")
                    ),
                    "result_path": artifact_path("result_path", "result.md"),
                    "discord_origin": payload.get("discord_origin"),
                    "launch_provenance": payload.get("launch_provenance"),
                    "completion_delivery": payload.get("completion_delivery"),
                    "status_history": payload.get("status_history"),
                    "terminal_outcome": payload.get("terminal_outcome"),
                    "worker_pid": payload.get("worker_pid"),
                    "retry_of_run_id": payload.get("retry_of_run_id"),
                    "parent_run_id": payload.get("parent_run_id"),
                    "lineage_key": payload.get("lineage_key"),
                    "links": payload.get("links"),
                    "query_relationship": payload.get("query_relationship"),
                    "aggregation": payload.get("aggregation"),
                    "queue": payload.get("queue"),
                    "queue_links": payload.get("queue_links"),
                    "execution_contract": projection["execution_contract"],
                    "status_projection": projection,
                }
            )
    rows.sort(key=lambda row: str(row.get("created_at") or ""), reverse=True)
    running = [row for row in rows if row["live"]]
    queued_all = [
        row
        for row in rows
        if isinstance(row.get("queue"), Mapping)
        and row["status"] not in _TERMINAL_STATUSES
        and not row["live"]
    ]
    queued = queued_all[: max(0, queue_limit)]
    terminal = [
        row
        for row in rows
        if not row["live"]
        and not (
            isinstance(row.get("queue"), Mapping)
            and row["status"] not in _TERMINAL_STATUSES
        )
    ]
    bounded_recent_limit = max(0, recent_limit)
    recent = terminal[:bounded_recent_limit]
    delivery_status_counts: dict[str, int] = {}
    terminal_delivery_status_counts: dict[str, int] = {}
    work_status_counts: dict[str, int] = {}
    request_status_counts: dict[str, int] = {}
    projections: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        delivery = row.get("completion_delivery")
        status = (
            str(delivery.get("status") or "pending")
            if isinstance(delivery, dict)
            else "not_applicable"
        )
        delivery_status_counts[status] = delivery_status_counts.get(status, 0) + 1
        projection = dict(row.get("status_projection") or {})
        projections[str(row["run_id"])] = projection
        work_status = str(dict(projection.get("work") or {}).get("status") or "unknown")
        request_status = str(dict(projection.get("request") or {}).get("status") or "unknown")
        work_status_counts[work_status] = work_status_counts.get(work_status, 0) + 1
        request_status_counts[request_status] = request_status_counts.get(request_status, 0) + 1
        if row["status"] in _TERMINAL_STATUSES:
            terminal_delivery_status_counts[status] = (
                terminal_delivery_status_counts.get(status, 0) + 1
            )
    attention = build_delivery_attention(
        manifest_index=manifest_index,
        projections=projections,
        now=now or datetime.now(timezone.utc),
    )
    legacy_delivery_attention_count = sum(
        count
        for status, count in terminal_delivery_status_counts.items()
        if status in {"pending", "retry_pending", "failed", "unknown"}
    )
    return {
        "schema_version": MANAGED_RUN_SCHEMA,
        "scope": "unified resident and automatic-repair managed agents",
        "run_root": str((Path(project_root).resolve() / DEFAULT_MANAGED_RUN_ROOT)),
        "running": running,
        "queued": queued,
        "queued_count": len(queued_all),
        "queued_omitted_count": max(0, len(queued_all) - len(queued)),
        "queue_attention_count": sum(
            1
            for row in rows
            if isinstance(row.get("queue"), Mapping)
            and str(row["queue"].get("attention") or "none")
            not in {"none", "waiting_for_predecessor", "waiting_for_predecessors"}
        ),
        "recent": recent,
        "running_count": len(running),
        "recent_count": len(recent),
        "recent_total_count": len(terminal),
        "recent_omitted_count": max(0, len(terminal) - len(recent)),
        "delivery_status_counts": delivery_status_counts,
        "terminal_delivery_status_counts": terminal_delivery_status_counts,
        "work_status_counts": work_status_counts,
        "request_status_counts": request_status_counts,
        "attention": attention,
        "delivery_attention_count": legacy_delivery_attention_count + len(attention),
    }


SUPERFIXER_PROACTIVE_MODEL_SPEC = "omp:deepseek/deepseek-v4-flash"


def launch_superfixer_proactive_managed(
    *,
    task: str,
    description: str | None = None,
    project_dir: str | None = None,
    request_id: str | None = None,
    launch_origin: Mapping[str, Any] | None = None,
    schedule_context: Mapping[str, Any] | None = None,
    model_spec: str | None = None,
) -> SubagentResult:
    """Launch the hourly superfixer backstop through the durable managed-run path.

    One managed agent per due occurrence: ``request_id`` and
    ``schedule_context`` bind the schedule occurrence and claim custody into
    the durable manifest (``schedule_occurrence``), and ``launch_origin``
    carries the scheduled-turn source kind, so the durable launch receipt
    links back to the occurrence claim and forward to the final run receipt.
    Legacy callers default to the fixed omp deepseek-v4-flash backstop.  A
    continuation caller must provide its exact profile-derived model spec;
    this seam never rewrites a legacy/default value into a continuation pin.
    """
    provider_probe: Mapping[str, Any] | None = None
    if project_dir is not None:
        from arnold_pipelines.megaplan.profiles import resolve_continuation_runtime_model

        canonical_model = resolve_continuation_runtime_model(Path(project_dir))
        if canonical_model is not None:
            if model_spec != canonical_model:
                raise ValueError(
                    "continuation superfixer requires the explicit canonical model"
                )
            route = canonical_model.removeprefix("omp:")
            provider, separator, model_and_effort = route.partition("/")
            model, effort_separator, effort = model_and_effort.rpartition(":")
            if not separator or not provider or not effort_separator or effort != "high":
                raise ValueError("continuation superfixer provider route is not canonical")
            from arnold_pipelines.megaplan.cloud.worker_dispatch import (
                ensure_continuation_provider_probe,
            )

            provider_probe = ensure_continuation_provider_probe(
                Path(project_dir), canonical_model
            )
    if model_spec is None:
        model_spec = SUPERFIXER_PROACTIVE_MODEL_SPEC
    if not model_spec.startswith("omp:"):
        raise ValueError(
            f"superfixer model spec requires the omp backend: {model_spec!r}"
        )
    backend, _, model = model_spec.partition(":")
    if backend != "omp":
        raise ValueError(
            f"superfixer backstop requires the omp backend: {model_spec!r}"
        )
    return launch_managed_subagent_detached(
        task=task,
        description=description,
        project_dir=project_dir,
        backend=backend,
        model=model,
        model_spec=model_spec,
        reasoning_effort="high" if model_spec.endswith(":high") else "medium",
        provider_probe=provider_probe,
        task_kind="autonomous",
        work_intent="execution",
        mutation_claim="auto",
        request_id=request_id,
        launch_origin=launch_origin,
        schedule_context=schedule_context,
    )


async def launch_subagent_task(
    config: ResidentConfig,
    *,
    task: str,
    description: str | None = None,
    aggregation_role: str = "synthesis_delivery_owner",
    synthesis_group: str | None = None,
    outcome_contract: str | None = None,
    outcome_key: str | None = None,
    delivery_suppression_override_reason: str | None = None,
    toolsets: str | None = None,
    project_dir: str | None = None,
    backend: str = "auto",
    background: bool = True,
    model: str | None = None,
    reasoning_effort: str | None = None,
    task_kind: DelegatedTaskKind = DEFAULT_DELEGATED_TASK_KIND,
    work_intent: DelegatedWorkIntent = DEFAULT_DELEGATED_WORK_INTENT,
    mutation_claim: DelegatedMutationClaim = "auto",
    difficulty: int = DEFAULT_DELEGATED_DIFFICULTY,
    request_id: str | None = None,
    launch_origin: Mapping[str, Any] | None = None,
    retry_of_run_id: str | None = None,
    query_relationship: Mapping[str, Any] | None = None,
    depends_on_run_id: str | None = None,
    depends_on_run_ids: Sequence[str] | None = None,
    queue_max_launch_attempts: int = _QUEUE_MAX_LAUNCH_ATTEMPTS,
    schedule_context: Mapping[str, Any] | None = None,
) -> SubagentResult:
    """Dispatch ``task`` through the resident-owned delegated-agent seam.

    The model/agent spec selects omp, Codex, or Claude when ``backend`` is
    ``"auto"``.  Explicit compatible overrides remain supported.  All three
    providers use the same durable background manifest and delivery lifecycle;
    old non-Discord callers may still request synchronous omp explicitly.
    """
    if len(task) > MAX_DELEGATED_TASK_CHARS:
        raise ValueError(
            f"delegated task exceeds {MAX_DELEGATED_TASK_CHARS} characters; "
            "store large evidence durably and pass paths/routes"
        )
    has_dependencies = depends_on_run_id is not None or depends_on_run_ids is not None
    if has_dependencies and not background:
        raise ValueError("queued successors require the durable managed background lifecycle")
    if backend == "codex":
        if not background:
            raise ValueError(
                "Codex resident subagents must use background=True for durable lifecycle tracking"
            )
    route = route_delegated_task(task_kind=task_kind, difficulty=difficulty)
    provider_route: ManagedAgentRoute = resolve_managed_agent_route(
        backend=backend,
        model=model,
        default_backend="codex",
        default_models={
            "codex": route.model,
            "omp": config.subagent_model_name,
            "claude": "opus",
        },
    )
    if project_dir is not None:
        from arnold_pipelines.megaplan.profiles import resolve_continuation_runtime_model

        canonical_model = resolve_continuation_runtime_model(Path(project_dir))
        if canonical_model is not None:
            if model is None or provider_route.model_spec != canonical_model:
                raise ValueError(
                    "continuation resident dispatch requires the explicit canonical model"
                )
            provider_route = ManagedAgentRoute(
                backend="omp",
                model=canonical_model.removeprefix("omp:"),
                model_spec=canonical_model,
                effort="high",
                backend_source="continuation_profile",
            )
    selected_effort = reasoning_effort or provider_route.effort or route.reasoning_effort
    if (
        project_dir is not None
        and provider_route.backend_source == "continuation_profile"
        and reasoning_effort not in {None, "high"}
    ):
        raise ValueError("continuation canonical model requires high reasoning effort")
    if selected_effort not in _VALID_DELEGATED_EFFORTS:
        raise ValueError(
            "reasoning_effort must be one of "
            f"{', '.join(sorted(_VALID_DELEGATED_EFFORTS))}; got {selected_effort!r}"
        )
    resolved_model_spec = provider_route.model_spec
    if provider_route.backend in {"codex", "claude"} and (
        provider_route.effort is not None or reasoning_effort is not None
    ):
        resolved_model_spec = format_agent_spec(
            AgentSpec(
                agent=provider_route.backend,
                model=provider_route.model,
                effort=selected_effort,
            )
        )

    if background:
        launch_kwargs = dict(
            task=task,
            description=description,
            aggregation_role=aggregation_role,
            synthesis_group=synthesis_group,
            outcome_contract=outcome_contract,
            outcome_key=outcome_key,
            delivery_suppression_override_reason=delivery_suppression_override_reason,
            project_dir=project_dir,
            model=provider_route.model,
            model_spec=resolved_model_spec,
            reasoning_effort=selected_effort,
            toolsets=toolsets or config.special_requests_subagent_toolsets,
            max_tokens=config.special_requests_subagent_max_tokens,
            provider_timeout_s=config.special_requests_subagent_timeout_s,
            task_kind=route.task_kind,
            work_intent=work_intent,
            mutation_claim=mutation_claim,
            difficulty=route.difficulty,
            route_class=(
                "explicit_override"
                if model is not None or reasoning_effort is not None or backend != "auto"
                else route.route_class
            ),
            request_id=request_id,
            launch_origin=launch_origin,
            retry_of_run_id=retry_of_run_id,
            query_relationship=query_relationship,
            depends_on_run_id=depends_on_run_id,
            depends_on_run_ids=depends_on_run_ids,
            queue_max_launch_attempts=queue_max_launch_attempts,
            schedule_context=schedule_context,
        )
        if provider_route.backend == "codex":
            return launch_codex_subagent_detached(**launch_kwargs)
        return launch_managed_subagent_detached(
            backend=provider_route.backend,
            **launch_kwargs,
        )

    if provider_route.backend != "omp" or backend == "auto":
        raise ValueError(
            "non-omp resident subagents and inferred provider routes require "
            "background=True for durable lifecycle tracking"
        )
    compatibility_provenance = _canonical_launch_provenance(
        launch_origin,
        project_root=Path(project_dir or Path.cwd()).resolve(),
        request_id=request_id,
    )
    if compatibility_provenance["applicability"] == "applicable":
        raise ValueError(
            "omp compatibility launches are synchronous and cannot satisfy durable Discord custody"
        )
    if not OMP_LAUNCHER_PATH.exists():
        raise FileNotFoundError(f"omp launcher not found: {OMP_LAUNCHER_PATH}")

    argv: list[str] = [
        sys.executable,
        str(OMP_LAUNCHER_PATH),
        "--model",
        provider_route.model,
        "--toolsets",
        toolsets or config.special_requests_subagent_toolsets,
        "--max-tokens",
        str(config.special_requests_subagent_max_tokens),
    ]
    if project_dir:
        argv += ["--project-dir", str(project_dir)]

    # Multi-line prompts are brittle on argv — write to a query file instead.
    with tempfile.NamedTemporaryFile(
        "w", suffix=".md", delete=False, encoding="utf-8"
    ) as handle:
        handle.write(
            _delivery_prompt(
                task,
                str(compatibility_provenance.get("timezone_name") or "UTC"),
                task_kind=task_kind,
                work_intent=work_intent,
                mutation_claim=mutation_claim,
                context_directory=_delegated_context_directory(
                    project_root=Path(project_dir or Path.cwd()).resolve(),
                    provenance=compatibility_provenance,
                ),
            )
        )
        query_path = handle.name
    argv += ["--query-file", query_path]

    timeout_s = config.special_requests_subagent_timeout_s
    try:
        completed = await asyncio.to_thread(_run_subprocess, argv, timeout_s)
    finally:
        try:
            Path(query_path).unlink(missing_ok=True)
        except OSError:
            LOGGER.debug("could not remove subagent query file %s", query_path, exc_info=True)

    return completed


def _build_local_seam_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m arnold_pipelines.megaplan.resident.subagent",
        description="Supported local seam for resident-managed delegated agents",
    )
    sub = parser.add_subparsers(dest="action", required=True)
    launch = sub.add_parser(
        "launch",
        help="Launch a durable provider-aware agent, inheriting resident delegation provenance",
    )
    task_source = launch.add_mutually_exclusive_group(required=True)
    task_source.add_argument("--task")
    task_source.add_argument("--task-file")
    launch.add_argument(
        "--description",
        help="Concise one-line human-readable description of the delegated work",
    )
    launch.add_argument(
        "--aggregation-role",
        choices=sorted(AGGREGATION_ROLES),
        default="synthesis_delivery_owner",
    )
    launch.add_argument("--synthesis-group")
    launch.add_argument("--project-dir")
    launch.add_argument(
        "--backend",
        default="auto",
        choices=("auto", "omp", "codex", "claude", "chatgpt", "shannon"),
        help="Provider override; auto infers from --model and is the default",
    )
    launch.add_argument("--model")
    launch.add_argument(
        "--reasoning-effort", choices=sorted(_VALID_DELEGATED_EFFORTS)
    )
    launch.add_argument("--task-kind", choices=DELEGATED_TASK_KINDS, default=DEFAULT_DELEGATED_TASK_KIND)
    launch.add_argument(
        "--work-intent",
        choices=DELEGATED_WORK_INTENTS,
        default=DEFAULT_DELEGATED_WORK_INTENT,
    )
    launch.add_argument(
        "--mutation-claim",
        choices=DELEGATED_MUTATION_CLAIMS,
        default="auto",
    )
    launch.add_argument("--difficulty", type=int, default=DEFAULT_DELEGATED_DIFFICULTY)
    launch.add_argument("--request-id")
    launch.add_argument("--retry-of-run-id")
    followup = sub.add_parser(
        "follow-up",
        aliases=["followup"],
        help=(
            "Durably continue one resident-managed run lineage; active parents are "
            "safely interrupted and terminal parents resume their persistent Codex session"
        ),
    )
    followup.add_argument("--run-id", required=True)
    message_source = followup.add_mutually_exclusive_group(required=True)
    message_source.add_argument("--message")
    message_source.add_argument("--message-file")
    followup.add_argument("--project-dir")
    followup.add_argument(
        "--idempotency-key",
        help="Stable retry key; reuse is allowed only with identical message and custody",
    )
    followup.add_argument(
        "--aggregation-role",
        choices=sorted(AGGREGATION_ROLES),
        default="synthesis_delivery_owner",
    )
    followup.add_argument("--synthesis-group")
    return parser


def _local_launch_task(args: argparse.Namespace) -> str:
    if args.task_file:
        try:
            return Path(args.task_file).expanduser().read_text(encoding="utf-8")
        except OSError as exc:
            raise SystemExit(f"cannot read --task-file: {exc}") from exc
    return str(args.task or "")


def _local_followup_message(args: argparse.Namespace) -> str:
    if args.message_file:
        try:
            return Path(args.message_file).expanduser().read_text(encoding="utf-8")
        except OSError as exc:
            raise SystemExit(f"cannot read --message-file: {exc}") from exc
    return str(args.message or "")


def _main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    # Private worker compatibility; deliberately absent from the public parser.
    if len(raw) == 2 and raw[0] == "--run-managed":
        return _run_managed_manifest(Path(raw[1]))
    if len(raw) == 2 and raw[0] == "--run-codex":
        return _run_codex_manifest(Path(raw[1]))
    args = _build_local_seam_parser().parse_args(raw)
    if args.action == "launch":
        task = _local_launch_task(args).strip()
        if not task:
            raise SystemExit("delegated task must not be empty")
        result = asyncio.run(
            launch_subagent_task(
                ResidentConfig(),
                task=task,
                description=args.description,
                aggregation_role=args.aggregation_role,
                synthesis_group=args.synthesis_group,
                project_dir=args.project_dir,
                backend=args.backend,
                model=args.model,
                reasoning_effort=args.reasoning_effort,
                task_kind=args.task_kind,
                work_intent=args.work_intent,
                mutation_claim=args.mutation_claim,
                difficulty=args.difficulty,
                request_id=args.request_id,
                retry_of_run_id=args.retry_of_run_id,
            )
        )
        print(json.dumps(result.__dict__, sort_keys=True))
        return 0 if result.ok else 1
    if args.action in {"follow-up", "followup"}:
        message = _local_followup_message(args).strip()
        try:
            result = follow_up_managed_subagent(
                run_id=args.run_id,
                message=message,
                project_dir=args.project_dir,
                workspace_root=None,
                idempotency_key=args.idempotency_key,
                aggregation_role=args.aggregation_role,
                synthesis_group=args.synthesis_group,
            )
        except (SubagentFollowupError, DelegationProvenanceError, OSError) as exc:
            print(
                json.dumps(
                    {
                        "ok": False,
                        "error": "resident_followup_rejected",
                        "message": str(exc),
                    },
                    sort_keys=True,
                )
            )
            return 2
        print(json.dumps(result.__dict__, sort_keys=True))
        return 0
    raise SystemExit(f"unsupported resident subagent action: {args.action}")


if __name__ == "__main__":
    raise SystemExit(_main())


def _run_subprocess(argv: list[str], timeout_s: float | None) -> SubagentResult:
    run_kwargs: dict[str, Any] = {"capture_output": True, "text": True, "check": False}
    if timeout_s is not None:
        run_kwargs["timeout"] = timeout_s
    try:
        completed = subprocess.run(argv, **run_kwargs)
    except subprocess.TimeoutExpired as exc:
        return SubagentResult(
            ok=False,
            final_text="",
            stderr=str(exc),
            returncode=-1,
            error=(f"subagent timed out after {timeout_s:.0f}s" if timeout_s is not None else "subagent timed out unexpectedly"),
        )
    final_text = (completed.stdout or "").strip()
    stderr = completed.stderr or ""
    returncode = completed.returncode
    ok = returncode == 0 and bool(final_text)
    error: str | None = None
    if not ok:
        tail = stderr.strip()[:500]
        error = f"subagent exit {returncode}" + (f": {tail}" if tail else " (no stdout)")
    return SubagentResult(
        ok=ok,
        final_text=final_text,
        stderr=stderr,
        returncode=returncode,
        error=error,
    )
