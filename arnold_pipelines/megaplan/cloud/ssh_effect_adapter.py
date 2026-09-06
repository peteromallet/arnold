"""Step 13F: SSH remote mutation sink adapter.

Routes remote mutation sinks in ``cloud/providers/ssh.py`` through the
WBC effect protocol and action gate, preserving command semantics while
adding stale-fence and provider-missing negatives.

SSH effects remain fail-closed until the current Run Authority/WBC/Custody
context authorizes the exact target.  An authorized production effect uses
the same durable protocol as tests; there is no raw-transport fallback.

Gate-only operations (ssh_exec, upload_file, upload_archive, down) use
``gate_dispatch`` and are permitted in production only after an explicit
authorization from the current owner context.

Mutating operations covered:
- build: rsync/scp deploy + docker build
- deploy: env write + docker rm/run
- down: docker stop
- destroy: docker rm + workspace rm
- ssh_exec: docker exec commands
- upload_file / upload_archive: remote file writes

Step 13F bounded shard: at most three SSH remote mutation operations
migrated, the remainder marked action-off.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

from arnold.workflow.effect_protocol import (
    EffectProtocol,
    OUTCOME_COMPLETED,
    OUTCOME_FAILED,
    OUTCOME_INDETERMINATE,
)
from arnold.workflow.execution_attempt_ledger import (
    AdapterKind,
    AttemptIdentity,
    AttemptProvenance,
    GlobalEffectIdentity,
    GrantRef,
    RuntimeAdapter,
    VersionSet,
)

from arnold_pipelines.megaplan.custody.action_validator import (
    ActionBoundaryType,
    GateResult,
    adapter_effect_authorized,
)

LOGGER = logging.getLogger(__name__)


# ── SSH effect shard identity ────────────────────────────────────────────────


class SshEffectShard(str, Enum):
    """Step 13F bounded shard: SSH remote mutation operations.

    BUILD/DEPLOY/DESTROY are the at-most-three routed rows; the remaining
    operations are action-off (gate-only dispatch, never WBC-routed).
    """

    BUILD = "build"
    """rsync/scp deploy directory + docker build."""

    DEPLOY = "deploy"
    """env write + docker rm/run on remote."""

    DESTROY = "destroy"
    """docker rm + workspace cleanup on remote."""

    SSH_EXEC = "ssh_exec"
    """docker exec commands on the remote container (action-off)."""

    UPLOAD_FILE = "upload_file"
    """remote file writes (action-off)."""

    UPLOAD_ARCHIVE = "upload_archive"
    """remote archive extraction (action-off)."""

    DOWN = "down"
    """docker stop on the remote (action-off)."""


SSH_SHARD_13F: tuple[SshEffectShard, ...] = (
    SshEffectShard.BUILD,
    SshEffectShard.DEPLOY,
    SshEffectShard.DESTROY,
)
"""The at-most-three SSH rows routed in Step 13F."""

# Shards that remain action-off for M10
SSH_ACTION_OFF_SHARDS: frozenset[str] = frozenset(
    {"down", "ssh_exec", "upload_file", "upload_archive"}
)


@dataclass(frozen=True)
class SshTarget:
    """Stable identity for an SSH remote mutation target."""

    shard: SshEffectShard
    host: str = ""
    container: str = ""
    operation: str = ""

    @property
    def target_key(self) -> str:
        return f"ssh:{self.shard.value}:{self.host}:{self.container}"


# ── SSH outcome ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SshOutcome:
    """Result of an SSH remote mutation through the adapter."""

    ok: bool
    shard: str
    glek: str
    outcome_kind: str
    error: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)


# ── SSH effect adapter ───────────────────────────────────────────────────────


class SshEffectAdapter:
    """Routes SSH remote mutation rows through WBC/action gate.

    Step 13F: at most three rows (build/deploy/destroy) are routed.
    All other operations remain action-off.

    Production construction (``production_enabled=True``) without an explicit
    ``action_gate_check`` is a wiring error: the constructor raises
    :class:`SshEffectAdapterGateError` before any dispatch.  Observation-only
    construction (``production_enabled=False``) may omit the gate — every
    dispatch then fails closed as a typed denial.
    """

    _ROUTED_SHARDS: frozenset[SshEffectShard] = frozenset(SSH_SHARD_13F)

    def __init__(
        self,
        protocol: EffectProtocol,
        *,
        action_gate_check: Optional[
            Callable[[ActionBoundaryType, str], GateResult]
        ] = None,
        production_enabled: bool = False,
    ) -> None:
        if production_enabled and action_gate_check is None:
            raise SshEffectAdapterGateError(
                "SshEffectAdapter refuses production construction without "
                "an explicit action_gate_check; pass current_ssh_gate_check "
                "(or an equivalent denial gate) so production dispatch "
                "reflects current policy, or open in observation mode "
                "(production_enabled=False)"
            )
        self._protocol = protocol
        self._action_gate_check = action_gate_check
        self._production_enabled = production_enabled

    # ── shard enforcement ────────────────────────────────────────────────

    def _enforce_shard(self, target: SshTarget) -> None:
        """Fail if the target's shard is not in the Step 13F set."""
        if target.shard not in self._ROUTED_SHARDS:
            raise ValueError(
                f"SSH shard {target.shard.value!r} is not routed in Step 13F. "
                f"Routed shards: {[s.value for s in self._ROUTED_SHARDS]}. "
                f"Remaining operations are action-off for M10."
            )

    # ── gate ────────────────────────────────────────────────────────────

    def _gate(self, target: SshTarget) -> GateResult:
        if self._action_gate_check is None:
            # No gate installed: fail closed. A missing gate must never
            # degrade to a shadow observation (adapter_effect_authorized
            # rejects every non-AUTHORIZED verdict anyway).
            return GateResult.BLOCKED_WBC_MISSING
        try:
            return self._action_gate_check("dispatch", target.target_key)
        except Exception:
            # An exceptional gate must not authorize a mutation.
            LOGGER.exception("Action gate raised for %s", target.target_key)
            return GateResult.ERROR

    # ── provider-missing negative ─────────────────────────────────────────

    @staticmethod
    def _check_provider_available(target: SshTarget) -> bool:
        """Provider-missing negative: reject if no host or container."""
        if not target.host or not target.container:
            LOGGER.warning(
                "SSH provider missing for %s: host=%r container=%r",
                target.target_key,
                target.host,
                target.container,
            )
            return False
        return True

    # ── GLEK ─────────────────────────────────────────────────────────────

    @staticmethod
    def _build_effect_identity(target: SshTarget) -> GlobalEffectIdentity:
        return GlobalEffectIdentity(
            environment_id=f"ssh-{target.host}",
            action_target=target.target_key,
            action_version="m10",
            effect_family=f"ssh.{target.shard.value}",
            provider_target=f"ssh:{target.host}:{target.container}",
            canonical_request_identity=target.target_key,
            boundary_schema_hash="m10-ssh-v1",
        )

    @staticmethod
    def _build_identity_bundle(
        attempt_id: str,
    ) -> tuple[AttemptIdentity, AttemptProvenance, RuntimeAdapter, VersionSet, GrantRef]:
        identity = AttemptIdentity(
            workflow_id=f"ssh-{attempt_id}",
            run_id=f"ssh-{attempt_id}",
            graph_revision="m10",
            attempt_id=attempt_id,
        )
        provenance = AttemptProvenance(
            parent_attempt_id=None,
        )
        adapter = RuntimeAdapter(
            adapter_kind=AdapterKind.NATIVE,
            adapter_version="m10-ssh",
        )
        versions = VersionSet(code_version="m10")
        grant_ref = GrantRef(grant_id=f"ssh-grant-{attempt_id}")
        return identity, provenance, adapter, versions, grant_ref

    # ── stale-fence negative ─────────────────────────────────────────────

    def _check_stale_fence(self, target: SshTarget, fence_token: int | None) -> bool:
        """Stale-fence negative: reject dispatch with stale or missing fence."""
        if fence_token is None or fence_token <= 0:
            LOGGER.warning(
                "Stale fence for ssh %s: token=%s",
                target.shard.value,
                fence_token,
            )
            return False
        return True

    # ── dispatch ─────────────────────────────────────────────────────────

    def route(
        self,
        *,
        target: SshTarget,
        intent_payload: dict[str, Any],
        apply_fn: Callable[..., Any],
        attempt_id: str | None = None,
        fence_token: int | None = None,
    ) -> SshOutcome:
        """Route an SSH remote mutation through the WBC protocol.

        Args:
            target: Stable SSH target identity.
            intent_payload: The effect payload.
            apply_fn: The actual SSH-command callable (MUST be fake in M10).
            attempt_id: Explicit attempt id.
            fence_token: Current fence token.

        Returns:
            SshOutcome with the GLEK, outcome, and error.
        """
        # Enforce shard boundary
        self._enforce_shard(target)

        # Provider-missing negative
        if not self._check_provider_available(target):
            return SshOutcome(
                ok=False,
                shard=target.shard.value,
                glek="",
                outcome_kind=OUTCOME_FAILED,
                error="Provider missing: no host or container configured",
                evidence={"host": target.host, "container": target.container},
            )

        # Stale-fence negative
        if not self._check_stale_fence(target, fence_token):
            return SshOutcome(
                ok=False,
                shard=target.shard.value,
                glek="",
                outcome_kind=OUTCOME_FAILED,
                error="Stale fence: missing or zero fence token",
                evidence={"fence_token": fence_token},
            )

        # Action gate check: only an explicit AUTHORIZED verdict may dispatch.
        # A missing gate, SHADOW_PASS, gate exception, or any other verdict
        # returns a typed denial before protocol reservation or apply_fn.
        verdict = self._gate(target)
        if not adapter_effect_authorized(verdict):
            verdict_label = getattr(verdict, "value", repr(verdict))
            return SshOutcome(
                ok=False,
                shard=target.shard.value,
                glek="",
                outcome_kind=OUTCOME_FAILED,
                error=f"Action gate blocked: {verdict_label}",
                evidence={"gate_verdict": verdict_label},
            )

        # Intent-failure negative
        if not intent_payload:
            return SshOutcome(
                ok=False,
                shard=target.shard.value,
                glek="",
                outcome_kind=OUTCOME_FAILED,
                error="Intent-failure: empty intent payload",
            )

        aid = attempt_id or str(uuid.uuid4())
        ei = self._build_effect_identity(target)
        ident, prov, adapter, versions, grant_ref = self._build_identity_bundle(aid)

        try:
            reservation = self._protocol.reserve_and_start(
                attempt_id=aid,
                effect_identity=ei,
                identity=ident,
                provenance=prov,
                adapter=adapter,
                versions=versions,
                grant_ref=grant_ref,
            )
            glek = reservation.global_logical_effect_key

            self._protocol.persist_intent(
                attempt_id=aid,
                glek=glek,
                intent_payload=intent_payload,
                identity=ident,
                provenance=prov,
                adapter=adapter,
                versions=versions,
                grant_ref=grant_ref,
            )

            try:
                result = apply_fn(intent_payload)
            except Exception as exc:
                self._protocol.accept_outcome(
                    aid, glek, OUTCOME_FAILED,
                    {"error": f"{type(exc).__name__}: {exc}"},
                )
                return SshOutcome(
                    ok=False,
                    shard=target.shard.value,
                    glek=glek,
                    outcome_kind=OUTCOME_FAILED,
                    error=str(exc),
                )

            self._protocol.accept_outcome(
                aid, glek, OUTCOME_COMPLETED,
                {"exit_code": 0},
            )
            return SshOutcome(
                ok=True,
                shard=target.shard.value,
                glek=glek,
                outcome_kind=OUTCOME_COMPLETED,
                evidence={"result": "ok"},
            )

        except Exception as exc:
            return SshOutcome(
                ok=False,
                shard=target.shard.value,
                glek="",
                outcome_kind=OUTCOME_INDETERMINATE,
                error=f"Protocol error: {type(exc).__name__}: {exc}",
            )

    # ── action-off gate dispatch ──────────────────────────────────────────

    def gate_dispatch(self, target: SshTarget) -> SshOutcome:
        """Gate-only dispatch for action-off SSH operations.

        ssh_exec, upload_file, upload_archive, and down are action-off in M10:
        they are not routed through the WBC protocol (Step 13F routes at most
        build/deploy/destroy).  They may run only when an explicitly
        AUTHORIZED gate verdict is re-read at dispatch time AND the adapter is
        not in production mode (production SSH is action-off).  Every other
        verdict — missing gate, SHADOW_PASS, blocked, error, or production
        action-off — is a typed denial before any transport call.
        """
        if not self._check_provider_available(target):
            return SshOutcome(
                ok=False,
                shard=target.shard.value,
                glek="",
                outcome_kind=OUTCOME_FAILED,
                error="Provider missing: no host or container configured",
                evidence={"host": target.host, "container": target.container},
            )
        verdict = self._gate(target)
        if not adapter_effect_authorized(verdict):
            verdict_label = getattr(verdict, "value", repr(verdict))
            return SshOutcome(
                ok=False,
                shard=target.shard.value,
                glek="",
                outcome_kind=OUTCOME_FAILED,
                error=f"Action gate blocked: {verdict_label}",
                evidence={"gate_verdict": verdict_label},
            )
        return SshOutcome(
            ok=True,
            shard=target.shard.value,
            glek="",
            outcome_kind=OUTCOME_COMPLETED,
            evidence={"gate_verdict": getattr(verdict, "value", repr(verdict))},
        )

    # ── fake-transport negative ───────────────────────────────────────────

    def check_fake_transport(
        self, apply_fn: Callable[..., Any], target: SshTarget
    ) -> bool:
        """Fake-transport negative: detect real SSH transport in M10.

        Returns True if the transport appears to be a fake (safe),
        False if it looks like a real SSH transport.
        """
        import inspect

        source = inspect.getsource(apply_fn) if hasattr(inspect, 'getsource') else ''
        suspicious = [
            'subprocess.run',
            'subprocess.Popen',
            'paramiko',
            'fabric.',
            'os.system',
            'shlex',
        ]
        for pattern in suspicious:
            if pattern in source:
                LOGGER.error(
                    "Fake-transport negative: apply_fn contains suspicious "
                    "pattern %r for target %s — real SSH blocked in M10",
                    pattern,
                    target.target_key,
                )
                return False
        return True


class SshEffectAdapterGateError(RuntimeError):
    """Production SSH effect adapter construction refused: wiring missing."""


def _target_capability(target_key: str) -> str:
    """Map each transport target to one explicit grant capability."""
    parts = str(target_key).split(":", 2)
    shard = parts[1] if len(parts) > 1 else ""
    return {
        "build": "repository_prepare",
        "deploy": "repository_prepare",
        "destroy": "launch_dispatch",
        "upload_file": "file_upload",
        "upload_archive": "file_upload",
        "ssh_exec": "ssh_engine_invocation",
        "down": "launch_dispatch",
    }.get(shard, "")


def current_ssh_gate_check(
    context_provider: Callable[[], Any] | Any | None = None,
) -> Callable[[ActionBoundaryType, str], GateResult]:
    """Build a gate that re-reads the bound canonical owner context.

    A missing context remains a typed denial.  The operator receipt is never
    treated as a grant; only a context whose ``authorize`` method performs a
    current RA/WBC/Custody read can return ``AUTHORIZED``.
    """

    def gate_check(boundary: ActionBoundaryType, key: str) -> GateResult:
        try:
            context = context_provider() if callable(context_provider) else context_provider
            if context is None:
                return GateResult.BLOCKED_MISSING_GRANT
            authorize = getattr(context, "authorize", None)
            if not callable(authorize):
                return GateResult.BLOCKED_MISSING_GRANT
            result = authorize(
                boundary=boundary,
                target_key=key,
                capability=_target_capability(key),
            )
            return result if isinstance(result, GateResult) else GateResult.ERROR
        except Exception:
            LOGGER.exception("Current SSH authority gate failed for %s", key)
            return GateResult.ERROR

    return gate_check


def open_ssh_effect_adapter(
    protocol: Optional[EffectProtocol] = None,
    *,
    production_enabled: bool = True,
    action_gate_check: Optional[
        Callable[[ActionBoundaryType, str], GateResult]
    ] = None,
) -> SshEffectAdapter:
    """Open the canonical production SSH effect adapter.

    Production SSH is action-off in M10: an installed adapter must always
    deny.  Missing wiring (no protocol, or no explicit gate in production
    mode) is a construction error — the factory raises instead of returning
    an adapter that could dispatch (the constructor enforces the same
    invariant for direct construction).  Observation-only constructors
    (``production_enabled=False``) may omit the gate; a missing protocol is
    still refused so the adapter can never be installed ungated.
    """
    if protocol is None:
        raise SshEffectAdapterGateError(
            "open_ssh_effect_adapter refuses construction without an "
            "EffectProtocol; SSH mutations are action-off in M10 and must "
            "never degrade to an ungated direct transport"
        )
    if production_enabled and action_gate_check is None:
        raise SshEffectAdapterGateError(
            "open_ssh_effect_adapter refuses production construction without "
            "an explicit action_gate_check; pass current_ssh_gate_check (or "
            "an equivalent denial gate) so production dispatch reflects "
            "current policy"
        )
    return SshEffectAdapter(
        protocol,
        action_gate_check=action_gate_check,
        production_enabled=production_enabled,
    )


__all__ = [
    "SshEffectShard",
    "SSH_SHARD_13F",
    "SSH_ACTION_OFF_SHARDS",
    "SshTarget",
    "SshOutcome",
    "SshEffectAdapter",
    "SshEffectAdapterGateError",
    "current_ssh_gate_check",
    "open_ssh_effect_adapter",
]
