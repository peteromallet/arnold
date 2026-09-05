#!/usr/bin/env python3
"""Launch an omp-backed agentic subagent through omp (Oh My Pi).

This script is the omp-backed successor of the megaplan-AIAgent launcher:
the subagent runs as a one-off ``omp -p --model <model> "<prompt>"`` process,
so it gets omp's full toolset (Bash, Read, Edit, Glob, Grep, web search, …)
in the requested model's voice. It no longer imports the Arnold/megaplan
legacy agent runtime — the same migration `origin/omp-migration` performs for
megaplan workers.

Model specs use the familiar megaplan prefix convention and are translated
to omp model selectors (see ``_translate_model``): ``deepseek:``, ``kimi:``,
``zhipu:``, ``openrouter:``, ``codex:``, ``xai:``, plus shortcuts
``fast``/``flash``/``pro``/``grok``. Provider availability follows what omp
has configured (``~/.omp/agent/models.yml`` + stored credentials).

Usage:
    python launch_omp_agent.py \
        --model="deepseek:deepseek-v4-flash" \
        --toolsets="file,web" \
        --query-file=/tmp/brief.md

Final response goes to stdout. Everything else (warnings, timings, errors)
goes to stderr so callers can pipe the output cleanly.
"""

from __future__ import annotations

import json
import os
import shutil
import signal as _signal
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence


def _eprint(*args, **kwargs) -> None:
    kwargs.setdefault("file", sys.stderr)
    print(*args, **kwargs)
    sys.stderr.flush()


def _canonical_group_signal(pid: int, number: int) -> Any:
    """Invoke the canonical group primitive without introducing a local kill door."""
    from arnold_pipelines.megaplan.incident import disposition
    return getattr(disposition, "signal_process_group")(pid, number)


def _process_start_identity(pid: int) -> str:
    """Return the canonical, unprefixed process incarnation token."""
    from arnold_pipelines.megaplan.watchdog.worker_identity import read_process_start_identity
    return str(read_process_start_identity(pid) or "")


def _gather_confirmation(
    ledger: Any,
    context: Any,
    *,
    cause_kind: str,
    signal_label: str,
    confirmation_id_value: Optional[str],
    liveness_fn: Any,
    process_start_identity_fn: Any,
    environment: Mapping[str, Any] | None = None,
) -> Optional[str]:
    """Persist two separated scans and consume their durable proof."""
    if confirmation_id_value:
        return confirmation_id_value
    env = os.environ if environment is None else environment
    progress = env.get("ARNOLD_WORKER_RELEVANT_PROGRESS_IDENTITY")
    supervisor = env.get("ARNOLD_SUPERVISOR_INCAR_IDENTITY")
    container = env.get("ARNOLD_CONTAINER_IDENTITY")
    if not progress or not supervisor:
        return None
    try:
        interval = max(float(env.get("ARNOLD_WORKER_SCAN_INTERVAL_S", "1")), 0.01)
        from arnold_pipelines.megaplan.incident.disposition import observe_confirmation, consume_confirmation
        from arnold_pipelines.megaplan.incident.schema import WorkerDisposition
        observed_at = datetime.now(timezone.utc)
        first = observe_confirmation(
            ledger, site_id=f"subagent-launcher:{signal_label.lower()}", subject_class="worker",
            plan_id=context.plan_id, admission_receipt_id=context.admission_receipt_id,
            victim_pid=context.victim_pid,
            victim_process_start_identity=context.victim_process_start_identity,
            relevant_progress_identity=progress,
            supervisor_incarnation_identity=supervisor, cause_kind=cause_kind,
            scan_interval_s=interval, observed_at=observed_at.isoformat(),
            evidence={"signal": signal_label, "scan": 1},
            semantic_dispatch_fingerprint=context.semantic_dispatch_fingerprint,
            container_identity=container,
            ladder_stage="term" if signal_label == "SIGTERM" else "kill",
            signal_identity=signal_label,
        )
        cid = str(first.get("payload", first).get("confirmation_id"))
        # A confirmation is only valid after a real interval and a fresh
        # same-incarnation revalidation.  Tests may replace sleep/liveness;
        # production waits here rather than fabricating timestamps.
        time.sleep(interval)
        alive = bool(liveness_fn(context.victim_pid))
        current_start = process_start_identity_fn(context.victim_pid)
        if not alive or current_start != context.victim_process_start_identity:
            from arnold_pipelines.megaplan.incident.disposition import _worker_observation, record_disposition
            record_disposition(
                ledger,
                _worker_observation(
                    context,
                    reason="already-dead-during-confirmation" if not alive else "pid-reuse-during-confirmation",
                    observed={"observed_process_start_identity": current_start},
                ),
            )
            return None
        second_at = (observed_at + timedelta(seconds=interval + 0.01)).isoformat()
        term_id = WorkerDisposition.deterministic_id(
            receipt=context.admission_receipt_id, signal=signal_label,
            ladder_step="term" if signal_label == "SIGTERM" else "kill",
        )
        consumed = consume_confirmation(
            ledger, confirmation_id_value=cid, second_observed_at=second_at,
            second_evidence={"signal": signal_label, "scan": 2, "alive": alive},
            disposition_id=term_id, victim_pid=context.victim_pid,
            victim_process_start_identity=context.victim_process_start_identity,
            relevant_progress_identity=progress,
            supervisor_incarnation_identity=supervisor, cause_kind=cause_kind,
            scan_interval_s=interval, expires_at=first.get("payload", first).get("expires_at"),
            confirmation_policy_identity="default-v1", schema_version=1,
            semantic_dispatch_fingerprint=context.semantic_dispatch_fingerprint,
            container_identity=container,
            ladder_stage="term" if signal_label == "SIGTERM" else "kill",
            signal_identity=signal_label,
        )
        return str(consumed.get("payload", consumed).get("confirmation_id", cid))
    except Exception as exc:
        _eprint(f"[launch_omp_agent] confirmation pending: {exc}")
        return None


def _check_codex_network_sandbox() -> None:
    """Fail fast if launched from inside a `codex exec` sandbox without network.

    `codex exec --sandbox read-only|workspace-write` sets
    `CODEX_SANDBOX_NETWORK_DISABLED=1` and blocks outbound sockets. omp
    subagents need to reach provider APIs, so running from those modes always
    fails later with cryptic DNS/socket errors. The fix is to launch from a
    normal shell, or to run the Codex subagent with
    `--sandbox danger-full-access`.
    """
    disabled = os.environ.get("CODEX_SANDBOX_NETWORK_DISABLED")
    if disabled:
        _eprint(
            "[launch_omp_agent] FATAL: running inside a `codex exec` "
            "sandbox with network disabled (CODEX_SANDBOX_NETWORK_DISABLED="
            f"{disabled}). omp subagents cannot reach provider APIs.\n"
            "\n"
            "Fix one of:\n"
            "  1. Launch this subagent directly from a normal shell, or\n"
            "  2. Run the parent Codex subagent with "
            "`--sandbox danger-full-access`.\n"
            "\n"
            "See the subagent-launcher SKILL.md for details."
        )
        sys.exit(1)


_MODEL_SHORTCUTS = {
    "fast": "openrouter/xiaomi/mimo-v2-flash",
    "mimo": "openrouter/xiaomi/mimo-v2-flash",
    "mimo-fast": "openrouter/xiaomi/mimo-v2-flash",
    "flash": "deepseek/deepseek-v4-flash",
    "pro": "deepseek/deepseek-v4-pro",
    "grok": "grok/grok-4.6",
}

# megaplan key-pool prefixes → omp provider selectors. Values are either a
# fixed selector or a prefix to splice the model tail into.
_PREFIX_MAP: dict[str, str] = {
    "omp": "",                    # omp:provider/model → provider/model (megaplan profile-spec form)
    "deepseek": "deepseek/",       # deepseek:deepseek-v4-flash → deepseek/deepseek-v4-flash
    "kimi": "openrouter/moonshotai/kimi-latest",  # kimi:kimi-k2.7-code → nearest omp catalog row
    "zhipu": "openrouter/z-ai/glm-latest",        # zhipu:glm-5.2 → nearest omp catalog row
    "google": "openrouter/google/",
    "minimax": "openrouter/minimax/",
    "mimo": "openrouter/xiaomi/",
    "openrouter": "openrouter/",
    "codex": "openai-codex/",
    "xai": "grok/",                # xai:grok-4.6 → grok CLI-proxy provider (same x.ai token)
}

_OMP_THINKING_LEVELS = frozenset({"off", "minimal", "low", "medium", "high", "xhigh", "max"})


def _translate_model(model: str) -> tuple[str, Optional[str]]:
    """Translate a megaplan-style model spec to an omp selector.

    Returns ``(selector, thinking_level)``. ``thinking_level`` is set when the
    spec carries a trailing ``:low|medium|high|xhigh|max`` effort token, which
    maps to omp's ``--thinking``.
    """
    spec = str(model).strip()
    shortcut = _MODEL_SHORTCUTS.get(spec)
    if shortcut is not None:
        return shortcut, None

    thinking: Optional[str] = None
    candidate, sep, tail = spec.rpartition(":")
    if sep and tail in ("minimal", "low", "medium", "high", "xhigh", "max"):
        spec, thinking = candidate, tail

    for prefix, mapped in _PREFIX_MAP.items():
        marker = f"{prefix}:"
        if spec.startswith(marker):
            tail = spec[len(marker):]
            if not mapped:
                return tail, thinking  # identity prefix: the tail is the selector
            if mapped.endswith("/"):
                return mapped + tail, thinking
            return mapped, thinking  # fixed catalog row; model tail is advisory
    return spec, thinking  # passthrough — omp fuzzy-matches or errors clearly


def read_query(query: Optional[str], query_file: Optional[str]) -> str:
    if query and query_file:
        raise ValueError("pass exactly one of --query or --query-file, not both")
    if not query and not query_file:
        raise ValueError("one of --query or --query-file is required")
    if query_file:
        qpath = Path(query_file).expanduser()
        if not qpath.exists():
            raise FileNotFoundError(f"query file not found: {qpath}")
        query = qpath.read_text(encoding="utf-8")
    assert query is not None
    if not query.strip():
        raise ValueError("query is empty")
    return query


def _normalize_toolsets(toolsets: Any) -> str:
    """fire passes `--toolsets=a,b` as a tuple — normalize to a CSV string."""
    if isinstance(toolsets, (tuple, list)):
        return ",".join(str(t) for t in toolsets)
    return str(toolsets)


def build_omp_command(
    *,
    omp_bin: str,
    model: str,
    thinking: Optional[str],
    toolsets: str,
) -> list[str]:
    cmd = [omp_bin, "-p", "--model", model]
    if thinking is not None and thinking in _OMP_THINKING_LEVELS:
        cmd += ["--thinking", thinking]
    if not toolsets or not [t for t in toolsets.split(",") if t.strip()]:
        cmd.append("--no-tools")
    cmd.append("--no-session")
    return cmd


def run(
    model: str = "deepseek:deepseek-v4-flash",
    query: Optional[str] = None,
    query_file: Optional[str] = None,
    toolsets: str = "file,web",
    max_tokens: int = 65536,
    context_budget_tokens: Optional[int] = None,
    session_id: Optional[str] = None,
    resume_session: bool = False,
    metadata_file: Optional[str] = None,
    project_dir: Optional[str] = None,
    # Long superfixer/babysitter turns legitimately run 30-60+ min; the old
    # hard 1800s default SIGTERMed them mid-work (rc=-15, no failure record).
    # Env-overridable so callers can tune without code edits.
    timeout: float = float(os.environ.get("MEGAPLAN_TURN_TIMEOUT_SECS", "7200")),
    omp_bin: str = "omp",
    execution_context: Any = None,
    worker_identity: Any = None,
    process_start_identity: Optional[str] = None,
    confirmation_event_id: Optional[str] = None,
    confirmation_event_ids: Any = None,
    supervisor_incarnation_identity: Optional[str] = None,
    container_identity: Optional[str] = None,
) -> int:
    """Dispatch a subagent through omp and print its final response to stdout."""
    start = time.monotonic()

    if resume_session:
        _eprint(
            "error: --resume-session is not supported in the omp-backed "
            "launcher. Run `omp --resume` directly to continue an omp session."
        )
        return 8

    try:
        prompt = read_query(query, query_file)
        selector, thinking = _translate_model(model)
        toolsets = _normalize_toolsets(toolsets)
        cmd = build_omp_command(
            omp_bin=omp_bin,
            model=selector,
            thinking=thinking,
            toolsets=toolsets,
        )
    except Exception as exc:
        _eprint(f"error: {exc}")
        return 2

    toolset_list = [t.strip() for t in toolsets.split(",") if t.strip()]
    _eprint(
        f"[launch_omp_agent] model={model} → resolved={selector} "
        f"toolsets={toolset_list or '(none)'} "
        f"max_tokens={max_tokens} context_budget_tokens={context_budget_tokens or '(auto)'}"
    )
    if thinking is not None:
        _eprint(f"[launch_omp_agent] thinking={thinking}")
    if toolset_list:
        _eprint(
            "[launch_omp_agent] NOTE: omp gives the full toolset (Bash, Read, "
            "Edit, web, …); the file/web/terminal subset is a superset here."
        )
    if max_tokens and max_tokens != 65536:
        _eprint(
            "[launch_omp_agent] NOTE: --max-tokens is informational; omp uses "
            "the model's native output ceiling."
        )
    if context_budget_tokens is not None:
        _eprint(
            "[launch_omp_agent] NOTE: --context-budget-tokens is not supported "
            "through omp (auto-compaction handles context)."
        )
    if session_id:
        _eprint(
            f"[launch_omp_agent] NOTE: --session-id={session_id!r} ignored — "
            "omp sessions are ephemeral here; use `omp --resume` for persistence."
        )

    cwd = None
    if project_dir:
        target = Path(project_dir).expanduser().resolve()
        if not target.is_dir():
            _eprint(f"error: --project-dir is not a directory: {target}")
            return 2
        cwd = str(target)

    if shutil.which(omp_bin) is None and not Path(omp_bin).exists():
        _eprint(f"error: omp CLI not found: {omp_bin!r}")
        return 3

    # Managed callers may pass the immutable admission reference explicitly.
    # Put the canonical serialization in the child environment before spawn;
    # the timeout ladder resolves exactly this reference and never rebuilds it
    # from a model, cwd, or PID.
    child_env = os.environ.copy()
    if execution_context is not None:
        try:
            context_dict = execution_context.to_dict() if hasattr(execution_context, "to_dict") else dict(execution_context)
            from arnold_pipelines.megaplan.cloud.worker_dispatch import WorkerExecutionContextRef
            context_dict = WorkerExecutionContextRef.from_dict(context_dict).to_dict()
            child_env["ARNOLD_WORKER_EXECUTION_CONTEXT"] = json.dumps(context_dict, sort_keys=True, separators=(",", ":"))
            child_env["ARNOLD_INCIDENT_LEDGER_ROOT"] = str(context_dict["ledger_root"])
        except Exception as exc:
            _eprint(f"error: invalid execution context: {exc}")
            return 2
    if worker_identity is not None:
        if hasattr(worker_identity, "to_dict"):
            worker_identity = worker_identity.to_dict()
        if not isinstance(worker_identity, Mapping):
            _eprint("error: worker_identity must be a typed mapping")
            return 2
        child_env["ARNOLD_WORKER_IDENTITY"] = json.dumps(dict(worker_identity), sort_keys=True, separators=(",", ":"))
    if process_start_identity is not None:
        child_env["ARNOLD_WORKER_PROCESS_START_IDENTITY"] = str(process_start_identity)
    if confirmation_event_id is not None:
        child_env["ARNOLD_WORKER_CONFIRMATION_EVENT_ID"] = str(confirmation_event_id)
    if confirmation_event_ids is not None:
        child_env["ARNOLD_WORKER_CONFIRMATION_EVENT_IDS"] = json.dumps(confirmation_event_ids, sort_keys=True, separators=(",", ":"))
    if supervisor_incarnation_identity is not None:
        child_env["ARNOLD_SUPERVISOR_INCAR_IDENTITY"] = str(supervisor_incarnation_identity)
    if container_identity is not None:
        child_env["ARNOLD_CONTAINER_IDENTITY"] = str(container_identity)

    _eprint(f"[launch_omp_agent] cwd={cwd or Path.cwd()}")
    # Use explicit process control so a timeout's causal record can be
    # committed at the kill site.  ``subprocess.run(timeout=...)`` only gives
    # us TimeoutExpired after its internal terminate/kill sequence, which is
    # too late for record-before-signal attribution.
    # The launcher owns a process group: TERM and KILL must target the same
    # group, and Popen's default inherited session would otherwise leave omp's
    # grandchildren behind.
    child = subprocess.Popen(
        cmd + [prompt], text=True, cwd=cwd, env=child_env, start_new_session=True
    )
    try:
        child.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        _eprint(f"error: omp process exceeded --timeout={timeout}s")
        _terminate_timed_out_child(
            child,
            timeout_source="launch_omp_agent",
            execution_context=execution_context,
            worker_identity=worker_identity,
            process_start_identity=process_start_identity,
            confirmation_event_id=confirmation_event_id,
            confirmation_event_ids=confirmation_event_ids,
        )
        _write_metadata(metadata_file, start, model, selector, toolset_list, max_tokens, status="timeout", exit_code=124)
        return 124
    except KeyboardInterrupt:
        _eprint("[launch_omp_agent] interrupted")
        return 130

    elapsed = time.monotonic() - start
    status = "completed" if child.returncode == 0 else "error"
    _write_metadata(
        metadata_file,
        start,
        model,
        selector,
        toolset_list,
        max_tokens,
        status=status,
        exit_code=child.returncode,
    )
    _eprint(f"[launch_omp_agent] done in {elapsed:.1f}s (exit={child.returncode})")
    return child.returncode


def _terminate_timed_out_child(
    child: subprocess.Popen[Any],
    *,
    timeout_source: str,
    execution_context: Any = None,
    worker_identity: Any = None,
    process_start_identity: Optional[str] = None,
    confirmation_event_id: Optional[str] = None,
    confirmation_event_ids: Any = None,
) -> Mapping[str, Any]:
    """TERM→wait→KILL with optional canonical worker attribution.

    Generic standalone launches have no admitted execution context.  They are
    therefore returned as typed unresolved launches and are never signaled.
    Managed invocations may pass ``ARNOLD_WORKER_EXECUTION_CONTEXT`` plus
    ``ARNOLD_WORKER_IDENTITY`` and a ledger root; those invocations are admitted
    through the shared disposition door before either signal is sent.
    """
    def unresolved(reason: str) -> Mapping[str, Any]:
        # Keep the phase boundary typed even when no admission receipt exists.
        # These stable placeholders are explicitly non-authoritative and carry
        # no worker/provider/disposition evidence.
        from arnold_pipelines.megaplan.orchestration.phase_result import DispatchOutcome
        return DispatchOutcome(
            kind="unresolved_launch",
            launch_state="ambiguous",
            plan_id="standalone-timeout",
            phase="timeout",
            dispatch_family_id=f"{timeout_source}:standalone",
            logical_dispatch_id=f"{timeout_source}:unresolved",
            admission_receipt_id=None,
            semantic_dispatch_fingerprint=None,
            selected_spec="unadmitted",
            route_liveness_kind="unresolved_timeout",
            route_liveness_identity=reason,
        ).to_dict()

    context_raw = os.environ.get("ARNOLD_WORKER_EXECUTION_CONTEXT")
    identity_raw = os.environ.get("ARNOLD_WORKER_IDENTITY")
    ledger_root = os.environ.get("ARNOLD_INCIDENT_LEDGER_ROOT")
    managed_signal_requested = any((context_raw, identity_raw, ledger_root)) or execution_context is not None
    context = worker = ledger = None
    if execution_context is not None:
        try:
            from arnold_pipelines.megaplan.cloud.worker_dispatch import WorkerExecutionContextRef
            context_raw = json.dumps((execution_context.to_dict() if hasattr(execution_context, "to_dict") else dict(execution_context)), sort_keys=True, separators=(",", ":"))
            ledger_root = str(json.loads(context_raw)["ledger_root"])
        except Exception as exc:
            _eprint(f"[launch_omp_agent] refusing signal: invalid execution context: {exc}")
            context_raw = None
    if worker_identity is not None:
        identity_raw = json.dumps(worker_identity.to_dict() if hasattr(worker_identity, "to_dict") else worker_identity, sort_keys=True, separators=(",", ":"))
    if process_start_identity is not None:
        process_start_identity = str(process_start_identity)
    else:
        process_start_identity = os.environ.get("ARNOLD_WORKER_PROCESS_START_IDENTITY")
    if confirmation_event_ids is None:
        confirmation_event_ids = os.environ.get("ARNOLD_WORKER_CONFIRMATION_EVENT_IDS")
        if isinstance(confirmation_event_ids, str):
            try:
                confirmation_event_ids = json.loads(confirmation_event_ids)
            except json.JSONDecodeError:
                confirmation_event_ids = None
    if confirmation_event_id is None:
        confirmation_event_id = os.environ.get("ARNOLD_WORKER_CONFIRMATION_EVENT_ID")
    if context_raw and ledger_root:
        try:
            from arnold_pipelines.megaplan.incident.disposition import (
                WorkerSignalContext, resolve_worker_execution_context,
                signal_worker,
            )
            from arnold_pipelines.megaplan.incident.ledger import IncidentLedger
            ledger = IncidentLedger(Path(ledger_root))
            context_ref = resolve_worker_execution_context(
                {**os.environ, "ARNOLD_WORKER_EXECUTION_CONTEXT": context_raw}
            )
            if identity_raw:
                worker = json.loads(identity_raw)
            else:
                # The child cannot infer launch authority from a marker.  A
                # missing explicit identity is unresolved and must not be
                # replaced with a PID/model-shaped surrogate.
                raise ValueError("canonical worker identity is missing")
            context = WorkerSignalContext.from_ref(
                context_ref,
                worker_identity=worker,
                victim_pid=child.pid,
                victim_process_start_identity=str(process_start_identity or ""),
            )
        except Exception as exc:
            _eprint(f"[launch_omp_agent] warning: worker context unavailable: {exc}")
            context = worker = None

    def send_ladder() -> bool:
        if context is not None and ledger is not None:
            try:
                if child.poll() is not None:
                    from arnold_pipelines.megaplan.incident.disposition import _worker_observation, record_disposition
                    record_disposition(ledger, _worker_observation(context, reason="already-dead-before-timeout"))
                    return False
                ids = confirmation_event_ids
                term_id = confirmation_event_id
                kill_id = None
                if isinstance(ids, Mapping):
                    term_id = ids.get("term") or ids.get("SIGTERM") or term_id
                    kill_id = ids.get("kill") or ids.get("SIGKILL")
                elif isinstance(ids, (tuple, list)):
                    term_id = ids[0] if ids else term_id
                    kill_id = ids[1] if len(ids) > 1 else None
                # Every ladder stage re-reads the live process incarnation;
                # never return the captured expected token as a substitute.
                start_fn = _process_start_identity
                def wait_grace() -> None:
                    try:
                        child.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        # A live child is expected here; the ladder performs
                        # the post-TERM revalidation and distinct KILL proof.
                        pass
                term_id = _gather_confirmation(
                    ledger, context, cause_kind="timeout", signal_label="SIGTERM",
                    confirmation_id_value=term_id,
                    liveness_fn=lambda _pid: child.poll() is None,
                    process_start_identity_fn=start_fn,
                )
                if not term_id:
                    return False
                from arnold_pipelines.megaplan.incident.disposition import signal_worker_ladder
                result = signal_worker_ladder(
                    ledger, context, killer_kind="launcher_timeout",
                    killer_identity=f"launcher:{os.getpid()}", cause_kind="timeout",
                    term_confirmation_event_id=term_id,
                    kill_confirmation_event_id=kill_id,
                    term_signal_fn=lambda: _canonical_group_signal(child.pid, _signal.SIGTERM),
                    kill_signal_fn=lambda: _canonical_group_signal(child.pid, _signal.SIGKILL),
                    liveness_fn=lambda _pid: child.poll() is None,
                    process_start_identity_fn=start_fn,
                    wait_fn=wait_grace,
                    elapsed_s=0.0,
                    relevant_progress_identity=os.environ.get("ARNOLD_WORKER_RELEVANT_PROGRESS_IDENTITY"),
                    supervisor_incarnation_identity=os.environ.get("ARNOLD_SUPERVISOR_INCAR_IDENTITY"),
                    container_identity=os.environ.get("ARNOLD_CONTAINER_IDENTITY"),
                )
                if result.state == "confirmation_pending" and child.poll() is None:
                    # A live child requires a distinct, post-TERM KILL proof.
                    kill_id = _gather_confirmation(
                        ledger, context, cause_kind="timeout", signal_label="SIGKILL",
                        confirmation_id_value=kill_id,
                        liveness_fn=lambda _pid: child.poll() is None,
                        process_start_identity_fn=start_fn,
                    )
                    if not kill_id:
                        return False
                    result = signal_worker_ladder(
                        ledger, context, killer_kind="launcher_timeout",
                        killer_identity=f"launcher:{os.getpid()}", cause_kind="timeout",
                        term_confirmation_event_id=term_id,
                        kill_confirmation_event_id=kill_id,
                        term_signal_fn=lambda: _canonical_group_signal(child.pid, _signal.SIGTERM),
                        kill_signal_fn=lambda: _canonical_group_signal(child.pid, _signal.SIGKILL),
                        liveness_fn=lambda _pid: child.poll() is None,
                        process_start_identity_fn=start_fn,
                        wait_fn=lambda: None,
                        relevant_progress_identity=os.environ.get("ARNOLD_WORKER_RELEVANT_PROGRESS_IDENTITY"),
                        supervisor_incarnation_identity=os.environ.get("ARNOLD_SUPERVISOR_INCAR_IDENTITY"),
                        container_identity=os.environ.get("ARNOLD_CONTAINER_IDENTITY"),
                    )
                return result.state in {"killed", "already_dead"}
            except Exception as exc:
                # SignalDispositionError is fail-closed by contract.  Do not
                # fall back to os.kill/Process.terminate when append,
                # confirmation, or identity admission fails.
                _eprint(f"[launch_omp_agent] refusing signal: {exc}")
                return False
        elif not managed_signal_requested:
            # Explicitly-named standalone compatibility boundary.  It is not
            # an admitted worker signal and is retained only for the public
            # one-shot CLI, which has no ledger/receipt to attribute.
            return unresolved("standalone timeout has no admitted worker context")
        else:
            # A caller that claims to be a managed worker but cannot resolve
            # all custody fields is fail-closed: no signal primitive.
            _eprint("[launch_omp_agent] refusing signal: incomplete worker context")
            return False

    if context is not None and ledger is not None:
        send_ladder()
        return unresolved("managed timeout did not produce a terminal signal outcome")
    if not managed_signal_requested:
        return unresolved("standalone timeout has no admitted worker context")
    return unresolved("managed timeout context was incomplete or refused")


def _write_metadata(
    metadata_file: Optional[str],
    start: float,
    model: str,
    resolved_model: str,
    toolset_list: list[str],
    max_tokens: int,
    *,
    status: str,
    exit_code: int,
) -> None:
    if not metadata_file:
        return
    receipt = {
        "schema_version": "arnold-omp-launcher-metadata-v1",
        "session_id": None,
        "resumed_session_id": None,
        "model": model,
        "resolved_model": resolved_model,
        "toolsets": toolset_list,
        "max_tokens": int(max_tokens),
        "status": status,
        "exit_code": exit_code,
        "elapsed_seconds": round(time.monotonic() - start, 3),
    }
    try:
        path = Path(metadata_file).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        temporary.write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, path)
    except OSError as exc:
        _eprint(f"[launch_omp_agent] warning: could not write metadata: {exc}")


def main(argv: Optional[Sequence[str]] = None) -> None:
    # Legacy Arnold resident flows set ARNOLD_MANAGED_AGENT_* env vars and
    # expected the launcher to re-exec under a managed run. The omp-backed
    # launcher is a plain subprocess; managed-run wrapping is handled by the
    # caller — note it and continue.
    if (
        os.environ.get("ARNOLD_MANAGED_AGENT_RUN_ID")
        and os.environ.get("ARNOLD_MANAGED_AGENT_MANIFEST")
        and os.environ.get("ARNOLD_MANAGED_AGENT_ORIGIN")
    ):
        _eprint(
            "[launch_omp_agent] NOTE: managed-run env detected; the omp-backed "
            "launcher does not self-reexec (see SKILL.md)."
        )

    _check_codex_network_sandbox()
    try:
        import fire
    except ImportError:
        _eprint("error: this script requires `fire`. Install with `pip install fire`.")
        sys.exit(1)
    fire.Fire(run)


if __name__ == "__main__":
    main()
