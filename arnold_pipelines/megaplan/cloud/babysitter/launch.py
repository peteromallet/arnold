#!/usr/bin/env python3
"""Status-trigger babysitter launch module.

The watchdog's status trigger (``MEGAPLAN_SUPERFIXER_ONLY=1``) Popen's
``arnold-babysitter``, which executes this module.  For ordinary sessions the
babysitter is one detached managed OMP agent whose goal prompt drives the
recovery flow itself.  The native-build-forward continuation is closed to one
exact Muse Spark 1.3 Contributor route with high thinking at every nested
dispatch.  There is deliberately NO coded multi-stage orchestrator: the single
agent IS the orchestrator.

Flow (fail closed at every step — the caller's grace poll turns an early
non-zero rc into a hard abort, never a fallthrough to another repair route):

    1. Parse the watchdog's flags (--goal-file, --session, --workspace,
       --plan, --run-kind, --occurrence, --remote-spec, --run-id, --run-root,
       --mode) with ARNOLD_BABYSITTER_* env fallbacks.
    2. Resolve the goal file (--goal-file / ARNOLD_BABYSITTER_GOAL_FILE), or
       render it via the live engine's
       ``skills/babysitter/scripts/render_babysitter_goal.py`` (watchdog-
       compatible engine-root resolution).
    3. Launch ONE managed Flash agent through
       ``arnold_pipelines.megaplan.managed_agent`` (backend=babysitter); the
       worker is ``launch_omp_agent.py`` with the resolved model route,
       ``--toolsets=file,web,terminal --query-file=<goal> --project-dir=<engine>``
       so the agent can run the bounded recovery flow.  Continuation sessions
       carry the exact Muse model/high-thinking suffix.  This process stays alive
       as the managed-agent supervisor for the whole run, so the watchdog's
       early-rc check and receipt pid liveness are honest.
    4. Emit terminal watchdog telemetry only after the canonical operation
       decision; receipts never gate admission or dedup a physical launch.

Env overrides (all optional):
    ARNOLD_BABYSITTER_SESSION / _WORKSPACE / _PLAN / _RUN_KIND / _OCCURRENCE /
    _GOAL_FILE / _MARKER_DIR / _REPAIR_DATA_DIR   watchdog-provided context
    ARNOLD_BABYSITTER_MODEL       ordinary-session model override
    ARNOLD_BABYSITTER_DIFFICULTY  managed-run difficulty D1-D10 (default 8)
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import runpy
import sys
import socket
from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping, Sequence

from arnold_pipelines.megaplan.cloud.babysitter.routing import (
    cli_model,
    CONTINUATION_MUSE_MODEL,
    CONTINUATION_MUSE_THINKING,
    resolve_babysitter_routing,
)
from arnold_pipelines.megaplan.cloud.cli import _omp_openrouter_capability_check
from arnold_pipelines.megaplan.managed_agent import (
    ManagedCommandSpec,
    machine_origin_provenance,
    run_managed_command,
    stable_managed_run_id,
)

LAUNCH_RECEIPT_SCHEMA = "arnold.superfixer.babysitter_launch_receipt.v1"
LAUNCH_RECEIPT_NAME = "{session}.babysitter-launch-receipt.json"

DEFAULT_MODEL = "codex:gpt-5.6-luna"
TOOLSETS = "file,web,terminal"
RUN_KIND = "automatic_watchdog_source_repair"
ORIGIN_KIND = "watchdog_source_repair"
ORIGIN_COMPONENT = "arnold-babysitter"
ROUTE_CLASS = "watchdog_babysitter"
BACKEND = "babysitter"
TASK_KIND = "autonomous"
REASONING_EFFORT = "bounded"
DEFAULT_DIFFICULTY = 8
_AUTOMATIC_FINAL_MARKER_LOCK_TIMEOUT_S = 5.0

_REPO_ROOT = Path(__file__).resolve().parents[4]


def _utcnow_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _provenance_safe(text: str) -> str:
    """Keep the managed-agent provenance-safe charset (letters, digits, . _ : / -)."""
    return "".join(
        character if character in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:/-" else "_"
        for character in text
    )


def _eprint(message: str) -> None:
    print(message, file=sys.stderr)
    sys.stderr.flush()


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.replace(tmp, path)


def _engine_roots() -> list[Path]:
    """Live engine roots in watchdog precedence, our own tree as the fallback.

    Mirrors the watchdog's ``_superfixer_engine_roots`` so the babysitter
    resolves the goal renderer / omp launcher from the SAME runtime the
    watchdog dispatch used, never a stale hardcoded tree.
    """
    roots: list[Path] = []
    for env_name in (
        "ARNOLD_WATCHDOG_MANIFEST_RUNTIME_ROOT",
        "ARNOLD_WATCHDOG_RUNTIME_SRC",
        "SRC_DIR",
    ):
        value = os.environ.get(env_name, "").strip()
        if value:
            roots.append(Path(value))
    origin = os.environ.get("ARNOLD_WATCHDOG_ORIGIN", "").strip()
    if origin:
        roots.append(Path(origin).resolve().parents[4])
    roots.append(_REPO_ROOT)
    return roots


def _resolve_asset(relative: str) -> Path:
    for root in _engine_roots():
        candidate = root / relative
        if candidate.is_file():
            return candidate
    raise RuntimeError(
        f"babysitter asset unavailable under live engine roots: {relative}"
    )


def _resolve_engine_root() -> Path:
    """The live engine root: the first candidate tree carrying the babysitter
    assets (renderer + omp subagent launcher), mirroring the watchdog."""
    renderer_rel = (
        "arnold_pipelines/megaplan/skills/babysitter/scripts/render_babysitter_goal.py"
    )
    launcher_rel = (
        "arnold_pipelines/megaplan/skills/subagent-launcher/launch_omp_agent.py"
    )
    for root in _engine_roots():
        if (root / renderer_rel).is_file() and (root / launcher_rel).is_file():
            return root.resolve()
    raise RuntimeError("babysitter launch: no live engine root with babysitter assets")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m arnold_pipelines.megaplan.cloud.babysitter.launch",
        description=(
            "Launch ONE detached managed OMP babysitter whose goal prompt "
            "drives investigate -> review -> implement -> relaunch -> prove."
        ),
    )
    parser.add_argument("--goal-file", default="", help="rendered goal prompt file")
    parser.add_argument("--session", default="", help="epic/session target")
    parser.add_argument(
        "--target", dest="session", default=None,
        help="alias for --session (renderer CLI naming)",
    )
    parser.add_argument("--workspace", default="", help="chain workspace path")
    parser.add_argument("--plan", default="", help="plan name")
    parser.add_argument("--run-kind", dest="run_kind", default="", help="chain|plan|epic_chain")
    parser.add_argument("--occurrence", default="", help="occurrence/failure digest")
    parser.add_argument(
        "--occurrence-digest", dest="occurrence", default=None,
        help="alias for --occurrence (renderer CLI naming)",
    )
    parser.add_argument("--remote-spec", dest="remote_spec", default="", help="remote spec path")
    parser.add_argument("--run-id", dest="run_id", default="", help="occurrence-scoped run id")
    parser.add_argument("--run-root", dest="run_root", default="", help="run directory")
    parser.add_argument("--mode", default="", help="babysitter mode (e.g. superfixer)")
    parser.add_argument("--failure-json", default=None, help="path to latest_failure JSON")
    parser.add_argument("--planner-repair-json", default=None, help="path to planner_repair JSON")
    return parser


def _env_or_flag(cli_value: str | None, env_name: str, default: str = "") -> str:
    if cli_value:
        return cli_value
    return os.environ.get(env_name, "").strip() or default


def _collect_context(args: argparse.Namespace) -> dict[str, Any]:
    """Merge CLI flags, ARNOLD_BABYSITTER_* env, and defaults into one ctx."""
    session = _env_or_flag(args.session, "ARNOLD_BABYSITTER_SESSION")
    if not session:
        raise ValueError("babysitter session is required (--session / ARNOLD_BABYSITTER_SESSION)")
    workspace = _env_or_flag(args.workspace, "ARNOLD_BABYSITTER_WORKSPACE")
    plan = _env_or_flag(args.plan, "ARNOLD_BABYSITTER_PLAN")
    run_kind = _env_or_flag(args.run_kind, "ARNOLD_BABYSITTER_RUN_KIND")
    occurrence = _env_or_flag(args.occurrence, "ARNOLD_BABYSITTER_OCCURRENCE")
    marker_dir_raw = _env_or_flag("", "ARNOLD_BABYSITTER_MARKER_DIR")
    repair_data_raw = _env_or_flag("", "ARNOLD_BABYSITTER_REPAIR_DATA_DIR")
    marker_dir = Path(marker_dir_raw) if marker_dir_raw else None
    repair_data_dir = (
        Path(repair_data_raw)
        if repair_data_raw
        else (marker_dir / "repair-data" if marker_dir else None)
    )
    run_id = args.run_id or f"babysitter-{_provenance_safe(session[:48])}-{occurrence or 'occurrence'}"
    run_root_raw = args.run_root
    if not run_root_raw and repair_data_dir is not None:
        run_root_raw = str(repair_data_dir / "babysitter-runs" / run_id)
    run_root = Path(run_root_raw) if run_root_raw else _REPO_ROOT / ".babysitter-runs" / run_id
    routing = resolve_babysitter_routing(
        session=session,
    )
    if routing.closed and not str(os.environ.get("ARNOLD_BABYSITTER_MODEL", "")).strip():
        raise ValueError(
            f"{session} requires explicit {routing.controller_model}:high "
            "for resident fixer registration"
        )
    return {
        "session": session,
        "workspace": workspace,
        "plan": plan,
        "run_kind": run_kind,
        "occurrence": occurrence,
        "remote_spec": args.remote_spec,
        "run_id": run_id,
        "run_root": run_root,
        "mode": args.mode,
        "marker_dir": marker_dir,
        "repair_data_dir": repair_data_dir,
        "goal_file_cli": args.goal_file,
        "failure_json": args.failure_json,
        "planner_repair_json": args.planner_repair_json,
        # Preserve the legacy environment override for ordinary babysitters;
        # the continuation resolver has already closed its model surface to
        # the exact Muse route and supplies that model here.
        "model": (
            routing.controller_model
            if routing.closed
            else os.environ.get("ARNOLD_BABYSITTER_MODEL", "").strip()
            or routing.controller_model
        ),
        "reasoning_effort": (
            CONTINUATION_MUSE_THINKING if routing.closed else REASONING_EFFORT
        ),
        "routing": routing,
        "difficulty": _difficulty_env(),
    }


def _difficulty_env() -> int:
    raw = os.environ.get("ARNOLD_BABYSITTER_DIFFICULTY", "").strip()
    if not raw:
        return DEFAULT_DIFFICULTY
    try:
        difficulty = int(raw)
    except ValueError as exc:
        raise ValueError("ARNOLD_BABYSITTER_DIFFICULTY must be an integer D1-D10") from exc
    if not 1 <= difficulty <= 10:
        raise ValueError("ARNOLD_BABYSITTER_DIFFICULTY must be D1-D10")
    return difficulty


def _continuation_capability_preflight(ctx: dict[str, Any]) -> dict[str, Any] | None:
    """Use the same authenticated OMP capability evidence as chain launch.

    Closed continuation fixers must prove the route through OMP's broker/store;
    an ambient ``OPENROUTER_API_KEY`` is neither required nor copied.  Keep the
    returned evidence sanitized (the shared helper only returns typed status
    and digests) so a failed fixer admission cannot leak provider credentials.
    """
    routing = ctx.get("routing")
    if routing is None or not getattr(routing, "closed", False):
        return None
    evidence = _omp_openrouter_capability_check(local=True)
    ctx["provider_capability"] = evidence
    if evidence.get("status") != "ok":
        reason = str(evidence.get("reason") or evidence.get("status") or "unknown")
        raise RuntimeError(f"babysitter OMP capability preflight failed: {reason}")
    return evidence


def _load_optional_json(path_raw: str | None) -> dict[str, object] | None:
    if not path_raw:
        return None
    path = Path(path_raw)
    if not path.is_file():
        raise RuntimeError(f"babysitter evidence JSON is not a file: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(f"babysitter evidence JSON is not an object: {path}")
    return payload


def _recovery_evidence_root(workspace: str) -> str:
    """Chain recovery evidence root, scanned for prior fixer occurrences.

    Each fixer incarnation persists its evidence under
    ``<workspace>/.megaplan/plans/.chains/recovery/<occurrence_digest>/``
    (swarm-briefs/, swarm-results/, codex/, execution/).  The goal renderer
    lists prior occurrences so the next babysitter reads the previous
    handoff instead of re-deriving the same diagnosis from scratch.
    """
    if not workspace:
        return ""
    return str(
        Path(workspace) / ".megaplan" / "plans" / ".chains" / "recovery"
    )


def _receipt_payload(ctx: dict[str, Any], *, status: str, **extra: Any) -> dict[str, Any]:
    from arnold_pipelines.megaplan.cloud.fixer_model_policy import model_policy_sha
    from arnold_pipelines.megaplan.cloud.fixer_prompt_policy import policy_sha

    resolved_model = str(ctx.get("model") or "")
    continuation_model = (
        resolved_model
        if resolved_model == "omp:openrouter/meta/muse-spark-1.3-contributor:high"
        else None
    )
    payload: dict[str, Any] = {
        "schema": LAUNCH_RECEIPT_SCHEMA,
        "session": ctx["session"],
        "occurrence_digest": ctx["occurrence"],
        "run_id": ctx["run_id"],
        "run_root": str(ctx["run_root"]),
        "plan": ctx["plan"],
        "run_kind": ctx["run_kind"],
        "workspace": ctx["workspace"],
        "remote_spec": ctx["remote_spec"],
        "mode": ctx["mode"],
        "model": ctx["model"],
        "reasoning_effort": ctx.get("reasoning_effort"),
        "provider_probe": ctx.get("provider_probe"),
        "policy_sha": policy_sha(),
        # Include the continuation override in the effective digest.  Legacy
        # receipts retain the historical table digest for compatibility.
        "model_policy_sha": model_policy_sha(
            continuation_model_spec=continuation_model
        ),
        "toolsets": TOOLSETS,
        "babysitter_pid": os.getpid(),
        "supervisor_pid": os.getpid(),
        "status": status,
        "authority": "telemetry_only",
        "launched_at": ctx["launched_at"],
    }
    if ctx.get("marker_dir") is not None:
        payload["marker_dir"] = str(ctx["marker_dir"])
    if ctx.get("repair_data_dir") is not None:
        payload["repair_data_dir"] = str(ctx["repair_data_dir"])
    if ctx.get("goal_path") is not None:
        payload["goal_path"] = str(ctx["goal_path"])
    if ctx.get("engine_root") is not None:
        payload["engine_root"] = str(ctx["engine_root"])
    if ctx.get("renderer_path") is not None:
        payload["renderer_path"] = str(ctx["renderer_path"])
    if ctx.get("identity_key") is not None:
        payload["identity_key"] = ctx["identity_key"]
    if ctx.get("managed_run_id") is not None:
        payload["managed_run_id"] = ctx["managed_run_id"]
    if ctx.get("managed_manifest_path") is not None:
        payload["managed_manifest_path"] = str(ctx["managed_manifest_path"])
    routing = ctx.get("routing")
    if routing is not None:
        payload.update(routing.as_dict())
    if ctx.get("provider_capability") is not None:
        # The shared OMP probe returns only typed status and fingerprints; do
        # not replace it with raw provider output in a fixer receipt.
        payload["provider_capability"] = ctx["provider_capability"]
    payload.update({key: value for key, value in extra.items() if value is not None})
    return payload


def _write_receipts(ctx: dict[str, Any], payload: dict[str, Any]) -> None:
    """Write one terminal watchdog telemetry record; never an admission fact."""
    target_root = ctx.get("repair_data_dir") or ctx["run_root"]
    _atomic_write_json(
        target_root / LAUNCH_RECEIPT_NAME.format(session=ctx["session"]),
        payload,
    )


def _terminal_returncode(returncode: int, terminal_status: str) -> int:
    """Make a downgraded managed completion visible to the watchdog."""
    return returncode if terminal_status == "completed" else (returncode or 1)


def _resolve_goal_file(ctx: dict[str, Any]) -> Path:
    """Prefer the supplied goal file; otherwise render one into the run root."""
    raw = ctx["goal_file_cli"] or os.environ.get("ARNOLD_BABYSITTER_GOAL_FILE", "").strip()
    if raw:
        candidate = Path(raw)
        if not candidate.is_file():
            raise RuntimeError(f"babysitter goal file is not a file: {candidate}")
        return candidate
    renderer = _resolve_asset(
        "arnold_pipelines/megaplan/skills/babysitter/scripts/render_babysitter_goal.py"
    )
    namespace = runpy.run_path(str(renderer))
    render = namespace.get("render_babysitter_goal")
    if not callable(render):
        raise RuntimeError("babysitter goal renderer is unavailable")
    goal_text = render(
        ctx["session"],
        session=ctx["session"],
        workspace=ctx["workspace"],
        plan=ctx["plan"],
        run_kind=ctx["run_kind"],
        latest_failure=_load_optional_json(ctx["failure_json"]),
        planner_repair=_load_optional_json(ctx["planner_repair_json"]),
        occurrence_digest=ctx["occurrence"],
        recovery_dir=_recovery_evidence_root(ctx["workspace"]),
    )
    goal_path = ctx["run_root"] / "babysitter-goal.md"
    goal_path.parent.mkdir(parents=True, exist_ok=True)
    goal_path.write_text(goal_text, encoding="utf-8")
    ctx["renderer_path"] = str(renderer)
    return goal_path


def _managed_spec(
    ctx: dict[str, Any], *, goal_path: Path, identity_key: str
) -> ManagedCommandSpec:
    engine_root = ctx["engine_root"]
    routing = ctx["routing"]
    if routing.closed or ctx.get("model") in {
        "omp:openrouter/meta/muse-spark-1.3-contributor",
        "omp:openrouter/meta/muse-spark-1.3-contributor:high",
    }:
        # A continuation's babysitter is also a fixer dispatch.  Resolve the
        # explicit fixer rung through its canonical policy seam so this
        # production consumer cannot accidentally fall back to the legacy
        # gated DeepSeek table.
        from arnold_pipelines.megaplan.cloud.fixer_model_policy import (
            CONTINUATION_FIXER_MODEL_SPEC,
            resolve_continuation_fixer_policy,
        )
        from arnold_pipelines.megaplan.profiles import resolve_continuation_runtime_model

        continuation_model = resolve_continuation_runtime_model(engine_root)
        if continuation_model is not None:
            fixer_policy = resolve_continuation_fixer_policy(
                "proactive", runtime_model_spec=continuation_model
            )
            expected_model = (
                CONTINUATION_MUSE_MODEL
                if routing.closed
                else f"omp:{fixer_policy.model}:high"
            )
            if continuation_model != CONTINUATION_FIXER_MODEL_SPEC:
                raise RuntimeError("continuation fixer policy/profile identity diverged")
            if ctx.get("model") != expected_model:
                raise RuntimeError(
                    "continuation babysitter model does not match the canonical fixer policy"
                )
    if routing.mode == "codex":
        # Codex reads the sealed goal from stdin.  Keeping the goal out of argv
        # also makes the managed manifest's stdin hash the exact controller
        # input used for this occurrence.
        # Strip ambient runtime-identity env (occurrence c2f73c7ddcef,
        # 2026-08-28): a launch seed or manifest inherited from the firing
        # parent silently lags generation advances and made every phase CLI
        # fail admission with source_revision_mismatch. The controller binds
        # identity explicitly from the marker/authoritative manifest instead.
        worker_argv = [
            "/usr/bin/env",
            "-u", "MEGAPLAN_RUNTIME_LAUNCH_SEED",
            "-u", "ARNOLD_RUNTIME_MANIFEST",
            "codex",
            "exec",
            "--sandbox", "danger-full-access",
            "--ephemeral",
            "-m", cli_model(routing.controller_model),
            "-c", "model_reasoning_effort=high",
            "--output-last-message", str(ctx["run_root"] / "controller-last-message.md"),
            "-",
        ]
        stdin_path = goal_path
        backend = "codex"
        route_class = "watchdog_babysitter_codex_override"
        description = (
            f"Codex babysitter session={ctx['session']} "
            f"occurrence={ctx['occurrence'] or 'unknown'} plan={ctx['plan'] or 'current target'} — "
            "codex investigators -> codex controller -> implement -> relaunch -> prove"
        )
    else:
        launcher = (
            engine_root
            / "arnold_pipelines/megaplan/skills/subagent-launcher/launch_omp_agent.py"
        )
        if not launcher.is_file():
            raise RuntimeError(f"omp subagent launcher unavailable: {launcher}")
        # Strip the managed-agent env vars the supervisor injects, so the omp
        # launcher runs the goal as a DIRECT worker of this managed run instead
        # of re-exec'ing itself as a nested "research" run.
        worker_argv = [
            "/usr/bin/env",
            "-u", "ARNOLD_MANAGED_AGENT_RUN_ID",
            "-u", "ARNOLD_MANAGED_AGENT_MANIFEST",
            "-u", "ARNOLD_MANAGED_AGENT_ORIGIN",
            "-u", "MEGAPLAN_RUNTIME_LAUNCH_SEED",
            "-u", "ARNOLD_RUNTIME_MANIFEST",
            sys.executable,
            str(launcher),
            f"--model={ctx['model']}"
            + (f":{CONTINUATION_MUSE_THINKING}" if routing.closed else ""),
            f"--toolsets={TOOLSETS}",
            f"--query-file={goal_path}",
            f"--project-dir={engine_root}",
        ]
        stdin_path = None
        backend = BACKEND
        route_class = ROUTE_CLASS
        description = (
            f"Single OMP babysitter session={ctx['session']} "
            f"occurrence={ctx['occurrence'] or 'unknown'} plan={ctx['plan'] or 'current target'} — "
            "swarm -> review -> implement -> relaunch -> prove"
        )
        if routing.closed:
            route_class = "watchdog_babysitter_continuation_muse"
            description = (
                f"Single Muse Spark 1.3 babysitter session={ctx['session']} "
                f"occurrence={ctx['occurrence'] or 'unknown'} plan={ctx['plan'] or 'current target'} — "
                "all roles Muse/high, no fallback"
            )
    links: dict[str, Any] = {
        "cloud_session": ctx["session"],
        "occurrence_digest": ctx["occurrence"],
        "run_id": ctx["run_id"],
        "goal_path": str(goal_path),
        "babysitter_mode": ctx["mode"] or "superfixer",
        "routing": routing.as_dict(),
    }
    if ctx.get("repair_data_dir") is not None:
        links["repair_data_dir"] = str(ctx["repair_data_dir"])
    if ctx.get("marker_dir") is not None:
        links["marker_dir"] = str(ctx["marker_dir"])
    if ctx["remote_spec"]:
        links["chain"] = ctx["remote_spec"]
    if ctx["plan"]:
        links["plan"] = ctx["plan"]
    if ctx["workspace"]:
        links["workspace"] = ctx["workspace"]
    spec = ManagedCommandSpec(
        run_kind=RUN_KIND,
        identity_key=identity_key,
        project_dir=engine_root,
        argv=tuple(worker_argv),
        task_kind=TASK_KIND,
        difficulty=ctx["difficulty"],
        model=ctx["model"],
        reasoning_effort=ctx.get(
            "reasoning_effort",
            CONTINUATION_MUSE_THINKING if routing.closed else REASONING_EFFORT,
        ),
        route_class=route_class,
        backend=backend,
        command_display=(
            f"arnold-babysitter {routing.controller_model} agent session={ctx['session']} "
            f"occurrence={ctx['occurrence'] or 'unknown'}"
        ),
        description=description,
        launch_provenance=machine_origin_provenance(
            origin_kind=ORIGIN_KIND,
            origin_id=_provenance_safe(ctx["run_id"]),
            component=ORIGIN_COMPONENT,
            trigger_id=_provenance_safe(ctx["occurrence"] or ctx["run_id"]),
        ),
        links=links,
        lineage_key=f"babysitter:{ctx['session']}",
        run_root=ctx["run_root"],
        stdin_path=stdin_path,
    )
    return spec


class ManagedLaunchUnresolved(RuntimeError):
    """Typed managed-door hold; keeps the legacy public return code intact."""

    def __init__(self, outcome: Any) -> None:
        self.outcome = outcome
        super().__init__("managed launch remains unresolved")


def canonical_launch_custody_view(
    store: Any,
    operation_id: str,
    *,
    observe: Any = None,
) -> dict[str, Any]:
    """Read the canonical launch view used by babysitter custody paths.

    This helper intentionally has no receipt/marker/WBC writer and no launch
    callback.  Babysitter status inspection must remain a projection of the
    durable OperationRun authority, including unresolved ``PENDING`` custody.
    """

    from arnold.runtime.durable_ops import inspect_launch

    inspection = inspect_launch(operation_id, store=store, observe=observe)
    return {
        "operation_id": operation_id,
        "result": inspection.result.value,
        "reason": inspection.reason.value,
        "envelope": inspection.envelope.to_json() if inspection.envelope else None,
        "operation_state": inspection.operation.state.value if inspection.operation else None,
        "event_types": [event.event_type for event in inspection.events],
        "resource_ids": [resource.id for resource in inspection.resources],
        "observation": dict(inspection.observation)
        if inspection.observation is not None
        else None,
    }


def _automatic_dispatch_preflight(ctx: dict[str, Any], spec: ManagedCommandSpec):
    """Return an observation-only managed-door preflight.

    Launch acceptance, identity, and replay are owned by the canonical
    OperationRun store.  The babysitter does not inspect or write a marker,
    reservation, receipt, or IncidentLedger launch projection.
    """
    del spec
    if os.environ.get("ARNOLD_BABYSITTER_AUTO_DISPATCH", "").strip() not in {"1", "true", "yes"}:
        return None
    workspace = str(ctx.get("workspace") or "").strip()

    def preflight(_receipt: Any) -> dict[str, Any]:
        if not workspace:
            return {"suppress": True, "reason": "managed launch workspace is unavailable"}
        if not Path(workspace).expanduser().exists():
            return {"suppress": True, "reason": "managed launch workspace is unavailable"}
        return {"observed": {"workspace": workspace}}

    return preflight


def _admit_managed_launch(ctx: dict[str, Any], spec: ManagedCommandSpec) -> int:
    """Run the managed command only after one canonical admission decision."""
    from arnold_pipelines.megaplan.cloud.runtime_attestation import require_production_worker_dispatch_runtime
    from arnold_pipelines.megaplan.cloud.runtime_attestation import configured_seed_path
    from arnold_pipelines.megaplan.cloud.runtime_provenance import runtime_provenance
    from arnold_pipelines.megaplan.cloud.worker_dispatch import (
        AdmissionRefusal,
        LaunchResult,
        ManagedCommandResult,
        SchedulingCondition,
        WorkerAdmissionRequest,
        dispatch_with_admission,
        production_provider_probe_executor,
    )
    from arnold_pipelines.megaplan.orchestration.phase_result import DispatchOutcome
    from arnold_pipelines.megaplan.types import parse_agent_spec

    # The immutable managed command spec is the authority for route identity;
    # ambient context cannot substitute a model after the spec is built.
    model = str(spec.model)
    plan = str(ctx.get("plan") or ctx["session"])
    identity = str(ctx.get("managed_run_id") or ctx["run_id"])
    seed_path = configured_seed_path()
    manifest_path = str(os.environ.get("ARNOLD_RUNTIME_MANIFEST") or "")
    seed_identity = ""
    manifest_identity = ""
    try:
        if seed_path is not None and seed_path.is_file():
            seed_identity = hashlib.sha256(seed_path.read_bytes()).hexdigest()
        if manifest_path and Path(manifest_path).is_file():
            manifest_identity = hashlib.sha256(Path(manifest_path).read_bytes()).hexdigest()
    except OSError:
        # Keep the identity empty so the canonical gate returns a typed refusal
        # before the managed command is constructed or started.
        seed_identity = ""
        manifest_identity = ""
    provenance = runtime_provenance()
    configured_specs = tuple(ctx.get("configured_fallback_specs") or (model,))
    request = WorkerAdmissionRequest(
        plan_id=plan,
        phase="babysitter",
        dispatch_family_id=f"babysitter:{ctx['session']}:{ctx['run_id']}",
        logical_dispatch_id=identity,
        physical_door_id="cloud.babysitter.launch",
        configured_spec=model,
        selected_spec=model,
        source_revision=str(provenance.get("source_revision") or ""),
        runtime_vector=provenance,
        manifest_identity=manifest_identity,
        seed_identity=seed_identity,
        dependency_interpreter_identity=str(Path(sys.executable).resolve()),
        prompt_or_phase_input_identity=str(ctx.get("goal_path") or ctx["run_id"]),
        configured_fallback_chain_identity=str(ctx.get("configured_fallback_chain_identity") or ""),
        configured_fallback_specs=configured_specs,
        authorized_route_identity=model,
        projection_key=f"babysitter:{ctx['session']}",
        timeout_budget_s=float(os.environ.get("ARNOLD_BABYSITTER_TIMEOUT_S", "3600")),
        production_intent=True,
        ledger_root=Path(ctx["run_root"]),
        admission_attempt=int(ctx.get("admission_attempt") or 1),
    )

    def launch(context: Any) -> LaunchResult:
        admitted = getattr(context, "selected_spec", None) or model
        parse_agent_spec(admitted)
        child_spec = spec if admitted == spec.model else replace(spec, model=admitted)
        pid = os.getpid()
        try:
            from arnold_pipelines.megaplan.watchdog.worker_identity import read_process_start_identity
            start_identity = read_process_start_identity(pid) or f"managed-supervisor:{pid}"
        except Exception:
            start_identity = f"managed-supervisor:{pid}"
        identity_payload = {
            "host": socket.gethostname(),
            "pid": pid,
            "boot_id": "managed-supervisor",
            "process_start_identity": start_identity,
        }
        return LaunchResult(
            True,
            ManagedCommandResult(
                run_managed_command(child_spec),
                worker_identity=identity_payload,
            ),
            worker_identity=identity_payload,
        )

    result = dispatch_with_admission(
        request, launch,
        # Keep the canonical typed outcome at the managed-door boundary.  The
        # integer API is restored below after the outcome is published on ctx.
        gate=require_production_worker_dispatch_runtime,
        probe_executor=production_provider_probe_executor(),
        child_launch=launch,
        admission_preflight=_automatic_dispatch_preflight(ctx, spec),
    )
    if isinstance(result, AdmissionRefusal):
        raise RuntimeError(f"babysitter admission refused: {result.code}: {result.reason}")
    if isinstance(result, SchedulingCondition):
        raise RuntimeError(f"babysitter admission scheduled: {result.reason}")
    if isinstance(result, DispatchOutcome):
        # The managed entry point is an established integer-returning API,
        # while the canonical dispatch path carries the lossless typed
        # terminal outcome.  Keep that outcome on the managed-door context so
        # launch_babysitter can publish it in the receipt without asking the
        # caller to unpack or reinterpret a transport value.
        ctx["dispatch_outcome"] = result.to_dict()
        if result.kind == "no_launch":
            # Suppression is a successful, durable no-start result.  The
            # watchdog maps the child receipt to babysitter_suppressed.
            return 0
        if result.kind == "unresolved_launch":
            raise ManagedLaunchUnresolved(result)
        if result.kind == "success":
            return 0
        if result.kind in {"ordinary_terminal_failure", "provider_exhausted", "worker_disposition"}:
            return 1
    if not isinstance(result, int):
        raise RuntimeError("babysitter admission returned an invalid managed result")
    return result


def _require_continuation_provider_probe(ctx: dict[str, Any]) -> None:
    """Require and retain a credentialed exact-output Muse proof before launch."""
    from arnold_pipelines.megaplan.cloud.worker_dispatch import (
        ensure_continuation_provider_probe,
    )
    from arnold_pipelines.megaplan.profiles import resolve_continuation_runtime_model

    continuation_model = resolve_continuation_runtime_model(ctx["engine_root"])
    if continuation_model is None:
        return
    if ctx.get("reasoning_effort") != "high":
        raise RuntimeError("continuation provider probe requires high reasoning effort")
    route = continuation_model.removeprefix("omp:")
    provider, separator, model_and_effort = route.partition("/")
    model_id, effort_separator, effort = model_and_effort.rpartition(":")
    if not separator or not provider or not effort_separator or effort != "high":
        raise RuntimeError("continuation provider probe route is not canonical")
    proof = ensure_continuation_provider_probe(ctx["engine_root"], continuation_model)
    ctx["provider_probe"] = {
        "spec": continuation_model,
        "provider": provider,
        "model": model_id,
        "reasoning_effort": effort,
        "identity": f"{provider}/{model_id}",
        "catalog_digest": proof["catalog_digest"],
        "probe_session": proof["probe_session"],
        "output": proof["output"],
        "output_sha256": proof["output_sha256"],
        "observed_at": proof["observed_at"],
        "profile_sha256": proof["profile_sha256"],
    }


def launch_babysitter(argv: Sequence[str] | None = None) -> int:
    """Run the single-flash babysitter launch flow; returns the process rc."""
    args = _build_parser().parse_args(argv)
    ctx = _collect_context(args)
    ctx["launched_at"] = _utcnow_iso()
    # ROOT FIX (grok consult 2026-08-17): assert session-identity consistency
    # before any worker spawn. If ARNOLD_REPAIR_SESSION disagrees with the
    # babysitter --session, a stale box-global env would leak into the
    # agent's resume/execute workers and hijack another session's liveness
    # lock/marker/lease (astrid -> mega collision observed 2026-08-17).
    _babysitter_session = str(ctx.get("session") or "").strip()
    _repair_env_session = str(os.environ.get("ARNOLD_REPAIR_SESSION") or "").strip()
    if _babysitter_session and _repair_env_session and _babysitter_session != _repair_env_session:
        os.environ["ARNOLD_REPAIR_SESSION"] = _babysitter_session
    os.environ["ARNOLD_BABYSITTER_SESSION"] = _babysitter_session
    try:
        ctx["engine_root"] = _resolve_engine_root()
        # Resolve continuation profiles from the actual engine root before
        # capability and provider gates; this prevents a stale environment
        # route from bypassing the project-local canonical model.
        ctx["routing"] = resolve_babysitter_routing(project_dir=ctx["engine_root"])
        if ctx["routing"].mode == "omp":
            ctx["model"] = ctx["routing"].controller_model
            if ctx["model"].endswith(":high"):
                ctx["reasoning_effort"] = "high"
        _continuation_capability_preflight(ctx)
        _require_continuation_provider_probe(ctx)
        goal_path = _resolve_goal_file(ctx)
        ctx["goal_path"] = str(goal_path)

        # The occurrence-scoped identity is stable across process restarts;
        # canonical OperationRun replay/inspection decides whether a physical
        # door may run.  A timestamp here would defeat exact replay.
        identity_key = f"babysitter:{ctx['session']}:{ctx['occurrence']}:{ctx['run_id']}"
        ctx["identity_key"] = identity_key
        managed_run_id = stable_managed_run_id(RUN_KIND, identity_key)
        ctx["managed_run_id"] = managed_run_id
        ctx["managed_manifest_path"] = str(ctx["run_root"] / managed_run_id / "manifest.json")
        spec = _managed_spec(ctx, goal_path=goal_path, identity_key=identity_key)

        # The managed supervisor reserves the run itself (clean
        # created=True "supervisor_start" path — no pre-reservation, which
        # would be misread as a dead-supervisor restart) and then blocks
        # until the Flash agent finishes.
        rc = _admit_managed_launch(ctx, spec)
        if (ctx.get("dispatch_outcome") or {}).get("kind") == "no_launch":
            _write_receipts(
                ctx,
                _receipt_payload(
                    ctx,
                    status="suppressed",
                    finished_at=_utcnow_iso(),
                    returncode=0,
                    dispatch_outcome=ctx.get("dispatch_outcome"),
                    suppression_reason=(ctx.get("dispatch_outcome") or {}).get("reconciliation_event_id"),
                ),
            )
            return 0
        managed_terminal = "unknown"
        try:
            managed_terminal = str(
                json.loads(
                    (ctx["run_root"] / managed_run_id / "manifest.json").read_text(
                        encoding="utf-8"
                    )
                ).get("status")
                or "unknown"
            )
        except (OSError, json.JSONDecodeError):
            pass
        terminal_status = (
            "completed"
            if rc == 0 and managed_terminal == "completed"
            else "interrupted"
            if managed_terminal == "interrupted"
            else "failed"
        )
        # False-success guard (J2/grok consult 2026-08-16): a managed fixer
        # that exits 0 while the target chain/plan is STILL in the failure
        # state is a false success — the watchdog will not re-dispatch a
        # `completed` run, so the chain strands. Downgrade to `failed` when
        # the plan the babysitter was dispatched for is still blocked/failed
        # with a matching failure kind, so the next watchdog scan relaunches
        # the repair for the same occurrence.
        false_success_reason = ""
        if terminal_status == "completed":
            try:
                plan_name = str(ctx.get("plan") or "").strip()
                workspace = str(ctx.get("workspace") or "").strip()
                if plan_name and workspace:
                    plan_state_path = (
                        Path(workspace) / ".megaplan" / "plans" / plan_name / "state.json"
                    )
                    if plan_state_path.is_file():
                        plan_payload = json.loads(
                            plan_state_path.read_text(encoding="utf-8")
                        )
                        state = str(plan_payload.get("current_state") or "")
                        if state in {"blocked", "failed"}:
                            failure = plan_payload.get("latest_failure") or {}
                            failure_kind = str(failure.get("kind") or "")
                            false_success_reason = (
                                f"plan still {state} after fixer exit; "
                                f"failure_kind={failure_kind or 'unknown'}"
                            )
            except (OSError, json.JSONDecodeError):
                pass
        if false_success_reason:
            terminal_status = "failed"
            _eprint(
                f"[babysitter] FALSE SUCCESS downgraded to failed "
                f"session={ctx.get('session', '?')} occurrence={ctx.get('occurrence', '?')} "
                f"reason={false_success_reason}"
            )
        _write_receipts(
            ctx,
            _receipt_payload(
                ctx,
                status=terminal_status,
                finished_at=_utcnow_iso(),
                returncode=rc,
                managed_terminal_status=managed_terminal,
                dispatch_outcome=ctx.get("dispatch_outcome"),
                false_success_reason=false_success_reason or None,
            ),
        )
        return _terminal_returncode(rc, terminal_status)
    except SystemExit:
        raise
    except ManagedLaunchUnresolved as exc:
        _eprint(json.dumps({"dispatch_outcome": exc.outcome.to_dict()}, sort_keys=True))
        try:
            _write_receipts(
                ctx,
                _receipt_payload(
                    ctx,
                    status="unresolved",
                    finished_at=_utcnow_iso(),
                    returncode=2,
                    dispatch_outcome=exc.outcome.to_dict(),
                ),
            )
        except BaseException as write_exc:
            _eprint(f"[babysitter] could not record unresolved receipt: {write_exc!r}")
        return 2
    except BaseException as exc:
        _eprint(f"[babysitter] launch failed session={ctx.get('session', '?')} err={exc!r}")
        try:
            _write_receipts(
                ctx,
                _receipt_payload(
                    ctx,
                    status="failed",
                    finished_at=_utcnow_iso(),
                    returncode=1,
                    error=f"{type(exc).__name__}: {exc}",
                ),
            )
        except BaseException as write_exc:
            _eprint(f"[babysitter] could not record failure receipt: {write_exc!r}")
        return 1


def main(argv: Sequence[str] | None = None) -> int:
    return launch_babysitter(argv)


if __name__ == "__main__":
    raise SystemExit(main())
