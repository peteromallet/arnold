"""CLI for running compiled workflow manifests.

Example::

    python -m arnold.cli.execution run-manifest \
        --manifest manifest.json \
        --state-store-dir ./runs \
        --budget '{"max_cost": 10.0}'
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from arnold.execution import run
from arnold.execution.observability import ExecutionLogger, build_progress_report
from arnold.execution.result import ExecutionResult
from arnold.execution.state_store import FileStateStore
from arnold.kernel import GovernorBudget
from arnold.kernel.journal import read_event_journal
from arnold.manifest import WorkflowManifest
from arnold.pipeline.resume import read_awaiting_user_checkpoint, read_resume_cursor
from arnold.runtime.durable_ops import (
    BROKER_APPROVAL_SUSPENSION_KIND,
    FileBackedDurableOpsStore,
    OperationNotFound,
)
from arnold.runtime.state_persistence import atomic_write_json
from arnold.security.approval import BROKER_APPROVAL_CHOICES, resolve_broker_approval
from arnold.security.types import ActionResult, ActionVerdict


@dataclass(frozen=True, slots=True)
class ApprovalSurface:
    artifact_root: Path
    checkpoint_path: Path
    cursor_path: Path
    checkpoint: dict[str, Any]
    cursor: dict[str, Any]
    operation_id: str
    action_id: str | None


@dataclass(frozen=True, slots=True)
class ApprovalOutcome:
    state: str
    action_id: str | None
    resume_cursor: str | None
    status: str


def _load_manifest(path: Path) -> WorkflowManifest:
    return WorkflowManifest.from_json(path.read_text(encoding="utf-8"))


def _parse_budget(raw: str | None) -> GovernorBudget | None:
    if not raw:
        return None
    payload = json.loads(raw)
    return GovernorBudget(
        cost_limit=payload.get("max_cost"),
        seconds_limit=payload.get("max_seconds"),
        token_limit=payload.get("token_budget"),
    )


def _print_result(result: ExecutionResult) -> None:
    payload = {
        "state": result.state.value,
        "manifest_id": result.manifest_id,
        "manifest_hash": result.manifest_hash,
        "artifact_root": str(result.artifact_root),
        "outputs": dict(result.outputs),
        "diagnostics": [
            {"code": d.code, "message": d.message, "node_id": d.node_id}
            for d in result.diagnostics
        ],
        "resume_cursor": result.resume_cursor.key if result.resume_cursor else None,
        "is_terminal": result.is_terminal,
    }
    print(json.dumps(payload, sort_keys=True, indent=2))


def _print_approval_outcome(outcome: ApprovalOutcome) -> None:
    print(
        json.dumps(
            {
                "state": outcome.state,
                "action_id": outcome.action_id,
                "resume_cursor": outcome.resume_cursor,
                "status": outcome.status,
            },
            sort_keys=True,
            indent=2,
        )
    )


def _cmd_run_manifest(args: argparse.Namespace) -> int:
    manifest_path = Path(args.manifest)
    if not manifest_path.exists():
        print(f"manifest not found: {manifest_path}", file=sys.stderr)
        return 2

    manifest = _load_manifest(manifest_path)

    state_store = None
    if args.state_store_dir:
        state_store = FileStateStore(args.state_store_dir)

    budget = _parse_budget(args.budget)
    registries = None
    if budget is not None:
        from arnold.execution import ExecutionRegistries

        registries = ExecutionRegistries()

    logger = ExecutionLogger()

    result = run(
        manifest,
        artifact_root=args.artifact_root or str(Path(args.state_store_dir or ".") / "artifacts"),
        registries=registries,
        state_store=state_store,
        logger=logger,
    )

    if args.progress:
        events = read_event_journal(result.artifact_root)
        report = build_progress_report(events)
        print(json.dumps({
            "state": result.state.value,
            "progress": {
                "total_nodes": report.total_nodes,
                "completed": report.completed,
                "failed": report.failed,
                "pending": report.pending,
                "suspended": report.suspended,
                "consumed_cost": report.consumed_cost,
                "remaining_cost": report.remaining_cost,
                "health_status": report.health_status,
            },
        }, sort_keys=True, indent=2))
    else:
        _print_result(result)

    return 0 if result.state.value == "completed" else 1


def _approval_store_root(args: argparse.Namespace, artifact_root: Path) -> Path:
    if args.state_store_dir:
        return Path(args.state_store_dir)
    return artifact_root


def _load_approval_surface(
    artifact_root: Path,
    *,
    operation_id: str | None = None,
) -> ApprovalSurface:
    checkpoint_path = artifact_root / "awaiting_user.json"
    cursor_path = artifact_root / "resume_cursor.json"
    checkpoint = read_awaiting_user_checkpoint(artifact_root)
    if checkpoint is None:
        raise ValueError(f"broker approval checkpoint not found: {checkpoint_path}")
    cursor = read_resume_cursor(artifact_root)
    if cursor is None:
        raise ValueError(f"broker approval cursor not found: {cursor_path}")
    if checkpoint.get("suspension_kind") != BROKER_APPROVAL_SUSPENSION_KIND:
        raise ValueError(
            f"{checkpoint_path} is not a broker approval gate checkpoint"
        )
    resume_cursor_raw = cursor.get("resume_cursor")
    cursor_payload = None
    if isinstance(resume_cursor_raw, str):
        try:
            cursor_payload = json.loads(resume_cursor_raw)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"{cursor_path} carries an unreadable broker resume cursor"
            ) from exc
    if not isinstance(cursor_payload, dict):
        raise ValueError(f"{cursor_path} does not contain a broker approval payload")
    detected_operation_id = cursor_payload.get("operation_id")
    if not isinstance(detected_operation_id, str) or not detected_operation_id:
        raise ValueError(f"{cursor_path} is missing broker operation_id")
    if operation_id is not None and operation_id != detected_operation_id:
        raise ValueError(
            f"operation_id mismatch: checkpoint has {detected_operation_id!r}, "
            f"CLI requested {operation_id!r}"
        )
    choices = checkpoint.get("choices")
    if choices is not None and list(choices) != list(BROKER_APPROVAL_CHOICES):
        raise ValueError(f"{checkpoint_path} does not expose broker approval choices")
    action_id = checkpoint.get("broker_action_id") or cursor.get("broker_action_id")
    if action_id is not None and not isinstance(action_id, str):
        action_id = str(action_id)
    return ApprovalSurface(
        artifact_root=artifact_root,
        checkpoint_path=checkpoint_path,
        cursor_path=cursor_path,
        checkpoint=checkpoint,
        cursor=cursor,
        operation_id=detected_operation_id,
        action_id=action_id,
    )


def _action_result_for_decision(
    decision: str,
    *,
    action_id: str | None,
    summary: str,
) -> ActionResult:
    verdict = (
        ActionVerdict.ALLOW if decision == "approve" else ActionVerdict.DENY
    )
    return ActionResult(
        verdict=verdict,
        summary=summary,
        action_id=action_id,
        metadata={"decision": decision, "source": "cli-execution"},
    )


def _write_decision_payload(surface: ApprovalSurface, decision: str) -> ActionResult:
    action_result = _action_result_for_decision(
        decision,
        action_id=surface.action_id,
        summary=f"broker approval {decision}",
    )
    updated = dict(surface.checkpoint)
    updated["_resume_choice"] = decision
    updated["_decision_payload"] = action_result.to_json()
    atomic_write_json(surface.checkpoint_path, updated)
    return action_result


def _resume_approval(surface: ApprovalSurface, args: argparse.Namespace) -> ApprovalOutcome:
    raw_decision = surface.checkpoint.get("_resume_choice")
    if not isinstance(raw_decision, str) or raw_decision not in BROKER_APPROVAL_CHOICES:
        return ApprovalOutcome(
            state="awaiting_approval",
            action_id=surface.action_id,
            resume_cursor=str(surface.cursor_path),
            status="awaiting_decision",
        )
    payload = surface.checkpoint.get("_decision_payload")
    if isinstance(payload, dict):
        summary = str(payload.get("summary") or f"broker approval {raw_decision}")
    else:
        summary = f"broker approval {raw_decision}"
    action_result = _action_result_for_decision(
        raw_decision,
        action_id=surface.action_id,
        summary=summary,
    )
    store = FileBackedDurableOpsStore(_approval_store_root(args, surface.artifact_root))
    updated = resolve_broker_approval(
        store,
        surface.operation_id,
        raw_decision,
        action_result=action_result,
    )
    surface.checkpoint_path.unlink(missing_ok=True)
    surface.cursor_path.unlink(missing_ok=True)
    status = {
        "approve": "approved",
        "deny": "denied",
        "cancel": "cancelled",
    }[raw_decision]
    return ApprovalOutcome(
        state=updated.state.value,
        action_id=surface.action_id,
        resume_cursor=str(surface.cursor_path),
        status=status,
    )


def _cmd_approval_decision(args: argparse.Namespace) -> int:
    artifact_root = Path(args.artifact_root)
    try:
        surface = _load_approval_surface(
            artifact_root,
            operation_id=args.operation_id,
        )
        _write_decision_payload(surface, args.command)
        outcome = _resume_approval(
            _load_approval_surface(
                artifact_root,
                operation_id=args.operation_id,
            ),
            args,
        )
    except (OperationNotFound, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    _print_approval_outcome(outcome)
    return 0


def _cmd_resume(args: argparse.Namespace) -> int:
    artifact_root = Path(args.artifact_root)
    try:
        surface = _load_approval_surface(
            artifact_root,
            operation_id=args.operation_id,
        )
        outcome = _resume_approval(surface, args)
    except (OperationNotFound, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    _print_approval_outcome(outcome)
    return 0


def main(argv: Sequence[str] | None = None, *, prog: str = "arnold") -> int:
    parser = argparse.ArgumentParser(
        prog=prog,
        description="Run compiled Arnold workflow manifests and broker approval gates.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser(
        "run-manifest",
        help="Run a compiled manifest from a JSON file.",
    )
    run_parser.add_argument("--manifest", required=True, help="Path to the compiled manifest JSON file.")
    run_parser.add_argument("--run-id", help="Optional run identity.")
    run_parser.add_argument("--artifact-root", help="Directory for the journal and artifacts.")
    run_parser.add_argument("--state-store-dir", help="Directory for JSON checkpoints.")
    run_parser.add_argument("--backend", default="local", help="Backend selector (default: local).")
    run_parser.add_argument("--budget", help='JSON budget object, e.g. {"max_cost": 10.0}.')
    run_parser.add_argument("--progress", action="store_true", help="Print progress report instead of result.")
    run_parser.set_defaults(func=_cmd_run_manifest)

    for command, help_text in [
        ("approve", "Approve a broker approval checkpoint and transition the durable run."),
        ("deny", "Deny a broker approval checkpoint and transition the durable run."),
        ("cancel", "Cancel a broker approval checkpoint and transition the durable run."),
        ("resume", "Resume a broker approval checkpoint after a decision was recorded."),
    ]:
        sub = subparsers.add_parser(command, help=help_text)
        sub.add_argument(
            "--artifact-root",
            required=True,
            help="Directory containing awaiting_user.json and resume_cursor.json.",
        )
        sub.add_argument(
            "--state-store-dir",
            help="Directory containing durable operation_runs.json (defaults to --artifact-root).",
        )
        sub.add_argument(
            "--operation-id",
            help="Optional operation id guard; defaults to the id embedded in the broker cursor.",
        )
        sub.set_defaults(func=_cmd_resume if command == "resume" else _cmd_approval_decision)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
