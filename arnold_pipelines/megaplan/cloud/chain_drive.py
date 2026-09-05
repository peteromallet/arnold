"""Authoritative cloud launch engine.

This module is executed in the provider's engine container (or directly by a
co-located local provider). The controller sends a JSON request and receives a
typed response; it never creates a receipt, marker, synthetic operation id,
replacement session, or retry attempt.
"""

from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
import shlex
from typing import Any, Mapping, Sequence

from arnold.runtime.durable_ops import (
    LaunchDispatchRejected,
    LaunchEnvelope,
    LaunchResult,
    ResourceType,
    TypedResource,
    launch_transaction,
    run_launch_preflight,
)

from agentbox.config import load_agentbox_config
from agentbox.operations import open_operation_store
from agentbox.tmux import inspect_session, new_session_argv, run_tmux


class ChainDriveError(RuntimeError):
    """A malformed or unplaceable authoritative launch request."""


def _json_response(
    *,
    result: LaunchResult | str,
    reason: str,
    operation_id: str,
    request_id: str,
    envelope_digest: str | None = None,
    detail: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema": "arnold.megaplan.cloud_launch_response.v1",
        "result": LaunchResult(result).value,
        "reason": reason,
        "operation_id": operation_id,
        "request_id": request_id,
    }
    if envelope_digest:
        payload["envelope_digest"] = envelope_digest
    if detail:
        payload["detail"] = detail
    return payload


def _request_mapping(raw: Mapping[str, Any] | str) -> dict[str, Any]:
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ChainDriveError("launch request is not JSON") from exc
    if not isinstance(raw, Mapping):
        raise ChainDriveError("launch request must be a JSON object")
    request = dict(raw)
    required = {"envelope", "preflight_observations", "command", "cwd", "session"}
    missing = required - set(request)
    if missing:
        raise ChainDriveError("launch request missing fields: " + ", ".join(sorted(missing)))
    return request


def execute_authoritative_launch(request: Mapping[str, Any]) -> dict[str, Any]:
    """Execute exactly one launch at the store's physical location."""

    request = _request_mapping(request)
    envelope = LaunchEnvelope.from_json(request["envelope"])
    config = load_agentbox_config()
    configured_store_root = str(request.get("ops_store_root") or "").strip()
    actual_store_root = str(config.ops_store_root)
    if configured_store_root and Path(configured_store_root).resolve() != Path(actual_store_root).resolve():
        return _json_response(
            result=LaunchResult.REJECTED,
            reason="store_placement_mismatch",
            operation_id=envelope.operation_id,
            request_id=envelope.request_id,
            envelope_digest=envelope.digest,
            detail="engine store does not match the configured authoritative store",
        )
    observations = request["preflight_observations"]
    if not isinstance(observations, Mapping):
        raise ChainDriveError("preflight_observations must be an object")
    preflight = run_launch_preflight(envelope.launch_spec, observations)
    if not preflight.accepted:
        return _json_response(
            result=LaunchResult.REJECTED,
            reason="preflight_rejected",
            operation_id=envelope.operation_id,
            request_id=envelope.request_id,
            envelope_digest=envelope.digest,
        )

    command = request["command"]
    if not isinstance(command, (str, list, tuple)):
        raise ChainDriveError("command must be a string or argv sequence")
    cwd = request["cwd"]
    session = request["session"]
    if not isinstance(cwd, str) or not cwd or not isinstance(session, str) or not session:
        raise ChainDriveError("cwd and session must be non-empty strings")
    store = open_operation_store(config)
    identity = {
        "ARNOLD_LAUNCH_OPERATION_ID": envelope.operation_id,
        "ARNOLD_LAUNCH_REQUEST_ID": envelope.request_id,
        "ARNOLD_LAUNCH_ENVELOPE_DIGEST": envelope.digest,
        "ARNOLD_LAUNCH_PROCESS_IDENTITY": str(envelope.launch_spec.get("process_session_identity") or session),
    }

    def dispatch(candidate: LaunchEnvelope) -> str:
        try:
            run_tmux(new_session_argv(session, command, cwd=Path(cwd), environment=identity))
        except Exception as exc:
            raise LaunchDispatchRejected(str(exc)) from exc
        return session

    def observe(dispatched: str, candidate: LaunchEnvelope) -> Mapping[str, Any]:
        status = inspect_session(dispatched, expected_identity=identity)
        return {
            "operation_id": status.operation_id,
            "request_id": status.request_id,
            "envelope_digest": status.envelope_digest,
            "process_session_identity": status.process_session_identity,
            "session_name": status.session_name,
            "liveness": status.state,
        }

    def resource_factory(dispatched: str, observation: Mapping[str, Any], candidate: LaunchEnvelope) -> TypedResource:
        return TypedResource(
            id=f"launch-process-session:{candidate.operation_id}:{candidate.request_id}",
            operation_id=candidate.operation_id,
            resource_type=ResourceType.PROCESS_SESSION,
            name=dispatched,
            details={dict_key: observation.get(dict_key) for dict_key in (
                "operation_id", "request_id", "envelope_digest", "process_session_identity", "session_name", "liveness"
            )},
        )

    transaction = launch_transaction(
        envelope,
        store=store,
        preflight=preflight,
        dispatch=dispatch,
        observe=observe,
        resource_factory=resource_factory,
        operation_type=str(envelope.launch_spec.get("operation_type") or "megaplan_chain"),
    )
    return _json_response(
        result=transaction.result,
        reason=transaction.reason.value,
        operation_id=envelope.operation_id,
        request_id=envelope.request_id,
        envelope_digest=envelope.digest,
    )


def build_launch_request(
    *,
    envelope: LaunchEnvelope,
    command: str | Sequence[str],
    cwd: str,
    session: str,
    preflight_observations: Mapping[str, Any],
    ops_store_root: str | None = None,
) -> dict[str, Any]:
    """Build the controller-to-engine request without opening the store."""

    return {
        "envelope": envelope.to_json(),
        "command": list(command) if not isinstance(command, str) else command,
        "cwd": cwd,
        "session": session,
        "preflight_observations": dict(preflight_observations),
        "ops_store_root": ops_store_root,
    }


def encode_launch_request(request: Mapping[str, Any]) -> str:
    raw = json.dumps(dict(request), sort_keys=True, separators=(",", ":")).encode()
    return base64.b64encode(raw).decode("ascii")


def launch_engine_command(encoded_request: str) -> str:
    """Return a fixed command that runs the co-located engine."""

    return (
        "python -P -m arnold_pipelines.megaplan.cloud.chain_drive "
        "--request-b64 " + shlex.quote(encoded_request)
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request-b64", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        raw = base64.b64decode(args.request_b64, validate=True)
        payload = execute_authoritative_launch(json.loads(raw.decode("utf-8")))
    except Exception as exc:
        payload = {
            "schema": "arnold.megaplan.cloud_launch_response.v1",
            "result": LaunchResult.UNKNOWN.value,
            "reason": "engine_error",
            "detail": f"{type(exc).__name__}: {exc}",
        }
    print(json.dumps(payload, sort_keys=True))
    # A typed UNKNOWN is still a successful engine response.  The controller
    # must not reinterpret a remote result as transport failure or retry it.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
