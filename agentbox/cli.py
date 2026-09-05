"""Command line interface for AgentBox."""

from __future__ import annotations

import argparse
import asyncio
import re
from dataclasses import asdict, is_dataclass
from datetime import datetime
import json
import os
import subprocess
import sys
from collections.abc import Sequence
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import uuid4

from arnold.runtime.durable_ops import TypedResource

from agentbox.adapters import get_operation_adapter, list_operation_adapters
from agentbox.bootstrap import bootstrap as bootstrap_agentbox
from agentbox.config import AgentBoxConfigError, load_agentbox_config
from agentbox.credentials.backend import (
    CredentialBackendError,
    list_credentials,
    push_credential,
    push_guide,
    run_credential_tests,
)
from agentbox.doctor import checkup
from agentbox.notify import notify_test
from agentbox.operations import (
    AgentBoxOperationError,
    load_agentbox_operation,
    open_operation_store,
)
from agentbox.operation_views import (
    logs_view,
    print_log_entries,
    resource_session_name,
    single_process_session_resource,
    status_view,
)
from agentbox.guardian.service import GuardianService
from agentbox.cleanup import apply_cleanup, survey_cleanup
from agentbox.reconcile import reconcile
from agentbox.reset_notifications import list_reset_notifications, reset_notification_root
from agentbox.run_dirs import run_dir_paths
from agentbox.services import list_services, restart_service, service_logs
from agentbox.tmux import attach_argv, inspect_session
from agentbox.version import agentbox_version


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentbox",
        description="AgentBox host provider CLI.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Write stable JSON output.",
    )
    subparsers = parser.add_subparsers(dest="command")

    run = subparsers.add_parser("run", help="Run a registered AgentBox operation adapter.")
    run.add_argument("--repo", required=True, help="Registered AgentBox repository name.")
    run.add_argument(
        "--kind",
        required=True,
        choices=[adapter.kind for adapter in list_operation_adapters()],
        help="Registered operation adapter kind.",
    )
    run.add_argument("--spec", required=True, help="Operation spec path.")
    run.add_argument("--operation-id")
    run.add_argument("--json", action="store_true", help="Write stable JSON output.")

    status = subparsers.add_parser("status", help="Show AgentBox host operation status.")
    status.add_argument("operation_id", nargs="?")
    status.add_argument("--json", action="store_true", help="Write stable JSON output.")

    logs = subparsers.add_parser("logs", help="Show bounded AgentBox host logs.")
    logs.add_argument("operation_id")
    logs.add_argument("--lines", type=_positive_int, default=100)
    logs.add_argument("--stream", choices=("stdout", "stderr", "all"), default="all")
    logs.add_argument("--json", action="store_true", help="Write stable JSON output.")

    attach = subparsers.add_parser("attach", help="Attach to a live AgentBox host session.")
    attach.add_argument("operation_id")

    reconcile_parser = subparsers.add_parser(
        "reconcile",
        help="Report AgentBox host-local state without mutating it.",
    )
    reconcile_parser.add_argument("--json", action="store_true", help="Write stable JSON output.")

    cleanup_parser = subparsers.add_parser(
        "cleanup",
        help="Survey and apply AgentBox cleanup recommendations.",
    )
    cleanup_subparsers = cleanup_parser.add_subparsers(dest="cleanup_command")
    cleanup_survey = cleanup_subparsers.add_parser(
        "survey",
        help="Report cleanup findings without mutating state.",
    )
    cleanup_survey.add_argument("--json", action="store_true", help="Write stable JSON output.")
    cleanup_apply = cleanup_subparsers.add_parser(
        "apply",
        help="Apply a cleanup action to a surveyed finding.",
    )
    cleanup_apply.add_argument("--finding", required=True, help="Finding ID from survey.")
    cleanup_apply.add_argument(
        "--action",
        required=True,
        choices=("land", "delete", "park", "reset"),
        help="Cleanup action to apply.",
    )
    cleanup_apply.add_argument("--confirm-request-id", help="Pending confirmation request ID.")
    cleanup_apply.add_argument("--confirm-phrase", help="Exact confirmation phrase.")
    cleanup_apply.add_argument("--json", action="store_true", help="Write stable JSON output.")

    guardian_parser = subparsers.add_parser(
        "guardian",
        help="Run or control the AgentBox Guardian worker.",
    )
    guardian_subparsers = guardian_parser.add_subparsers(dest="guardian_command")

    for name, help_text in (
        ("run-once", "Run a single Guardian tick and exit."),
        ("pause", "Pause the Guardian without touching operations or leases."),
        ("resume", "Resume the Guardian worker."),
    ):
        sub = guardian_subparsers.add_parser(name, help=help_text)
        sub.add_argument("--json", action="store_true", help="Write stable JSON output.")

    run_parser = guardian_subparsers.add_parser(
        "run",
        help="Run the Guardian worker loop until interrupted.",
    )
    run_parser.add_argument(
        "--poll-interval",
        type=float,
        default=60.0,
        help="Seconds between ticks.",
    )
    run_parser.add_argument("--json", action="store_true", help="Write stable JSON output.")

    status_parser = guardian_subparsers.add_parser(
        "status",
        help="Show Guardian status.",
    )
    status_parser.add_argument("--json", action="store_true", help="Write stable JSON output.")

    creds_parser = subparsers.add_parser("creds", help="Manage AgentBox host credentials.")
    creds_subparsers = creds_parser.add_subparsers(dest="creds_command")

    creds_list = creds_subparsers.add_parser("list", help="List credential names and status.")
    creds_list.add_argument("--json", action="store_true", help="Write stable JSON output.")

    creds_test = creds_subparsers.add_parser("test", help="Run health checks on credentials.")
    creds_test.add_argument("name", nargs="?", help="Credential name to test (default: all).")
    creds_test.add_argument("--json", action="store_true", help="Write stable JSON output.")

    creds_push = creds_subparsers.add_parser("push", help="Push a credential to the host.")
    creds_push.add_argument("name", help="Credential name or 'guide'.")
    creds_push.add_argument("--json", action="store_true", help="Write stable JSON output.")

    bootstrap_parser = subparsers.add_parser(
        "bootstrap",
        help="Ensure the AgentBox workspace layout and systemd units exist.",
    )
    bootstrap_parser.add_argument("--json", action="store_true", help="Write stable JSON output.")

    doctor_parser = subparsers.add_parser(
        "doctor",
        help="Run read-only health checks for the AgentBox host.",
    )
    doctor_parser.add_argument("--json", action="store_true", help="Write stable JSON output.")
    doctor_parser.add_argument(
        "--onboard",
        action="store_true",
        help="Run the interactive first-run provider onboarding flow.",
    )

    services_parser = subparsers.add_parser(
        "services",
        help="List, inspect, or restart AgentBox systemd services.",
    )
    services_subparsers = services_parser.add_subparsers(dest="services_command")

    services_list = services_subparsers.add_parser("list", help="List known services.")
    services_list.add_argument("--json", action="store_true", help="Write stable JSON output.")

    services_logs = services_subparsers.add_parser("logs", help="Show service logs.")
    services_logs.add_argument("service", help="Service name.")
    services_logs.add_argument("--lines", type=_positive_int, default=50)
    services_logs.add_argument("--json", action="store_true", help="Write stable JSON output.")

    services_restart = services_subparsers.add_parser(
        "restart",
        help="Restart a service through its guarded local supervisor.",
    )
    services_restart.add_argument("service", help="Service name.")
    services_restart.add_argument("--json", action="store_true", help="Write stable JSON output.")

    services_notifications = services_subparsers.add_parser(
        "reset-notifications",
        help="Show durable Discord resident reset-confirmation delivery state.",
    )
    services_notifications.add_argument("--limit", type=_positive_int, default=20)
    services_notifications.add_argument("--json", action="store_true", help="Write stable JSON output.")

    notify_parser = subparsers.add_parser(
        "notify",
        help="Test AgentBox resident notifications.",
    )
    notify_subparsers = notify_parser.add_subparsers(dest="notify_command")

    notify_test_parser = notify_subparsers.add_parser(
        "test",
        help="Send a test notification through Discord.",
    )
    notify_test_parser.add_argument("--conversation-key", help="Target conversation key.")
    notify_test_parser.add_argument("--dm-user-id", help="Target DM user id.")
    notify_test_parser.add_argument("--json", action="store_true", help="Write stable JSON output.")

    version_parser = subparsers.add_parser("version", help="Show AgentBox version.")
    version_parser.add_argument("--json", action="store_true", help="Write stable JSON output.")

    install_parser = subparsers.add_parser(
        "install-omp-agent",
        help="Install a packaged omp agent definition into ~/.omp/agent/agents.",
    )
    install_parser.add_argument(
        "template_name",
        help="Packaged source agent name (e.g. 'arnold').",
    )
    install_parser.add_argument(
        "--name",
        dest="output_name",
        help="Override the installed filename and frontmatter name.",
    )
    install_parser.add_argument(
        "--description",
        help="Override the installed frontmatter description.",
    )
    install_parser.add_argument(
        "--target",
        help="Target agents directory (default ~/.omp/agent/agents).",
    )
    install_parser.add_argument("--json", action="store_true", help="Write stable JSON output.")
    resident_parser = subparsers.add_parser(
        "new-resident",
        help="Create a five-file Discord resident scaffold in another repository.",
    )
    resident_parser.add_argument("name", help="Resident name.")
    resident_parser.add_argument("--repo", required=True, help="Target repository root.")
    resident_parser.add_argument("--description", help="Resident prompt description.")
    resident_parser.add_argument("--json", action="store_true", help="Write stable JSON output.")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 1
    if args.command is None:
        return 0

    json_output = bool(getattr(args, "json", False))
    try:
        config = load_agentbox_config()
        if args.command == "run":
            return _run(
                config,
                repo_name=args.repo,
                kind=args.kind,
                spec_path=args.spec,
                operation_id=args.operation_id,
                json_output=json_output,
            )
        if args.command == "status":
            return _status(config, args.operation_id, json_output=json_output)
        if args.command == "logs":
            return _logs(
                config,
                args.operation_id,
                lines=args.lines,
                stream=args.stream,
                json_output=json_output,
            )
        if args.command == "attach":
            return _attach(config, args.operation_id)
        if args.command == "reconcile":
            return _reconcile(config, json_output=json_output)
        if args.command == "cleanup":
            return _cleanup(config, args, json_output=json_output)
        if args.command == "guardian":
            return _guardian(config, args, json_output=json_output)
        if args.command == "creds":
            return _creds(config, args, json_output=json_output)
        if args.command == "bootstrap":
            return _bootstrap(config, json_output=json_output)
        if args.command == "doctor":
            if getattr(args, "onboard", False):
                from agentbox.onboarding.flow import run_flow

                return run_flow().exit_code
            return _doctor(config, json_output=json_output)
        if args.command == "services":
            return _services(config, args, json_output=json_output)
        if args.command == "notify":
            return _notify(config, args, json_output=json_output)
        if args.command == "version":
            return _version(json_output=json_output)
        if args.command == "install-omp-agent":
            return _install_omp_agent(args, json_output=json_output)
        if args.command == "new-resident":
            return _new_resident(args, json_output=json_output)
    except (AgentBoxConfigError, AgentBoxOperationError, CredentialBackendError, FileNotFoundError, ValueError) as exc:
        return _diagnostic(str(exc), json_output=json_output)
    return _diagnostic(f"unknown command: {args.command}", json_output=json_output)


def _run(
    config: Any,
    *,
    repo_name: str,
    kind: str,
    spec_path: str,
    operation_id: str | None,
    json_output: bool,
) -> int:
    operation_id = operation_id or _new_operation_id(kind)
    try:
        registration = get_operation_adapter(kind)
    except KeyError as exc:
        return _diagnostic(str(exc), json_output=json_output)

    handler = registration.load()
    try:
        result = handler.launch(
            config,
            operation_id,
            repo_name=repo_name,
            spec_path=Path(spec_path),
        )
    except Exception as exc:
        payload = _run_error_payload(
            config,
            operation_id,
            kind=kind,
            operation_type=registration.operation_type,
            exc=exc,
        )
        _emit(payload, json_output=json_output)
        return 1

    payload = _run_result_payload(
        config,
        operation_id,
        kind=kind,
        operation_type=registration.operation_type,
        result=result,
        handler=handler,
    )
    _emit(payload, json_output=json_output)
    return 0


def _status(config: Any, operation_id: str | None, *, json_output: bool) -> int:
    _emit(status_view(config, operation_id), json_output=json_output)
    return 0


def _logs(
    config: Any,
    operation_id: str,
    *,
    lines: int,
    stream: str,
    json_output: bool,
) -> int:
    payload = logs_view(config, operation_id, lines=lines, stream=stream)
    if json_output:
        _emit(payload, json_output=True)
    else:
        print_log_entries(payload["logs"])
    return 0


def _attach(config: Any, operation_id: str) -> int:
    load_agentbox_operation(config, operation_id)
    session_resource = single_process_session_resource(config, operation_id)
    if session_resource is None:
        return _diagnostic(
            f"operation {operation_id!r} has no recorded process-session resource; run `agentbox reconcile`",
            json_output=False,
        )

    session_name = resource_session_name(session_resource)
    if not session_name:
        return _diagnostic(
            f"operation {operation_id!r} has a process-session resource without a session name",
            json_output=False,
        )

    status = inspect_session(session_name)
    if not status.exists:
        detail = f": {status.detail}" if status.detail else ""
        return _diagnostic(
            f"session {session_name!r} is {status.state}{detail}; run `agentbox reconcile`",
            json_output=False,
        )

    return subprocess.run(attach_argv(session_name), check=False).returncode


def _reconcile(config: Any, *, json_output: bool) -> int:
    report = reconcile(config).to_dict()
    _emit(report, json_output=json_output)
    return 0


def _cleanup(config: Any, args: argparse.Namespace, *, json_output: bool) -> int:
    command = getattr(args, "cleanup_command", None)
    if command is None:
        return _diagnostic("cleanup subcommand required", json_output=json_output)
    if command == "survey":
        report = survey_cleanup(config)
        _emit(report.to_dict(), json_output=json_output)
        return 0
    if command == "apply":
        import importlib

        auth_module = importlib.import_module("arnold_pipelines.megaplan.resident.auth")
        config_module = importlib.import_module("arnold_pipelines.megaplan.resident.config")
        ConfirmationManager = auth_module.ConfirmationManager
        AuthorizationSubject = auth_module.AuthorizationSubject
        ResidentConfig = config_module.ResidentConfig

        manager = ConfirmationManager(ResidentConfig())
        subject = AuthorizationSubject(user_id="agentbox-cli")
        result = apply_cleanup(
            config,
            args.finding,
            args.action,
            confirmation_request_id=args.confirm_request_id,
            confirmation_phrase=args.confirm_phrase,
            confirmation_manager=manager,
            subject=subject,
        )
        if result.get("confirmation_required") and not args.confirm_request_id:
            if json_output:
                _emit(result, json_output=True)
            else:
                print(
                    f"Confirmation required. Run again with --confirm-request-id "
                    f"{result['request_id']} --confirm-phrase {result['exact_phrase']!r}"
                )
            return 0
        _emit(result, json_output=json_output)
        return 0 if result.get("ok") else 1
    return _diagnostic(f"unknown cleanup command: {command}", json_output=json_output)


def _creds(config: Any, args: argparse.Namespace, *, json_output: bool) -> int:
    command = getattr(args, "creds_command", None)
    if command is None:
        return _diagnostic("creds subcommand required", json_output=json_output)
    if command == "list":
        records = list_credentials(config)
        payload = [
            {
                "name": record.name,
                "provider": record.provider,
                "present": record.present,
                "pushed": record.pushed,
                "test_status": record.test_status,
                "last_tested": record.last_tested,
            }
            for record in records
        ]
        _emit(payload, json_output=json_output)
        return 0
    if command == "test":
        names = [args.name] if args.name else None
        results = run_credential_tests(config, names=names)
        _emit(results, json_output=json_output)
        return 0
    if command == "push":
        if args.name == "guide":
            guide = push_guide(config)
            _emit(guide, json_output=json_output)
            return 0
        record = push_credential(config, args.name)
        _emit(
            {
                "name": record.name,
                "provider": record.provider,
                "pushed": record.pushed,
                "destination": record.destination,
                "status": "pushed",
            },
            json_output=json_output,
        )
        return 0
    return _diagnostic(f"unknown creds command: {command}", json_output=json_output)


def _bootstrap(config: Any, *, json_output: bool) -> int:
    result = bootstrap_agentbox(config)
    _emit(result, json_output=json_output)
    return 0


def _doctor(config: Any, *, json_output: bool) -> int:
    report = checkup(config)
    _emit(report.to_dict(), json_output=json_output)
    return 0 if report.ok else 1


def _services(config: Any, args: argparse.Namespace, *, json_output: bool) -> int:
    command = getattr(args, "services_command", None)
    if command is None:
        return _diagnostic("services subcommand required", json_output=json_output)
    if command == "list":
        _emit(list_services(), json_output=json_output)
        return 0
    if command == "logs":
        _emit(service_logs(args.service, lines=args.lines), json_output=json_output)
        return 0
    if command == "restart":
        result = restart_service(
            args.service,
            notification_root=reset_notification_root(config.workspace_root),
        )
        _emit(result, json_output=json_output)
        return 0 if result.get("ok") else 1
    if command == "reset-notifications":
        _emit(
            list_reset_notifications(
                notification_root=reset_notification_root(config.workspace_root),
                limit=args.limit,
            ),
            json_output=json_output,
        )
        return 0
    return _diagnostic(f"unknown services command: {command}", json_output=json_output)


def _notify(config: Any, args: argparse.Namespace, *, json_output: bool) -> int:
    command = getattr(args, "notify_command", None)
    if command is None:
        return _diagnostic("notify subcommand required", json_output=json_output)
    if command == "test":
        result = notify_test(
            config,
            conversation_key=args.conversation_key,
            dm_user_id=args.dm_user_id,
        )
        _emit(result, json_output=json_output)
        return 0 if result.get("ok") else 1
    return _diagnostic(f"unknown notify command: {command}", json_output=json_output)


def _version(*, json_output: bool) -> int:
    _emit(agentbox_version(), json_output=json_output)
    return 0


def _packaged_omp_agent_path(name: str) -> Path:
    return Path(__file__).resolve().parent / "agents" / f"{name}.md"


_FRONTMATTER_DELIMITER = re.compile(r"^---[ \t]*\r?(?:\n|$)", re.MULTILINE)


def _split_frontmatter(text: str) -> tuple[str, str] | None:
    """Split a leading YAML frontmatter block into (frontmatter, body).

    Delimiters must be whole lines, so a ``---`` inside a quoted scalar stays
    content. Returns None when there is no well-formed frontmatter block.
    """
    opening = _FRONTMATTER_DELIMITER.match(text)
    if opening is None:
        return None
    close = _FRONTMATTER_DELIMITER.search(text, opening.end())
    if close is None:
        return None
    return text[opening.end() : close.start()], text[close.end() :]


def _agent_frontmatter_name(text: str) -> str | None:
    split = _split_frontmatter(text)
    if split is None:
        return None
    frontmatter, _body = split
    for line in frontmatter.splitlines():
        stripped = line.strip()
        if stripped.startswith("name:"):
            value = stripped[len("name:"):].strip().strip("\"'")
            return value or None
    return None


_AGENT_NAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")


def _valid_agent_name(name: str) -> bool:
    return name not in {".", ".."} and bool(_AGENT_NAME_PATTERN.fullmatch(name))


def _frontmatter_scalar(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


_YAML_AMBIGUOUS_PLAIN_NAMES = frozenset(
    {"y", "n", "yes", "no", "true", "false", "on", "off", "null", "none"}
)


def _frontmatter_name_scalar(name: str) -> str:
    """Render an agent name as a frontmatter scalar a YAML parser reads back verbatim."""
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", name) and name.lower() not in _YAML_AMBIGUOUS_PLAIN_NAMES:
        return name
    return _frontmatter_scalar(name)


def _rewrite_agent_frontmatter(
    text: str,
    *,
    name: str | None,
    description: str | None,
) -> str:
    if name is None and description is None:
        return text
    split = _split_frontmatter(text)
    if split is None:
        raise ValueError("agent file has no YAML frontmatter to rewrite")
    frontmatter, body = split
    lines = frontmatter.splitlines(keepends=True)
    found_description = False
    rewritten: list[str] = []
    for index, line in enumerate(lines):
        content = line.rstrip("\r\n")
        newline = line[len(content):]
        key, separator, source_value = content.partition(":")
        if separator and key.strip() == "name" and name is not None:
            line = f"name: {_frontmatter_name_scalar(name)}{newline}"
        elif separator and key.strip() == "description" and description is not None:
            if source_value.strip().startswith((">", "|")) or (
                index + 1 < len(lines)
                and lines[index + 1].strip()
                and lines[index + 1][0].isspace()
            ):
                raise ValueError(
                    "description override requires a single-line frontmatter scalar"
                )
            line = f"description: {_frontmatter_scalar(description)}{newline}"
            found_description = True
        rewritten.append(line)
    if description is not None and not found_description:
        rewritten.append(f"description: {_frontmatter_scalar(description)}\n")
    return "---\n" + "".join(rewritten) + "---\n" + body


def _install_omp_agent(args: argparse.Namespace, *, json_output: bool) -> int:
    template_name = args.template_name
    output_name = args.output_name if args.output_name is not None else template_name
    for label, name in (("template", template_name), ("output", output_name)):
        if not _valid_agent_name(name):
            return _diagnostic(
                f"invalid {label} agent name {name!r}; use only ASCII letters, numbers, '.', '_' and '-'",
                json_output=json_output,
            )
    source = _packaged_omp_agent_path(template_name)
    if not source.is_file():
        return _diagnostic(
            f"no packaged omp agent named {template_name!r} (expected {source})",
            json_output=json_output,
        )
    source_bytes = source.read_bytes()
    text = source_bytes.decode("utf-8")
    parsed_name = _agent_frontmatter_name(text)
    if parsed_name != template_name:
        return _diagnostic(
            f"frontmatter name mismatch: {parsed_name!r} != {template_name!r}",
            json_output=json_output,
        )
    installed_text = _rewrite_agent_frontmatter(
        text,
        name=output_name if args.output_name is not None else None,
        description=args.description,
    )
    if _agent_frontmatter_name(installed_text) != output_name:
        return _diagnostic(
            f"installed frontmatter name mismatch: {_agent_frontmatter_name(installed_text)!r} != {output_name!r}",
            json_output=json_output,
        )
    if args.target is not None and not args.target.strip():
        return _diagnostic(
            f"invalid target directory {args.target!r}; omit --target for the default",
            json_output=json_output,
        )
    target_dir = Path(args.target).expanduser() if args.target else Path.home() / ".omp" / "agent" / "agents"
    if target_dir.exists() and not target_dir.is_dir():
        return _diagnostic(
            f"target is not a directory: {target_dir}",
            json_output=json_output,
        )
    target = target_dir / f"{output_name}.md"
    if target.exists():
        return _diagnostic(
            f"target already exists: {target}",
            json_output=json_output,
        )
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(f".{output_name}.md.tmp-{uuid4().hex[:8]}")
        try:
            tmp.write_bytes(installed_text.encode("utf-8"))
            os.link(tmp, target, follow_symlinks=False)
        except FileExistsError:
            return _diagnostic(
                f"target already exists: {target}",
                json_output=json_output,
            )
        finally:
            tmp.unlink(missing_ok=True)
    except OSError as exc:
        return _diagnostic(
            f"failed to install omp agent: {exc}",
            json_output=json_output,
        )
    _emit(
        {
            "agent": output_name,
            "source": str(source),
            "target": str(target),
            "installed": True,
        },
        json_output=json_output,
    )
    return 0


def _resident_template_path(name: str) -> Path:
    return Path(__file__).resolve().parent / "templates" / "resident" / name


def _resident_pascal_name(name: str) -> str:
    parts = [part for part in re.split(r"[^A-Za-z0-9]+", name) if part]
    result = "".join(part[:1].upper() + part[1:] for part in parts)
    if not result or not result[0].isalpha():
        result = f"Resident{result}"
    return result


_PLACEHOLDER_PATTERN = re.compile(r"\{\{([A-Za-z0-9_]+)\}\}")


def _render_resident_template(path: Path, replacements: dict[str, str]) -> str:
    rendered = path.read_text(encoding="utf-8")
    return _PLACEHOLDER_PATTERN.sub(
        lambda match: replacements.get(match.group(1), match.group(0)),
        rendered,
    )


def _prune_empty_dirs(start: Path, stop: Path) -> None:
    """Remove `start` and its ancestors inside `stop` while they are empty."""
    directory = start
    while directory != stop and directory.is_relative_to(stop):
        try:
            directory.rmdir()
        except OSError:
            return
        directory = directory.parent


def _new_resident(args: argparse.Namespace, *, json_output: bool) -> int:
    name = args.name
    if not _valid_agent_name(name):
        return _diagnostic(
            f"invalid resident name {name!r}; use only ASCII letters, numbers, '.', '_' and '-'",
            json_output=json_output,
        )

    if not args.repo.strip():
        return _diagnostic(
            f"invalid repository directory {args.repo!r}",
            json_output=json_output,
        )
    repo = Path(args.repo).expanduser().resolve()
    if not repo.is_dir():
        if repo.exists() or repo.is_symlink():
            return _diagnostic(f"repository is not a directory: {repo}", json_output=json_output)
        return _diagnostic(
            f"repository directory does not exist: {repo}", json_output=json_output
        )

    description = (
        args.description if args.description is not None else f"Resident operator ({name})"
    )
    pascal_name = _resident_pascal_name(name)
    replacements = {
        "NAME": name,
        "NAME_SCALAR": _frontmatter_name_scalar(name),
        "PASCAL_NAME": pascal_name,
        "DESCRIPTION": _frontmatter_scalar(description),
        "REPO": str(repo),
    }
    destinations = [
        repo / ".omp" / "agents" / f"{name}.md",
        repo / ".agentbox" / "resident_profile.py",
        repo / ".agentbox" / "resident.env.example",
        repo / ".agentbox" / "run-resident",
        repo / ".agentbox" / f"{name}-resident.service",
    ]
    template_names = (
        "agent.md.tmpl",
        "resident_profile.py.tmpl",
        "resident.env.example.tmpl",
        "run-resident.tmpl",
        "service.tmpl",
    )

    rendered = [
        (destination, _render_resident_template(_resident_template_path(template), replacements))
        for destination, template in zip(destinations, template_names)
    ]
    # Frontmatter name follows the same YAML-safe scalar convention as
    # install-omp-agent (quoted when a parser would misread it).
    agent_destination, agent_text = rendered[0]
    rendered[0] = (
        agent_destination,
        _rewrite_agent_frontmatter(agent_text, name=name, description=None),
    )
    collisions = [path for path in destinations if path.exists() or path.is_symlink()]
    if collisions:
        return _diagnostic(
            f"resident destination already exists: {collisions[0]}",
            json_output=json_output,
        )

    temporary: list[Path] = []
    created: list[Path] = []
    try:
        for destination, content in rendered:
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary_path = destination.with_name(
                f".{destination.name}.tmp-{uuid4().hex}"
            )
            temporary.append(temporary_path)
            temporary_path.write_text(content, encoding="utf-8")
            if destination.name == "run-resident":
                temporary_path.chmod(0o755)
        for temporary_path, destination in zip(temporary, destinations):
            os.link(temporary_path, destination, follow_symlinks=False)
            created.append(destination)
    except OSError as exc:
        for temporary_path in temporary:
            temporary_path.unlink(missing_ok=True)
        for destination in created:
            destination.unlink(missing_ok=True)
        for destination in destinations:
            _prune_empty_dirs(destination.parent, repo)
        return _diagnostic(
            f"failed to create resident scaffold: {exc}",
            json_output=json_output,
        )
    finally:
        for temporary_path in temporary:
            temporary_path.unlink(missing_ok=True)

    _emit(
        {
            "name": name,
            "repo": str(repo),
            "files": [str(path) for path in destinations],
            "created": True,
        },
        json_output=json_output,
    )
    return 0




def _guardian(config: Any, args: argparse.Namespace, *, json_output: bool) -> int:
    service = GuardianService.default(config)
    command = getattr(args, "guardian_command", None)
    if command is None:
        return _diagnostic("guardian subcommand required", json_output=json_output)
    if command == "run-once":
        result = asyncio.run(service.run_once())
        _emit(result, json_output=json_output)
        return 0
    if command == "run":
        service.poll_interval_seconds = getattr(args, "poll_interval", 60.0)
        try:
            asyncio.run(service.run_forever())
        except KeyboardInterrupt:
            pass
        return 0
    if command == "pause":
        result = service.pause()
        _emit(result, json_output=json_output)
        return 0
    if command == "resume":
        result = service.resume()
        _emit(result, json_output=json_output)
        return 0
    if command == "status":
        result = service.status()
        _emit(result, json_output=json_output)
        return 0
    return _diagnostic(f"unknown guardian command: {command}", json_output=json_output)


def _run_result_payload(
    config: Any,
    operation_id: str,
    *,
    kind: str,
    operation_type: str,
    result: Any,
    handler: Any,
) -> dict[str, Any]:
    run = load_agentbox_operation(config, operation_id, operation_types=(operation_type,))
    resources = open_operation_store(config).list_typed_resources(operation_id)
    paths = run_dir_paths(config, operation_id)
    diagnostics = _result_diagnostics(result)
    classification = _handler_classification(config, operation_id, handler, diagnostics)
    return {
        "operation_id": operation_id,
        "kind": kind,
        "operation_type": run.operation_type,
        "operation_state": run.state.value,
        "launch_state": run.metadata.get("launch_state") or getattr(result, "launch_state", None),
        "run_dir": str(paths.root),
        "resources": _resource_payloads(resources),
        "resolved_spec_path": _resolved_spec_path(result, run.metadata),
        "validation": run.metadata.get("validation"),
        "classification": classification,
        "diagnostics": diagnostics,
    }


def _run_error_payload(
    config: Any,
    operation_id: str,
    *,
    kind: str,
    operation_type: str,
    exc: Exception,
) -> dict[str, Any]:
    run = None
    resources: tuple[TypedResource, ...] = ()
    try:
        run = load_agentbox_operation(config, operation_id, operation_types=(operation_type,))
        resources = open_operation_store(config).list_typed_resources(operation_id)
    except Exception:
        pass

    paths = run_dir_paths(config, operation_id)
    diagnostics = _exception_diagnostics(exc)
    return {
        "operation_id": operation_id,
        "kind": kind,
        "operation_type": operation_type,
        "operation_state": run.state.value if run is not None else None,
        "launch_state": run.metadata.get("launch_state") if run is not None else None,
        "run_dir": str(paths.root),
        "resources": _resource_payloads(resources),
        "resolved_spec_path": (
            str(run.metadata.get("resolved_spec_path"))
            if run is not None and run.metadata.get("resolved_spec_path")
            else None
        ),
        "validation": run.metadata.get("validation") if run is not None else None,
        "classification": run.metadata.get("chain_status") if run is not None else None,
        "diagnostics": diagnostics,
        "error": str(exc),
    }


def _handler_classification(
    config: Any,
    operation_id: str,
    handler: Any,
    diagnostics: dict[str, Any] | None,
) -> dict[str, Any] | None:
    status = getattr(handler, "status", None)
    if not callable(status):
        return None
    try:
        snapshot = status(config, operation_id)
    except Exception as exc:
        if diagnostics is not None:
            diagnostics["classification"] = {
                "kind": type(exc).__name__,
                "message": str(exc),
            }
        return None
    classification = getattr(snapshot, "classification", None)
    to_dict = getattr(classification, "to_dict", None)
    if callable(to_dict):
        return to_dict()
    return _jsonable(classification) if classification is not None else None


def _result_diagnostics(result: Any) -> dict[str, Any] | None:
    host_result = getattr(result, "host_result", None)
    diagnostics = getattr(host_result, "diagnostics", None)
    return dict(diagnostics) if isinstance(diagnostics, dict) else _jsonable(diagnostics)


def _exception_diagnostics(exc: Exception) -> dict[str, Any]:
    diagnostics = getattr(exc, "diagnostics", None)
    if isinstance(diagnostics, dict):
        return dict(diagnostics)
    return {"kind": getattr(exc, "kind", type(exc).__name__), "message": str(exc)}


def _resolved_spec_path(result: Any, metadata: dict[str, Any]) -> str | None:
    value = getattr(result, "resolved_spec_path", None) or metadata.get("resolved_spec_path")
    return str(value) if value else None


def _resource_payloads(resources: Sequence[TypedResource]) -> list[dict[str, Any]]:
    return [
        {
            "id": resource.id,
            "type": resource.resource_type.value,
            "name": resource.name,
            "details": dict(resource.details),
        }
        for resource in resources
    ]


def _emit(payload: Any, *, json_output: bool) -> None:
    if json_output:
        print(json.dumps(_jsonable(payload), indent=2, sort_keys=True))
    else:
        print(json.dumps(_jsonable(payload), indent=2, sort_keys=True))


def _diagnostic(message: str, *, json_output: bool) -> int:
    if json_output:
        _emit({"error": message}, json_output=True)
    else:
        print(f"agentbox: {message}", file=sys.stderr)
    return 1


def _jsonable(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return _jsonable(asdict(value))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be >= 0")
    return parsed


def _new_operation_id(kind: str) -> str:
    return f"{kind}-{uuid4().hex[:12]}"


__all__ = ["build_parser", "main"]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
