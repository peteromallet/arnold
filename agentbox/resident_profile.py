"""AgentBox-owned resident Operator profile for Discord."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from importlib import import_module
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse
from uuid import uuid4

from pydantic import BaseModel, Field

from agentbox.adapters import load_operation_adapter
from agentbox.config import AgentBoxConfig, load_agentbox_config
from agentbox.operation_resolver import OperationResolveResult, resolve_operation
from agentbox.operation_views import logs_view, status_view
from agentbox.operations import list_agentbox_operations, load_agentbox_operation
from arnold_pipelines.megaplan.resident.timezone import (
    TimezoneService,
    add_localized_timestamp_fields,
)

AGENTBOX_OPERATOR_PROMPT_VERSION = "agentbox-operator-v1"
MEGAPLAN_CHAIN_OPERATION_TYPE = "megaplan_chain"
SUBAGENT_SYSTEM_PROMPT = (
    "You are a one-shot subagent dispatched by the AgentBox Operator to investigate "
    "a focused question or check on something. Use the available tools (such as "
    "search_messages, status, logs, resolve) to gather facts, then return a concise "
    "final answer for the operator to use. You cannot satisfy confirmation challenges, "
    "so avoid tools that require confirmation. Do not attempt to spawn further subagents."
)
AGENTBOX_OPERATOR_TOOL_NAMES = (
    "ticket_new",
    "chain_launch",
    "status",
    "logs",
    "help",
    "resolve",
    "cleanup_survey",
    "cleanup_apply",
    "search_messages",
    "read_reply_chain",
    "subagent",
)


class TicketNewInput(BaseModel):
    title: str
    body: str = ""
    tags: list[str] = Field(default_factory=list)
    repo: str | None = None
    codebase_id: str | None = None


class ChainLaunchInput(BaseModel):
    repo: str
    spec: str
    operation_id: str | None = None
    base_ref: str | None = None
    confirmation_request_id: str | None = None
    confirmation_phrase: str | None = None


class StatusInput(BaseModel):
    operation: str | None = None


class LogsInput(BaseModel):
    operation: str
    stream: Literal["stdout", "stderr", "all"] = "all"
    lines: int = Field(default=80, gt=0, le=200)


class ResolveInput(BaseModel):
    kind: Literal["operation", "repo", "ticket"] = "operation"
    query: str


class HelpInput(BaseModel):
    pass


class CleanupSurveyInput(BaseModel):
    operation: str | None = None


class CleanupApplyInput(BaseModel):
    finding_id: str
    action: Literal["land", "delete", "park", "reset"]
    confirmation_request_id: str | None = None
    confirmation_phrase: str | None = None


class SearchMessagesInput(BaseModel):
    query: str = ""
    limit: int = Field(default=10, gt=0, le=50)


class ReadReplyChainInput(BaseModel):
    source_message_id: str | None = None
    cursor: str | None = None
    limit: int = Field(default=5, gt=0, le=10)


class SubagentInput(BaseModel):
    prompt: str
    model: str | None = None
    max_tool_calls: int | None = Field(default=None, gt=0, le=8)


@dataclass
class AgentBoxOperatorProfile:
    """Discord-first profile exposing the AgentBox Operator v0 tool catalog."""

    store: Any | None = None
    authorizer: Any | None = None
    config: Any = field(default_factory=lambda: _resident_symbol("config", "ResidentConfig")())
    confirmation_manager: Any | None = None
    agentbox_config_factory: Callable[[], AgentBoxConfig] = load_agentbox_config
    tool_registry: Any = field(default_factory=lambda: _resident_symbol("tool_registry", "ToolRegistry")())
    _registered_default_tools: bool = False

    def __post_init__(self) -> None:
        if not self._registered_default_tools:
            self._register_default_tools()
            self._registered_default_tools = True

    def system_prompt(self) -> str:
        return (
            "You are the AgentBox Operator for Discord. Keep responses concise, "
            "include operation ids whenever an operation is involved, inspect "
            "ambiguous machine state before asking, and ask exactly one concrete "
            "clarifying question when intent or target state is ambiguous. Up to three "
            "exact Discord reply ancestors are preloaded nearest-first. Never infer reply "
            "ancestry from recent messages; use `read_reply_chain` with the supplied cursor "
            "when older ancestors remain. Hot context's `user_timezone` is the presentation "
            "authority: render absolute user-visible times from deterministic `*_local` fields, "
            "keep stored/control-plane timestamps in UTC, and preserve relative durations."
        )

    async def load_hot_context(self, conversation_id: str) -> dict[str, Any]:
        base: dict[str, Any] = {
            "conversation_id": conversation_id,
            "prompt_version": AGENTBOX_OPERATOR_PROMPT_VERSION,
            "profile": "agentbox_operator",
        }
        conversation = self.store.load_resident_conversation(conversation_id) if self.store is not None else None
        if conversation is not None:
            base["conversation"] = conversation.model_dump(mode="json")
            context = self.store.load_hot_context(conversation.active_epic_id)
            base["recent_messages"] = [
                row.model_dump(mode="json") for row in context.recent_messages[:5]
            ]
            base["recent_tool_calls"] = [
                row.model_dump(mode="json") for row in context.recent_tool_calls[:5]
            ]
        else:
            base["recent_messages"] = []
            base["recent_tool_calls"] = []

        if self.confirmation_manager is not None:
            base["pending_confirmations"] = [
                _confirmation_context(row) for row in self.confirmation_manager.pending()[:5]
            ]
        else:
            base["pending_confirmations"] = []

        try:
            agentbox_config = self.agentbox_config_factory()
            operations = list_agentbox_operations(agentbox_config)[:5]
            base["recent_operations"] = [
                _operation_context(agentbox_config, operation.id) for operation in operations
            ]
        except Exception as exc:
            base["recent_operations"] = []
            base["agentbox_context_error"] = f"{exc.__class__.__name__}: {exc}"
        subject_user_id = None
        if conversation is not None:
            subject_user_id = str(
                conversation.metadata.get("last_subject_user_id")
                or conversation.dm_user_id
                or ""
            ) or None
        resolved = TimezoneService(self.store, self.config).resolve(
            user_id=subject_user_id,
            conversation=conversation,
            guild_id=(conversation.guild_id if conversation is not None else None),
        )
        base["user_timezone"] = resolved.hot_context()
        return add_localized_timestamp_fields(base, resolved.name)

    def tools(self) -> Any:
        return self.tool_registry

    def _register_default_tools(self) -> None:
        ToolRegistration = _resident_symbol("tool_registry", "ToolRegistration")
        ToolResult = _resident_symbol("tool_schemas", "ToolResult")
        registrations = (
            ToolRegistration("ticket_new", "Create a tracked AgentBox ticket.", "write", TicketNewInput, ToolResult, self._ticket_new),
            ToolRegistration("chain_launch", "Launch a Megaplan chain through AgentBox.", "cloud_start", ChainLaunchInput, ToolResult, self._chain_launch),
            ToolRegistration("status", "Inspect AgentBox operation status.", "read", StatusInput, ToolResult, self._status),
            ToolRegistration("logs", "Read bounded AgentBox operation logs.", "read", LogsInput, ToolResult, self._logs),
            ToolRegistration("help", "List AgentBox Operator v0 capabilities.", "read", HelpInput, ToolResult, self._help),
            ToolRegistration("resolve", "Resolve an AgentBox operation reference.", "read", ResolveInput, ToolResult, self._resolve),
            ToolRegistration("cleanup_survey", "Survey AgentBox resources and classify cleanup recommendations.", "read", CleanupSurveyInput, ToolResult, self._cleanup_survey),
            ToolRegistration("cleanup_apply", "Apply a cleanup action to a surveyed finding.", "reconcile_apply", CleanupApplyInput, ToolResult, self._cleanup_apply),
            ToolRegistration("search_messages", "Search earlier messages in this conversation.", "read", SearchMessagesInput, ToolResult, self._search_messages),
            ToolRegistration("read_reply_chain", "Read bounded, store-backed Discord reply ancestry inside this conversation.", "read", ReadReplyChainInput, ToolResult, self._read_reply_chain),
            ToolRegistration("subagent", "Dispatch a one-shot subagent on a configurable model to investigate and report back inline.", "read", SubagentInput, ToolResult, self._subagent),
        )
        for registration in registrations:
            self.tool_registry.register(registration)

    def _help(self, payload: HelpInput) -> Any:
        ToolResult = _resident_symbol("tool_schemas", "ToolResult")
        return ToolResult(
            ok=True,
            message="AgentBox Operator v0 tools are available.",
            data=_tool_payload(
                action="help",
                next_state="choose_v0_tool",
                tools=[
                    {
                        "name": "ticket_new",
                        "capability": "create a tracked AgentBox ticket",
                        "required_fields": ["title"],
                        "optional_fields": ["body", "tags", "repo", "codebase_id"],
                    },
                    {
                        "name": "chain_launch",
                        "capability": "launch a Megaplan chain through AgentBox",
                        "required_fields": ["repo", "spec"],
                        "optional_fields": [
                            "operation_id",
                            "base_ref",
                            "confirmation_request_id",
                            "confirmation_phrase",
                        ],
                    },
                    {
                        "name": "status",
                        "capability": "inspect AgentBox operation status",
                        "required_fields": [],
                        "optional_fields": ["operation"],
                    },
                    {
                        "name": "logs",
                        "capability": "read bounded AgentBox operation logs",
                        "required_fields": ["operation"],
                        "optional_fields": ["stream", "lines"],
                    },
                    {
                        "name": "help",
                        "capability": "list AgentBox Operator v0 tool capabilities",
                        "required_fields": [],
                        "optional_fields": [],
                    },
                    {
                        "name": "resolve",
                        "capability": "resolve operation, repo, or ticket references without side effects",
                        "required_fields": ["query"],
                        "optional_fields": ["kind"],
                    },
                ],
            ),
        )

    def _status(self, payload: StatusInput) -> Any:
        ToolResult = _resident_symbol("tool_schemas", "ToolResult")
        agentbox_config = self.agentbox_config_factory()
        if not payload.operation:
            return ToolResult(
                ok=True,
                message="operation status",
                data=_tool_payload(
                    action="status",
                    next_state="inspected_operations",
                    status=status_view(agentbox_config),
                ),
            )
        resolved = resolve_operation(agentbox_config, payload.operation)
        if unresolved := _unresolved_operation_result(
            resolved,
            action="status",
            message="operation status needs clarification",
        ):
            return unresolved
        assert resolved.operation is not None
        operation_id = resolved.operation.operation_id
        return ToolResult(
            ok=True,
            message=f"operation status: {operation_id}",
            data=_tool_payload(
                action="status",
                operation_id=operation_id,
                next_state="inspected_operation",
                resolve=resolved.to_dict(),
                status=status_view(agentbox_config, operation_id),
            ),
        )

    def _logs(self, payload: LogsInput) -> Any:
        ToolResult = _resident_symbol("tool_schemas", "ToolResult")
        agentbox_config = self.agentbox_config_factory()
        resolved = resolve_operation(agentbox_config, payload.operation)
        if unresolved := _unresolved_operation_result(
            resolved,
            action="logs",
            message="operation logs need clarification",
        ):
            return unresolved
        assert resolved.operation is not None
        operation_id = resolved.operation.operation_id
        return ToolResult(
            ok=True,
            message=f"operation logs: {operation_id}",
            data=_tool_payload(
                action="logs",
                operation_id=operation_id,
                next_state="inspected_logs",
                resolve=resolved.to_dict(),
                logs=logs_view(
                    agentbox_config,
                    operation_id,
                    lines=payload.lines,
                    stream=payload.stream,
                ),
            ),
        )

    def _resolve(self, payload: ResolveInput) -> Any:
        ToolResult = _resident_symbol("tool_schemas", "ToolResult")
        resolved = self._resolve_reference(payload.kind, payload.query)
        entity = resolved.get(payload.kind)
        entity_id = entity.get("operation_id") if payload.kind == "operation" and entity else None
        ticket_id = entity.get("ticket_id") if payload.kind == "ticket" and entity else None
        return ToolResult(
            ok=resolved["status"] == "single",
            message=_resolve_message(payload.kind, resolved),
            data=_tool_payload(
                action="resolve",
                operation_id=entity_id,
                ticket_id=ticket_id,
                next_state=_resolve_next_state(resolved),
                resolve=resolved,
            ),
        )

    def _ticket_new(self, payload: TicketNewInput) -> Any:
        ToolResult = _resident_symbol("tool_schemas", "ToolResult")
        if self.store is None:
            return ToolResult(
                ok=False,
                message="AgentBox ticket_new requires a Store.",
                data={"profile": "agentbox_operator", "error": "store_required"},
            )
        subject = _runtime_subject()
        if subject is None:
            return ToolResult(
                ok=False,
                message="ticket_new requires an authorized runtime subject.",
                data={"profile": "agentbox_operator", "error": "runtime_subject_required"},
            )
        if denied := self._authorization_denied(subject, "write"):
            return denied
        codebase = _resolve_ticket_codebase(self.store, payload)
        if codebase is None:
            return ToolResult(
                ok=False,
                message="codebase not found",
                data={"codebase_id": payload.codebase_id, "repo": payload.repo},
            )
        slug = _ticket_slug(payload.title)
        try:
            ticket = self.store.create_ticket(
                codebase_id=codebase.id,
                title=payload.title,
                body=payload.body,
                source="discord",
                tags=list(payload.tags or []),
                filed_by_actor_id=subject.user_id,
                slug=slug,
            )
        except Exception as exc:
            return ToolResult(
                ok=False,
                message=str(exc),
                data={"error": exc.__class__.__name__},
            )
        return ToolResult(
            ok=True,
            message=f"ticket created: {ticket.id}",
            data=_tool_payload(
                action="ticket_new",
                ticket_id=ticket.id,
                next_state="ticket_open",
                ticket={
                    "id": ticket.id,
                    "title": ticket.title,
                    "status": ticket.status,
                    "codebase_id": ticket.codebase_id,
                    "slug": ticket.slug,
                    "tags": list(ticket.tags or []),
                    "filed_by_actor_id": ticket.filed_by_actor_id,
                },
            ),
        )

    def _chain_launch(self, payload: ChainLaunchInput) -> Any:
        ToolResult = _resident_symbol("tool_schemas", "ToolResult")
        subject = _runtime_subject()
        if subject is None:
            return ToolResult(
                ok=False,
                message="chain_launch requires an authorized runtime subject.",
                data={"profile": "agentbox_operator", "error": "runtime_subject_required"},
            )
        if denied := self._authorization_denied(subject, "cloud_start"):
            return denied
        if confirm := self._require_confirmation(
            subject=subject,
            action="cloud_start",
            tool_name="chain_launch",
            target_summary=_chain_launch_target_summary(payload),
            request_id=payload.confirmation_request_id,
            phrase=payload.confirmation_phrase,
        ):
            return confirm

        agentbox_config = self.agentbox_config_factory()
        operation_id = (payload.operation_id or "").strip() or _new_chain_operation_id()
        handler = load_operation_adapter(MEGAPLAN_CHAIN_OPERATION_TYPE)
        guardian_notification_metadata = self._guardian_notification_metadata()
        try:
            result = handler.launch(
                agentbox_config,
                operation_id,
                repo_name=payload.repo,
                spec_path=Path(payload.spec),
                base_ref=payload.base_ref,
                metadata=guardian_notification_metadata,
            )
        except Exception as exc:
            return ToolResult(
                ok=False,
                message=str(exc),
                data=_tool_payload(
                    action="chain_launch",
                    next_state="launch_failed",
                    **_chain_launch_payload(
                        agentbox_config,
                        operation_id,
                        repo=payload.repo,
                        result=None,
                        diagnostics=_exception_diagnostics(exc),
                    ),
                ),
            )
        return ToolResult(
            ok=True,
            message=(
                f"chain launched: {operation_id}"
                if getattr(result, "launch_state", None) in {"accepted", "replay"}
                else f"chain launch outcome: {getattr(result, 'launch_state', 'unknown')}"
            ),
            data=_tool_payload(
                action="chain_launch",
                next_state=_chain_launch_next_state(result),
                **_chain_launch_payload(
                    agentbox_config,
                    operation_id,
                    repo=payload.repo,
                    result=result,
                    diagnostics=_result_diagnostics(result),
                ),
            ),
            )

    def _cleanup_survey(self, payload: CleanupSurveyInput) -> Any:
        ToolResult = _resident_symbol("tool_schemas", "ToolResult")
        agentbox_config = self.agentbox_config_factory()
        from agentbox.cleanup import survey_cleanup

        report = survey_cleanup(agentbox_config)
        return ToolResult(
            ok=True,
            message="cleanup survey complete",
            data=_tool_payload(
                action="cleanup_survey",
                next_state="cleanup_surveyed",
                findings=report.to_dict()["findings"],
            ),
        )

    def _cleanup_apply(self, payload: CleanupApplyInput) -> Any:
        ToolResult = _resident_symbol("tool_schemas", "ToolResult")
        subject = _runtime_subject()
        if subject is None:
            return ToolResult(
                ok=False,
                message="cleanup_apply requires an authorized runtime subject.",
                data={"profile": "agentbox_operator", "error": "runtime_subject_required"},
            )
        if denied := self._authorization_denied(subject, "reconcile_apply"):
            return denied

        target_summary = f"{payload.action} {payload.finding_id}"
        destructive_actions = {"delete", "reset", "merge"}
        if payload.action in destructive_actions:
            if confirm := self._require_confirmation(
                subject=subject,
                action="reconcile_apply",
                tool_name="cleanup_apply",
                target_summary=target_summary,
                request_id=payload.confirmation_request_id,
                phrase=payload.confirmation_phrase,
            ):
                return confirm

        agentbox_config = self.agentbox_config_factory()
        from agentbox.cleanup import apply_cleanup

        result = apply_cleanup(
            agentbox_config,
            payload.finding_id,
            payload.action,
            confirmation_request_id=payload.confirmation_request_id,
            confirmation_phrase=payload.confirmation_phrase,
            confirmation_manager=None,
            subject=subject,
        )
        return ToolResult(
            ok=result.get("ok", False),
            message=result.get("error") or f"cleanup {payload.action}: {payload.finding_id}",
            data=_tool_payload(
                action="cleanup_apply",
                finding_id=payload.finding_id,
                next_state="cleanup_applied" if result.get("ok") else "cleanup_failed",
                result=result,
            ),
        )

    def _search_messages(self, payload: SearchMessagesInput) -> Any:
        ToolResult = _resident_symbol("tool_schemas", "ToolResult")
        subject = _runtime_subject()
        if subject is None:
            return ToolResult(
                ok=False,
                message="search_messages requires an authorized runtime subject.",
                data={"profile": "agentbox_operator", "error": "runtime_subject_required"},
            )
        if denied := self._authorization_denied(subject, "read"):
            return denied
        runtime_context = _runtime_context()
        conversation_id = getattr(runtime_context, "conversation_id", None)
        if self.store is None or not conversation_id:
            return ToolResult(
                ok=False,
                message="search_messages requires a store and an active conversation.",
                data={"profile": "agentbox_operator", "error": "conversation_required"},
            )
        rows = self.store.search_messages(query=payload.query, epic_id=None, limit=payload.limit)
        rows = [row for row in rows if row.conversation_id == conversation_id][:payload.limit]
        return ToolResult(
            ok=True,
            message=f"{len(rows)} messages",
            data=_tool_payload(
                action="search_messages",
                next_state="messages_searched",
                count=len(rows),
                limit=payload.limit,
                messages=[_message_hit_payload(row) for row in rows],
            ),
        )

    def _read_reply_chain(self, payload: ReadReplyChainInput) -> Any:
        ToolResult = _resident_symbol("tool_schemas", "ToolResult")
        subject = _runtime_subject()
        if subject is None:
            return ToolResult(
                ok=False,
                message="read_reply_chain requires an authorized runtime subject.",
                data={"profile": "agentbox_operator", "error": "runtime_subject_required"},
            )
        if denied := self._authorization_denied(subject, "read"):
            return denied
        context = _runtime_context()
        conversation_id = getattr(context, "conversation_id", None)
        if self.store is None or not conversation_id:
            return ToolResult(
                ok=False,
                message="read_reply_chain requires a store and active conversation.",
                data={"profile": "agentbox_operator", "error": "conversation_required"},
            )
        from arnold_pipelines.megaplan.resident.reply_chain import (
            decode_reply_cursor,
            reply_chain_page,
        )

        cursor_source = None
        offset = 0
        if payload.cursor:
            try:
                cursor_source, offset = decode_reply_cursor(payload.cursor)
            except ValueError as exc:
                return ToolResult(
                    ok=False,
                    message=str(exc),
                    data={"profile": "agentbox_operator", "error": "invalid_cursor"},
                )
        requested = (payload.source_message_id or "").strip() or cursor_source
        launch_origin = getattr(context, "launch_origin", None)
        if requested is None and isinstance(launch_origin, dict):
            requested = str(
                launch_origin.get("source_record_id")
                or launch_origin.get("discord_message_id")
                or ""
            ).strip() or None
        if requested is None:
            return ToolResult(
                ok=False,
                message="source_message_id is required when the current source is ambiguous.",
                data={"profile": "agentbox_operator", "error": "source_message_required"},
            )
        message = self.store.load_message(requested)
        if message is not None and message.conversation_id != conversation_id:
            return ToolResult(
                ok=False,
                message="reply-chain source is outside the active conversation.",
                data={"profile": "agentbox_operator", "error": "cross_conversation_rejected"},
            )
        if message is None:
            message = self.store.find_conversation_message_by_discord_id(
                conversation_id, requested
            )
        if message is None:
            return ToolResult(
                ok=False,
                message="reply-chain source was not found in the active conversation.",
                data={"profile": "agentbox_operator", "error": "source_not_found"},
            )
        if cursor_source is not None and cursor_source != message.id:
            return ToolResult(
                ok=False,
                message="cursor does not belong to the requested source message.",
                data={"profile": "agentbox_operator", "error": "cursor_source_mismatch"},
            )
        return ToolResult(
            ok=True,
            message="reply ancestry read",
            data=_tool_payload(
                action="read_reply_chain",
                next_state="reply_ancestry_read",
                **reply_chain_page(message, offset=offset, limit=payload.limit),
            ),
        )

    def _build_subagent_registry(self) -> Any:
        """Subagent tool catalog: the full registry minus the subagent tool (no recursion)."""
        ToolRegistry = _resident_symbol("tool_registry", "ToolRegistry")
        registry = ToolRegistry()
        for registration in self.tool_registry.list():
            if registration.name == "subagent":
                continue
            registry.register(registration)
        return registry

    def _resolve_subagent_model(self, payload: SubagentInput) -> tuple[str, Any | None]:
        ToolResult = _resident_symbol("tool_schemas", "ToolResult")
        chosen = (payload.model or "").strip() or self.config.subagent_model_name
        if (
            payload.model
            and chosen != self.config.subagent_model_name
            and chosen not in self.config.subagent_models
        ):
            error = ToolResult(
                ok=False,
                message="requested subagent model is not in the allowlist",
                data=_tool_payload(
                    action="subagent",
                    next_state="model_not_allowed",
                    allowed=list(self.config.subagent_models),
                    default=self.config.subagent_model_name,
                    requested=chosen,
                ),
            )
            return chosen, error
        return chosen, None

    def _build_subagent_runner(self, chosen: str, sub_config: Any, max_calls: int) -> tuple[Any, str]:
        """Resolve the subagent model client and build the one-shot runner. Override in tests."""
        OpenAICompatibleAgentRunner = _resident_symbol("agent_loop", "OpenAICompatibleAgentRunner")
        _client_for_model = _resident_symbol("agent_loop", "_client_for_model")
        client, normalized = _client_for_model(chosen)
        runner = OpenAICompatibleAgentRunner(
            sub_config,
            client_override=client,
            model_override=normalized,
            max_tool_calls=max_calls,
        )
        return runner, normalized

    async def _subagent(self, payload: SubagentInput) -> Any:
        ToolResult = _resident_symbol("tool_schemas", "ToolResult")
        subject = _runtime_subject()
        if subject is None:
            return ToolResult(
                ok=False,
                message="subagent requires an authorized runtime subject.",
                data={"profile": "agentbox_operator", "error": "runtime_subject_required"},
            )
        if denied := self._authorization_denied(subject, "read"):
            return denied
        chosen, model_error = self._resolve_subagent_model(payload)
        if model_error is not None:
            return model_error
        max_calls = payload.max_tool_calls or self.config.subagent_max_tool_calls
        sub_registry = self._build_subagent_registry()
        sub_config = self.config.model_copy(
            update={"model_name": chosen, "max_tool_calls_per_turn": max_calls}
        )
        try:
            runner, normalized = self._build_subagent_runner(chosen, sub_config, max_calls)
        except Exception as exc:
            return ToolResult(
                ok=False,
                message=f"subagent setup failed: {exc}",
                data={"profile": "agentbox_operator", "model": chosen, "error": exc.__class__.__name__},
            )
        runtime_context = _runtime_context()
        AgentRequest = _resident_symbol("agent_loop", "AgentRequest")
        request = AgentRequest(
            conversation_id=getattr(runtime_context, "conversation_id", None) or "",
            messages=({"role": "user", "content": payload.prompt},),
            system_prompt=SUBAGENT_SYSTEM_PROMPT,
            subject=subject,
        )
        _per_call_timeout = self.config.model_timeout_s or 120.0
        timeout = _per_call_timeout * (max_calls + 1)
        try:
            response = await asyncio.wait_for(runner.run(request, sub_registry), timeout=timeout)
        except asyncio.TimeoutError:
            return ToolResult(
                ok=False,
                message=f"subagent timed out after {timeout:g}s",
                data={"profile": "agentbox_operator", "model": normalized},
            )
        except Exception as exc:
            return ToolResult(
                ok=False,
                message=str(exc),
                data={"profile": "agentbox_operator", "model": normalized, "error": exc.__class__.__name__},
            )
        return ToolResult(
            ok=True,
            message="subagent complete",
            data=_tool_payload(
                action="subagent",
                next_state="subagent_complete",
                final_text=response.final_text,
                model=normalized,
                inner_tool_calls=[record.model_dump(mode="json") for record in response.tool_calls],
            ),
        )

    def _guardian_notification_metadata(self) -> dict[str, Any]:
        runtime_context = _runtime_context()
        conversation_id = getattr(runtime_context, "conversation_id", None)
        if not conversation_id:
            return {
                "guardian_notifications_disabled": True,
                "guardian_notifications_disabled_reason": "runtime_conversation_id_missing",
            }
        metadata: dict[str, Any] = {
            "guardian_notification_conversation_id": conversation_id,
        }
        if self.store is None:
            metadata.update(
                {
                    "guardian_notifications_disabled": True,
                    "guardian_notifications_disabled_reason": "resident_store_unavailable",
                }
            )
            return metadata
        conversation = self.store.load_resident_conversation(conversation_id)
        if conversation is None:
            metadata.update(
                {
                    "guardian_notifications_disabled": True,
                    "guardian_notifications_disabled_reason": "resident_conversation_not_found",
                }
            )
            return metadata
        metadata.update(
            {
                "guardian_notification_conversation_key": conversation.conversation_key,
                "guardian_notifications_disabled": False,
            }
        )
        return metadata

    def _resolve_reference(self, kind: str, query: str) -> dict[str, Any]:
        if kind == "operation":
            return resolve_operation(self.agentbox_config_factory(), query).to_dict()
        if kind == "repo":
            return _resolve_repo(self.store, query)
        if kind == "ticket":
            return _resolve_ticket(self.store, query)
        return {
            "status": "no_match",
            "kind": kind,
            "query": query,
            kind: None,
            "candidates": [],
            "question": f"Resolve kind {kind!r} is not supported.",
        }

    def _require_confirmation(
        self,
        *,
        subject: Any,
        action: str,
        tool_name: str,
        target_summary: str,
        request_id: str | None,
        phrase: str | None,
    ) -> Any | None:
        ToolResult = _resident_symbol("tool_schemas", "ToolResult")
        manager = self.confirmation_manager
        if manager is None or not manager.required_for(action):
            return None
        if not request_id or not phrase:
            request = manager.request_confirmation(
                subject=subject,
                action=action,
                target_summary=target_summary,
                metadata={"tool": tool_name, "profile": "agentbox_operator"},
            )
            return ToolResult(
                ok=False,
                message="confirmation required",
                data={
                    "confirmation_required": True,
                    "request_id": request.id,
                    "exact_phrase": request.exact_phrase,
                    "expires_at": request.expires_at.isoformat().replace("+00:00", "Z"),
                    "target_summary": target_summary,
                },
            )
        decision = manager.confirm(request_id=request_id, subject=subject, phrase=phrase)
        if not decision.allowed:
            return ToolResult(
                ok=False,
                message=f"confirmation {decision.status}: {decision.reason}",
                data={"confirmation_required": True, "request_id": request_id, "reason": decision.reason},
            )
        return None

    def _authorization_denied(self, subject: Any, action: str) -> Any | None:
        if self.authorizer is None:
            return None
        decision = self.authorizer.authorize_action(subject, action)
        if decision.allowed:
            return None
        ToolResult = _resident_symbol("tool_schemas", "ToolResult")
        return ToolResult(
            ok=False,
            message=f"authorization denied: {decision.reason}",
            data={"authorization_denied": True, "reason": decision.reason, "audit": decision.audit},
        )

    def _not_implemented(self, payload: BaseModel) -> Any:
        ToolResult = _resident_symbol("tool_schemas", "ToolResult")
        return ToolResult(
            ok=False,
            message="This AgentBox Operator tool is registered for M4 but implemented in a later task.",
            data={"profile": "agentbox_operator"},
        )


def _unresolved_operation_result(
    resolved: OperationResolveResult,
    *,
    action: str,
    message: str,
) -> Any | None:
    if resolved.operation is not None:
        return None
    ToolResult = _resident_symbol("tool_schemas", "ToolResult")
    return ToolResult(
        ok=False,
        message=resolved.question or message,
        data=_tool_payload(
            action=action,
            next_state=_resolve_next_state(resolved.to_dict()),
            resolve=resolved.to_dict(),
        ),
    )


def _tool_payload(
    *,
    action: str,
    next_state: str,
    operation_id: str | None = None,
    ticket_id: str | None = None,
    **fields: Any,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "profile": "agentbox_operator",
        "action": action,
        "next_state": next_state,
    }
    if operation_id is not None:
        payload["operation_id"] = operation_id
    if ticket_id is not None:
        payload["ticket_id"] = ticket_id
    payload.update(fields)
    return payload


def _message_hit_payload(row: Any) -> dict[str, Any]:
    direction = getattr(row, "direction", None)
    return {
        "id": row.id,
        "direction": str(getattr(direction, "value", direction)),
        "content": row.content,
        "sent_at": row.sent_at.isoformat().replace("+00:00", "Z") if row.sent_at else None,
        "snippet": getattr(row, "snippet", None),
    }


def _resolve_next_state(resolved: dict[str, Any]) -> str:
    status = resolved.get("status")
    if status == "single":
        return "resolved"
    if status == "ambiguous":
        return "needs_clarification"
    return "not_found"


def _resolve_message(kind: str, resolved: dict[str, Any]) -> str:
    entity = resolved.get(kind)
    if kind == "operation" and entity:
        return str(entity["operation_id"])
    if kind == "repo" and entity:
        return str(entity["repo"])
    if kind == "ticket" and entity:
        return str(entity["ticket_id"])
    return str(resolved.get("question") or f"No {kind} matched.")


def _resolve_repo(store: Any | None, query: str, *, limit: int = 5) -> dict[str, Any]:
    base = _empty_resolve("repo", query)
    if store is None:
        base["question"] = "Repo resolution requires a Store."
        return base
    normalized = _normalize_reference(query)
    if not normalized:
        base["question"] = "Which repo should I resolve?"
        return base

    codebases = list(store.list_codebases())
    exact = [
        row
        for row in codebases
        if normalized in {
            _normalize_reference(row.id),
            _normalize_reference(f"{row.owner}/{row.name}"),
        }
    ]
    candidates = exact or [
        row
        for row in codebases
        if _repo_match(row, normalized)
    ]
    candidates = sorted(candidates, key=lambda row: (row.owner, row.name, row.id))
    candidate_payloads = [_repo_candidate(row) for row in candidates[:limit]]
    return _resolve_payload(
        "repo",
        query,
        candidate_payloads,
        question=_repo_question(query, candidate_payloads),
    )


def _resolve_ticket(store: Any | None, query: str, *, limit: int = 5) -> dict[str, Any]:
    base = _empty_resolve("ticket", query)
    if store is None:
        base["question"] = "Ticket resolution requires a Store."
        return base
    normalized = _normalize_reference(query)
    if not normalized:
        base["question"] = "Which ticket should I resolve?"
        return base

    tickets = list(store.list_tickets(limit=None))
    exact = [
        row
        for row in tickets
        if normalized in {
            _normalize_reference(row.id),
            _normalize_reference(row.slug),
        }
    ]
    candidates = exact or [
        row
        for row in tickets
        if _ticket_match(row, normalized)
    ]
    candidates = sorted(candidates, key=lambda row: (row.slug, row.title, row.id))
    candidate_payloads = [_ticket_candidate(row) for row in candidates[:limit]]
    return _resolve_payload(
        "ticket",
        query,
        candidate_payloads,
        question=_ticket_question(query, candidate_payloads),
    )


def _resolve_payload(
    kind: str,
    query: str,
    candidates: list[dict[str, Any]],
    *,
    question: str,
) -> dict[str, Any]:
    if not candidates:
        payload = _empty_resolve(kind, query)
        payload["question"] = question
        return payload
    if len(candidates) == 1:
        return {
            "status": "single",
            "kind": kind,
            "query": query,
            kind: candidates[0],
            "candidates": [],
            "question": None,
        }
    return {
        "status": "ambiguous",
        "kind": kind,
        "query": query,
        kind: None,
        "candidates": candidates,
        "question": question,
    }


def _empty_resolve(kind: str, query: str) -> dict[str, Any]:
    return {
        "status": "no_match",
        "kind": kind,
        "query": query,
        kind: None,
        "candidates": [],
        "question": f"No {kind} matched {query!r}.",
    }


def _repo_candidate(row: Any) -> dict[str, Any]:
    return {
        "codebase_id": row.id,
        "repo": f"{row.owner}/{row.name}",
        "owner": row.owner,
        "name": row.name,
        "default_branch": row.default_branch,
    }


def _ticket_candidate(row: Any) -> dict[str, Any]:
    return {
        "ticket_id": row.id,
        "title": row.title,
        "status": row.status,
        "slug": row.slug,
        "codebase_id": row.codebase_id,
    }


def _repo_match(row: Any, normalized: str) -> bool:
    values = (
        row.id,
        row.owner,
        row.name,
        f"{row.owner}/{row.name}",
        row.repo_url,
        row.repo_workspace,
        row.associated_epic_id,
    )
    return any(normalized in _normalize_reference(str(value)) for value in values if value)


def _ticket_match(row: Any, normalized: str) -> bool:
    values = (row.id, row.slug, row.title, row.body, row.status, row.codebase_id, *row.tags)
    return any(normalized in _normalize_reference(str(value)) for value in values if value)


def _repo_question(query: str, candidates: list[dict[str, Any]]) -> str:
    if not candidates:
        return f"No AgentBox repo matched {query!r}. Which repo should I use?"
    repos = ", ".join(str(row["repo"]) for row in candidates[:3])
    return f"Which repo did you mean: {repos}?"


def _ticket_question(query: str, candidates: list[dict[str, Any]]) -> str:
    if not candidates:
        return f"No AgentBox ticket matched {query!r}. Which ticket id should I use?"
    tickets = ", ".join(str(row["ticket_id"]) for row in candidates[:3])
    return f"Which ticket did you mean: {tickets}?"


def _normalize_reference(value: str) -> str:
    return " ".join(value.lower().strip().split())


def _operation_context(config: AgentBoxConfig, operation_id: str) -> dict[str, Any]:
    status = status_view(config, operation_id)
    assert isinstance(status, dict)
    log_summary = logs_view(config, operation_id, lines=5, stream="all")
    return {
        "status": {
            key: status.get(key)
            for key in (
                "operation_id",
                "operation_type",
                "operation_state",
                "launch_state",
                "repo_names",
                "run_dir_exists",
                "session",
            )
        },
        "logs": [
            {
                "stream": entry.get("stream"),
                "exists": entry.get("exists"),
                "requested_lines": entry.get("requested_lines"),
                "returned_lines": entry.get("returned_lines"),
                "truncated": entry.get("truncated"),
                "source": entry.get("source"),
            }
            for entry in log_summary.get("logs", [])
        ],
    }


def _runtime_subject() -> Any | None:
    runtime_context = _runtime_context()
    return getattr(runtime_context, "subject", None)


def _runtime_context() -> Any | None:
    return _resident_symbol("agent_loop", "current_tool_runtime_context")()


def _chain_launch_target_summary(payload: ChainLaunchInput) -> str:
    return f"{payload.repo} {payload.spec}".strip()


def _chain_launch_next_state(result: Any) -> str:
    """Project the durable launch result without inventing a running state."""

    state = getattr(result, "launch_state", None)
    if state in {"accepted", "replay"}:
        return "operation_running"
    if state == "rejected":
        return "launch_rejected"
    return "operation_unknown"


def _new_chain_operation_id() -> str:
    return f"chain-{uuid4().hex[:12]}"


def _chain_launch_payload(
    config: AgentBoxConfig,
    operation_id: str,
    *,
    repo: str,
    result: Any | None,
    diagnostics: dict[str, Any],
) -> dict[str, Any]:
    run = None
    try:
        run = load_agentbox_operation(
            config,
            operation_id,
            operation_types=(MEGAPLAN_CHAIN_OPERATION_TYPE,),
        )
    except Exception:
        pass
    metadata = run.metadata if run is not None else {}
    resolved_spec = getattr(result, "resolved_spec_path", None) or metadata.get("resolved_spec_path")
    return {
        "operation_id": getattr(result, "operation_id", operation_id),
        "operation_type": run.operation_type if run is not None else MEGAPLAN_CHAIN_OPERATION_TYPE,
        "operation_state": run.state.value if run is not None else None,
        "launch_state": metadata.get("launch_state") or getattr(result, "launch_state", None),
        "repo": repo,
        "resolved_spec_path": str(resolved_spec) if resolved_spec else None,
        "validation": metadata.get("validation"),
        "diagnostics": diagnostics,
    }


def _result_diagnostics(result: Any | None) -> dict[str, Any]:
    if result is None:
        return {}
    host_result = getattr(result, "host_result", None)
    diagnostics = getattr(host_result, "diagnostics", None)
    return dict(diagnostics or {})


def _exception_diagnostics(exc: Exception) -> dict[str, Any]:
    diagnostics = getattr(exc, "diagnostics", None)
    if isinstance(diagnostics, dict):
        return dict(diagnostics)
    return {
        "kind": getattr(exc, "kind", exc.__class__.__name__),
        "message": str(exc),
    }


def _confirmation_context(request: Any) -> dict[str, Any]:
    return {
        "id": request.id,
        "action": request.action,
        "target_summary": request.target_summary,
        "expires_at": request.expires_at.isoformat().replace("+00:00", "Z"),
    }


def _resolve_ticket_codebase(store: Any, payload: TicketNewInput) -> Any | None:
    if payload.codebase_id:
        return store.load_codebase(payload.codebase_id)
    repo = (payload.repo or "").strip()
    if not repo:
        return None
    owner_name = _repo_owner_name(repo)
    if owner_name is None:
        return None
    owner, name = owner_name
    return store.find_codebase(owner.lower(), name.lower())


def _repo_owner_name(repo: str) -> tuple[str, str] | None:
    candidate = repo.removesuffix(".git").strip("/")
    if "://" in candidate:
        parsed = urlparse(candidate)
        parts = [part for part in parsed.path.strip("/").split("/") if part]
    elif candidate.startswith("git@") and ":" in candidate:
        parts = [part for part in candidate.split(":", 1)[1].strip("/").split("/") if part]
    else:
        parts = [part for part in candidate.split("/") if part]
    if len(parts) < 2:
        return None
    return parts[-2], parts[-1]


def _ticket_slug(title: str) -> str:
    return import_module("arnold_pipelines.megaplan.tickets.files").slugify(title)


def _resident_symbol(module_name: str, symbol_name: str) -> Any:
    module = import_module(f"arnold_pipelines.megaplan.resident.{module_name}")
    return getattr(module, symbol_name)


__all__ = [
    "AGENTBOX_OPERATOR_PROMPT_VERSION",
    "AGENTBOX_OPERATOR_TOOL_NAMES",
    "AgentBoxOperatorProfile",
    "ChainLaunchInput",
    "CleanupApplyInput",
    "CleanupSurveyInput",
    "HelpInput",
    "LogsInput",
    "ResolveInput",
    "SearchMessagesInput",
    "StatusInput",
    "SubagentInput",
    "TicketNewInput",
]
