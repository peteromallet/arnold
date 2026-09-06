from __future__ import annotations

import pytest

from arnold.agent import (
    AgentRequest,
    AgentResult,
    AgentSpec,
    ArnoldDispatcher,
    BackendAdapter,
    FanoutUnit,
    format_agent_spec,
    parse_agent_spec,
    scatter_agent_units,
)


def test_agent_spec_round_trips_premium_and_provider_specs() -> None:
    assert parse_agent_spec("claude:low") == AgentSpec("claude", effort="low")
    assert parse_agent_spec("codex:gpt-5.3-codex:high") == AgentSpec(
        "codex",
        model="gpt-5.3-codex",
        effort="high",
    )
    omp_spec = parse_agent_spec("omp:fireworks/accounts/foo")
    assert omp_spec == AgentSpec("omp", model="fireworks/accounts/foo")
    assert format_agent_spec(omp_spec) == "omp:fireworks/accounts/foo"


def test_invalid_premium_spec_fails_closed() -> None:
    with pytest.raises(ValueError):
        parse_agent_spec("claude:gpt-5.3-codex")


def test_dispatcher_routes_to_registered_adapter() -> None:
    dispatcher = ArnoldDispatcher()

    def adapter(request: AgentRequest) -> AgentResult:
        return AgentResult(
            payload={"agent": request.agent, "prompt": request.prompt},
            raw_output="ok",
            duration_ms=5,
            cost_usd=0.0,
        )

    dispatcher.register("fake", adapter)
    result = dispatcher.dispatch(AgentRequest(agent="fake", mode="unit", prompt="hello"))

    assert result.payload == {"agent": "fake", "prompt": "hello"}
    assert result.tokens.total_tokens == 0
    assert result.cost.cost_usd == 0.0


def test_backend_adapter_protocol_accepts_function_adapter() -> None:
    def adapter(request: AgentRequest) -> AgentResult:
        return AgentResult(
            payload={"agent": request.agent},
            raw_output="ok",
            duration_ms=1,
            cost_usd=0.0,
        )

    assert isinstance(adapter, BackendAdapter)

    dispatcher = ArnoldDispatcher()
    dispatcher.register("fake", adapter)

    assert dispatcher.dispatch(AgentRequest(agent="fake", mode="unit")).payload == {
        "agent": "fake",
    }


def test_backend_adapter_protocol_accepts_class_adapter() -> None:
    class ClassAdapter:
        def __call__(self, request: AgentRequest) -> AgentResult:
            return AgentResult(
                payload={"mode": request.mode},
                raw_output="ok",
                duration_ms=1,
                cost_usd=0.0,
            )

    adapter = ClassAdapter()
    assert isinstance(adapter, BackendAdapter)

    dispatcher = ArnoldDispatcher()
    dispatcher.register("fake", adapter)

    assert dispatcher.dispatch(AgentRequest(agent="fake", mode="unit")).payload == {
        "mode": "unit",
    }


def test_dispatcher_unknown_agent_fails_closed() -> None:
    with pytest.raises(LookupError):
        ArnoldDispatcher().dispatch(AgentRequest(agent="missing", mode="unit"))


def test_scatter_agent_units_preserves_input_order() -> None:
    dispatcher = ArnoldDispatcher()

    def adapter(request: AgentRequest) -> AgentResult:
        return AgentResult(
            payload={"prompt": request.prompt},
            raw_output=request.prompt or "",
            duration_ms=1,
            cost_usd=1.5,
            prompt_tokens=2,
            completion_tokens=3,
            total_tokens=5,
        )

    dispatcher.register("fake", adapter)
    result = scatter_agent_units(
        units=[
            FanoutUnit(AgentRequest(agent="fake", mode="unit", prompt="first")),
            FanoutUnit(AgentRequest(agent="fake", mode="unit", prompt="second")),
        ],
        dispatcher=dispatcher,
        max_concurrent=2,
    )

    assert [item.raw_output for item in result.results] == ["first", "second"]
    assert result.cost_usd == 3.0
    assert result.total_tokens == 10
