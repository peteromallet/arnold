from __future__ import annotations

import pytest

from arnold.runtime.durable_ops import LaunchEnvelope
from arnold_pipelines.megaplan.cloud.providers import on_box


def _provider() -> on_box.OnBoxProvider:
    # The launch boundary is intentionally independent of the provider's
    # transport/spec fields; no shell or filesystem setup is needed here.
    return object.__new__(on_box.OnBoxProvider)


def _request() -> dict[str, object]:
    envelope = LaunchEnvelope(
        version=1,
        operation_id="operation-1",
        request_id="request-1",
        venue="cloud:ssh",
        launch_spec={},
        preflight_digest="preflight-digest",
    )
    return {
        "envelope": envelope.to_json()
    }


def _response(*, reason: str = "admitted", result: str = "ACCEPTED") -> dict[str, object]:
    return {
        "schema": "arnold.megaplan.cloud_launch_response.v1",
        "result": result,
        "reason": reason,
        "operation_id": "operation-1",
        "request_id": "request-1",
        "envelope_digest": LaunchEnvelope.from_json(_request()["envelope"]).digest,
    }


@pytest.mark.parametrize("reason", ["admitted", "replay"])
def test_on_box_calls_authoritative_engine_once_for_accept_and_replay(
    monkeypatch: pytest.MonkeyPatch, reason: str
) -> None:
    calls: list[dict[str, object]] = []
    response = _response(reason=reason)

    def execute(request: dict[str, object]) -> dict[str, object]:
        calls.append(request)
        return response

    monkeypatch.setattr(on_box.chain_drive, "execute_authoritative_launch", execute)
    monkeypatch.setattr(
        on_box.OnBoxProvider,
        "ssh_exec",
        lambda *_a, **_k: pytest.fail("ssh_exec called"),
    )
    monkeypatch.setattr(
        on_box.subprocess,
        "run",
        lambda *_a, **_k: pytest.fail("subprocess transport called"),
    )

    provider = _provider()
    assert provider.invoke_launch_engine(_request()) == response
    assert calls == [_request()]


def test_on_box_preserves_valid_unknown_without_redispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = {
        "schema": "arnold.megaplan.cloud_launch_response.v1",
        "result": "UNKNOWN",
        "reason": "dispatch_uncertain",
        "operation_id": "operation-1",
        "request_id": "request-1",
        "detail": "identity unavailable",
    }
    calls = 0

    def execute(_request: dict[str, object]) -> dict[str, object]:
        nonlocal calls
        calls += 1
        return response

    monkeypatch.setattr(on_box.chain_drive, "execute_authoritative_launch", execute)
    assert _provider().invoke_launch_engine(_request()) == response
    assert calls == 1


def test_on_box_converts_nonmapping_response_to_invoked_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def execute(_request: dict[str, object]) -> object:
        nonlocal calls
        calls += 1
        return ["not a response mapping"]

    monkeypatch.setattr(on_box.chain_drive, "execute_authoritative_launch", execute)
    result = _provider().invoke_launch_engine(_request())

    assert result["result"] == "UNKNOWN"
    assert result["invoked"] is True
    assert result["reason"] == "malformed_engine_response"
    assert calls == 1


def test_on_box_converts_exception_and_malformed_response_to_invoked_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def execute(_request: dict[str, object]) -> object:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("engine failed")
        return {"schema": "wrong", "result": "ACCEPTED"}

    monkeypatch.setattr(on_box.chain_drive, "execute_authoritative_launch", execute)
    first = _provider().invoke_launch_engine(_request())
    second = _provider().invoke_launch_engine(_request())

    assert first["result"] == "UNKNOWN"
    assert first["invoked"] is True
    assert first["reason"] == "engine_exception"
    assert second["result"] == "UNKNOWN"
    assert second["invoked"] is True
    assert second["reason"] == "malformed_engine_response"
    assert calls == 2


def test_on_box_rejects_accepted_identity_mismatch_without_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def execute(_request: dict[str, object]) -> dict[str, object]:
        nonlocal calls
        calls += 1
        return {**_response(), "operation_id": "other-operation"}

    monkeypatch.setattr(on_box.chain_drive, "execute_authoritative_launch", execute)
    result = _provider().invoke_launch_engine(_request())

    assert result["result"] == "UNKNOWN"
    assert result["invoked"] is True
    assert result["reason"] == "malformed_engine_response"
    assert calls == 1


@pytest.mark.parametrize("digest", [None, "wrong-digest", ""])
def test_on_box_rejects_missing_or_wrong_accepted_digest_without_retry(
    monkeypatch: pytest.MonkeyPatch, digest: str | None
) -> None:
    calls = 0

    def execute(_request: dict[str, object]) -> dict[str, object]:
        nonlocal calls
        calls += 1
        response = _response()
        if digest is None:
            response.pop("envelope_digest")
        else:
            response["envelope_digest"] = digest
        return response

    monkeypatch.setattr(on_box.chain_drive, "execute_authoritative_launch", execute)
    result = _provider().invoke_launch_engine(_request())

    assert result["result"] == "UNKNOWN"
    assert result["invoked"] is True
    assert result["reason"] == "malformed_engine_response"
    assert calls == 1


@pytest.mark.parametrize("result_value", ["ACCEPTED", "REJECTED", "UNKNOWN", "CONFLICT"])
@pytest.mark.parametrize("invalid_reason", [None, "", 42])
def test_on_box_rejects_invalid_reason_for_every_result(
    monkeypatch: pytest.MonkeyPatch,
    result_value: str,
    invalid_reason: object,
) -> None:
    calls = 0

    def execute(_request: dict[str, object]) -> dict[str, object]:
        nonlocal calls
        calls += 1
        response = _response(result=result_value)
        response["reason"] = invalid_reason
        return response

    monkeypatch.setattr(on_box.chain_drive, "execute_authoritative_launch", execute)
    result = _provider().invoke_launch_engine(_request())

    assert result["result"] == "UNKNOWN"
    assert result["invoked"] is True
    assert result["reason"] == "malformed_engine_response"
    assert calls == 1


def test_on_box_boundary_has_no_authoritative_store_override() -> None:
    assert "authoritative_store_root" not in on_box.OnBoxProvider.__dict__
