"""Tests for Step 13F: SSH remote mutation sink routing.

Covers:
- Three routed shards (build/deploy/destroy) go through WBC
- Action-off shards (down/ssh_exec/upload_file/upload_archive) not routed
- Provider-missing negatives (no host or container)
- Stale-fence negatives
- Fake-transport detection
- Default-deny gate contract: only an explicit AUTHORIZED verdict dispatches;
  a missing gate, SHADOW_PASS, or an exceptional gate makes zero protocol
  reservation and zero transport (apply_fn) calls
"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch

from arnold.workflow.effect_protocol import (
    EffectProtocol,
    OUTCOME_COMPLETED,
    OUTCOME_FAILED,
    OUTCOME_INDETERMINATE,
)
from arnold_pipelines.megaplan.cloud.ssh_effect_adapter import (
    SshEffectShard,
    SSH_SHARD_13F,
    SSH_ACTION_OFF_SHARDS,
    SshTarget,
    SshOutcome,
    SshEffectAdapter,
)
from arnold_pipelines.megaplan.custody.action_validator import (
    GateResult,
    adapter_effect_authorized,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def mock_protocol():
    """Create a mock EffectProtocol."""
    protocol = MagicMock(spec=EffectProtocol)
    reservation = MagicMock()
    reservation.global_logical_effect_key = "glek-ssh-123"
    protocol.reserve_and_start.return_value = reservation
    return protocol


@pytest.fixture
def adapter(mock_protocol):
    """Create an SshEffectAdapter with an explicit authorized gate."""
    return SshEffectAdapter(
        mock_protocol,
        action_gate_check=lambda _boundary, _target_key: GateResult.AUTHORIZED,
        production_enabled=False,
    )


@pytest.fixture
def gated_adapter_factory(mock_protocol):
    """Factory to build adapters with a chosen gate verdict/callable."""

    def build(gate_check):
        return SshEffectAdapter(
            mock_protocol,
            action_gate_check=gate_check,
            production_enabled=False,
        )

    return build


@pytest.fixture
def build_target():
    return SshTarget(
        shard=SshEffectShard.BUILD,
        host="example.com",
        container="arnold-app",
        operation="build",
    )


@pytest.fixture
def deploy_target():
    return SshTarget(
        shard=SshEffectShard.DEPLOY,
        host="example.com",
        container="arnold-app",
        operation="deploy",
    )


@pytest.fixture
def destroy_target():
    return SshTarget(
        shard=SshEffectShard.DESTROY,
        host="example.com",
        container="arnold-app",
        operation="destroy",
    )


# ── Shard enforcement ────────────────────────────────────────────────────────


def test_routed_shards_are_build_deploy_destroy():
    """Only BUILD, DEPLOY, DESTROY are in the 13F routed set."""
    assert set(SSH_SHARD_13F) == {
        SshEffectShard.BUILD,
        SshEffectShard.DEPLOY,
        SshEffectShard.DESTROY,
    }


def test_action_off_shards_not_routed():
    """down, ssh_exec, upload_file, upload_archive are action-off."""
    assert "down" in SSH_ACTION_OFF_SHARDS
    assert "ssh_exec" in SSH_ACTION_OFF_SHARDS
    assert "upload_file" in SSH_ACTION_OFF_SHARDS
    assert "upload_archive" in SSH_ACTION_OFF_SHARDS


def test_non_routed_shard_raises(adapter):
    """A shard not in 13F raises ValueError."""
    class BogusShard:
        value = "bogus"

    target = MagicMock()
    target.shard = BogusShard()

    with pytest.raises((ValueError, TypeError)):
        adapter.route(
            target=target,
            intent_payload={},
            apply_fn=lambda x: x,
        )


# ── Provider-missing negative ────────────────────────────────────────────────


def test_missing_host_blocks_dispatch(adapter, mock_protocol):
    """Missing host is a provider-missing negative."""
    target = SshTarget(
        shard=SshEffectShard.BUILD,
        host="",  # empty host
        container="test-container",
    )
    result = adapter.route(
        target=target,
        intent_payload={"cmd": "build"},
        apply_fn=lambda x: x,
        fence_token=1,
    )
    assert not result.ok
    assert "Provider missing" in result.error


def test_missing_container_blocks_dispatch(adapter, mock_protocol):
    """Missing container is a provider-missing negative."""
    target = SshTarget(
        shard=SshEffectShard.BUILD,
        host="example.com",
        container="",  # empty container
    )
    result = adapter.route(
        target=target,
        intent_payload={"cmd": "build"},
        apply_fn=lambda x: x,
        fence_token=1,
    )
    assert not result.ok
    assert "Provider missing" in result.error


# ── Successful dispatch ──────────────────────────────────────────────────────


def test_build_succeeds_with_valid_target(adapter, build_target, mock_protocol):
    """BUILD with valid target dispatches successfully."""
    result = adapter.route(
        target=build_target,
        intent_payload={"deploy_dir": "/tmp/deploy"},
        apply_fn=lambda x: {"exit_code": 0},
        fence_token=1,
    )
    assert result.ok
    assert result.glek != ""
    assert result.outcome_kind == OUTCOME_COMPLETED


def test_deploy_succeeds_with_valid_target(adapter, deploy_target, mock_protocol):
    """DEPLOY with valid target dispatches successfully."""
    result = adapter.route(
        target=deploy_target,
        intent_payload={"port": 8080},
        apply_fn=lambda x: {"exit_code": 0},
        fence_token=1,
    )
    assert result.ok
    assert result.glek != ""
    assert result.outcome_kind == OUTCOME_COMPLETED


def test_destroy_succeeds_with_valid_target(adapter, destroy_target, mock_protocol):
    """DESTROY with valid target dispatches successfully."""
    result = adapter.route(
        target=destroy_target,
        intent_payload={"container": "arnold-app"},
        apply_fn=lambda x: {"exit_code": 0},
        fence_token=1,
    )
    assert result.ok
    assert result.glek != ""
    assert result.outcome_kind == OUTCOME_COMPLETED


# ── Gate contract (default-deny) ────────────────────────────────────────────


def test_missing_gate_blocks_dispatch_before_any_effect(
    mock_protocol, build_target
):
    """A missing gate check is a typed denial with zero protocol/transport."""
    no_gate = SshEffectAdapter(
        mock_protocol,
        production_enabled=False,
    )
    apply_calls: list[dict] = []

    result = no_gate.route(
        target=build_target,
        intent_payload={"deploy_dir": "/tmp/deploy"},
        apply_fn=lambda payload: apply_calls.append(payload),
        fence_token=1,
    )

    assert not result.ok
    assert "Action gate blocked" in result.error
    assert result.evidence["gate_verdict"] == GateResult.BLOCKED_WBC_MISSING
    mock_protocol.reserve_and_start.assert_not_called()
    mock_protocol.persist_intent.assert_not_called()
    assert apply_calls == []


def test_shadow_pass_blocks_dispatch_before_any_effect(
    gated_adapter_factory, mock_protocol, build_target
):
    """SHADOW_PASS is not authority: zero protocol/transport calls."""
    shadow = gated_adapter_factory(
        lambda _boundary, _target_key: GateResult.SHADOW_PASS
    )
    apply_calls: list[dict] = []

    result = shadow.route(
        target=build_target,
        intent_payload={"deploy_dir": "/tmp/deploy"},
        apply_fn=lambda payload: apply_calls.append(payload),
        fence_token=1,
    )

    assert not result.ok
    assert "Action gate blocked" in result.error
    assert result.evidence["gate_verdict"] == GateResult.SHADOW_PASS
    mock_protocol.reserve_and_start.assert_not_called()
    mock_protocol.persist_intent.assert_not_called()
    assert apply_calls == []


def test_exceptional_gate_blocks_dispatch_before_any_effect(
    gated_adapter_factory, mock_protocol, build_target
):
    """A gate that raises becomes a typed denial, never a dispatch."""
    def exploding_gate(_boundary, _target_key):
        raise RuntimeError("gate database unreachable")

    failing = gated_adapter_factory(exploding_gate)
    apply_calls: list[dict] = []

    result = failing.route(
        target=build_target,
        intent_payload={"deploy_dir": "/tmp/deploy"},
        apply_fn=lambda payload: apply_calls.append(payload),
        fence_token=1,
    )

    assert not result.ok
    assert "Action gate blocked" in result.error
    assert result.evidence["gate_verdict"] == GateResult.ERROR
    mock_protocol.reserve_and_start.assert_not_called()
    mock_protocol.persist_intent.assert_not_called()
    assert apply_calls == []


def test_blocked_verdicts_never_dispatch(
    gated_adapter_factory, mock_protocol, build_target
):
    """Every blocked/error enum verdict is denied before any effect."""
    for verdict in (
        GateResult.BLOCKED_MISSING_GRANT,
        GateResult.BLOCKED_STALE_GRANT,
        GateResult.BLOCKED_WBC_MISSING,
        GateResult.BLOCKED_NO_LEASE,
        GateResult.BLOCKED_NOT_OWNER,
        GateResult.ERROR,
    ):
        mock_protocol.reset_mock()
        gated = gated_adapter_factory(
            lambda _b, _k, v=verdict: v
        )
        apply_calls: list[dict] = []

        result = gated.route(
            target=build_target,
            intent_payload={"deploy_dir": "/tmp/deploy"},
            apply_fn=lambda payload: apply_calls.append(payload),
            fence_token=1,
        )

        assert not result.ok, verdict
        assert "Action gate blocked" in result.error, verdict
        mock_protocol.reserve_and_start.assert_not_called(), verdict
        assert apply_calls == [], verdict


def test_authorized_gate_dispatches_with_apply_fn_and_protocol(
    mock_protocol, build_target
):
    """AUTHORIZED is the only verdict that reaches protocol + transport."""
    authorized = SshEffectAdapter(
        mock_protocol,
        action_gate_check=lambda _boundary, _target_key: GateResult.AUTHORIZED,
        production_enabled=False,
    )
    apply_calls: list[dict] = []

    result = authorized.route(
        target=build_target,
        intent_payload={"deploy_dir": "/tmp/deploy"},
        apply_fn=lambda payload: apply_calls.append(payload),
        fence_token=1,
    )

    assert result.ok
    assert result.outcome_kind == OUTCOME_COMPLETED
    mock_protocol.reserve_and_start.assert_called_once()
    mock_protocol.persist_intent.assert_called_once()
    mock_protocol.accept_outcome.assert_called_once()
    assert apply_calls == [{"deploy_dir": "/tmp/deploy"}]


def test_production_route_dispatches_after_current_authorization(
    mock_protocol, build_target
):
    """Production route uses the same gated protocol after authorization."""
    gate = MagicMock(return_value=GateResult.AUTHORIZED)
    production = SshEffectAdapter(
        mock_protocol,
        action_gate_check=gate,
        production_enabled=True,
    )
    apply_calls: list[dict] = []

    result = production.route(
        target=build_target,
        intent_payload={"deploy_dir": "/tmp/deploy"},
        apply_fn=lambda payload: apply_calls.append(payload),
        fence_token=1,
    )

    assert result.ok
    assert result.outcome_kind == OUTCOME_COMPLETED
    gate.assert_called_once()
    mock_protocol.reserve_and_start.assert_called_once()
    assert apply_calls == [{"deploy_dir": "/tmp/deploy"}]


def test_adapter_effect_authorized_is_strict_authorized_only():
    """The shared predicate admits only the canonical AUTHORIZED verdict."""
    assert adapter_effect_authorized(GateResult.AUTHORIZED) is True
    assert adapter_effect_authorized(GateResult.SHADOW_PASS) is False
    assert adapter_effect_authorized(None) is False
    assert adapter_effect_authorized("authorized") is False


# ── Action-off gate dispatch ────────────────────────────────────────────────


def test_gate_dispatch_production_runs_when_authorized(
    mock_protocol, build_target
):
    """Gate-only production dispatch is allowed by canonical authorization."""
    production = SshEffectAdapter(
        mock_protocol,
        action_gate_check=lambda _boundary, _target_key: GateResult.AUTHORIZED,
        production_enabled=True,
    )

    result = production.gate_dispatch(build_target)

    assert result.ok
    assert result.evidence["gate_verdict"] == GateResult.AUTHORIZED.value
    mock_protocol.reserve_and_start.assert_not_called()


def test_gate_dispatch_missing_gate_denies(mock_protocol, build_target):
    """A missing gate is a typed denial before any transport."""
    no_gate = SshEffectAdapter(mock_protocol, production_enabled=False)

    result = no_gate.gate_dispatch(build_target)

    assert not result.ok
    assert "Action gate blocked" in result.error
    assert result.evidence["gate_verdict"] == GateResult.BLOCKED_WBC_MISSING.value


def test_gate_dispatch_non_authorized_verdicts_deny(
    gated_adapter_factory, build_target
):
    """Every non-AUTHORIZED verdict denies with zero transport."""
    for verdict in (
        GateResult.SHADOW_PASS,
        GateResult.BLOCKED_MISSING_GRANT,
        GateResult.BLOCKED_STALE_GRANT,
        GateResult.BLOCKED_WBC_MISSING,
        GateResult.BLOCKED_NO_LEASE,
        GateResult.BLOCKED_NOT_OWNER,
        GateResult.ERROR,
    ):
        gated = gated_adapter_factory(lambda _b, _k, v=verdict: v)

        result = gated.gate_dispatch(build_target)

        assert not result.ok, verdict
        assert "Action gate blocked" in result.error, verdict
        assert result.evidence["gate_verdict"] == verdict.value, verdict


def test_gate_dispatch_authorized_outside_production_dispatches(
    gated_adapter_factory, build_target
):
    """Explicit AUTHORIZED in a non-production adapter is the only dispatch."""
    gated = gated_adapter_factory(
        lambda _boundary, _target_key: GateResult.AUTHORIZED
    )

    result = gated.gate_dispatch(build_target)

    assert result.ok
    assert result.outcome_kind == OUTCOME_COMPLETED
    assert result.evidence["gate_verdict"] == GateResult.AUTHORIZED.value


def test_gate_dispatch_provider_missing_denies(adapter):
    """Missing host/container is a provider-missing negative."""
    missing_host = SshTarget(
        shard=SshEffectShard.SSH_EXEC,
        host="",
        container="megaplan-cloud-agent",
        operation="ssh_exec",
    )
    missing_container = SshTarget(
        shard=SshEffectShard.UPLOAD_FILE,
        host="example.com",
        container="",
        operation="upload_file",
    )

    for target in (missing_host, missing_container):
        result = adapter.gate_dispatch(target)

        assert not result.ok, target.target_key
        assert "Provider missing" in result.error, target.target_key


def test_gate_dispatch_supports_action_off_shard_identity():
    """Action-off shard names resolve to stable enum identities."""
    for name in ("ssh_exec", "upload_file", "upload_archive", "down"):
        shard = SshEffectShard(name)
        assert shard.value == name
        assert shard.value in SSH_ACTION_OFF_SHARDS


def test_open_ssh_effect_adapter_fails_closed_without_wiring(mock_protocol):
    """Production construction without protocol or gate is refused."""
    from arnold_pipelines.megaplan.cloud.ssh_effect_adapter import (
        SshEffectAdapterGateError,
        current_ssh_gate_check,
        open_ssh_effect_adapter,
    )

    with pytest.raises(SshEffectAdapterGateError, match="EffectProtocol"):
        open_ssh_effect_adapter()

    with pytest.raises(SshEffectAdapterGateError, match="action_gate_check"):
        open_ssh_effect_adapter(mock_protocol)

    installed = open_ssh_effect_adapter(mock_protocol, production_enabled=False)
    assert isinstance(installed, SshEffectAdapter)
    assert installed._production_enabled is False

    gated = open_ssh_effect_adapter(
        mock_protocol, action_gate_check=current_ssh_gate_check()
    )
    assert isinstance(gated, SshEffectAdapter)
    assert gated._production_enabled is True
    assert adapter_effect_authorized(gated._gate(SshTarget(
        shard=SshEffectShard.SSH_EXEC,
        host="example.com",
        container="megaplan-cloud-agent",
    ))) is False


def test_constructor_production_without_gate_raises(mock_protocol):
    """T-0018: the public constructor itself refuses production construction
    without an explicit action_gate_check, mirroring the factory."""
    from arnold_pipelines.megaplan.cloud.ssh_effect_adapter import (
        SshEffectAdapterGateError,
    )

    # production_enabled=True with no gate is a wiring error at construction
    with pytest.raises(SshEffectAdapterGateError, match="action_gate_check"):
        SshEffectAdapter(mock_protocol, production_enabled=True)

    # observation-mode construction may omit the gate (fail closed per dispatch)
    observed = SshEffectAdapter(mock_protocol, production_enabled=False)
    assert observed._action_gate_check is None
    assert observed._production_enabled is False

    # production construction with an explicit gate is allowed
    gated = SshEffectAdapter(
        mock_protocol,
        action_gate_check=lambda _boundary, _target_key: GateResult.AUTHORIZED,
        production_enabled=True,
    )
    assert gated._production_enabled is True


def test_current_ssh_gate_check_requires_and_reads_current_context():
    """The production SSH gate reads one exact owner context per dispatch."""
    from arnold_pipelines.megaplan.cloud.ssh_effect_adapter import (
        current_ssh_gate_check,
    )

    gate = current_ssh_gate_check()
    verdict = gate("dispatch", "ssh:ssh_exec:example.com:megaplan-cloud-agent")
    assert verdict == GateResult.BLOCKED_MISSING_GRANT
    assert adapter_effect_authorized(verdict) is False

    class Context:
        def authorize(self, **kwargs):
            assert kwargs["capability"] == "ssh_engine_invocation"
            return GateResult.AUTHORIZED

    authorized = current_ssh_gate_check(Context())
    assert authorized("dispatch", "ssh:ssh_exec:example.com:megaplan-cloud-agent") == GateResult.AUTHORIZED


# ── Stale-fence negatives ────────────────────────────────────────────────────


def test_stale_fence_blocks_ssh(adapter, build_target):
    """Missing fence_token blocks SSH dispatch."""
    result = adapter.route(
        target=build_target,
        intent_payload={"cmd": "build"},
        apply_fn=lambda x: x,
        fence_token=None,
    )
    assert not result.ok
    assert "Stale fence" in result.error


def test_zero_fence_token_blocks_ssh(adapter, build_target):
    """Zero fence_token blocks SSH dispatch."""
    result = adapter.route(
        target=build_target,
        intent_payload={"cmd": "build"},
        apply_fn=lambda x: x,
        fence_token=0,
    )
    assert not result.ok
    assert "Stale fence" in result.error


# ── Intent-failure negatives ─────────────────────────────────────────────────


def test_empty_intent_payload_blocks_dispatch(adapter, build_target):
    """Empty intent payload is rejected."""
    result = adapter.route(
        target=build_target,
        intent_payload={},
        apply_fn=lambda x: x,
        fence_token=1,
    )
    assert not result.ok
    assert "Intent-failure" in result.error


# ── Crash behavior ───────────────────────────────────────────────────────────


def test_protocol_exception_produces_indeterminate(adapter, build_target, mock_protocol):
    """If the protocol raises, the outcome is INDETERMINATE."""
    mock_protocol.reserve_and_start.side_effect = RuntimeError("SSH DB crashed")

    result = adapter.route(
        target=build_target,
        intent_payload={"cmd": "build"},
        apply_fn=lambda x: x,
        fence_token=1,
    )
    assert not result.ok
    assert result.outcome_kind == OUTCOME_INDETERMINATE
    assert "Protocol error" in result.error


def test_apply_fn_exception_produces_failed(adapter, build_target, mock_protocol):
    """If the apply_fn raises, the outcome is FAILED."""
    def failing_apply(payload):
        raise ConnectionError("SSH connection refused")

    result = adapter.route(
        target=build_target,
        intent_payload={"cmd": "build"},
        apply_fn=failing_apply,
        fence_token=1,
    )
    assert not result.ok
    assert result.outcome_kind == OUTCOME_FAILED
    assert "connection refused" in result.error


# ── Fake-transport negative ──────────────────────────────────────────────────


def test_fake_transport_detects_real_subprocess(adapter, build_target):
    """Fake-transport detection flags subprocess.run usage."""
    def real_ssh(payload):
        import subprocess
        subprocess.run(["ssh", "example.com", "ls"])

    # Source inspection may not work with lambdas, but the method exists
    result = adapter.check_fake_transport(real_ssh, build_target)
    # Should detect the suspicious pattern
    assert not result


def test_fake_transport_allows_clean_lambda(adapter, build_target):
    """A clean lambda without suspicious patterns passes."""
    def fake_transport(payload):
        return {"exit_code": 0, "output": "ok"}

    result = adapter.check_fake_transport(fake_transport, build_target)
    # A simple function without real subprocess calls should pass
    assert result


# ── GLEK stability ───────────────────────────────────────────────────────────


def test_glek_stable_for_same_target(adapter, build_target):
    """Same target produces same GLEK identity inputs."""
    ei1 = adapter._build_effect_identity(build_target)
    ei2 = adapter._build_effect_identity(build_target)
    assert ei1.environment_id == ei2.environment_id
    assert ei1.action_target == ei2.action_target
    assert ei1.effect_family == ei2.effect_family


def test_glek_differs_for_different_operations(adapter, build_target, deploy_target):
    """Different operations produce different effect identities."""
    ei_build = adapter._build_effect_identity(build_target)
    ei_deploy = adapter._build_effect_identity(deploy_target)
    assert ei_build.effect_family != ei_deploy.effect_family


# ── SshTarget identity ───────────────────────────────────────────────────────


def test_ssh_target_key_is_stable():
    """SshTarget.target_key is stable and deterministic."""
    target = SshTarget(
        shard=SshEffectShard.BUILD,
        host="example.com",
        container="my-app",
    )
    assert target.target_key == "ssh:build:example.com:my-app"


def test_ssh_target_different_hosts_produce_different_keys():
    """Different hosts produce different target keys."""
    t1 = SshTarget(SshEffectShard.BUILD, host="h1", container="c1")
    t2 = SshTarget(SshEffectShard.BUILD, host="h2", container="c1")
    assert t1.target_key != t2.target_key
