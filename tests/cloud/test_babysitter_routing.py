from __future__ import annotations

from pathlib import Path

import pytest

from arnold_pipelines.megaplan.cloud.babysitter import launch
from arnold_pipelines.megaplan.cloud.babysitter.routing import (
    CHAIN_PROFILE_ENV,
    CLOSED_PROFILE_ENV,
    CONTINUATION_FIXER_ROLES,
    CONTINUATION_MUSE_MODEL,
    CONTINUATION_MUSE_PROFILE,
    CONTINUATION_MUSE_THINKING,
    resolve_babysitter_routing,
)

CONTINUATION_SESSION = "native-build-forward-c2-780129da-20260903-r5"


def _closed_env(**extra: str) -> dict[str, str]:
    values = {
        CHAIN_PROFILE_ENV: CONTINUATION_MUSE_PROFILE,
        CLOSED_PROFILE_ENV: CONTINUATION_MUSE_PROFILE,
    }
    values.update(extra)
    return values


def test_babysitter_routing_defaults_to_legacy_deepseek() -> None:
    route = resolve_babysitter_routing({})
    assert route.mode == "legacy"
    assert route.controller_backend == "hermes"
    assert route.controller_model == "omp:deepseek/deepseek-v4-flash"
    assert route.investigator_model == route.controller_model


def test_codex_override_resolves_controller_and_investigators() -> None:
    route = resolve_babysitter_routing({"ARNOLD_BABYSITTER_ROUTING": "codex"})
    assert route.as_dict() == {
        "mode": "codex",
        "controller_backend": "codex",
        "controller_model": "codex:gpt-5.6-luna",
        "investigator_backend": "codex",
        "investigator_model": "codex:gpt-5.6-luna",
    }


def test_unknown_routing_value_fails_closed() -> None:
    import pytest

    with pytest.raises(ValueError, match="ARNOLD_BABYSITTER_ROUTING"):
        resolve_babysitter_routing({"ARNOLD_BABYSITTER_ROUTING": "deepseek"})


def test_continuation_route_closes_every_fixer_role_to_muse_high() -> None:
    session = CONTINUATION_SESSION
    route = resolve_babysitter_routing(_closed_env(), session=session)
    assert route.closed is True
    assert route.mode == "continuation-muse"
    assert route.controller_model == CONTINUATION_MUSE_MODEL
    assert route.investigator_model == CONTINUATION_MUSE_MODEL
    assert route.thinking == CONTINUATION_MUSE_THINKING == "high"
    assert route.as_dict()["role_models"] == {
        role: CONTINUATION_MUSE_MODEL for role in CONTINUATION_FIXER_ROLES
    }


@pytest.mark.parametrize(
    "session",
    [
        CONTINUATION_SESSION,
        "native-build-forward-c2-future-generation-r99",
    ],
)
def test_closed_route_accepts_r5_and_future_sessions_without_prefix_allowlist(
    session: str,
) -> None:
    route = resolve_babysitter_routing(_closed_env(), session=session)
    assert route.closed
    assert route.controller_model == CONTINUATION_MUSE_MODEL
    assert route.thinking == "high"


def test_continuation_profile_without_explicit_closed_config_fails_closed() -> None:
    with pytest.raises(ValueError, match="explicit"):
        resolve_babysitter_routing(
            {CHAIN_PROFILE_ENV: CONTINUATION_MUSE_PROFILE},
            session=CONTINUATION_SESSION,
        )


def test_forged_closed_config_and_profile_mismatch_fails_closed() -> None:
    with pytest.raises(ValueError, match="contradict"):
        resolve_babysitter_routing(
            {
                CHAIN_PROFILE_ENV: "partnered-5",
                CLOSED_PROFILE_ENV: CONTINUATION_MUSE_PROFILE,
            },
            session="native-build-forward-c2-forged",
        )


def test_unrelated_profile_keeps_ordinary_routing_defaults() -> None:
    route = resolve_babysitter_routing(
        {CHAIN_PROFILE_ENV: "partnered-5"},
        session=CONTINUATION_SESSION,
    )
    assert not route.closed
    assert route.controller_model == "omp:deepseek/deepseek-v4-flash"


def test_continuation_route_rejects_ambient_alternate_model() -> None:
    session = CONTINUATION_SESSION
    import pytest

    with pytest.raises(ValueError, match="closed to Muse"):
        resolve_babysitter_routing(
            _closed_env(ARNOLD_BABYSITTER_MODEL="omp:deepseek/deepseek-v4-flash"),
            session=session,
        )
    with pytest.raises(ValueError, match="closed to Muse"):
        resolve_babysitter_routing(
            _closed_env(ARNOLD_BABYSITTER_ROUTING="codex"), session=session
        )


def test_continuation_launch_requires_explicit_closed_fixer_registration(
    monkeypatch,
) -> None:
    from arnold_pipelines.megaplan.cloud.babysitter import launch as launch_module

    session = CONTINUATION_SESSION
    monkeypatch.delenv("ARNOLD_BABYSITTER_MODEL", raising=False)
    monkeypatch.setenv(CHAIN_PROFILE_ENV, CONTINUATION_MUSE_PROFILE)
    monkeypatch.setenv(CLOSED_PROFILE_ENV, CONTINUATION_MUSE_PROFILE)
    args = launch_module._build_parser().parse_args(["--session", session])
    with pytest.raises(ValueError, match="explicit"):
        launch_module._collect_context(args)

    monkeypatch.setenv(
        "ARNOLD_BABYSITTER_MODEL",
        f"{CONTINUATION_MUSE_MODEL}:high",
    )
    ctx = launch_module._collect_context(args)
    assert ctx["model"] == CONTINUATION_MUSE_MODEL


def test_continuation_route_normalizes_all_thinking_inputs_to_high() -> None:
    session = CONTINUATION_SESSION
    for level in ("auto", "off", "minimal", "low", "medium", "high", "xhigh", "max"):
        route = resolve_babysitter_routing(
            _closed_env(ARNOLD_BABYSITTER_MODEL=f"{CONTINUATION_MUSE_MODEL}:{level}"),
            session=session,
        )
        assert route.controller_model == CONTINUATION_MUSE_MODEL
        assert route.thinking == "high"


def test_continuation_managed_spec_pins_nested_omp_dispatch_to_muse_high(
    tmp_path: Path,
) -> None:
    goal = tmp_path / "goal.md"
    goal.write_text("prove movement", encoding="utf-8")
    session = CONTINUATION_SESSION
    route = resolve_babysitter_routing(_closed_env(), session=session)
    ctx = {
        "engine_root": Path(__file__).resolve().parents[2],
        "run_root": tmp_path / "run",
        "session": session,
        "occurrence": "occurrence",
        "run_id": "run",
        "plan": "native-c2",
        "routing": route,
        "model": route.controller_model,
        "difficulty": 8,
        "remote_spec": "",
        "workspace": str(tmp_path),
        "mode": "superfixer",
    }
    spec = launch._managed_spec(ctx, goal_path=goal, identity_key="identity")
    assert spec.backend == "babysitter"
    assert spec.model == CONTINUATION_MUSE_MODEL
    assert spec.reasoning_effort == CONTINUATION_MUSE_THINKING == "high"
    assert f"--model={CONTINUATION_MUSE_MODEL}:{CONTINUATION_MUSE_THINKING}" in spec.argv
    joined = " ".join(spec.argv).lower()
    assert all(name not in joined for name in ("deepseek", "codex", "luna", "grok"))
    assert spec.links["routing"]["thinking"] == CONTINUATION_MUSE_THINKING


def test_continuation_fixer_uses_shared_omp_capability_preflight(monkeypatch) -> None:
    session = CONTINUATION_SESSION
    route = resolve_babysitter_routing(
        _closed_env(ARNOLD_BABYSITTER_MODEL=f"{CONTINUATION_MUSE_MODEL}:high"),
        session=session,
    )
    calls = []

    def fake_probe(*, local=False, provider=None):
        calls.append((local, provider))
        return {
            "status": "ok",
            "provider": "openrouter",
            "model": "meta/muse-spark-1.3-contributor",
            "thinking": "high",
            "fallback": False,
            "probe": "omp_sessionless_no_tools",
        }

    monkeypatch.setattr(launch, "_omp_openrouter_capability_check", fake_probe)
    ctx = {"routing": route}
    evidence = launch._continuation_capability_preflight(ctx)
    assert evidence["status"] == "ok"
    assert ctx["provider_capability"] is evidence
    assert calls == [(True, None)]


def test_continuation_fixer_capability_auth_failure_fails_closed(monkeypatch) -> None:
    session = CONTINUATION_SESSION
    route = resolve_babysitter_routing(
        _closed_env(ARNOLD_BABYSITTER_MODEL=f"{CONTINUATION_MUSE_MODEL}:high"),
        session=session,
    )
    monkeypatch.setattr(
        launch,
        "_omp_openrouter_capability_check",
        lambda *, local=False, provider=None: {
            "status": "authentication_failed",
            "reason": "omp_authentication_failed",
            "provider": "openrouter",
            "model": "meta/muse-spark-1.3-contributor",
            "thinking": "high",
            "fallback": False,
            "probe": "omp_sessionless_no_tools",
        },
    )
    with pytest.raises(RuntimeError, match="capability preflight failed"):
        launch._continuation_capability_preflight({"routing": route})


def test_managed_spec_records_codex_route_and_sealed_goal(tmp_path: Path) -> None:
    goal = tmp_path / "goal.md"
    goal.write_text("prove movement", encoding="utf-8")
    route = resolve_babysitter_routing({"ARNOLD_BABYSITTER_ROUTING": "codex"})
    ctx = {
        "engine_root": Path(__file__).resolve().parents[2],
        "run_root": tmp_path / "run",
        "session": "astrid-first",
        "occurrence": "occurrence",
        "run_id": "run",
        "plan": "m7",
        "routing": route,
        "model": route.controller_model,
        "difficulty": 8,
        "remote_spec": "",
        "workspace": str(tmp_path),
        "mode": "superfixer",
    }
    spec = launch._managed_spec(ctx, goal_path=goal, identity_key="identity")
    assert spec.backend == "codex"
    assert spec.model == "codex:gpt-5.6-luna"
    assert spec.stdin_path == goal
    # The controller boundary strips ambient runtime-identity env (occurrence
    # c2f73c7ddcef) before codex exec.
    assert spec.argv[:5] == (
        "/usr/bin/env",
        "-u",
        "MEGAPLAN_RUNTIME_LAUNCH_SEED",
        "-u",
        "ARNOLD_RUNTIME_MANIFEST",
    )
    assert spec.argv[5:7] == ("codex", "exec")
    assert "gpt-5.6-luna" in spec.argv
    assert all("deepseek" not in arg for arg in spec.argv)
    assert spec.links["routing"] == route.as_dict()


def test_default_managed_spec_uses_canonical_omp_controller(tmp_path: Path) -> None:
    goal = tmp_path / "goal.md"
    goal.write_text("prove movement", encoding="utf-8")
    route = resolve_babysitter_routing({})
    ctx = {
        "engine_root": Path(__file__).resolve().parents[2],
        "run_root": tmp_path / "run",
        "session": "astrid-first",
        "occurrence": "occurrence",
        "run_id": "run",
        "plan": "m7",
        "routing": route,
        "model": route.controller_model,
        "difficulty": 8,
        "remote_spec": "",
        "workspace": str(tmp_path),
        "mode": "superfixer",
    }
    spec = launch._managed_spec(ctx, goal_path=goal, identity_key="identity")
    assert spec.backend == "babysitter"
    assert spec.model == route.controller_model
    assert spec.stdin_path is None
    assert any("launch_omp_agent.py" in arg for arg in spec.argv)


def test_launch_receipt_contains_resolved_controller_and_investigator_models(tmp_path: Path) -> None:
    route = resolve_babysitter_routing({"ARNOLD_BABYSITTER_ROUTING": "codex"})
    ctx = {
        "session": "astrid-first",
        "occurrence": "occurrence",
        "run_id": "run",
        "run_root": tmp_path,
        "plan": "m7",
        "run_kind": "chain",
        "workspace": str(tmp_path),
        "remote_spec": "",
        "mode": "superfixer",
        "model": route.controller_model,
        "routing": route,
        "launched_at": "2026-08-20T10:00:00Z",
    }
    payload = launch._receipt_payload(ctx, status="running")
    assert payload["controller_backend"] == "codex"
    assert payload["controller_model"] == "codex:gpt-5.6-luna"
    assert payload["investigator_backend"] == "codex"
    assert payload["investigator_model"] == "codex:gpt-5.6-luna"
