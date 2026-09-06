"""B2.2 terminal authority regressions with side-effect assertions."""

import json


def test_destructive_spellings_and_git_global_options_are_classified():
    from arnold.agent.tools.terminal_tool import _dangerous_command

    dangerous = [
        "rm -fr target", "rm --recursive --force target",
        "rm -r --force target", "rm --force -r target",
        "git -C /tmp/repo push", "git --git-dir=/tmp/repo/.git push",
        "git -c user.name=x push", "git -cuser.name=x push",
        "git --work-tree /tmp/repo reset --hard",
        "git -C /tmp/repo clean -fd", "git --namespace=origin checkout main",
        "echo $(rm -rf target)", "echo `rm -rf target`",
        'bash -c "rm -rf target"', "env FOO=bar rm -rf target",
        "command -- rm -rf target", "printf x | xargs rm -rf",
    ]
    safe = ["rm -f target", "git status", "git -C /tmp/repo log"]
    assert all(_dangerous_command(command) for command in dangerous)
    assert not any(_dangerous_command(command) for command in safe)


def test_shell_control_tokens_and_newlines_cannot_hide_destructive_commands():
    from arnold.agent.tools.terminal_tool import _dangerous_command

    for operator in ("&&", "||", "&", "|", ";"):
        assert _dangerous_command(f"echo ok {operator} rm -rf target")
    assert _dangerous_command("echo ok\nrm -rf target")
    assert not _dangerous_command('printf "rm -rf target"')


def test_compound_denial_still_has_no_config_or_environment_side_effect(monkeypatch):
    from arnold.agent.tools import terminal_tool as terminal

    calls = []
    monkeypatch.setattr(terminal, "_approval_callback", None)
    monkeypatch.setattr(terminal, "_get_env_config", lambda: calls.append("config"))
    monkeypatch.setattr(terminal, "_environment_for", lambda *a, **k: calls.append("env"))
    for command in (
        "echo ok && rm -rf target",
        "echo $(rm -rf target)",
        'bash -c "rm -rf target"',
        "env rm -rf target",
    ):
        result = json.loads(terminal.terminal_tool(command))
        assert result["status"] == "approval_required"
        assert result["exit_code"] == -1
    assert calls == []


def test_denial_happens_before_config_or_environment_even_with_force(monkeypatch):
    from arnold.agent.tools import terminal_tool as terminal

    calls = []
    monkeypatch.setattr(terminal, "_approval_callback", None)
    monkeypatch.setattr(terminal, "_get_env_config", lambda: calls.append("config"))
    monkeypatch.setattr(terminal, "_environment_for", lambda *a, **k: calls.append("env"))
    result = json.loads(terminal.terminal_tool("rm -fr target", force=True))
    assert result["status"] == "approval_required"
    assert result["exit_code"] == -1
    assert calls == []


def test_denied_callback_has_no_environment_side_effect(monkeypatch):
    from arnold.agent.tools import terminal_tool as terminal

    calls = []
    monkeypatch.setattr(terminal, "_approval_callback", lambda *args: "deny")
    monkeypatch.setattr(terminal, "_get_env_config", lambda: calls.append("config"))
    monkeypatch.setattr(terminal, "_environment_for", lambda *a, **k: calls.append("env"))
    for command in ("git -C /tmp push", "git -c user.name=x push"):
        result = json.loads(terminal.terminal_tool(command))
        assert result["status"] == "blocked"
        assert result["exit_code"] == -1
    assert calls == []


def test_malformed_callback_result_fails_closed(monkeypatch):
    from arnold.agent.tools import terminal_tool as terminal

    monkeypatch.setattr(terminal, "_approval_callback", lambda *args: {"approved": True})
    result = json.loads(terminal.terminal_tool("rm --force --recursive target"))
    assert result["status"] == "blocked"
    assert result["exit_code"] == -1


def test_approved_destructive_command_reaches_existing_environment_once(monkeypatch):
    from arnold.agent.tools import terminal_tool as terminal

    calls = []

    class FakeEnvironment:
        def execute(self, command, **kwargs):
            calls.append((command, kwargs))
            return {"output": "approved", "returncode": 0}

    monkeypatch.setattr(terminal, "_approval_callback", lambda *args: "once")
    monkeypatch.setattr(terminal, "_get_env_config", lambda: {
        "timeout": 5, "cwd": ".", "local_persistent": False,
    })
    monkeypatch.setattr(terminal, "_environment_for", lambda *a, **k: FakeEnvironment())
    monkeypatch.setattr(terminal, "_start_cleanup_thread", lambda: None)
    result = json.loads(terminal.terminal_tool("git -C /tmp push"))
    assert result["error"] is None
    assert result["exit_code"] == 0
    assert calls == [("git -C /tmp push", {"cwd": "", "timeout": 5})]
