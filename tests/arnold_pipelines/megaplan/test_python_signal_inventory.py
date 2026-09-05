"""Mechanical, repository-wide inventory of Python process-signal sites.

This is the small live-discovery side of NBF-04.  It deliberately inventories
*call expressions*, rather than looking for a helper name somewhere in the
containing file: a direct ``proc.kill()`` in a file which also imports the
canonical door is still an unclassified site.  NBF-05 owns the generated
cross-language artifact; this test only provides a deterministic Python
inventory and regression boundary for it.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[3]
SOURCE_ROOTS = ("arnold", "arnold_pipelines", "agentbox", "scripts", "tools")
SKIP_PARTS = {"tests", "vendor", "generated", "__pycache__", ".git", ".venv", "venv"}

CANONICAL_WRAPPERS = frozenset({"signal_process", "signal_process_group", "signal_worker"})
NEUTRAL_WRAPPERS = frozenset({"kill_group"})
KNOWN_LOCAL_WRAPPERS = frozenset({
    "_signal", "_signal_process", "_kill_tree", "_kill_process_group",
    "_terminate_process_group", "_terminate_timed_out_child",
})
METHOD_SIGNALS = frozenset({"terminate", "kill", "send_signal"})


@dataclass(frozen=True)
class SignalSite:
    path: str
    symbol: str
    action: str
    target_class: str
    branch_label: str
    lineno: int

    @property
    def key(self) -> str:
        return "|".join((self.path, self.symbol, self.action, self.target_class, self.branch_label))


@dataclass
class _ImportedNames:
    os_modules: set[str]
    kill_names: set[str]
    killpg_names: set[str]
    canonical_names: set[str]
    neutral_names: set[str]


def _qualified(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _qualified(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _imported_names(tree: ast.AST) -> _ImportedNames:
    names = _ImportedNames(set(), set(), set(), set(), set())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "os":
                    names.os_modules.add(alias.asname or "os")
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                local = alias.asname or alias.name
                if module == "os" and alias.name == "kill":
                    names.kill_names.add(local)
                elif module == "os" and alias.name == "killpg":
                    names.killpg_names.add(local)
                elif alias.name in CANONICAL_WRAPPERS:
                    names.canonical_names.add(local)
                elif alias.name in NEUTRAL_WRAPPERS:
                    names.neutral_names.add(local)
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)) or not isinstance(node.value, ast.Name):
                continue
            targets = list(node.targets) if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if not isinstance(target, ast.Name):
                    continue
                if node.value.id in names.canonical_names and target.id not in names.canonical_names:
                    names.canonical_names.add(target.id)
                    changed = True
                if node.value.id in names.neutral_names and target.id not in names.neutral_names:
                    names.neutral_names.add(target.id)
                    changed = True
    return names


def _probe(call: ast.Call, symbol: str) -> bool:
    if symbol != "os.kill" or len(call.args) < 2:
        return False
    return isinstance(call.args[1], ast.Constant) and call.args[1].value == 0


def _method_symbol(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Attribute) and node.func.attr in METHOD_SIGNALS:
        return f"process.{node.func.attr}"
    return None


def _symbol(node: ast.Call, imported: _ImportedNames) -> str | None:
    raw = _qualified(node.func)
    if raw is None:
        return None
    if isinstance(node.func, ast.Attribute) and node.func.attr in {"kill", "killpg"}:
        if raw.rsplit(".", 1)[0] in imported.os_modules:
            return f"os.{node.func.attr}"
    if isinstance(node.func, ast.Name):
        if node.func.id in imported.kill_names:
            return "os.kill"
        if node.func.id in imported.killpg_names:
            return "os.killpg"
        if node.func.id in imported.canonical_names:
            return node.func.id if node.func.id in CANONICAL_WRAPPERS else "signal_process"
        if node.func.id in imported.neutral_names:
            return "kill_group"
        if node.func.id in CANONICAL_WRAPPERS:
            return node.func.id
        if node.func.id in NEUTRAL_WRAPPERS:
            return "kill_group"
        if node.func.id in KNOWN_LOCAL_WRAPPERS:
            return node.func.id
    return _method_symbol(node)


def _target_class(path: str, symbol: str, action: str, functions: tuple[str, ...] = ()) -> str:
    if action == "probe":
        return "liveness-probe"
    if path == "arnold_pipelines/megaplan/incident/disposition.py":
        return "canonical-disposition"
    # These physical callbacks are nested beneath a durable disposition
    # writer.  They are not raw worker callers: the enclosing function first
    # validates context and records a typed non-worker disposition.
    if path == "arnold_pipelines/megaplan/cloud/operator_control.py":
        return "non-worker-disposition"
    if path == "arnold_pipelines/megaplan/skills/subagent-launcher/fan_kill.py":
        return "non-worker-lifecycle"
    if path == "arnold_pipelines/megaplan/managed_agent.py" and "signal_managed_process" in functions:
        return "non-worker-disposition"
    if path == "arnold_pipelines/megaplan/cloud/controlled_final_launch.py" and (
        "signal_ladder" in functions or "immediate_timeout" in functions
    ):
        return "canonical-disposition"
    if path == "arnold/adapters/ledger_store_adapter.py":
        return "ledger-self-resignal"
    if path == "arnold/runtime/process.py":
        return "runtime-support"
    if path == "arnold_pipelines/megaplan/runtime/process.py":
        return "validation-custody"
    if path in {"arnold_pipelines/megaplan/runtime/batch.py", "scripts/run_m11_validation_shard.py"}:
        return "validation-shard"
    if path == "scripts/simulate_watchdog_end_to_end.py":
        return "simulation"
    if path == "arnold/agent/tools/terminal_tool.py":
        return "external-sandbox-cleanup"
    if path == "arnold_pipelines/megaplan/bakeoff/handlers.py":
        return "external-bakeoff-cleanup"
    if symbol == "kill_group":
        return "neutral-process-group"
    return "worker"


def _iter_children(node: ast.AST) -> Iterable[tuple[str | None, ast.AST]]:
    for field, value in ast.iter_fields(node):
        if isinstance(value, ast.AST):
            yield field, value
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, ast.AST):
                    yield field, item


def discover_signal_sites(path: Path) -> list[SignalSite]:
    """Discover executable signal calls in *path* using only Python AST."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imported = _imported_names(tree)
    rel = path.relative_to(ROOT).as_posix()
    found: list[SignalSite] = []
    occurrences: dict[tuple[str, tuple[str, ...], str, str, str], int] = {}

    def walk(node: ast.AST, functions: tuple[str, ...], branches: tuple[str, ...]) -> None:
        next_functions = functions
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            next_functions += (node.name,)
        elif isinstance(node, ast.Lambda):
            next_functions += ("<lambda>",)
        if isinstance(node, ast.Call):
            symbol = _symbol(node, imported)
            if symbol is not None:
                action = "probe" if _probe(node, symbol) else "signal"
                target = _target_class(rel, symbol, action, next_functions)
                count_key = ("/".join(next_functions) or "<module>", branches, symbol, action, target)
                occurrence = occurrences.get(count_key, 0) + 1
                occurrences[count_key] = occurrence
                branch = "/".join(branches) if branches else "root"
                owner = "/".join(next_functions) if next_functions else "<module>"
                found.append(SignalSite(rel, symbol, action, target, f"{owner}/{branch}/{occurrence}", node.lineno))
        for field, child in _iter_children(node):
            child_branches = branches
            if isinstance(node, (ast.If, ast.IfExp, ast.Try, ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith)):
                child_branches = branches + (f"{type(node).__name__.lower()}:{field}",)
            walk(child, next_functions, child_branches)

    walk(tree, (), ())
    return found


def _iter_source_files() -> Iterable[Path]:
    for root_name in SOURCE_ROOTS:
        root = ROOT / root_name
        if not root.exists():
            continue
        for path in sorted(root.rglob("*.py")):
            if not any(part in SKIP_PARTS for part in path.relative_to(ROOT).parts):
                yield path


@lru_cache(maxsize=1)
def discover_all_signal_sites() -> list[SignalSite]:
    sites: list[SignalSite] = []
    for path in _iter_source_files():
        sites.extend(discover_signal_sites(path))
    return sites


REVIEWED_CLASS_REASONS = {
    "runtime-support": "Arnold-neutral process-group implementation; cannot import product incident authority.",
    "ledger-self-resignal": "Ledger adapter closes its store then re-sends the already-delivered OS signal to itself.",
    "validation-custody": "Validation custody cutover preserves recorded validation outcome and uses neutral group cleanup.",
    "validation-shard": "Frozen M11 validation shard/batch child cleanup; not a managed worker disposition.",
    "simulation": "End-to-end watchdog simulation cleanup of its intentionally fake worker.",
    "external-sandbox-cleanup": "External sandbox environment cleanup; no managed worker execution context.",
    "external-bakeoff-cleanup": "External bakeoff tail-process cleanup; no managed worker execution context.",
    "neutral-process-group": "Neutral runtime kill_group call; caller has no incident worker context.",
    "non-worker-disposition": "Physical callback is reached only after the typed non-worker disposition writer succeeds.",
    "non-worker-lifecycle": "Fan lifecycle shutdown uses the typed non-worker disposition door with an identity-locked preflight.",
}


def _is_reviewed(site: SignalSite) -> bool:
    if site.action == "probe" or site.target_class in REVIEWED_CLASS_REASONS or site.target_class == "canonical-disposition":
        return True
    # A worker row is acceptable only when this *call expression* is the
    # canonical door (or one of the explicitly known local forwarding
    # wrappers).  Merely importing a canonical helper in the same file does
    # not satisfy this predicate.
    return site.target_class == "worker" and (
        site.symbol in CANONICAL_WRAPPERS or site.symbol in KNOWN_LOCAL_WRAPPERS
    )


# Filled from the current reviewed discovery below; stable keys make new,
# vanished, duplicate, or renamed sites fail loudly until deliberately reviewed.
EXPECTED_SITE_KEYS: frozenset[str] = frozenset(
    line for line in """
agentbox/reset_notifications.py|os.kill|probe|liveness-probe|_pid_is_live/try:body/1
arnold/adapters/ledger_store_adapter.py|os.kill|signal|ledger-self-resignal|_signal_handler/root/1
arnold/agent/agent/copilot_acp_client.py|kill_group|signal|neutral-process-group|_run_prompt/if:body/1
arnold/agent/agent/copilot_acp_client.py|kill_group|signal|neutral-process-group|close/try:body/1
arnold/agent/tools/code_execution_tool.py|kill_group|signal|neutral-process-group|execute_code/try:body/while:body/if:body/1
arnold/agent/tools/code_execution_tool.py|kill_group|signal|neutral-process-group|execute_code/try:body/while:body/if:body/2
arnold/agent/tools/environments/local.py|kill_group|signal|neutral-process-group|_execute_oneshot/while:body/if:body/1
arnold/agent/tools/environments/local.py|kill_group|signal|neutral-process-group|_execute_oneshot/while:body/if:body/2
arnold/agent/tools/environments/persistent_shell.py|kill_group|signal|neutral-process-group|_cleanup_persistent_shell/root/1
arnold/agent/tools/rl_training_tool.py|kill_group|signal|neutral-process-group|_stop_training_run/if:body/1
arnold/agent/tools/rl_training_tool.py|kill_group|signal|neutral-process-group|_stop_training_run/if:body/2
arnold/agent/tools/rl_training_tool.py|kill_group|signal|neutral-process-group|_stop_training_run/if:body/3
arnold/agent/tools/rl_training_tool.py|kill_group|signal|neutral-process-group|rl_test_inference/for:body/try:body/try:handlers/1
arnold/runtime/process.py|os.killpg|signal|runtime-support|_reap_descendants/for:body/if:body/try:body/1
arnold/runtime/process.py|os.killpg|signal|runtime-support|kill_group/try:body/1
arnold/runtime/process.py|os.killpg|signal|runtime-support|kill_group/try:body/2
arnold/runtime/process.py|os.kill|probe|liveness-probe|_reap_descendants/for:body/try:body/1
arnold/runtime/process.py|os.kill|signal|runtime-support|_reap_descendants/for:body/try:body/1
arnold/runtime/process.py|process.kill|signal|runtime-support|_fallback_kill/try:body/1
arnold/runtime/process.py|process.terminate|signal|runtime-support|_fallback_kill/try:body/1
arnold_pipelines/megaplan/_core/phase_runtime.py|os.kill|probe|liveness-probe|_pid_alive/try:body/1
arnold_pipelines/megaplan/_core/phase_runtime.py|os.kill|probe|liveness-probe|_process_start_identity/try:handlers/try:body/1
arnold_pipelines/megaplan/_core/state.py|os.kill|probe|liveness-probe|_pid_is_live/try:body/1
arnold_pipelines/megaplan/auto.py|kill_group|signal|neutral-process-group|_supervise_subprocess/if:body/1
arnold_pipelines/megaplan/bakeoff/handlers.py|process.terminate|signal|external-bakeoff-cleanup|_tail_many/try:finalbody/for:body/if:body/1
arnold_pipelines/megaplan/cloud/recovered_prechain_admission.py|os.kill|probe|liveness-probe|_pid_dead/try:body/1
arnold_pipelines/megaplan/incident/chain_control.py|os.kill|probe|liveness-probe|_migration_pid_alive/try:body/1
arnold_pipelines/megaplan/cloud/current_target.py|os.kill|probe|liveness-probe|_pid_is_live_probe/try:body/1
arnold_pipelines/megaplan/cloud/current_target.py|os.kill|probe|liveness-probe|_pid_is_live_probe/try:handlers/try:body/1
arnold_pipelines/megaplan/cloud/current_target_liveness.py|os.kill|probe|liveness-probe|_pid_live/try:body/1
arnold_pipelines/megaplan/cloud/liveness_lease.py|os.kill|probe|liveness-probe|_proc_start_identity/try:handlers/try:body/1
arnold_pipelines/megaplan/cloud/liveness_lease.py|os.kill|probe|liveness-probe|_process_is_runnable/try:handlers/try:body/1
arnold_pipelines/megaplan/cloud/m11_live_canary.py|os.kill|probe|liveness-probe|_pid_live/try:body/1
arnold_pipelines/megaplan/cloud/operator_control.py|os.killpg|signal|non-worker-disposition|_stop_owned_pidfile/<lambda>/try:body/1
arnold_pipelines/megaplan/cloud/controlled_final_launch.py|process.send_signal|signal|canonical-disposition|signal_ladder/<lambda>/try:body/ifexp:body/1
arnold_pipelines/megaplan/cloud/controlled_final_launch.py|process.send_signal|signal|canonical-disposition|signal_ladder/<lambda>/try:body/ifexp:body/2
arnold_pipelines/megaplan/cloud/controlled_final_launch.py|process.send_signal|signal|canonical-disposition|immediate_timeout/<lambda>/try:body/if:body/try:body/1
arnold_pipelines/megaplan/cloud/controlled_final_launch.py|process.send_signal|signal|canonical-disposition|immediate_timeout/<lambda>/try:body/if:body/try:body/2
arnold_pipelines/megaplan/cloud/controlled_final_launch.py|os.kill|probe|liveness-probe|reconcile_spawn_cleanup/if:body/if:orelse/if:orelse/try:body/1
arnold_pipelines/megaplan/cloud/repair_goal.py|os.kill|probe|liveness-probe|_pid_live/try:body/1
arnold_pipelines/megaplan/cloud/repair_lock.py|os.kill|probe|liveness-probe|_default_is_pid_live/try:body/1
arnold_pipelines/megaplan/cloud/status_snapshot.py|os.kill|probe|liveness-probe|_pid_is_live/try:body/1
arnold_pipelines/megaplan/custody/contracts.py|os.kill|probe|liveness-probe|owner_observably_dead/try:body/1
arnold_pipelines/megaplan/handlers/finalize.py|os.kill|probe|liveness-probe|enforce_process_custody_cutover/for:body/if:body/try:body/1
arnold_pipelines/megaplan/incident/disposition.py|os.killpg|signal|canonical-disposition|signal_process_group/<lambda>/if:body/1
arnold_pipelines/megaplan/incident/disposition.py|os.killpg|signal|canonical-disposition|signal_process_group/try:body/1
arnold_pipelines/megaplan/incident/disposition.py|os.kill|signal|canonical-disposition|signal_process/<lambda>/try:body/1
arnold_pipelines/megaplan/incident/disposition.py|os.kill|signal|canonical-disposition|signal_worker/<lambda>/root/1
arnold_pipelines/megaplan/incident/disposition.py|os.kill|signal|canonical-disposition|signal_worker_ladder/invoke_kill/<lambda>/try:body/if:body/try:body/1
arnold_pipelines/megaplan/incident/disposition.py|os.kill|signal|canonical-disposition|signal_worker_ladder/invoke_term/<lambda>/try:body/1
arnold_pipelines/megaplan/incident/disposition.py|signal_worker|signal|canonical-disposition|signal_process_group/if:body/1
arnold_pipelines/megaplan/incident/disposition.py|os.kill|signal|canonical-disposition|_signal_non_worker_cli/<lambda>/try:body/1
arnold_pipelines/megaplan/loop/engine.py|kill_group|signal|neutral-process-group|_terminate_process/root/1
arnold_pipelines/megaplan/managed_agent.py|os.killpg|signal|non-worker-disposition|signal_managed_process/<lambda>/try:body/ifexp:body/1
arnold_pipelines/megaplan/managed_agent.py|os.killpg|signal|non-worker-disposition|signal_managed_process/send/if:body/try:body/if:body/1
arnold_pipelines/megaplan/managed_agent.py|os.kill|probe|liveness-probe|_pid_live/try:body/1
arnold_pipelines/megaplan/managed_agent.py|os.kill|signal|non-worker-disposition|signal_managed_process/<lambda>/try:body/ifexp:orelse/1
arnold_pipelines/megaplan/managed_agent.py|os.kill|signal|non-worker-disposition|signal_managed_process/send/if:body/try:body/if:orelse/1
arnold_pipelines/megaplan/orchestration/suite_runner.py|kill_group|signal|neutral-process-group|_wait_for_process/if:body/1
arnold_pipelines/megaplan/resident/agent_loop.py|_kill_process_group|signal|worker|run/with:body/if:body/1
arnold_pipelines/megaplan/resident/agent_loop.py|signal_process_group|signal|worker|_kill_process_group/try:body/1
arnold_pipelines/megaplan/resident/agent_loop.py|signal_process_group|signal|worker|_kill_process_group/try:handlers/if:body/1
arnold_pipelines/megaplan/resident/agent_loop.py|signal_process_group|signal|worker|_kill_process_group/try:handlers/if:body/2
arnold_pipelines/megaplan/resident/agent_loop.py|_terminate_process_group|signal|worker|_run_locked/with:body/try:handlers/1
arnold_pipelines/megaplan/resident/runtime.py|os.kill|probe|liveness-probe|_pid_is_live/try:body/1
arnold_pipelines/megaplan/runtime/batch.py|process.kill|signal|validation-shard|scatter_gather_processes/_cleanup_active/for:body/if:body/1
arnold_pipelines/megaplan/runtime/batch.py|process.kill|signal|validation-shard|scatter_gather_processes/try:body/while:body/for:body/if:body/if:body/1
arnold_pipelines/megaplan/runtime/batch.py|process.terminate|signal|validation-shard|scatter_gather_processes/_cleanup_active/for:body/if:body/1
arnold_pipelines/megaplan/runtime/batch.py|process.terminate|signal|validation-shard|scatter_gather_processes/try:body/while:body/for:body/if:body/if:body/1
arnold_pipelines/megaplan/runtime/process.py|kill_group|signal|validation-custody|apply_cutover_decision/if:body/1
arnold_pipelines/megaplan/skills/subagent-launcher/fan.py|_kill_tree|signal|worker|_run_one/try:body/try:handlers/1
arnold_pipelines/megaplan/skills/subagent-launcher/fan.py|_kill_tree|signal|worker|_run_one/try:body/try:handlers/if:body/try:handlers/1
arnold_pipelines/megaplan/skills/subagent-launcher/fan.py|os.kill|probe|liveness-probe|_pid_live/try:body/1
arnold_pipelines/megaplan/skills/subagent-launcher/fan_kill.py|_signal|signal|non-worker-lifecycle|main/if:test/1
arnold_pipelines/megaplan/skills/subagent-launcher/fan_kill.py|os.kill|probe|liveness-probe|_pid_alive/try:body/1
arnold_pipelines/megaplan/skills/subagent-launcher/fan_kill.py|signal_process|signal|non-worker-lifecycle|_signal/<lambda>/try:body/if:body/1
arnold_pipelines/megaplan/skills/subagent-launcher/fan_process.py|_signal_process|signal|worker|poll/for:body/if:body/try:body/1
arnold_pipelines/megaplan/skills/subagent-launcher/fan_process.py|_signal_process|signal|worker|poll/for:body/if:body/try:body/2
arnold_pipelines/megaplan/skills/subagent-launcher/fan_process.py|_signal_process|signal|worker|shutdown/for:body/try:body/if:body/1
arnold_pipelines/megaplan/skills/subagent-launcher/fan_process.py|_signal_process|signal|worker|terminate_all/for:body/try:body/if:body/1
arnold_pipelines/megaplan/skills/subagent-launcher/launch_omp_agent.py|_terminate_timed_out_child|signal|worker|run/try:handlers/1
arnold_pipelines/megaplan/watchdog/worker_identity.py|os.kill|probe|liveness-probe|_check_pid_live/try:body/1
scripts/run_m11_validation_shard.py|kill_group|signal|validation-shard|run_validation_shard/with:body/with:body/try:handlers/1
scripts/simulate_watchdog_end_to_end.py|os.kill|signal|simulation|main/with:body/if:body/try:body/1
    """.splitlines()
    if line.strip()
)


def test_python_signal_sites_are_live_and_classified():
    sites = discover_all_signal_sites()
    assert sites, "live Python signal discovery unexpectedly found no sites"
    keys = [site.key for site in sites]
    assert len(keys) == len(set(keys)), "duplicate signal inventory key(s) discovered"
    assert EXPECTED_SITE_KEYS, "inventory baseline must be populated from reviewed discovery"
    assert set(keys) == EXPECTED_SITE_KEYS, "signal inventory drift (vanished/new/renamed site)"
    unclassified = [site for site in sites if not _is_reviewed(site)]
    assert not unclassified, "unclassified Python signal site(s):\n" + "\n".join(
        f"{site.key} (line {site.lineno})" for site in unclassified
    )
    counts: dict[str, int] = {}
    for site in sites:
        counts[site.target_class] = counts.get(site.target_class, 0) + 1
    print("Python signal inventory:")
    for target_class, count in sorted(counts.items()):
        print(f"  {target_class}: {count}")


def test_reviewed_exclusions_are_narrow_and_reasoned():
    assert REVIEWED_CLASS_REASONS
    assert all(reason and len(reason.split()) >= 5 for reason in REVIEWED_CLASS_REASONS.values())
    reviewed_classes = {site.target_class for site in discover_all_signal_sites() if site.action == "signal"}
    assert reviewed_classes <= set(REVIEWED_CLASS_REASONS) | {"canonical-disposition", "worker"}


def test_direct_worker_signal_cannot_hide_behind_file_level_helper():
    tree = ast.parse("""
from arnold_pipelines.megaplan.incident.disposition import signal_process
def stop(proc):
    signal_process(proc.pid, 15)
    proc.kill()
""")
    imported = _imported_names(tree)
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
    symbols = {_symbol(call, imported) for call in calls}
    assert "signal_process" in symbols
    assert "process.kill" in symbols


def test_canonical_door_is_record_before_signal():
    source = (ROOT / "arnold_pipelines/megaplan/incident/disposition.py").read_text(encoding="utf-8")
    door = source[source.index("def record_before_signal("):source.index("\ndef _signal_name")]
    # The preflight path claims and invokes under the ledger lock; the simple
    # path appends the typed disposition before its physical callback.
    assert "signal_fn=invoke_locked" in door
    assert door.index("record = record_disposition") < door.rindex("signal_fn()")
    assert "terminal append failure" in source


def test_record_failure_is_fail_closed():
    from arnold_pipelines.megaplan.incident.disposition import SignalDispositionError, record_before_signal

    class BrokenLedger:
        def append_disposition(self, _value):
            raise OSError("disk full")

    called: list[bool] = []
    try:
        record_before_signal(BrokenLedger(), {"event_type": "worker_disposition"}, lambda: called.append(True))
    except SignalDispositionError:
        pass
    else:
        raise AssertionError("broken ledger must reject signal")
    assert called == []
