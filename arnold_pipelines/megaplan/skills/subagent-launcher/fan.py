#!/usr/bin/env python3
"""Fan out N omp subagent calls through omp (Oh My Pi).

Companion to ``launch_omp_agent.py``: each task runs the
launcher as its own subprocess — which is itself a one-off ``omp -p`` run —
so N independent agents run concurrently without the Arnold/megaplan runtime
in the picture. No shared imports, no SessionDB, no in-process AIAgent.

    <output-dir>/<brief-stem>.txt       — final response (if any)
    <output-dir>/<brief-stem>.meta.json — timestamps, elapsed, status, pid
    <output-dir>/<brief-stem>.pid       — launcher subprocess pid (killable)
    <output-dir>/<brief-stem>.error.txt — traceback (on failure)
    <output-dir>/_fan.pid               — fan parent pid (fan_kill.py reads it)
    <output-dir>/_report.json           — aggregate (per-task summaries + totals)

Each task subprocess is spawned in its own session (``start_new_session``) so
the whole tree — launcher + omp child — can be SIGTERM/SIGKILL'd as a group.
"""

from __future__ import annotations

import concurrent.futures
import json
import multiprocessing
import os
import signal
import subprocess
import sys
import threading
import time
import traceback
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Mapping, Optional


_SCRIPT_DIR = Path(__file__).resolve().parent
_LAUNCHER = _SCRIPT_DIR / "launch_omp_agent.py"

# Stop-event plumbing (same contract as the old fan): SIGINT/SIGTERM set it,
# workers stop submitting, in-flight tasks get a grace window, then children
# are terminated.
_STOP_EVENT = threading.Event()
_SIGINT_TIMES: list[float] = []


def _eprint(*args, **kwargs) -> None:
    kwargs.setdefault("file", sys.stderr)
    print(*args, **kwargs)
    sys.stderr.flush()


def _canonical_group_signal(pid: int, number: int) -> Any:
    """Invoke the canonical group primitive without a PID-only signal door."""
    from arnold_pipelines.megaplan.incident import disposition
    return getattr(disposition, "signal_process_group")(pid, number)


def _pid_live(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _process_start_identity(pid: int) -> str:
    """Read the live canonical, unprefixed process incarnation token."""
    from arnold_pipelines.megaplan.watchdog.worker_identity import read_process_start_identity
    return str(read_process_start_identity(pid) or "")


def _check_codex_network_sandbox() -> None:
    disabled = os.environ.get("CODEX_SANDBOX_NETWORK_DISABLED")
    if disabled:
        _eprint(
            "[fan] FATAL: running inside a `codex exec` sandbox with network "
            f"disabled (CODEX_SANDBOX_NETWORK_DISABLED={disabled}). omp "
            "subagents cannot reach provider APIs.\n"
            "Fix: launch from a normal shell, or run the parent Codex subagent "
            "with `--sandbox danger-full-access`."
        )
        sys.exit(1)


def _sigint_handler(signum, frame):  # noqa: ARG001
    _SIGINT_TIMES.append(time.monotonic())
    _STOP_EVENT.set()


def _sigterm_handler(signum, frame):  # noqa: ARG001
    _STOP_EVENT.set()


def _install_signal_handlers() -> None:
    try:
        signal.signal(signal.SIGINT, _sigint_handler)
        signal.signal(signal.SIGTERM, _sigterm_handler)
    except ValueError:
        # Not on the main thread (shouldn't happen) — skip handlers.
        pass


def _write_pidfile(output_dir: Path) -> Path:
    pidfile = output_dir / "_fan.pid"
    pidfile.write_text(str(os.getpid()) + "\n", encoding="utf-8")
    return pidfile


def _kill_tree(
    pid: int,
    sig: int,
    *,
    environment: Mapping[str, Any] | None = None,
    ladder_step: str | None = None,
) -> bool:
    """Signal one admitted worker process group through ``signal_worker``.

    Fan tasks are workers, even though their transport is a launcher process.
    A missing/inconsistent context is deliberately a no-op: the old PID-only
    compatibility fallback could kill a recycled, unrelated process.
    """
    import sys as _sys
    _root = str(_SCRIPT_DIR.parents[4])
    if _root not in _sys.path:
        _sys.path.insert(0, _root)
    env = os.environ if environment is None else environment
    context_raw = env.get("ARNOLD_WORKER_EXECUTION_CONTEXT")
    identity_raw = env.get("ARNOLD_WORKER_IDENTITY")
    ledger_root = env.get("ARNOLD_INCIDENT_LEDGER_ROOT")
    if not (context_raw and ledger_root):
        _eprint("[fan] refusing worker signal: incomplete execution context")
        return False
    try:
        from arnold_pipelines.megaplan.incident.disposition import WorkerSignalContext, confirmation_id, resolve_worker_execution_context, signal_worker_ladder
        from launch_omp_agent import _gather_confirmation
        from arnold_pipelines.megaplan.incident.ledger import IncidentLedger
        ledger = IncidentLedger(Path(ledger_root))
        context_ref = resolve_worker_execution_context(env)
        if identity_raw:
            worker = json.loads(identity_raw) if isinstance(identity_raw, str) else dict(identity_raw)
        else:
            # A physical worker identity must be supplied by the canonical
            # launch response.  Never recover it from an IncidentLedger
            # launch marker or synthesize it from a PID.
            raise ValueError("canonical worker identity is missing")
        process_start = str(env.get("ARNOLD_WORKER_PROCESS_START_IDENTITY") or "")
        if not process_start:
            raise ValueError("canonical worker process identity is missing")
        context = WorkerSignalContext.from_ref(
            context_ref, worker_identity=worker,
            victim_pid=pid,
            victim_process_start_identity=process_start,
        )
        number = int(sig)
        ids = env.get("ARNOLD_WORKER_CONFIRMATION_EVENT_IDS")
        if isinstance(ids, str):
            ids = json.loads(ids)
        term_id = env.get("ARNOLD_WORKER_CONFIRMATION_EVENT_ID")
        kill_id = None
        if isinstance(ids, Mapping):
            term_id = ids.get("term") or ids.get("SIGTERM") or term_id
            kill_id = ids.get("kill") or ids.get("SIGKILL")
        elif isinstance(ids, (tuple, list)):
            term_id = ids[0] if ids else term_id
            kill_id = ids[1] if len(ids) > 1 else None
        step = ladder_step or ("kill" if number == signal.SIGKILL else "term")
        if not _pid_live(pid):
            from arnold_pipelines.megaplan.incident.disposition import _worker_observation, record_disposition
            record_disposition(ledger, _worker_observation(context, reason="already-dead-before-signal"))
            return False
        chosen = kill_id if step == "kill" else term_id
        # Do not echo the captured expected token: PID reuse must become a
        # typed observation and a zero-signal outcome.
        start_fn = _process_start_identity
        chosen = _gather_confirmation(
            ledger, context, cause_kind="timeout", signal_label="SIGKILL" if step == "kill" else "SIGTERM",
            confirmation_id_value=chosen, liveness_fn=_pid_live,
            process_start_identity_fn=start_fn, environment=env,
        )
        if not chosen:
            return False
        if step == "kill":
            kill_id = chosen
            if not term_id:
                # TERM proof identity is deterministic across the two caller
                # invocations (_run_one calls us once per ladder step).
                term_id = confirmation_id(
                    site_id="subagent-launcher:sigterm", subject_class="worker",
                    victim_pid=pid, victim_process_start_identity=process_start,
                    relevant_progress_identity=str(env.get("ARNOLD_WORKER_RELEVANT_PROGRESS_IDENTITY") or ""),
                    supervisor_incarnation_identity=str(env.get("ARNOLD_SUPERVISOR_INCAR_IDENTITY") or ""),
                    cause_kind="timeout",
                    semantic_dispatch_fingerprint=context.semantic_dispatch_fingerprint,
                    container_identity=env.get("ARNOLD_CONTAINER_IDENTITY"),
                    ladder_stage="term", signal_identity="SIGTERM",
                )
        else:
            term_id = chosen
        result = signal_worker_ladder(
            ledger, context, killer_kind="resident_supervisor", killer_identity=f"fan:{os.getpid()}",
            cause_kind="timeout", term_confirmation_event_id=term_id,
            kill_confirmation_event_id=kill_id,
            term_signal_fn=lambda: _canonical_group_signal(pid, signal.SIGTERM),
            kill_signal_fn=lambda: _canonical_group_signal(pid, signal.SIGKILL),
            liveness_fn=_pid_live,
            process_start_identity_fn=start_fn,
            relevant_progress_identity=env.get("ARNOLD_WORKER_RELEVANT_PROGRESS_IDENTITY"),
            supervisor_incarnation_identity=env.get("ARNOLD_SUPERVISOR_INCAR_IDENTITY"),
            container_identity=env.get("ARNOLD_CONTAINER_IDENTITY"),
        )
        return result.state in {"killed", "already_dead"}
    except ProcessLookupError:
        return False
    except Exception as exc:
        _eprint(f"[fan] refusing worker signal: {exc}")
        return False


@dataclass
class TaskResult:
    brief: str
    stem: str
    model: str
    status: str  # ok | error | timeout | interrupted | cancelled
    elapsed_s: float
    started_at: str
    finished_at: str
    error: Optional[str] = None
    error_class: Optional[str] = None
    finish_reason: Optional[str] = None
    tool_calls: int = 0
    response_chars: int = 0
    response_file: Optional[str] = None
    meta_file: Optional[str] = None
    raw_result_keys: list[str] = field(default_factory=list)
    task_timeout_s: Optional[float] = None
    pid: Optional[int] = None


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _stub_task_result(
    bp: Path,
    model: str,
    *,
    status: str,
    error: str,
    error_class: str,
    task_timeout: float,
) -> TaskResult:
    now = _now()
    return TaskResult(
        brief=str(bp),
        stem=bp.stem,
        model=model,
        status=status,
        elapsed_s=0.0,
        started_at=now,
        finished_at=now,
        error=error,
        error_class=error_class,
        task_timeout_s=task_timeout,
    )


def _parse_model_map(spec: Optional[str]) -> list[tuple[str, str]]:
    """Parse a `--model-map='alias_or_model:glob,...'` spec.

    Aliases are resolved against the launcher's shortcuts; anything containing
    a ``/`` is treated as a literal model selector. First glob match wins.
    """
    out: list[tuple[str, str]] = []
    if not spec:
        return out
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        alias, _, glob = chunk.partition(":")
        alias = alias.strip()
        glob = glob.strip()
        if not alias or not glob:
            continue
        out.append((alias, glob))
    return out


def _pick_model(brief: Path, default_model: str, model_map: list[tuple[str, str]]) -> str:
    for alias, glob in model_map:
        if brief.match(glob) or brief.name.startswith(glob.rstrip("*")):
            return alias
    return default_model


def _collect_briefs(briefs: tuple[str, ...], briefs_dir: Optional[str]) -> list[Path]:
    if briefs and briefs_dir:
        raise SystemExit("error: pass positional briefs OR --briefs-dir, not both")
    if briefs:
        return [Path(b).expanduser().resolve() for b in briefs]
    if briefs_dir:
        d = Path(briefs_dir).expanduser().resolve()
        if not d.is_dir():
            raise SystemExit(f"error: --briefs-dir is not a directory: {d}")
        return sorted(d.glob("*.md"))
    raise SystemExit("error: pass positional briefs or --briefs-dir")


def _run_one(
    brief_path: Path,
    output_dir: Path,
    model: str,
    toolset_list: list[str],
    max_tokens: int,
    task_timeout: float,
    project_dir: Optional[str],
    execution_context: Any = None,
    worker_identity: Any = None,
    process_start_identity: Optional[str] = None,
    confirmation_event_id: Optional[str] = None,
    confirmation_event_ids: Any = None,
) -> TaskResult:
    """Worker — one launcher subprocess (omp run), one brief in/out."""
    stem = brief_path.stem
    tag = stem[:40]
    started_at = _now()
    start = time.monotonic()

    result = TaskResult(
        brief=str(brief_path),
        stem=stem,
        model=model,
        status="error",
        elapsed_s=0.0,
        started_at=started_at,
        finished_at=started_at,
        task_timeout_s=task_timeout,
        pid=os.getpid(),
    )
    response_path = output_dir / f"{stem}.txt"
    meta_path = output_dir / f"{stem}.meta.json"
    result.response_file = str(response_path)
    result.meta_file = str(meta_path)

    def _finalize(write_response: Optional[str] = None) -> None:
        result.elapsed_s = round(time.monotonic() - start, 3)
        result.finished_at = _now()
        try:
            if write_response is not None:
                response_path.write_text(write_response, encoding="utf-8")
                result.response_chars = len(write_response)
            meta_path.write_text(
                json.dumps(asdict(result), indent=2, sort_keys=True),
                encoding="utf-8",
            )
        except OSError as exc:
            _eprint(f"[fan:{tag}] warning: could not write outputs: {exc}")

    try:
        query = brief_path.read_text(encoding="utf-8")
        if not query.strip():
            raise ValueError("brief is empty")

        toolsets_arg = ",".join(toolset_list)
        cmd = [
            sys.executable,
            str(_LAUNCHER),
            f"--model={model}",
            f"--query-file={brief_path}",
            f"--toolsets={toolsets_arg}",
            f"--max-tokens={max_tokens}",
            f"--timeout={task_timeout}",
        ]
        if project_dir:
            cmd.append(f"--project-dir={project_dir}")

        _eprint(
            f"[fan:{tag}] start model={model} toolsets={toolset_list or '(none)'} "
            f"max_tokens={max_tokens} task_timeout={task_timeout}s"
        )

        child_env = os.environ.copy()
        if execution_context is not None:
            context_dict = execution_context.to_dict() if hasattr(execution_context, "to_dict") else dict(execution_context)
            from arnold_pipelines.megaplan.cloud.worker_dispatch import WorkerExecutionContextRef
            context_dict = WorkerExecutionContextRef.from_dict(context_dict).to_dict()
            child_env["ARNOLD_WORKER_EXECUTION_CONTEXT"] = json.dumps(context_dict, sort_keys=True, separators=(",", ":"))
            child_env["ARNOLD_INCIDENT_LEDGER_ROOT"] = str(context_dict["ledger_root"])
        if worker_identity is not None:
            identity_dict = worker_identity.to_dict() if hasattr(worker_identity, "to_dict") else dict(worker_identity)
            child_env["ARNOLD_WORKER_IDENTITY"] = json.dumps(identity_dict, sort_keys=True, separators=(",", ":"))
        if process_start_identity is not None:
            child_env["ARNOLD_WORKER_PROCESS_START_IDENTITY"] = str(process_start_identity)
        if confirmation_event_id is not None:
            child_env["ARNOLD_WORKER_CONFIRMATION_EVENT_ID"] = str(confirmation_event_id)
        if confirmation_event_ids is not None:
            child_env["ARNOLD_WORKER_CONFIRMATION_EVENT_IDS"] = json.dumps(confirmation_event_ids, sort_keys=True, separators=(",", ":"))

        child = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
            cwd=project_dir or None,
            env=child_env,
        )
        result.pid = child.pid
        pidfile = output_dir / f"{stem}.pid"
        try:
            pidfile.write_text(str(child.pid) + "\n", encoding="utf-8")
        except OSError:
            pass

        try:
            stdout, stderr = child.communicate(timeout=task_timeout)
        except subprocess.TimeoutExpired:
            term_sent = _kill_tree(
                child.pid, signal.SIGTERM, environment=child_env, ladder_step="term"
            )
            if term_sent:
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    kill_sent = _kill_tree(
                        child.pid, signal.SIGKILL,
                        environment=child_env, ladder_step="kill"
                    )
                    # A failed canonical admission is fail-closed; never
                    # block forever waiting for a process we were forbidden
                    # to signal.
                    if kill_sent:
                        child.wait()
            result.status = "timeout"
            result.error = f"task exceeded --task-timeout={task_timeout}s"
            result.error_class = "TimeoutError"
            _eprint(f"[fan:{tag}] TIMEOUT after {time.monotonic() - start:.1f}s")
            try:
                pidfile.unlink()
            except OSError:
                pass
            _finalize()
            return result

        # Forward the launcher's diagnostics (tagged).
        for line in (stderr or "").splitlines():
            if line.strip():
                _eprint(f"[fan:{tag}] {line}")

        final = (stdout or "").strip()
        if child.returncode != 0:
            raise RuntimeError(
                f"launcher exited {child.returncode}: "
                f"{(stderr or '').strip()[-300:] or 'no stderr'}"
            )
        if not final:
            raise RuntimeError("launcher returned empty stdout (no final response)")

        result.status = "ok"
        result.raw_result_keys = ["stdout"]
        _eprint(f"[fan:{tag}] ok elapsed={time.monotonic() - start:.1f}s chars={len(final)}")
        _finalize(write_response=final)
        return result

    except KeyboardInterrupt:
        result.status = "interrupted"
        result.error = "KeyboardInterrupt"
        result.error_class = "KeyboardInterrupt"
        _eprint(f"[fan:{tag}] interrupted")
        _finalize()
        raise
    except BaseException as exc:  # noqa: BLE001 — one bad task != fan death
        result.status = "timeout" if isinstance(exc, subprocess.TimeoutExpired) else "error"
        result.error = f"{exc}"
        result.error_class = type(exc).__name__
        _eprint(f"[fan:{tag}] FAIL ({type(exc).__name__}): {exc}")
        try:
            (output_dir / f"{stem}.error.txt").write_text(
                traceback.format_exc(), encoding="utf-8"
            )
        except OSError:
            pass
        _finalize()
        return result


def run(
    *briefs: str,
    briefs_dir: Optional[str] = None,
    output_dir: str = "./fan_out",
    max_workers: int = 5,
    model: str = "deepseek:deepseek-v4-flash",
    model_map: Optional[str] = None,
    toolsets: str = "file,web",
    max_tokens: int = 65536,
    project_dir: Optional[str] = None,
    session_id: Optional[str] = None,
    task_timeout: float = 1800.0,
    isolation: str = "threads",
    execution_context: Any = None,
    execution_contexts: Any = None,
    worker_identities: Any = None,
    process_start_identities: Any = None,
    confirmation_event_ids: Any = None,
) -> None:
    """Fan out N omp-backed subagent calls.

    Args:
        briefs: Positional brief paths (mutually exclusive with --briefs-dir).
        briefs_dir: Directory of `*.md` briefs. Sorted alphabetically.
        output_dir: Per-brief `.txt` / `.meta.json` / `.pid` and aggregate
            `_report.json` land here. Created if missing.
        max_workers: Concurrent task subprocesses.
        model: Default model spec (megaplan prefix convention, translated by
            the launcher to an omp selector).
        model_map: Optional `"alias_or_model:glob,..."` mapping. Aliases:
            fast/mimo/mimo-fast/pro/flash/grok, or a literal model selector.
            First glob match wins; falls back to `--model`.
        toolsets: Comma-separated subset of {file, web, terminal}; `""` for
            pure chat (omp --no-tools).
        max_tokens: Informational (omp uses the model's native ceiling).
        project_dir: cwd for the subagent processes.
        session_id: Ignored (omp sessions are ephemeral in this launcher).
        task_timeout: Per-task wall-clock deadline (seconds), enforced with
            SIGTERM → SIGKILL on the task's process group. Default 1800.
        isolation: ``"threads"`` (default) or ``"processes"``. Both run one
            subprocess per task; "processes" uses a fork pool so a single
            SIGKILL cannot take down the fan parent.
    """
    overall_start = time.monotonic()

    if isolation not in ("threads", "processes"):
        raise SystemExit(
            f"error: --isolation must be 'threads' or 'processes', got {isolation!r}"
        )
    if session_id:
        _eprint("[fan] NOTE: --session-id is ignored (omp sessions are ephemeral).")

    if project_dir:
        target = Path(project_dir).expanduser().resolve()
        if not target.is_dir():
            raise SystemExit(f"error: --project-dir is not a directory: {target}")

    brief_paths = _collect_briefs(briefs, briefs_dir)
    out_root = Path(output_dir).expanduser().resolve()
    out_root.mkdir(parents=True, exist_ok=True)

    toolset_list = [t.strip() for t in str(toolsets).split(",") if t.strip()]
    parsed_map = _parse_model_map(model_map)

    pidfile_path = _write_pidfile(out_root)
    _install_signal_handlers()

    _eprint(
        f"[fan] briefs={len(brief_paths)} max_workers={max_workers} "
        f"default_model={model} toolsets={toolset_list or '(none)'} "
        f"max_tokens={max_tokens} task_timeout={task_timeout}s "
        f"isolation={isolation} output_dir={out_root} pid={os.getpid()}"
    )
    if parsed_map:
        _eprint(f"[fan] model_map={parsed_map}")

    results: list[TaskResult] = []
    exit_code = 0

    def _submit_loop(executor) -> None:
        futures: dict = {}
        try:
            for bp in brief_paths:
                if _STOP_EVENT.is_set():
                    results.append(
                        _stub_task_result(
                            bp,
                            _pick_model(bp, model, parsed_map),
                            status="cancelled",
                            error="not started (stop event set before submit)",
                            error_class="Cancelled",
                            task_timeout=task_timeout,
                        )
                    )
                    continue
                chosen = _pick_model(bp, model, parsed_map)
                fut = executor.submit(
                    _run_one,
                    bp,
                    out_root,
                    chosen,
                    toolset_list,
                    max_tokens,
                    task_timeout,
                    project_dir,
                    (execution_contexts or {}).get(bp.stem, execution_context) if isinstance(execution_contexts, Mapping) else execution_context,
                    (worker_identities or {}).get(bp.stem) if isinstance(worker_identities, Mapping) else None,
                    (process_start_identities or {}).get(bp.stem) if isinstance(process_start_identities, Mapping) else None,
                    (confirmation_event_ids or {}).get(bp.stem) if isinstance(confirmation_event_ids, Mapping) else confirmation_event_ids,
                )
                futures[fut] = (bp, chosen)

            signal_at: Optional[float] = None
            grace_s = 10.0
            while futures:
                if _STOP_EVENT.is_set():
                    if signal_at is None:
                        signal_at = time.monotonic()
                    pending = [f for f in futures if not f.running() and not f.done()]
                    for f in pending:
                        if f.cancel():
                            bp, chosen = futures.pop(f)
                            results.append(
                                _stub_task_result(
                                    bp,
                                    chosen,
                                    status="cancelled",
                                    error="cancelled by signal before start",
                                    error_class="Cancelled",
                                    task_timeout=task_timeout,
                                )
                            )
                    if time.monotonic() - signal_at > grace_s:
                        _eprint(
                            f"[fan] grace expired after {grace_s}s — terminating "
                            f"{len(futures)} in-flight task(s)"
                        )
                        for f, (bp, chosen) in list(futures.items()):
                            results.append(
                                _stub_task_result(
                                    bp,
                                    chosen,
                                    status="interrupted",
                                    error="in-flight at signal; terminated after grace",
                                    error_class="Interrupted",
                                    task_timeout=task_timeout,
                                )
                            )
                            futures.pop(f, None)
                        break

                done, _ = concurrent.futures.wait(
                    list(futures.keys()),
                    timeout=0.5,
                    return_when=concurrent.futures.FIRST_COMPLETED,
                )
                for fut in done:
                    bp, chosen = futures.pop(fut)
                    try:
                        results.append(fut.result())
                    except (concurrent.futures.CancelledError, KeyboardInterrupt) as exc:
                        results.append(
                            _stub_task_result(
                                bp,
                                chosen,
                                status="interrupted",
                                error=f"{exc}",
                                error_class=type(exc).__name__,
                                task_timeout=task_timeout,
                            )
                        )
                    except BaseException as exc:  # noqa: BLE001
                        results.append(
                            _stub_task_result(
                                bp,
                                chosen,
                                status="error",
                                error=f"executor: {exc}",
                                error_class=type(exc).__name__,
                                task_timeout=task_timeout,
                            )
                        )
        finally:
            stopped = _STOP_EVENT.is_set()
            try:
                executor.shutdown(wait=not stopped, cancel_futures=True)
            except TypeError:
                executor.shutdown(wait=not stopped)

    try:
        if isolation == "processes":
            ctx = multiprocessing.get_context("fork")
            pool = ctx.Pool(processes=max_workers)
            try:
                _submit_loop(_ThreadPoolFromPool(pool))
            finally:
                pool.close()
                pool.join()
        else:
            executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
            _submit_loop(executor)
    finally:
        try:
            if pidfile_path.exists():
                pidfile_path.unlink()
        except OSError:
            pass

    if _STOP_EVENT.is_set():
        exit_code = 130 if _SIGINT_TIMES else 143

    results.sort(key=lambda r: r.stem)
    elapsed_total = time.monotonic() - overall_start
    succeeded = [r for r in results if r.status == "ok"]
    failed = [r for r in results if r.status != "ok"]

    report = {
        "briefs_dir": briefs_dir,
        "output_dir": str(out_root),
        "default_model": model,
        "model_map": parsed_map,
        "max_workers": max_workers,
        "toolsets": toolset_list,
        "max_tokens": max_tokens,
        "task_timeout_s": task_timeout,
        "isolation": isolation,
        "project_dir": project_dir,
        "total_count": len(results),
        "succeeded_count": len(succeeded),
        "failed_count": len(failed),
        "stopped_by_signal": _STOP_EVENT.is_set(),
        "wall_clock_s": round(elapsed_total, 3),
        "sum_agent_seconds": round(sum(r.elapsed_s for r in results), 3),
        "tasks": [asdict(r) for r in results],
    }
    report_path = out_root / "_report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    print(
        f"fan: {len(succeeded)}/{len(results)} ok, {len(failed)} failed "
        f"in {elapsed_total:.1f}s (sum_agent={report['sum_agent_seconds']}s) "
        f"→ {report_path}"
    )
    for r in failed:
        print(f"  {r.status.upper()} {r.stem}: [{r.error_class}] {r.error}")

    if exit_code:
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(exit_code)
    if failed:
        sys.exit(1)


class _ThreadPoolFromPool:
    """Minimal adapter so the threads-style submit loop drives a fork pool."""

    def __init__(self, pool: Any) -> None:
        self._pool = pool

    def submit(self, fn, *args, **kwargs):
        return _PoolFuture(self._pool.apply_async(fn, args, kwargs))


class _PoolFuture:
    def __init__(self, result: Any) -> None:
        self._result = result

    def done(self) -> bool:
        return self._result.ready()

    def running(self) -> bool:
        return not self._result.ready()

    def cancel(self) -> bool:
        return False  # already-started pool tasks can't be cancelled

    def result(self, timeout: Optional[float] = None):
        return self._result.get(timeout)


def main() -> None:
    _check_codex_network_sandbox()
    try:
        import fire
    except ImportError:
        _eprint("error: this script requires `fire`. Install with `pip install fire`.")
        sys.exit(1)
    fire.Fire(run)


if __name__ == "__main__":
    main()
