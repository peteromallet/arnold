"""Arnold workflow CLI.

Subcommands operate on a single builder target:

    arnold workflow check --module package.module:build_pipeline
    arnold workflow manifest --module package.module:build_pipeline
    arnold workflow dot --module package.module:build_pipeline
    arnold workflow dry-run --module package.module:build_pipeline
    arnold workflow run --module package.module:build_pipeline
    arnold workflow resume --module package.module:build_pipeline
    arnold workflow describe --module package.module:build_pipeline
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Sequence

import arnold.workflow as workflow
from arnold.cli.workflow_diagnostics import (
    render_human_diagnostics,
    render_json_envelope,
)
from arnold.cli.workflow_explain import build_explain_entries
from arnold.cli.workflow_source_topology import build_source_topology
from arnold.execution import ExecutionRegistries, run
from arnold.execution.backend import SkeletalBackend
from arnold.execution.observability import ExecutionLogger
from arnold.execution.state_store import FileStateStore
from arnold.execution.result import ExecutionResult
from arnold.manifest.refs import NodeRef, manifest_coordinate
from arnold.workflow import (
    compile_pipeline,
    dry_run,
    inspect_manifest,
    to_dot,
    to_yaml,
)
from arnold.pipeline.types import Pipeline as GraphPipeline
from arnold.workflow.dsl import Pipeline as WorkflowPipeline, Route as WorkflowRoute, Step as WorkflowStep
from arnold_pipelines.discovery import load_builder


def _load_builder(target: str) -> Callable[[], Any]:
    return load_builder(target)


def _ref_token(value: str) -> str:
    token = re.sub(r"[^A-Za-z0-9_.:-]+", "_", value.strip())
    return token or "default"


def _graph_stage_kind(stage: Any) -> str:
    step = getattr(stage, "step", None)
    if step is not None:
        return _ref_token(str(getattr(step, "kind", "compute")))
    steps = getattr(stage, "steps", None) or ()
    kinds = [_ref_token(str(getattr(item, "kind", "compute"))) for item in steps]
    if not kinds:
        return "parallel"
    return _ref_token("parallel:" + "+".join(kinds))


def _workflow_from_graph_pipeline(pipeline: GraphPipeline, *, target: str) -> WorkflowPipeline:
    steps = tuple(
        WorkflowStep(
            id=_ref_token(name),
            kind=_graph_stage_kind(stage),
            label=name,
            metadata={"source": "arnold.pipeline", "builder": target},
        )
        for name, stage in pipeline.stages.items()
    )
    routes: list[WorkflowRoute] = []
    for source, stage in pipeline.stages.items():
        for edge in getattr(stage, "edges", ()) or ():
            target_name = getattr(edge, "target", "")
            if not target_name or target_name == "halt":
                continue
            label = _ref_token(str(getattr(edge, "label", "default") or "default"))
            routes.append(
                WorkflowRoute(
                    id=_ref_token(f"{source}:{target_name}:{label}"),
                    source=_ref_token(source),
                    target=_ref_token(str(target_name)),
                    label=label,
                )
            )
    return WorkflowPipeline(
        id=_ref_token(getattr(pipeline, "entry", None) or target.rsplit(":", 1)[0]),
        version="1.0",
        steps=steps,
        routes=tuple(routes),
        metadata={"source": "arnold.pipeline", "builder": target},
    )


def _source_path_from_advertised_value(value: Any, *, module_file: str | None) -> Path | None:
    if value is None:
        return None
    try:
        path = Path(value)
    except TypeError:
        return None
    if not path.is_absolute() and module_file:
        cwd_path = Path.cwd() / path
        if cwd_path.exists():
            return cwd_path
        path = Path(module_file).resolve().parent / path
    return path


def _advertised_authoring_source_path(target: str) -> Path | None:
    builder = _load_builder(target)
    module = sys.modules.get(getattr(builder, "__module__", ""))
    if module is None and ":" in target:
        module_name, _ = target.rsplit(":", 1)
        module = importlib.import_module(module_name)
    module_file = getattr(module, "__file__", None) if module is not None else None
    for owner in (builder, module):
        if owner is None:
            continue
        for attr in (
            "AUTHORING_SOURCE_PATH",
            "authoring_source_path",
            "__authoring_source_path__",
        ):
            path = _source_path_from_advertised_value(
                getattr(owner, attr, None),
                module_file=module_file,
            )
            if path is not None:
                return path
    return None


def _compile_from_target(target: str) -> workflow.WorkflowManifest:
    builder = _load_builder(target)
    pipeline = builder()
    if isinstance(pipeline, GraphPipeline):
        pipeline = _workflow_from_graph_pipeline(pipeline, target=target)
    if not isinstance(pipeline, WorkflowPipeline):
        raise ValueError(
            f"builder {target!r} returned {type(pipeline).__name__}, expected Pipeline"
        )
    return compile_pipeline(pipeline)


def _output(data: Any, fmt: str) -> str:
    if fmt == "json":
        return json.dumps(data, sort_keys=True, indent=2)
    return to_yaml(data)


def _write_atomic(path: Path, content: str) -> None:
    """Write ``content`` to ``path`` atomically via a temporary file."""

    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        shutil.move(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise


def _print_result(result: ExecutionResult) -> None:
    payload = {
        "state": result.state.value,
        "manifest_id": result.manifest_id,
        "manifest_hash": result.manifest_hash,
        "artifact_root": str(result.artifact_root),
        "outputs": dict(result.outputs),
        "diagnostics": [
            {"code": d.code, "message": d.message, "node_id": d.node_id}
            for d in result.diagnostics
        ],
        "resume_cursor": result.resume_cursor.key if result.resume_cursor else None,
        "is_terminal": result.is_terminal,
    }
    print(json.dumps(payload, sort_keys=True, indent=2))


def _cmd_check(args: argparse.Namespace) -> int:
    try:
        source_path = _source_path_from_args_or_module(args)
    except Exception as exc:
        if args.format == "json":
            print(render_json_envelope(exc, source_kind="module"))
        else:
            print(f"check failed: {exc}", file=sys.stderr)
        return 1

    if source_path is not None:
        result = workflow.check_workflow_file(source_path)
        if args.format == "json":
            if result.ok:
                print(
                    json.dumps(
                        {
                            "ok": True,
                            "source": {"kind": "python", "path": str(source_path)},
                            "diagnostics": [],
                        },
                        sort_keys=True,
                        indent=2,
                    )
                )
            else:
                print(render_json_envelope(result.diagnostics, source_path=source_path))
        elif result.ok:
            print(f"ok: {source_path}")
        else:
            print(render_human_diagnostics(result.diagnostics, source_path=source_path))
        return 0 if result.ok else 1

    if not args.module:
        print(
            render_human_diagnostics(
                "check requires either <workflow.py|.pypeline> or --module package.module:build_pipeline"
            ),
            file=sys.stderr,
        )
        return 2

    try:
        manifest = _compile_from_target(args.module)
    except Exception as exc:
        if args.format == "json":
            print(render_json_envelope(exc, source_kind="module"))
        else:
            print(f"check failed: {exc}", file=sys.stderr)
        return 1
    print(f"ok: {manifest.id} ({manifest.manifest_hash})")
    return 0


def _cmd_manifest(args: argparse.Namespace) -> int:
    try:
        manifest = _compile_from_target(args.module)
    except Exception as exc:
        print(f"manifest failed: {exc}", file=sys.stderr)
        return 1
    print(_output(manifest.to_dict(include_hashes=True), args.format))
    return 0


def _cmd_dot(args: argparse.Namespace) -> int:
    try:
        manifest = _compile_from_target(args.module)
    except Exception as exc:
        print(f"dot failed: {exc}", file=sys.stderr)
        return 1
    print(to_dot(manifest))
    return 0


def _cmd_dry_run(args: argparse.Namespace) -> int:
    try:
        manifest = _compile_from_target(args.module)
    except Exception as exc:
        print(f"dry-run failed: {exc}", file=sys.stderr)
        return 1
    print(_output(dry_run(manifest), args.format))
    return 0


def _parse_budget(raw: str | None) -> dict[str, Any] | None:
    if not raw:
        return None
    return json.loads(raw)


def _cmd_run(args: argparse.Namespace) -> int:
    try:
        manifest = _compile_from_target(args.module)
    except Exception as exc:
        print(f"run failed: {exc}", file=sys.stderr)
        return 1

    artifact_root = Path(args.artifact_root or f"./runs/{manifest.id}")
    backend = None
    if args.backend == "fake":
        backend = SkeletalBackend()

    state_store = None
    if args.state_store_dir:
        state_store = FileStateStore(args.state_store_dir)

    registries = ExecutionRegistries()
    budget = _parse_budget(args.budget)
    if budget is not None:
        from arnold.kernel import GovernorBudget

        registries.budget = GovernorBudget(
            cost_limit=budget.get("max_cost"),
            seconds_limit=budget.get("max_seconds"),
            token_limit=budget.get("token_budget"),
        )

    logger = ExecutionLogger()
    result = run(
        manifest,
        artifact_root=artifact_root,
        backend=backend,
        state_store=state_store,
        registries=registries,
        logger=logger,
    )
    _print_result(result)
    return 0 if result.state.value == "completed" else 1


def _cmd_resume(args: argparse.Namespace) -> int:
    try:
        manifest = _compile_from_target(args.module)
    except Exception as exc:
        print(f"resume failed: {exc}", file=sys.stderr)
        return 1

    resume_cursor = None
    if args.cursor:
        # cursor is the manifest coordinate key; resume from the manifest start.
        resume_cursor = manifest_coordinate(
            manifest.id, manifest.manifest_hash or ""
        ).cursor()
    elif args.node:
        resume_cursor = manifest_coordinate(
            manifest.id, manifest.manifest_hash or ""
        ).cursor(node=NodeRef(args.node))

    artifact_root = Path(args.artifact_root or f"./runs/{manifest.id}")
    backend = None
    if args.backend == "fake":
        backend = SkeletalBackend()

    state_store = None
    if args.state_store_dir:
        state_store = FileStateStore(args.state_store_dir)

    logger = ExecutionLogger()
    result = run(
        manifest,
        artifact_root=artifact_root,
        backend=backend,
        state_store=state_store,
        resume_cursor=resume_cursor,
        logger=logger,
    )
    _print_result(result)
    return 0 if result.state.value == "completed" else 1


def _cmd_describe(args: argparse.Namespace) -> int:
    try:
        manifest = _compile_from_target(args.module)
    except Exception as exc:
        print(f"describe failed: {exc}", file=sys.stderr)
        return 1
    view = inspect_manifest(manifest)
    view["builder_target"] = args.module
    print(_output(view, args.format))
    return 0


def _source_path_or_none(args: argparse.Namespace) -> Path | None:
    raw = getattr(args, "source_path", None)
    return Path(raw) if raw else None


def _source_path_from_args_or_module(args: argparse.Namespace) -> Path | None:
    source_path = _source_path_or_none(args)
    if source_path is not None:
        return source_path
    module = getattr(args, "module", None)
    if module:
        return _advertised_authoring_source_path(module)
    return None


def _cmd_compile(args: argparse.Namespace) -> int:
    source_path = _source_path_or_none(args)
    try:
        if source_path is not None:
            manifest = workflow.compile_workflow_file(source_path)
        elif args.module:
            manifest = _compile_from_target(args.module)
        else:
            print(
                "compile requires either <workflow.py|.pypeline> or --module package.module:build_pipeline",
                file=sys.stderr,
            )
            return 2
    except (workflow.SourceCompileError, workflow.ManifestValidationError) as exc:
        diagnostics_json = getattr(args, "diagnostics_json", None)
        if diagnostics_json:
            rendered = render_json_envelope(exc, source_path=source_path)
            if diagnostics_json == "-":
                print(rendered)
            else:
                _write_atomic(Path(diagnostics_json), rendered + "\n")
        else:
            print(
                render_human_diagnostics(exc, source_path=source_path),
                file=sys.stderr,
            )
        return 1
    except Exception as exc:
        print(f"compile failed: {exc}", file=sys.stderr)
        return 1

    manifest_json = manifest.to_json()
    if args.out:
        _write_atomic(Path(args.out), manifest_json + "\n")
    else:
        print(manifest_json)
    return 0


def _cmd_inspect(args: argparse.Namespace) -> int:
    try:
        source_path = _source_path_from_args_or_module(args)
        if source_path is not None:
            check_result = workflow.check_workflow_file(source_path)
            manifest = workflow.compile_workflow_file(source_path)
        elif args.module:
            check_result = None
            manifest = _compile_from_target(args.module)
        else:
            print(
                "inspect requires either <workflow.py|.pypeline> or --module package.module:build_pipeline",
                file=sys.stderr,
            )
            return 2
    except (workflow.SourceCompileError, workflow.ManifestValidationError) as exc:
        if args.format == "json":
            print(render_json_envelope(exc, source_path=source_path))
        else:
            print(
                render_human_diagnostics(exc, source_path=source_path),
                file=sys.stderr,
            )
        return 1
    except Exception as exc:
        print(f"inspect failed: {exc}", file=sys.stderr)
        return 1

    view = inspect_manifest(manifest)
    if source_path is not None and check_result is not None:
        decl = check_result.parsed_source.workflow
        if decl is not None:
            view["workflow"] = {
                "id": decl.id,
                "version": decl.version,
                "source_form": decl.source_form,
                "function_name": decl.function_name,
                "parameters": decl.parameters,
                "source_path": str(source_path),
            }
            view["components"] = [
                {
                    "id": step.id,
                    "component_ref": step.component_ref,
                    "source_span": _span_dict(step.source_span),
                }
                for step in decl.source_block.steps
            ]
        view.pop("hash_inputs", None)
    if args.module:
        view["builder_target"] = args.module
    print(_output(view, args.format))
    return 0


def _span_dict(span: Any) -> dict[str, Any] | None:
    if span is None:
        return None
    return {
        "path": span.path,
        "start_line": span.start_line,
        "start_column": span.start_column,
        "end_line": span.end_line,
        "end_column": span.end_column,
    }


def _cmd_explain(args: argparse.Namespace) -> int:
    try:
        source_path = _source_path_from_args_or_module(args)
    except Exception as exc:
        print(f"explain failed: {exc}", file=sys.stderr)
        return 1
    if source_path is None:
        print(
            "explain requires <workflow.py|.pypeline> or --module with AUTHORING_SOURCE_PATH",
            file=sys.stderr,
        )
        return 2

    try:
        check_result = workflow.check_workflow_file(source_path)
        manifest = workflow.compile_workflow_file(source_path)
    except (workflow.SourceCompileError, workflow.ManifestValidationError) as exc:
        if args.format == "json":
            print(render_json_envelope(exc, source_path=source_path))
        else:
            print(
                render_human_diagnostics(exc, source_path=source_path),
                file=sys.stderr,
            )
        return 1
    except Exception as exc:
        print(f"explain failed: {exc}", file=sys.stderr)
        return 1

    decl = check_result.parsed_source.workflow
    if decl is None:
        print("explain failed: no workflow declaration found", file=sys.stderr)
        return 1

    entries = build_explain_entries(decl, manifest)

    if args.format == "json":
        print(
            json.dumps(
                {
                    "workflow": {
                        "id": decl.id,
                        "version": decl.version,
                        "source_path": str(source_path),
                    },
                    "entries": entries,
                },
                sort_keys=True,
                indent=2,
            )
        )
    else:
        print(f"Workflow {decl.id} (v{decl.version}) in {source_path}")
        def render_entry(entry: dict[str, Any], *, prefix: str, depth: int) -> None:
            source = entry.get("source") or {}
            line = source.get("start_line")
            loc = f"line {line}" if line is not None else "unknown location"
            indent = "  " * depth
            print(f"{indent}{prefix} [{entry['kind']}] {entry['id']} ({loc}) - {entry['summary']}")
            for child_index, child in enumerate(entry.get("children", []), start=1):
                render_entry(child, prefix=f"{prefix}.{child_index}", depth=depth + 1)

        for idx, entry in enumerate(entries, start=1):
            render_entry(entry, prefix=str(idx), depth=0)
    return 0


def _graph_annotations_from_source_topology(
    source_topology: dict[str, Any],
    manifest: workflow.WorkflowManifest,
) -> dict[str, Any]:
    edge_annotations: dict[str, dict[str, str]] = {}
    for branch in source_topology.get("branches", []):
        if not isinstance(branch, dict):
            continue
        decision_output = branch.get("decision_output")
        if not isinstance(decision_output, str) or not decision_output:
            continue
        for arm in branch.get("arms", []):
            if not isinstance(arm, dict):
                continue
            condition = arm.get("condition")
            if isinstance(condition, dict):
                literal = condition.get("literal")
                suffix = f".{decision_output}.eq.{literal}"
                label = str(literal) if literal is not None else None
            else:
                suffix = f".{decision_output}.else"
                label = "else"
            if not label:
                continue
            for edge in manifest.edges:
                if edge.condition_ref and edge.condition_ref.endswith(suffix):
                    edge_annotations[edge.id] = {
                        "label": label,
                        "condition_ref": edge.condition_ref,
                    }
    return {"edges": edge_annotations}


def _mermaid_group_id(raw: str) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in raw)


def _mermaid_node_line(node: Any) -> str:
    label = node.label or node.id
    return f"    {node.id}[\"{label}\"]"


def _render_mermaid_graph(
    manifest: workflow.WorkflowManifest,
    source_topology: dict[str, Any],
) -> str:
    grouped_node_ids: set[str] = set()
    lines = ["flowchart TD"]

    for loop in source_topology.get("loops", []):
        if not isinstance(loop, dict):
            continue
        body_node_ids = [
            node_id for node_id in loop.get("body_node_ids", []) if isinstance(node_id, str)
        ]
        if not body_node_ids:
            continue
        loop_id = str(loop.get("id") or "loop")
        lines.append(f"    subgraph {_mermaid_group_id(loop_id)}[\"loop: {loop_id}\"]")
        for node in manifest.nodes:
            if node.id in body_node_ids:
                lines.append("    " + _mermaid_node_line(node))
                grouped_node_ids.add(node.id)
        lines.append("    end")

    for branch in source_topology.get("branches", []):
        if not isinstance(branch, dict):
            continue
        branch_id = str(branch.get("id") or "branch")
        arms = [arm for arm in branch.get("arms", []) if isinstance(arm, dict)]
        if not arms:
            continue
        lines.append(f"    subgraph {_mermaid_group_id(branch_id)}[\"branch: {branch_id}\"]")
        for arm in arms:
            node_ids = [
                node_id for node_id in arm.get("node_ids", []) if isinstance(node_id, str)
            ]
            if not node_ids:
                continue
            condition = arm.get("condition")
            arm_label = "else"
            if isinstance(condition, dict) and condition.get("literal") is not None:
                arm_label = str(condition["literal"])
            arm_id = str(arm.get("id") or f"{branch_id}-arm-{arm.get('index', 0)}")
            lines.append(f"        subgraph {_mermaid_group_id(arm_id)}[\"{arm_label}\"]")
            for node in manifest.nodes:
                if node.id in node_ids:
                    lines.append("        " + _mermaid_node_line(node))
                    grouped_node_ids.add(node.id)
            lines.append("        end")
        lines.append("    end")

    for node in manifest.nodes:
        if node.id not in grouped_node_ids:
            lines.append(_mermaid_node_line(node))
    for edge in manifest.edges:
        label = edge.label or ""
        if edge.condition_ref:
            label = f"{label}:{edge.condition_ref}"
        lines.append(f"    {edge.source} -->|{label}| {edge.target}")
    return "\n".join(lines)


def _cmd_graph(args: argparse.Namespace) -> int:
    source_path = _source_path_or_none(args)
    if source_path is None:
        print("graph requires <workflow.py|.pypeline>", file=sys.stderr)
        return 2

    try:
        check_result = workflow.check_workflow_file(source_path)
        if not check_result.ok:
            if args.format == "json":
                print(render_json_envelope(check_result.diagnostics, source_path=source_path))
            else:
                print(
                    render_human_diagnostics(check_result.diagnostics, source_path=source_path),
                    file=sys.stderr,
                )
            return 1
        manifest = workflow.compile_workflow_file(source_path)
    except (workflow.SourceCompileError, workflow.ManifestValidationError) as exc:
        if args.format == "json":
            print(render_json_envelope(exc, source_path=source_path))
        else:
            print(
                render_human_diagnostics(exc, source_path=source_path),
                file=sys.stderr,
            )
        return 1
    except Exception as exc:
        print(f"graph failed: {exc}", file=sys.stderr)
        return 1

    fmt = args.format
    output: str
    decl = check_result.parsed_source.workflow
    source_topology = (
        build_source_topology(decl, manifest)
        if decl is not None
        else {"nodes": {}, "branches": [], "loops": []}
    )
    if fmt == "dot":
        output = workflow.to_dot(
            manifest,
            annotations=_graph_annotations_from_source_topology(source_topology, manifest),
        )
    elif fmt == "mermaid":
        output = _render_mermaid_graph(manifest, source_topology)
    elif fmt == "json":
        nodes = []
        for node in manifest.nodes:
            annotation = source_topology["nodes"].get(node.id, {})
            nodes.append(
                {
                    "id": node.id,
                    "kind": node.kind,
                    "label": node.label,
                    "source_span": _span_dict(node.source_span),
                    "nesting_depth": annotation.get("nesting_depth"),
                    "source_role": annotation.get("source_role") or annotation.get("kind"),
                    "branch_id": annotation.get("branch_id"),
                    "branch_arm_id": annotation.get("branch_arm_id"),
                    "branch_decision_output": annotation.get("branch_decision_output"),
                    "branch_condition_literal": annotation.get("branch_condition_literal"),
                    "loop_id": annotation.get("loop_id"),
                    "loop_policy_ref": annotation.get("loop_policy_ref"),
                    "loop_reentry_id": annotation.get("loop_reentry_id"),
                }
            )
        edges = [
            {
                "id": edge.id,
                "source": edge.source,
                "target": edge.target,
                "label": edge.label,
                "condition_ref": edge.condition_ref,
            }
            for edge in manifest.edges
        ]
        output = json.dumps(
            {
                "nodes": nodes,
                "edges": edges,
                "source_topology": source_topology,
            },
            sort_keys=True,
            indent=2,
        )
    else:
        print(f"unsupported graph format: {fmt}", file=sys.stderr)
        return 2

    if args.out:
        _write_atomic(Path(args.out), output + "\n")
    else:
        print(output)
    return 0


def build_parser(prog: str = "arnold workflow") -> argparse.ArgumentParser:
    """Return the ``<program> workflow`` argument parser."""

    parser = argparse.ArgumentParser(
        prog=prog,
        description="Compile, inspect, and run explicit-node Arnold workflows.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    source_file_commands = {"check", "compile", "inspect", "explain", "graph"}
    for name, help_text in [
        ("check", "Validate a workflow source file or builder target."),
        ("compile", "Compile a workflow source file or builder target to a manifest."),
        ("inspect", "Inspect a workflow source file or builder target."),
        ("explain", "Explain a workflow source file as an ordered narrative."),
        ("graph", "Render a topology graph of a workflow source file."),
        ("manifest", "Emit the compiled workflow manifest."),
        ("dot", "Emit a DOT graph of the compiled manifest."),
        ("dry-run", "Print a dry-run report without executing."),
        ("run", "Run a compiled workflow manifest."),
        ("resume", "Resume a workflow from a checkpoint or cursor."),
        ("describe", "Inspect a compiled workflow manifest."),
    ]:
        sub = subparsers.add_parser(name, help=help_text)
        if name in source_file_commands:
            sub.add_argument(
                "source_path",
                nargs="?",
                help="Python-shaped workflow source file (.py or .pypeline).",
            )
        sub.add_argument(
            "--module",
            required=name not in source_file_commands,
            help="Builder target: package.module:build_pipeline",
        )
        if name == "graph":
            sub.add_argument(
                "--format",
                choices=["dot", "mermaid", "json"],
                default="dot",
                help="Graph output format.",
            )
            sub.add_argument(
                "--out",
                help="Output path for the graph.",
            )
        else:
            default_fmt = "human" if name in {"check", "inspect", "explain"} else "yaml"
            sub.add_argument(
                "--format",
                choices=["human", "yaml", "json"],
                default=default_fmt,
                help="Output format.",
            )
        if name == "compile":
            sub.add_argument(
                "--out",
                help="Output path for the compiled manifest JSON.",
            )
            sub.add_argument(
                "--diagnostics-json",
                dest="diagnostics_json",
                help="Write machine-readable failure diagnostics to PATH or '-' for stdout.",
            )
        if name in {"run", "resume"}:
            sub.add_argument(
                "--artifact-root",
                help="Directory for the journal and artifacts.",
            )
            sub.add_argument(
                "--state-store-dir",
                help="Directory for JSON checkpoints.",
            )
            sub.add_argument(
                "--backend",
                choices=["local", "fake"],
                default="local",
                help="Execution backend (default: local).",
            )
        if name == "run":
            sub.add_argument(
                "--budget",
                help='JSON budget object, e.g. {"max_cost": 10.0}.',
            )
        if name == "resume":
            sub.add_argument(
                "--cursor",
                action="store_true",
                help="Resume from the manifest coordinate cursor.",
            )
            sub.add_argument(
                "--node",
                help="Resume from a specific node id.",
            )

    return parser


def main(argv: Sequence[str] | None = None, prog: str = "arnold workflow") -> int:
    parser = build_parser(prog)

    dispatch = {
        "check": _cmd_check,
        "compile": _cmd_compile,
        "inspect": _cmd_inspect,
        "explain": _cmd_explain,
        "graph": _cmd_graph,
        "manifest": _cmd_manifest,
        "dot": _cmd_dot,
        "dry-run": _cmd_dry_run,
        "run": _cmd_run,
        "resume": _cmd_resume,
        "describe": _cmd_describe,
    }

    args = parser.parse_args(argv)
    return dispatch[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
