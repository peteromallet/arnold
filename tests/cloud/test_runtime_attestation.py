from __future__ import annotations

import json
import hashlib
import importlib.metadata
import os
import shutil
import subprocess
import sys
import types
import venv
from pathlib import Path

import pytest

from arnold_pipelines.megaplan.cloud import runtime_attestation as attestation
from arnold_pipelines.megaplan.cloud.runtime_provenance import (
    normalized_runtime_identity,
)
from arnold_pipelines.megaplan.types import CliError


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def _release_seed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    **build_kwargs: object,
) -> tuple[dict[str, object], dict[str, Path]]:
    root = tmp_path / "runtime"
    wrapper_dir = root / "arnold_pipelines" / "megaplan" / "cloud" / "wrappers"
    wrapper_dir.mkdir(parents=True)
    (wrapper_dir / "arnold-watchdog").write_text("#!/bin/sh\n", encoding="utf-8")
    revision = "a" * 40
    receipt = tmp_path / "supervisor-receipt.json"
    hot_env = tmp_path / "runtime.env"
    marker = tmp_path / "marker.json"
    chain_spec = tmp_path / "chain.yaml"
    seed_doc = tmp_path / "NORTHSTAR.md"
    manifest = tmp_path / "runtime-manifest.json"
    _write_json(
        receipt,
        {
            "fingerprint": "supervisor-fingerprint",
            "runtime": sys.prefix,
            "source": str(root),
            "source_revision": revision,
            "imports": {"arnold_pipelines": str(root / "arnold_pipelines")},
        },
    )
    hot_env.write_text(
        f"export MEGAPLAN_RUNTIME_SRC={root}\n",
        encoding="utf-8",
    )
    runtime_identity = {
        "import_root": str(root),
        "source_revision": revision,
        "content_sha256": "b" * 64,
    }
    _write_json(
        marker,
        {
            "session": "m10",
            "workspace": str(tmp_path),
            "remote_spec": str(chain_spec),
            "identity_digest": "identity-123",
            "run_kind": "chain",
            "relaunch_command": "python -m arnold_pipelines.megaplan chain tick",
            "editable_source_branch": "fix/m10",
            "editable_source_head": revision,
            "operator_pause": {"active": True},
            "should_run": False,
            "runtime_binding": {"current_identity": runtime_identity},
        },
    )
    chain_spec.write_text("milestones: []\n", encoding="utf-8")
    seed_doc.write_text("# North Star\n", encoding="utf-8")
    manifest.write_bytes(b'{"schema":"1","generation":1}\n')
    provenance = {
        "ok": True,
        "ready": True,
        "errors": [],
        "import_root": str(root),
        "source_revision": revision,
    }
    modules = [
        {
            "module": "arnold_pipelines.megaplan.cloud.runtime_attestation",
            "path": str(
                root
                / "arnold_pipelines"
                / "megaplan"
                / "cloud"
                / "runtime_attestation.py"
            ),
            "root": str(root),
        }
    ]
    chain_binding = {
        "spec_path": str(chain_spec),
        "current_milestone_index": 0,
        "current_plan_name": "m10",
        "runtime_identity": runtime_identity,
    }
    chain_binding["content_sha256"] = attestation._canonical_sha256(chain_binding)
    monkeypatch.setattr(attestation, "runtime_provenance", lambda **_kwargs: provenance)
    monkeypatch.setattr(attestation, "_pth_vector", lambda _root: ([], []))
    monkeypatch.setattr(attestation, "_chain_binding", lambda _path: chain_binding)
    supervisor_modules = [
        {"module": "arnold", "path": str(root / "arnold" / "__init__.py"), "root": str(root)},
        {
            "module": "arnold_pipelines",
            "path": str(root / "arnold_pipelines" / "__init__.py"),
            "root": str(root),
        },
        {
            "module": "arnold_pipelines.megaplan",
            "path": str(root / "arnold_pipelines" / "megaplan" / "__init__.py"),
            "root": str(root),
        },
    ]
    supervisor_vector = {
        "source": str(root),
        "source_revision": revision,
        "source_fingerprint": "supervisor-fingerprint",
        "runtime": sys.prefix,
        "runtime_provenance": {"install_mode": "noneditable", "direct_url": {}},
        "loaded_modules": supervisor_modules,
        "interpreter": {},
        "site_pth": [],
        "errors": [],
        "ready": True,
    }
    supervisor_vector["content_sha256"] = attestation._canonical_sha256(
        supervisor_vector
    )
    monkeypatch.setattr(
        attestation,
        "_module_vector",
        lambda scan_root: (
            supervisor_modules
            if Path(scan_root).resolve(strict=False)
            == Path(sys.prefix).resolve(strict=False)
            else modules,
            [],
        ),
    )
    monkeypatch.setattr(
        attestation,
        "_supervisor_module_vector",
        lambda _root: (supervisor_modules, []),
    )
    monkeypatch.setattr(
        attestation,
        "_probe_supervisor_runtime",
        lambda _receipt: supervisor_vector,
    )
    monkeypatch.setattr(
        attestation,
        "supervisor_runtime_vector",
        lambda **_kwargs: supervisor_vector,
    )
    _write_json(
        receipt,
        {
            "fingerprint": "supervisor-fingerprint",
            "runtime": sys.prefix,
            "source": str(root),
            "source_revision": revision,
            "imports": {
                "arnold": supervisor_modules[0]["path"],
                "arnold_pipelines": supervisor_modules[1]["path"],
                "megaplan": supervisor_modules[2]["path"],
            },
        },
    )
    seed = attestation.build_runtime_launch_seed(
        expected_root=root,
        expected_revision=revision,
        supervisor_receipt_path=receipt,
        hot_env_path=hot_env,
        marker_path=marker,
        chain_spec_path=chain_spec,
        seed_doc_paths=[seed_doc],
        manifest_path=manifest,
        **build_kwargs,
    )
    return seed, {
        "root": root,
        "receipt": receipt,
        "hot_env": hot_env,
        "marker": marker,
        "chain_spec": chain_spec,
        "seed_doc": seed_doc,
        "manifest": manifest,
        "wrapper": wrapper_dir / "arnold-watchdog",
    }


def test_release_seed_binds_full_runtime_and_seed_document_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seed, paths = _release_seed(tmp_path, monkeypatch)

    assert seed["ready"] is True
    assert seed["errors"] == []
    assert seed["expected_root"] == str(paths["root"])
    assert seed["loaded_modules"]
    assert seed["interpreter"]["executable"] == str(Path(sys.executable).resolve())
    assert seed["interpreter"]["direct_url"] == {}
    assert seed["supervisor_receipt"]["fingerprint"] == "supervisor-fingerprint"
    assert seed["hot_env"]["selectors"]["MEGAPLAN_RUNTIME_SRC"] == str(paths["root"])
    assert seed["wrappers"][0]["sha256"]
    assert seed["chain_runtime_binding"]["runtime_identity"]["import_root"] == str(
        paths["root"]
    )
    manifest_paths = {
        item["path"] for item in seed["seed_document_manifest"]["entries"]
    }
    assert str(paths["seed_doc"]) in manifest_paths
    assert str(paths["marker"]) not in manifest_paths
    assert (
        attestation.validate_runtime_launch_seed(seed, component="worker")["status"]
        == "ready"
    )


def test_cloud_seed_manifest_identity_is_exact_bytes_and_rejects_format_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seed, paths = _release_seed(tmp_path, monkeypatch)
    expected = hashlib.sha256(paths["manifest"].read_bytes()).hexdigest()
    assert seed["manifest_identity"] == expected
    assert seed["manifest_sha256"] == expected

    # Same JSON meaning, different bytes: the launch identity must still
    # change, and the worker-side admission gate must reject before dispatch.
    paths["manifest"].write_bytes(b'{"generation":1,"schema":"1"}\n')
    with pytest.raises(CliError, match="manifest identity drifted"):
        attestation.validate_runtime_launch_seed(seed, component="worker")


def test_complete_loaded_module_vector_rejects_mixed_and_late_modules(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seed, _paths = _release_seed(tmp_path, monkeypatch)
    original = list(seed["loaded_modules"])
    monkeypatch.setattr(
        attestation,
        "_module_vector",
        lambda _root: (
            [
                *original,
                {
                    "module": "arnold_pipelines.late_import",
                    "path": "/other/arnold_pipelines/late_import.py",
                    "root": "",
                },
            ],
            ["mixed_module_root:arnold_pipelines.late_import"],
        ),
    )

    with pytest.raises(CliError, match="escaped the expected root"):
        attestation.validate_runtime_launch_seed(seed, component="worker")


def test_worker_with_fewer_modules_than_seed_validates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Builder-only seed modules (chain-CLI imports) are not worker requirements.

    Occurrence prep-retry-20260815T0020Z: the seed was rebuilt by the fat
    chain CLI (325 loaded_modules incl. relaunch_resolution/runtime_cutover/
    runtime_manifest/shadow_attestation) and the thin prep worker imports
    none of those.  Presence is optional; identity, when present, is strict.
    """
    seed, _paths = _release_seed(tmp_path, monkeypatch)
    # A worker that imports none of the seed-listed modules (strictly weaker
    # than the real 321/325 case) must still validate.
    monkeypatch.setattr(attestation, "_module_vector", lambda _root: ([], []))

    result = attestation.validate_runtime_launch_seed(seed, component="worker")
    assert result["status"] == "ready"


def test_worker_module_identity_drift_still_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Presence is optional, but a present module must match exactly."""
    seed, _paths = _release_seed(tmp_path, monkeypatch)
    drifted = [
        {
            "module": "arnold_pipelines.megaplan.cloud.runtime_attestation",
            "path": "/other/arnold_pipelines/megaplan/cloud/runtime_attestation.py",
            "root": "/other",
        }
    ]
    monkeypatch.setattr(attestation, "_module_vector", lambda _root: (drifted, []))

    with pytest.raises(CliError, match="loaded module identity changed"):
        attestation.validate_runtime_launch_seed(seed, component="worker")


def test_unowned_executable_pth_is_recorded_and_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    site_dir = tmp_path / "site-packages"
    site_dir.mkdir()
    pth = site_dir / "unowned.pth"
    pth.write_text(
        "import sys; sys.path.insert(0, '/tmp/ambient')\n../runtime\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(attestation, "_active_site_dirs", lambda: [site_dir])
    monkeypatch.setattr(attestation, "_pth_owners", lambda _path: {})

    vector, errors = attestation._pth_vector(tmp_path / "runtime")

    assert vector[0]["lines"][0] == {
        "kind": "executable",
        "raw": "import sys; sys.path.insert(0, '/tmp/ambient')",
        "resolved": "",
    }
    assert errors == [f"unowned_executable_pth:{pth}"]


def _write_generated_virtualenv_bootstrap(site_dir: Path) -> Path:
    """Copy the real uv-seeded bootstrap used by this test interpreter."""

    source = (
        Path(sys.prefix)
        / "lib"
        / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages"
        / "_virtualenv.py"
    )
    if not source.is_file() or source.is_symlink():
        pytest.skip("tests require a uv/virtualenv-seeded interpreter")
    bootstrap = site_dir / "_virtualenv.py"
    shutil.copyfile(source, bootstrap)
    return bootstrap


def test_generated_virtualenv_bootstrap_is_the_only_unowned_executable_pth_exception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    site_dir = tmp_path / "site-packages"
    site_dir.mkdir()
    _write_generated_virtualenv_bootstrap(site_dir)
    pth = site_dir / "_virtualenv.pth"
    pth.write_bytes(attestation._VIRTUALENV_PTH_CONTENT)
    monkeypatch.setattr(attestation, "_active_site_dirs", lambda: [site_dir])
    monkeypatch.setattr(attestation, "_pth_owners", lambda _path: {})

    vector, errors = attestation._pth_vector(tmp_path / "runtime")

    assert errors == []
    assert vector[0]["path"] == str(pth)
    assert vector[0]["lines"] == [
        {"kind": "executable", "raw": "import _virtualenv", "resolved": ""}
    ]


@pytest.mark.parametrize("mutation", ["pth", "module", "missing", "symlink"])
def test_virtualenv_bootstrap_exception_fails_closed_on_any_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    site_dir = tmp_path / "site-packages"
    site_dir.mkdir()
    bootstrap = _write_generated_virtualenv_bootstrap(site_dir)
    pth = site_dir / "_virtualenv.pth"
    pth.write_bytes(attestation._VIRTUALENV_PTH_CONTENT)
    if mutation == "pth":
        pth.write_bytes(b"import _virtualenv; __import__('os')\n")
    elif mutation == "module":
        bootstrap.write_bytes(bootstrap.read_bytes() + b"# altered\n")
    elif mutation == "missing":
        bootstrap.unlink()
    else:
        target = tmp_path / "trusted-copy.py"
        shutil.copyfile(bootstrap, target)
        bootstrap.unlink()
        bootstrap.symlink_to(target)
    monkeypatch.setattr(attestation, "_active_site_dirs", lambda: [site_dir])
    monkeypatch.setattr(attestation, "_pth_owners", lambda _path: {})

    _vector, errors = attestation._pth_vector(tmp_path / "runtime")

    assert errors == [f"unowned_executable_pth:{pth}"]


@pytest.mark.parametrize("drift_target", ["wrapper", "seed_doc", "hot_env"])
def test_release_seed_rejects_runtime_and_seed_input_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift_target: str,
) -> None:
    seed, paths = _release_seed(tmp_path, monkeypatch)
    paths[drift_target].write_text("changed\n", encoding="utf-8")

    with pytest.raises(CliError):
        attestation.validate_runtime_launch_seed(seed, component="worker")


def test_release_seed_allows_marker_lifecycle_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seed, paths = _release_seed(tmp_path, monkeypatch)
    marker = json.loads(paths["marker"].read_text(encoding="utf-8"))
    marker.update(
        {
            "should_run": True,
            "launch_outcome": {"status": "running"},
            "updated_at": "2026-07-23T12:00:00Z",
        }
    )
    marker.pop("operator_pause", None)
    _write_json(paths["marker"], marker)

    assert (
        attestation.validate_runtime_launch_seed(seed, component="worker")["status"]
        == "ready"
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("workspace", "/workspace/other"),
        ("remote_spec", "/workspace/other/chain.yaml"),
        ("relaunch_command", "python -m other"),
        ("editable_source_head", "c" * 40),
    ],
)
def test_release_seed_rejects_marker_launch_identity_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: str,
) -> None:
    seed, paths = _release_seed(tmp_path, monkeypatch)
    marker = json.loads(paths["marker"].read_text(encoding="utf-8"))
    marker[field] = value
    _write_json(paths["marker"], marker)

    with pytest.raises(CliError, match="cloud marker launch binding drifted"):
        attestation.validate_runtime_launch_seed(seed, component="worker")


def test_release_seed_rejects_marker_runtime_identity_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seed, paths = _release_seed(tmp_path, monkeypatch)
    marker = json.loads(paths["marker"].read_text(encoding="utf-8"))
    marker["runtime_binding"]["current_identity"]["source_revision"] = "c" * 40
    _write_json(paths["marker"], marker)

    with pytest.raises(CliError, match="cloud marker launch binding drifted"):
        attestation.validate_runtime_launch_seed(seed, component="worker")


def test_stale_process_attestation_is_rejected_after_restart_or_selector_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seed, paths = _release_seed(tmp_path, monkeypatch)
    original = {
        "pid": 123,
        "start_ticks": "100",
        "executable": "/bin/bash",
        "executable_sha256": "c" * 64,
        "selectors": {"MEGAPLAN_RUNTIME_SRC": str(paths["root"])},
    }
    monkeypatch.setattr(attestation, "_proc_identity", lambda _pid: original)
    process_attestation = attestation.create_runtime_process_attestation(
        seed,
        component="watchdog",
        target_pid=123,
    )
    restarted = {**original, "start_ticks": "101"}
    monkeypatch.setattr(attestation, "_proc_identity", lambda _pid: restarted)

    with pytest.raises(CliError, match="stale or belongs to another process"):
        attestation.validate_runtime_process_attestation(
            seed,
            process_attestation,
            component="watchdog",
            target_pid=123,
        )


def test_real_module_scan_reports_an_import_outside_expected_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = types.ModuleType("arnold_pipelines.foreign_runtime")
    module.__file__ = "/tmp/foreign/arnold_pipelines/foreign_runtime.py"
    monkeypatch.setitem(sys.modules, module.__name__, module)

    _vector, errors = attestation._module_vector(Path(__file__).resolve().parents[2])

    assert "mixed_module_root:arnold_pipelines.foreign_runtime" in errors


def _venv_site(python: Path) -> Path:
    result = subprocess.check_output(
        [
            str(python),
            "-c",
            "import sysconfig; print(sysconfig.get_paths()['purelib'])",
        ],
        text=True,
    )
    return Path(result.strip())


def _install_test_runtime(
    runtime: Path,
    source: Path,
    *,
    editable: bool,
) -> Path:
    venv.EnvBuilder(with_pip=False).create(runtime)
    python = runtime / "bin" / "python3"
    site_dir = _venv_site(python)
    for dependency in (
        "yaml",
        "pydantic",
        "pydantic_core",
        "annotated_types",
        "typing_extensions",
        "typing_inspection",
        "ulid",
        "psutil",
    ):
        module_path = Path(__import__(dependency).__file__).resolve()
        if module_path.name == "__init__.py":
            shutil.copytree(module_path.parent, site_dir / dependency)
        else:
            shutil.copy2(module_path, site_dir / module_path.name)
        for distribution_name in importlib.metadata.packages_distributions().get(
            dependency, []
        ):
            distribution = importlib.metadata.distribution(distribution_name)
            metadata_dir = Path(distribution._path)  # type: ignore[attr-defined]
            destination = site_dir / metadata_dir.name
            if metadata_dir.is_dir() and not destination.exists():
                shutil.copytree(metadata_dir, destination)
    dist = site_dir / "arnold-0.0.dist-info"
    dist.mkdir()
    (dist / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: arnold\nVersion: 0.0\n",
        encoding="utf-8",
    )
    (dist / "direct_url.json").write_text(
        json.dumps(
            {
                "url": source.resolve().as_uri(),
                "dir_info": {"editable": True} if editable else {},
            }
        ),
        encoding="utf-8",
    )
    if editable:
        pth = site_dir / "arnold-editable.pth"
        pth.write_text(str(source.resolve()) + "\n", encoding="utf-8")
        (dist / "RECORD").write_text("arnold-editable.pth,,\n", encoding="utf-8")
    else:
        for package in ("arnold", "arnold_pipelines", "agentbox"):
            shutil.copytree(source / package, site_dir / package)
        (dist / "RECORD").write_text("", encoding="utf-8")
    return python


def test_real_editable_launch_and_noneditable_supervisor_vectors(
    tmp_path: Path,
) -> None:
    source = Path(__file__).resolve().parents[2]
    revision = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"],
        text=True,
    ).strip()
    launch_python = _install_test_runtime(
        tmp_path / "launch-venv",
        source,
        editable=True,
    )
    supervisor_runtime = tmp_path / "supervisor-venv"
    supervisor_python = _install_test_runtime(
        supervisor_runtime,
        source,
        editable=False,
    )
    receipt_path = tmp_path / "supervisor-receipt.json"
    import_program = (
        "import json,pathlib,arnold,arnold_pipelines,arnold_pipelines.megaplan as m;"
        "print(json.dumps({'arnold':str(pathlib.Path(arnold.__file__).resolve()),"
        "'arnold_pipelines':str(pathlib.Path(arnold_pipelines.__file__).resolve()),"
        "'megaplan':str(pathlib.Path(m.__file__).resolve())}))"
    )
    imports = json.loads(
        subprocess.check_output(
            [str(supervisor_python), "-P", "-c", import_program],
            text=True,
            cwd=tmp_path,
            env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        )
    )
    _write_json(
        receipt_path,
        {
            "schema_version": "arnold-supervisor-runtime-receipt-v1",
            "fingerprint": "real-two-venv",
            "runtime": str(supervisor_runtime),
            "source": str(source),
            "source_revision": revision,
            "imports": imports,
            "status": "ready",
        },
    )
    runtime_library = (
        source
        / "arnold_pipelines"
        / "megaplan"
        / "cloud"
        / "wrappers"
        / "arnold-supervisor-runtime-lib"
    )
    wrapper_check = subprocess.run(
        [
            "bash",
            "-c",
            (
                f"source {str(runtime_library)!r}; "
                f"arnold_supervisor_runtime_init test-component {str(source)!r}; "
                "printf 'isolated=%s\\n' \"$MEGAPLAN_SUPERVISOR_ISOLATED\""
            ),
        ],
        cwd=tmp_path,
        env={
            **{key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
            "MEGAPLAN_SUPERVISOR_PYTHON": str(supervisor_python),
            "MEGAPLAN_SUPERVISOR_RUNTIME_REQUIRED": "1",
            "MEGAPLAN_SUPERVISOR_RUNTIME_RECEIPT": str(receipt_path),
            "MEGAPLAN_RUNTIME_ATTESTATION_REQUIRED": "0",
        },
        text=True,
        capture_output=True,
    )
    assert wrapper_check.returncode == 0, wrapper_check.stderr
    assert "isolated=1" in wrapper_check.stdout
    program = tmp_path / "build-and-validate.py"
    program.write_text(
        """
import json
import pathlib
import sys
from arnold_pipelines.megaplan.chain import spec as chain_spec
from arnold_pipelines.megaplan.cloud.runtime_attestation import (
    build_runtime_launch_seed,
    validate_runtime_launch_seed,
)
from arnold_pipelines.megaplan.cloud.runtime_provenance import (
    normalized_runtime_identity,
    runtime_provenance,
)

source, revision, receipt, output, work = sys.argv[1:]
source = pathlib.Path(source)
work = pathlib.Path(work)
spec = work / "chain.yaml"
spec.write_text("milestones: []\\n")
manifest = work / "runtime-manifest.json"
manifest.write_bytes(b'{"schema":"1","generation":1}\\n')
identity = normalized_runtime_identity(
    runtime_provenance(expected_root=source, expected_revision=revision)
)
state = chain_spec.ChainState(
    metadata={"execution_binding": {"runtime_binding": {"current_identity": identity}}}
)
state_path = chain_spec._state_path_for(spec)
state_path.parent.mkdir(parents=True, exist_ok=True)
state_path.write_text(json.dumps(state.to_dict()))
marker = work / "marker.json"
marker.write_text(json.dumps({"runtime_binding": {"current_identity": identity}}))
hot = work / "hot.env"
hot.write_text("\\n".join([
    f"export MEGAPLAN_RUNTIME_SRC={source}",
    f"export MEGAPLAN_LAUNCH_RUNTIME_SRC={source}",
    f"export MEGAPLAN_SUPERVISOR_SOURCE={source}",
    f"export CLOUD_WATCHDOG_ARNOLD_SRC={source}",
    f"export MEGAPLAN_META_ARNOLD_SRC={source}",
    f"export MEGAPLAN_AUDIT_ARNOLD_SRC={source}",
]) + "\\n")
doc = work / "NORTHSTAR.md"
doc.write_text("# real two venv seed\\n")
seed = build_runtime_launch_seed(
    expected_root=source,
    expected_revision=revision,
    supervisor_receipt_path=pathlib.Path(receipt),
    hot_env_path=hot,
    marker_path=marker,
    chain_spec_path=spec,
    seed_doc_paths=[doc],
    manifest_path=manifest,
)
assert seed["ready"], seed["errors"]
assert validate_runtime_launch_seed(seed, component="worker")["status"] == "ready"
pathlib.Path(output).write_text(json.dumps(seed))
""",
        encoding="utf-8",
    )
    seed_path = tmp_path / "seed.json"
    clean_env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
    subprocess.run(
        [
            str(launch_python),
            "-P",
            str(program),
            str(source),
            revision,
            str(receipt_path),
            str(seed_path),
            str(tmp_path),
        ],
        check=True,
        cwd=tmp_path,
        env=clean_env,
    )
    validate_program = (
        "import json,pathlib,sys;"
        "from arnold_pipelines.megaplan.cloud.runtime_attestation import "
        "validate_runtime_launch_seed;"
        "s=json.loads(pathlib.Path(sys.argv[1]).read_text());"
        "assert validate_runtime_launch_seed(s,component='supervisor')['status']=='ready'"
    )
    subprocess.run(
        [str(supervisor_python), "-P", "-c", validate_program, str(seed_path)],
        check=True,
        cwd=tmp_path,
        env=clean_env,
    )
    seed = json.loads(seed_path.read_text(encoding="utf-8"))
    assert seed["interpreter"]["venv"] == str(tmp_path / "launch-venv")
    assert seed["runtime_provenance"]["direct_url"]["dir_info"]["editable"] is True
    assert seed["supervisor_runtime"]["interpreter"]["venv"] == str(supervisor_runtime)
    assert (
        seed["supervisor_runtime"]["runtime_provenance"]["direct_url"]["dir_info"]
        == {}
    )


def test_long_lived_entrypoints_validate_attestation_before_work() -> None:
    repo = Path(__file__).resolve().parents[2]
    wrappers = repo / "arnold_pipelines" / "megaplan" / "cloud" / "wrappers"
    library = (wrappers / "arnold-supervisor-runtime-lib").read_text(encoding="utf-8")
    watchdog = (wrappers / "arnold-watchdog").read_text(encoding="utf-8")
    supervise = (wrappers / "arnold-supervise").read_text(encoding="utf-8")
    resident_cli = (
        repo / "arnold_pipelines" / "megaplan" / "resident" / "cli.py"
    ).read_text(encoding="utf-8")
    resident_runtime = (
        repo / "arnold_pipelines" / "megaplan" / "resident" / "runtime.py"
    ).read_text(encoding="utf-8")

    assert "arnold_runtime_attestation_start" in library
    assert "verify-process" in library
    assert "arnold_runtime_attestation_check watchdog" in watchdog
    assert "arnold_supervisor_runtime_init supervisor" in supervise
    assert "arnold_runtime_attestation_check supervisor" in supervise
    assert 'require_configured_runtime_launch("resident", create=True)' in resident_cli
    assert 'require_configured_runtime_launch("resident")' in resident_runtime


def test_configured_runtime_attestation_required_defaults_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """P3 deny-by-default: attestation is required unless explicitly disabled."""
    monkeypatch.delenv("MEGAPLAN_RUNTIME_ATTESTATION_REQUIRED", raising=False)
    assert attestation.configured_runtime_attestation_required() is True

    monkeypatch.setenv("MEGAPLAN_RUNTIME_ATTESTATION_REQUIRED", "1")
    assert attestation.configured_runtime_attestation_required() is True

    monkeypatch.setenv("MEGAPLAN_RUNTIME_ATTESTATION_REQUIRED", "")
    assert attestation.configured_runtime_attestation_required() is True

    monkeypatch.setenv("MEGAPLAN_RUNTIME_ATTESTATION_REQUIRED", "0")
    assert attestation.configured_runtime_attestation_required() is False


def test_release_seed_accepts_supervisor_receipt_from_another_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """G14 regression: the Jul-31 supervisor wheel is prepared from its own
    consolidated source, which legitimately differs from the per-epic worker
    root/revision.  The seed must still build ready=true — the supervisor is
    attested independently (probe ready + fingerprint + import-receipt
    self-consistency + runtime prefix), never by source/revision equality."""
    seed, paths = _release_seed(tmp_path, monkeypatch)
    assert seed["ready"] is True

    receipt = json.loads(paths["receipt"].read_text(encoding="utf-8"))
    receipt["source"] = str(tmp_path / "supervisor-src")
    receipt["source_revision"] = "d" * 40
    _write_json(paths["receipt"], receipt)

    seed2 = attestation.build_runtime_launch_seed(
        expected_root=paths["root"],
        expected_revision="a" * 40,
        supervisor_receipt_path=paths["receipt"],
        hot_env_path=paths["hot_env"],
            marker_path=paths["marker"],
            chain_spec_path=paths["chain_spec"],
            seed_doc_paths=[paths["seed_doc"]],
            manifest_path=paths["manifest"],
        )
    assert seed2["ready"] is True
    assert seed2["errors"] == []
    assert seed2["supervisor_receipt"]["source"] == str(
        (tmp_path / "supervisor-src").resolve()
    )
    assert seed2["supervisor_receipt"]["source_revision"] == "d" * 40


def test_normalized_identity_mirrors_active_execution_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """d587/a2c3644905c0 regression: normalized_runtime_identity forced
    editable_revision='' while active_execution_identity derives it from the
    editable root's git revision, so _strict_external_runtime_shape raised
    editable_revision_mismatch on a launch-ready runtime.  Mirror the chain
    binding: fall back to the editable root's git revision when one exists."""
    from arnold_pipelines.megaplan.cloud import runtime_provenance as rp

    # A git root exists -> identity derives its HEAD revision, matching
    # active_execution_identity's editable_revision.
    git_root = tmp_path / "editable-root"
    git_root.mkdir()
    subprocess.run(["git", "-C", str(git_root), "init", "-q"], check=True)
    (git_root / "marker.txt").write_text("x", encoding="utf-8")
    subprocess.run(
        ["git", "-C", str(git_root), "add", "-A"], check=True, capture_output=True
    )
    subprocess.run(
        ["git", "-C", str(git_root), "commit", "-qm", "seed"],
        check=True,
        capture_output=True,
    )
    head = subprocess.run(
        ["git", "-C", str(git_root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    prov = {
        "editable_root": str(git_root),
        "source_revision": head,
        "editable_revision": "",
    }
    identity = normalized_runtime_identity(prov)
    assert identity["editable_revision"] == head
    assert len(identity["content_sha256"]) == 64

    # No editable root -> stays empty (worktree-first T-0301 runtime).
    prov_none = {"editable_root": "", "source_revision": "a" * 40}
    identity_none = normalized_runtime_identity(prov_none)
    assert identity_none["editable_revision"] == ""

    # Explicit editable_revision wins over the fallback.
    prov_explicit = {
        "editable_root": str(git_root),
        "source_revision": "b" * 40,
        "editable_revision": "c" * 40,
    }
    identity_explicit = normalized_runtime_identity(prov_explicit)
    assert identity_explicit["editable_revision"] == "c" * 40


def _ensure_seed_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    revision: str = "a" * 40,
) -> dict[str, object]:
    """A manifest-pinned launch-seed environment reusing the release-seed mocks.

    The marker is written in the FULL content-addressed identity form and its
    relaunch command names root + revision, so a stale marker can be rebound
    through the CAS helper when the head advances.
    """
    seed, paths = _release_seed(tmp_path, monkeypatch)
    root = paths["root"]
    state = {"revision": revision}

    def _provenance(**_kwargs: object) -> dict[str, object]:
        return {
            "ok": True,
            "ready": True,
            "errors": [],
            "import_root": str(root),
            "editable_root": str(root),
            "source_revision": state["revision"],
            "runtime_revision": state["revision"],
            "direct_url": {},
            "pth": [],
            "imports": {
                "arnold": str(root / "arnold" / "__init__.py"),
                "arnold_pipelines": str(root / "arnold_pipelines" / "__init__.py"),
                "megaplan": str(root / "arnold_pipelines" / "megaplan" / "__init__.py"),
            },
        }

    monkeypatch.setattr(attestation, "runtime_provenance", _provenance)
    monkeypatch.setattr(attestation, "_git_revision", lambda _root: state["revision"])
    identity = normalized_runtime_identity(_provenance())
    marker = json.loads(paths["marker"].read_text(encoding="utf-8"))
    marker["runtime_binding"]["current_identity"] = dict(identity)
    marker["bootstrap_manifest_path"] = str(tmp_path / "runtime-manifest.json")
    marker["relaunch_command"] = (
        f"python -m arnold_pipelines.megaplan chain {root} {state['revision']}"
    )
    _write_json(paths["marker"], marker)

    def _regenerate_relaunch_command() -> None:
        """Simulate the repair-loop regenerating a command that binds the
        CURRENT runtime (root + revision) while the identity stays stale."""
        marker = json.loads(paths["marker"].read_text(encoding="utf-8"))
        marker["relaunch_command"] = (
            f"python -m arnold_pipelines.megaplan chain {root} {state['revision']}"
        )
        _write_json(paths["marker"], marker)

    manifest_path = tmp_path / "runtime-manifest.json"

    def _write_manifest() -> None:
        _write_json(
            manifest_path,
            {
                "runtime_id": "runtime-test-1",
                "schema": "1",
                "generation": 3,
                "epic_id": "epic-demo",
                "state": "active",
                "owner": "test",
                "base": {
                    "ref": "refs/heads/base/editable-install",
                    "commit": "87a912beb",
                    "editable_install_path": str(root / "base"),
                    "venv_path": str(root / "base" / "venv"),
                },
                "epic": {
                    "branch": "fixer/epic-demo-20260807",
                    "worktree_path": str(root),
                    "venv_path": str(root / "venv"),
                    "runtime_root": str(root),
                    "expected_head": state["revision"],
                    "repair_bin": str(root / "venv" / "bin" / "arnold-babysitter"),
                    "deps_lockfile": str(root / "uv.lock"),
                },
                "indirection": {
                    "host_path": str(root),
                    "container_path": "/workspace/epic-demo",
                    "mount_table": [],
                    "execution_namespace": "epic-demo-ns",
                    "verified_head": state["revision"],
                    "last_verified_at": "2026-08-13T00:00:00+00:00",
                    "attestation": {
                        "module_file": str(root / "arnold_pipelines" / "__init__.py"),
                        "module_digest": "d41d8cd98f00b204e9800998ecf8427e",
                        "mount_id": "0:42",
                    },
                },
                "policy": {
                    "policy_sha": "policy-sha-1",
                    "model_policy_sha": "model-sha-1",
                    "sync_policy": "push-on-promote",
                },
                "promotions": [],
                "timestamps": {
                    "created": "2026-08-13T00:00:00+00:00",
                    "updated": "2026-08-13T00:00:00+00:00",
                    "closed": "",
                },
                "gc_policy": "closed-only",
                "commands": ["megaplan chain"],
            },
        )

    _write_manifest()
    marker = json.loads(paths["marker"].read_text(encoding="utf-8"))
    manifest_identity = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    marker["manifest_identity"] = manifest_identity
    marker["manifest_sha256"] = manifest_identity
    _write_json(paths["marker"], marker)
    seed_dir = tmp_path / "launch-seeds"
    return {
        "manifest": manifest_path,
        "paths": paths,
        "seed_dir": seed_dir,
        "identity": identity,
        "state": state,
        "write_manifest": _write_manifest,
        "provenance": _provenance,
        "regenerate_relaunch_command": _regenerate_relaunch_command,
    }


def test_ensure_runtime_launch_seed_rebuilds_on_head_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """G14: ensure_runtime_launch_seed writes the canonical seed once and
    rebuilds it when the manifest-pinned HEAD changes (missing -> build,
    current -> reuse, drifted -> rebuild)."""
    env = _ensure_seed_env(tmp_path, monkeypatch)
    assert isinstance(env["manifest"], Path)
    manifest = env["manifest"]
    paths = env["paths"]
    assert isinstance(paths, dict)
    state = env["state"]
    assert isinstance(state, dict)
    seed_dir = env["seed_dir"]
    assert isinstance(seed_dir, Path)
    revision = str(state["revision"])
    root = paths["root"]
    identity = env["identity"]
    assert isinstance(identity, dict)

    first = attestation.ensure_runtime_launch_seed(
        manifest_path=manifest,
        chain_spec_path=paths["chain_spec"],
        marker_path=paths["marker"],
        chain_runtime_identity=identity,
        seed_dir=seed_dir,
        supervisor_receipt_path=paths["receipt"],
        hot_env_path=paths["hot_env"],
    )
    # T-0303 immutable content-addressed seed: <generation>-<rev>-<seed-sha>.json
    # plus a dispatch-current.json pointer. Not the old mutable per-runtime slot.
    assert first.name != "runtime-test-1.json"
    assert first.parent == seed_dir / "runtime-test-1"
    assert first.exists()
    assert json.loads(first.read_text(encoding="utf-8"))[
        "expected_revision"
    ] == revision
    pointer = seed_dir / "runtime-test-1" / "dispatch-current.json"
    assert pointer.exists()
    assert json.loads(pointer.read_text(encoding="utf-8"))["seed_path"] == str(first)

    # unchanged pin -> reuse the existing seed (no rebuild, no marker churn)
    second = attestation.ensure_runtime_launch_seed(
        manifest_path=manifest,
        chain_spec_path=paths["chain_spec"],
        marker_path=paths["marker"],
        chain_runtime_identity=identity,
        seed_dir=seed_dir,
        supervisor_receipt_path=paths["receipt"],
        hot_env_path=paths["hot_env"],
    )
    assert second == first  # immutable seed reused, pointer unchanged

    # head advances: manifest pin, live HEAD, and the chain identity move.
    # The marker's relaunch command was regenerated to bind the current
    # runtime (root + revision) while its identity stays stale — the CAS
    # rebind then converges the marker to the live identity.
    new_revision = "c" * 40
    state["revision"] = new_revision
    env["regenerate_relaunch_command"]()  # type: ignore[operator]
    env["write_manifest"]()  # type: ignore[operator]
    new_identity = normalized_runtime_identity(
        env["provenance"]()  # type: ignore[operator]
    )
    third = attestation.ensure_runtime_launch_seed(
        manifest_path=manifest,
        chain_spec_path=paths["chain_spec"],
        marker_path=paths["marker"],
        chain_runtime_identity=new_identity,
        seed_dir=seed_dir,
        supervisor_receipt_path=paths["receipt"],
        hot_env_path=paths["hot_env"],
    )
    # A new generation -> a NEW immutable seed (content-addressed by the new
    # revision); the old seed file is never rewritten.
    assert third != first
    assert third.parent == seed_dir / "runtime-test-1"
    assert third.exists()
    rebuilt = json.loads(third.read_text(encoding="utf-8"))
    assert rebuilt["expected_revision"] == new_revision
    assert json.loads(first.read_text(encoding="utf-8"))[
        "expected_revision"
    ] == revision  # old seed untouched (immutability)
    # dispatch pointer now targets the new generation
    pointer = seed_dir / "runtime-test-1" / "dispatch-current.json"
    assert json.loads(pointer.read_text(encoding="utf-8"))["seed_path"] == str(third)
    # the stale marker was CAS-rebound to the new identity
    marker = json.loads(paths["marker"].read_text(encoding="utf-8"))
    marker_identity = marker["runtime_binding"]["current_identity"]
    assert marker_identity["source_revision"] == new_revision
    assert marker_identity["import_root"] == str(root)
    assert len(marker["runtime_binding"].get("rebind_events") or []) == 1


def test_initial_seed_adopts_empty_chain_runtime_identity_before_worker_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R9: a first managed seed cannot leave the chain binding empty.

    This follows the production boundary in order: manifest validation and
    seed issuance, canonical chain-state persistence, then the worker's seed
    validation immediately before its external provider call.
    """
    from arnold_pipelines.megaplan.chain.spec import (
        ChainState,
        load_chain_state,
        save_chain_state,
    )

    real_chain_binding = attestation._chain_binding
    env = _ensure_seed_env(tmp_path, monkeypatch)
    paths = env["paths"]
    assert isinstance(paths, dict)
    monkeypatch.setattr(attestation, "_chain_binding", real_chain_binding)
    save_chain_state(
        paths["chain_spec"],
        ChainState(
            current_milestone_index=0,
            current_plan_name="m10",
            metadata={
                "execution_binding": {
                    "schema": "megaplan.chain.execution-binding.v1",
                    "launched_identity": {"content_sha256": "launch-binding"},
                    "runtime_binding": {"current_identity": {}},
                }
            },
        ),
        _record_projection=False,
    )
    seed_path = attestation.ensure_runtime_launch_seed(
        manifest_path=env["manifest"],
        chain_spec_path=paths["chain_spec"],
        marker_path=paths["marker"],
        chain_runtime_identity=None,
        seed_dir=env["seed_dir"],
        supervisor_receipt_path=paths["receipt"],
        hot_env_path=paths["hot_env"],
    )
    seed = json.loads(seed_path.read_text(encoding="utf-8"))

    monkeypatch.setenv("MEGAPLAN_RUNTIME_LAUNCH_SEED", str(seed_path))
    monkeypatch.setenv("ARNOLD_RUNTIME_MANIFEST", str(env["manifest"]))
    from arnold_pipelines.megaplan.cloud.worker_dispatch import (
        _runtime_binding_proof,
    )

    proof = _runtime_binding_proof(
        types.SimpleNamespace(
            production_intent=True,
            source_runtime_validator=None,
        )
    )
    from arnold_pipelines.megaplan.workers import _impl as worker_impl
    from arnold_pipelines.megaplan.cloud import runtime_provenance as provenance_module
    from tests.arnold_pipelines.megaplan.test_fresh_child_launch import (
        _admit_worker_child,
        _worker_dispatch_for_phase,
    )

    plan_dir, pointer = _admit_worker_child(tmp_path / "worker-child")
    dispatch = _worker_dispatch_for_phase(
        plan_dir, pointer, "plan", "r9-first-plan"
    )
    fixture_home = tmp_path / "home"
    codex_home = fixture_home / ".codex"
    codex_home.mkdir(parents=True)
    _write_json(
        codex_home / "auth.json",
        {
            "auth_mode": "chatgpt",
            "tokens": {
                "access_token": "fixture",
                "refresh_token": "fixture",
                "id_token": "fixture",
            },
        },
    )
    monkeypatch.setenv("HOME", str(fixture_home))
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    from arnold_pipelines.megaplan.runtime import memory_headroom

    cgroup = tmp_path / "cgroup"
    cgroup.mkdir()
    (cgroup / "memory.current").write_text("0\n", encoding="utf-8")
    (cgroup / "memory.max").write_text(str(1024**3), encoding="utf-8")
    (cgroup / "memory.swap.max").write_text("0\n", encoding="utf-8")
    (cgroup / "memory.events").write_text("oom_kill 0\n", encoding="utf-8")
    monkeypatch.setattr(memory_headroom, "_CGROUP_BASE", cgroup)
    monkeypatch.setattr(
        provenance_module,
        "runtime_provenance",
        lambda: proof["runtime_vector"],
    )
    provider_calls: list[dict[str, object]] = []

    def provider_stub(*_args, **_kwargs):
        provider_calls.append(
            {
                "import_root": proof["runtime_vector"]["import_root"],
                "source_revision": proof["source_revision"],
                "generation": seed["manifest_generation"],
            }
        )
        return (
            worker_impl.WorkerResult(
                payload={"success": True},
                raw_output="ok",
                duration_ms=1,
                cost_usd=0.0,
                session_id="r9-provider-stub",
                worker_identity={
                    "host": "fixture",
                    "pid": os.getpid(),
                    "boot_id": "fixture-boot",
                    "process_start_identity": "fixture-start",
                },
            ),
            "codex",
            "fresh",
            False,
        )

    monkeypatch.setattr(worker_impl, "_run_step_with_worker_legacy", provider_stub)
    worker_impl.run_step_with_worker(
        "plan",
        {
            "name": "child-plan",
            "iteration": 1,
            "config": {"project_dir": str(plan_dir.parent.parent.parent)},
            "meta": {"current_invocation_id": "r9-first-plan"},
            "active_step": {"run_id": "r9-first-plan"},
        },
        plan_dir,
        types.SimpleNamespace(),
        root=plan_dir.parent.parent.parent,
        resolved=("codex", "fresh", False, "gpt-5.5"),
        wbc_dispatch=dispatch,
    )
    assert provider_calls == [
        {
            "import_root": str(paths["root"]),
            "source_revision": "a" * 40,
            "generation": 3,
        }
    ]
    persisted = load_chain_state(
        paths["chain_spec"], verify_execution_binding=False
    ).metadata["execution_binding"]["runtime_binding"]
    assert persisted["current_identity"] == env["identity"]
    assert persisted["rebind_events"][-1]["reason"] == (
        "manifest_initial_runtime_identity_adopt"
    )
    assert persisted["current_identity"] == seed["chain_runtime_binding"][
        "runtime_identity"
    ]
    assert seed["manifest_generation"] == 3


def test_initial_seed_refuses_nonempty_different_runtime_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env = _ensure_seed_env(tmp_path, monkeypatch)
    paths = env["paths"]
    assert isinstance(paths, dict)
    chain_binding = {
        "spec_path": str(paths["chain_spec"]),
        "current_milestone_index": 0,
        "current_plan_name": "m10",
        "runtime_identity": {
            "import_root": "/foreign/runtime",
            "source_revision": "f" * 40,
        },
    }
    chain_binding["content_sha256"] = attestation._canonical_sha256(
        chain_binding
    )
    monkeypatch.setattr(attestation, "_chain_binding", lambda _path: chain_binding)

    with pytest.raises(
        CliError,
        match="chain execution binding does not match the live manifest-pinned runtime",
    ):
        attestation.ensure_runtime_launch_seed(
            manifest_path=env["manifest"],
            chain_spec_path=paths["chain_spec"],
            marker_path=paths["marker"],
            chain_runtime_identity=None,
            seed_dir=env["seed_dir"],
            supervisor_receipt_path=paths["receipt"],
            hot_env_path=paths["hot_env"],
        )


def test_ensure_runtime_launch_seed_rebuilds_on_seed_document_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Occurrence 35afd4e47587: a seed whose live seed documents (hot-env
    selector / supervisor receipt) drifted is STALE — the dispatcher must
    rebuild it (mirroring the worker-side seed-document-manifest gate)
    instead of re-issuing a seed every worker refuses with 'seed document
    manifest drifted'. Chain-spec full-file drift is advisory ONLY (plan
    state carries the recorded binding; a spec edit must not hard-block
    every launch until a rebuild)."""
    env = _ensure_seed_env(tmp_path, monkeypatch)
    assert isinstance(env["manifest"], Path)
    manifest = env["manifest"]
    paths = env["paths"]
    assert isinstance(paths, dict)
    seed_dir = env["seed_dir"]
    assert isinstance(seed_dir, Path)
    identity = env["identity"]
    assert isinstance(identity, dict)
    root = paths["root"]

    def _ensure() -> Path:
        return attestation.ensure_runtime_launch_seed(
            manifest_path=manifest,
            chain_spec_path=paths["chain_spec"],
            marker_path=paths["marker"],
            chain_runtime_identity=identity,
            seed_dir=seed_dir,
            supervisor_receipt_path=paths["receipt"],
            hot_env_path=paths["hot_env"],
        )

    def _current(seed_path: Path) -> bool:
        return attestation._launch_seed_current(
            seed_path,
            root=root,
            expected_revision=str(env["state"]["revision"]),  # type: ignore[index]
            marker_path=paths["marker"],
            manifest_path=manifest,
            generation=3,
        )

    first = _ensure()
    assert _current(first)  # dispatcher gate accepts the fresh seed

    # A chain-spec edit must NOT mark the seed stale: the chain spec is a
    # planning input baked into plan state at init; workers resolve the
    # plan's recorded binding, and the chain runtime binding is enforced
    # separately. Blocking here would hard-block every launch after any
    # legitimate spec edit (e.g. the partnered-5 profile switch).
    chain_spec = paths["chain_spec"]
    assert isinstance(chain_spec, Path)
    chain_spec.write_text(
        chain_spec.read_text(encoding="utf-8") + "# supervisor profile edit\n",
        encoding="utf-8",
    )
    assert _current(first)

    # A hot-env change (still load-bearing: launch credentials/environment)
    # DOES mark the seed stale, and ensure_runtime_launch_seed rebuilds a
    # NEW immutable seed; the dispatch pointer follows it.
    hot_env = paths["hot_env"]
    assert isinstance(hot_env, Path)
    hot_env.write_text(hot_env.read_text(encoding="utf-8") + "KEY=rotated\n", encoding="utf-8")
    assert not _current(first)

    rebuilt = _ensure()
    assert rebuilt != first
    assert rebuilt.parent == first.parent
    first_doc = json.loads(first.read_text(encoding="utf-8"))[
        "seed_document_manifest"
    ]
    rebuilt_doc = json.loads(rebuilt.read_text(encoding="utf-8"))[
        "seed_document_manifest"
    ]
    rebuilt_entries = {
        str(entry["path"]): entry for entry in rebuilt_doc["entries"]
    }
    hot_env_entry = rebuilt_entries[str(hot_env)]
    assert hot_env_entry["sha256"] != dict(
        (str(entry["path"]), entry) for entry in first_doc["entries"]
    )[str(hot_env)]["sha256"]
    assert rebuilt_doc["content_sha256"] != first_doc["content_sha256"]
    assert _current(rebuilt)  # rebuilt seed passes the dispatcher gate
    pointer = seed_dir / "runtime-test-1" / "dispatch-current.json"
    assert json.loads(pointer.read_text(encoding="utf-8"))["seed_path"] == str(
        rebuilt
    )
    # Old seed untouched (immutability).
    assert json.loads(first.read_text(encoding="utf-8"))[
        "seed_document_manifest"
    ] == first_doc


def test_ensure_runtime_launch_seed_refuses_drifted_head(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """G14 fail-closed: the live runtime HEAD MUST equal the manifest pin."""
    env = _ensure_seed_env(tmp_path, monkeypatch)
    assert isinstance(env["manifest"], Path)
    manifest = env["manifest"]
    paths = env["paths"]
    assert isinstance(paths, dict)
    state = env["state"]
    assert isinstance(state, dict)
    monkeypatch.setattr(attestation, "_git_revision", lambda _root: "e" * 40)

    with pytest.raises(CliError, match="HEAD does not match the manifest pin"):
        attestation.ensure_runtime_launch_seed(
            manifest_path=manifest,
            chain_spec_path=paths["chain_spec"],
            marker_path=paths["marker"],
            chain_runtime_identity=env["identity"],
            seed_dir=env["seed_dir"],
            supervisor_receipt_path=paths["receipt"],
            hot_env_path=paths["hot_env"],
        )


def test_ensure_runtime_launch_seed_rebinds_stale_marker_with_regenerated_relaunch_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stale marker whose relaunch command names the OLD revision is
    rebound to the LIVE runtime: the rebind path regenerates the command's
    revision pin (same runtime root, new source revision) so the CAS
    cutover accepts it — the blocked-plan auto-adopt (5f34c4a202) then
    completes instead of failing with runtime_marker_relaunch_mismatch."""
    env = _ensure_seed_env(tmp_path, monkeypatch)
    assert isinstance(env["manifest"], Path)
    manifest = env["manifest"]
    paths = env["paths"]
    assert isinstance(paths, dict)
    state = env["state"]
    assert isinstance(state, dict)
    # head advances; the persisted command still names the old revision
    state["revision"] = "c" * 40
    env["write_manifest"]()  # type: ignore[operator]
    new_identity = normalized_runtime_identity(
        env["provenance"]()  # type: ignore[operator]
    )

    attestation.ensure_runtime_launch_seed(
        manifest_path=manifest,
        chain_spec_path=paths["chain_spec"],
        marker_path=paths["marker"],
        chain_runtime_identity=new_identity,
        seed_dir=env["seed_dir"],
        supervisor_receipt_path=paths["receipt"],
        hot_env_path=paths["hot_env"],
    )
    # the marker was CAS-rebound: identity + command now bind the live rev
    marker = json.loads(paths["marker"].read_text(encoding="utf-8"))
    identity = marker["runtime_binding"]["current_identity"]
    assert identity["source_revision"] == "c" * 40
    assert "c" * 40 in marker["relaunch_command"]
    assert "a" * 40 not in marker["relaunch_command"]
    assert (marker["runtime_binding"].get("rebind_events") or [])
    assert marker["editable_source_head"] == "c" * 40


def test_ensure_runtime_launch_seed_refuses_unverifiable_marker_rebind(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """G14 fail-closed: a stale marker whose relaunch command does NOT name
    the old revision at all cannot be regenerated by a revision-pin swap —
    the CAS rebind still fails with a typed error and the marker JSON is
    never hand-edited."""
    env = _ensure_seed_env(tmp_path, monkeypatch)
    assert isinstance(env["manifest"], Path)
    manifest = env["manifest"]
    paths = env["paths"]
    assert isinstance(paths, dict)
    state = env["state"]
    assert isinstance(state, dict)
    # head advances, but the marker command carries NO revision token
    state["revision"] = "c" * 40
    env["write_manifest"]()  # type: ignore[operator]
    marker = json.loads(paths["marker"].read_text(encoding="utf-8"))
    marker["relaunch_command"] = "python -m arnold_pipelines.megaplan chain tick"
    _write_json(paths["marker"], marker)
    new_identity = normalized_runtime_identity(
        env["provenance"]()  # type: ignore[operator]
    )

    with pytest.raises(CliError, match="relaunch command does not bind"):
        attestation.ensure_runtime_launch_seed(
            manifest_path=manifest,
            chain_spec_path=paths["chain_spec"],
            marker_path=paths["marker"],
            chain_runtime_identity=new_identity,
            seed_dir=env["seed_dir"],
            supervisor_receipt_path=paths["receipt"],
            hot_env_path=paths["hot_env"],
        )
    # the marker was left untouched
    marker = json.loads(paths["marker"].read_text(encoding="utf-8"))
    assert marker["runtime_binding"]["current_identity"]["source_revision"] == (
        "a" * 40
    )
    assert not (marker["runtime_binding"].get("rebind_events") or [])


def test_regenerate_relaunch_command_swaps_revision_pins() -> None:
    """The regenerated command rewrites every 40-hex revision occurrence —
    env pins (MEGAPLAN_BOUND_RUNTIME_REVISION / RUNTIME_REVISION) and bare
    tokens — while leaving every other token byte-identical."""
    old = "a" * 40
    new = "b" * 40
    command = (
        f"cd /ws && env -u PYTHONHOME RUNTIME_REVISION={old} "
        f"MEGAPLAN_BOUND_RUNTIME_REVISION={old} "
        f"python -m arnold_pipelines.megaplan chain start {old}"
    )
    regenerated = attestation._regenerate_relaunch_command(
        command, old_revision=old, new_revision=new
    )
    assert regenerated == (
        f"cd /ws && env -u PYTHONHOME RUNTIME_REVISION={new} "
        f"MEGAPLAN_BOUND_RUNTIME_REVISION={new} "
        f"python -m arnold_pipelines.megaplan chain start {new}"
    )
    assert old not in regenerated


def test_regenerate_relaunch_command_noop_cases() -> None:
    """No-op when the old revision is absent, empty, malformed, or equal to
    the new revision — the caller fails closed downstream."""
    old = "a" * 40
    command = "python -m arnold_pipelines.megaplan chain tick"
    assert (
        attestation._regenerate_relaunch_command(
            command, old_revision=old, new_revision="b" * 40
        )
        == command
    )
    assert (
        attestation._regenerate_relaunch_command(
            command, old_revision="", new_revision="b" * 40
        )
        == command
    )
    assert (
        attestation._regenerate_relaunch_command(
            command, old_revision="short", new_revision="b" * 40
        )
        == command
    )
    assert (
        attestation._regenerate_relaunch_command(
            f"RUNTIME_REVISION={old}",
            old_revision=old,
            new_revision=old,
        )
        == f"RUNTIME_REVISION={old}"
    )


def test_regenerate_relaunch_command_does_not_touch_hex_neighbors() -> None:
    """Word-boundary guard: a revision that is a prefix of another hex token
    (e.g. inside a longer digest or a path) is not swapped."""
    old = "a" * 40
    new = "b" * 40
    command = f"python -m chain {old} extra-{old}deadbeef"
    regenerated = attestation._regenerate_relaunch_command(
        command, old_revision=old, new_revision=new
    )
    assert regenerated == f"python -m chain {new} extra-{old}deadbeef"


def test_worker_preflight_reads_configured_launch_seed_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """G14: the worker launch preflight sees the env export — with
    MEGAPLAN_RUNTIME_LAUNCH_SEED set, require_configured_runtime_launch reads
    that exact seed path instead of failing with 'required but missing'."""
    seed_path = tmp_path / "seed.json"
    seed_path.write_text(
        json.dumps(
            {
                "schema": "x",
                "ready": True,
                "authority": attestation.RUNTIME_LAUNCH_CLOUD_AUTHORITY,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("MEGAPLAN_RUNTIME_LAUNCH_SEED", str(seed_path))
    monkeypatch.delenv("MEGAPLAN_RUNTIME_PROCESS_ATTESTATION", raising=False)
    observed: dict[str, str] = {}
    monkeypatch.setattr(
        attestation,
        "_json_file",
        lambda path, label: (
            observed.update(path=str(path))
            or {
                "schema": "x",
                "ready": True,
                "authority": attestation.RUNTIME_LAUNCH_CLOUD_AUTHORITY,
            }
        ),
    )
    monkeypatch.setattr(
        attestation,
        "create_runtime_process_attestation",
        lambda *args, **kwargs: {"pid": 123},
    )
    monkeypatch.setattr(attestation, "_atomic_write", lambda *args, **kwargs: None)

    seed = attestation.require_configured_runtime_launch(
        "worker", target_pid=123, create=True
    )
    assert seed["schema"] == "x"
    assert seed["ready"] is True
    assert seed["authority"] == attestation.RUNTIME_LAUNCH_CLOUD_AUTHORITY
    assert observed["path"] == str(seed_path)


def test_attestation_disable_without_seed_does_not_authorize_production_launch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """P3 follow-up: explicit attestation-disable (MEGAPLAN_RUNTIME_ATTESTATION_REQUIRED=0)
    without a launch seed must NOT authorize a production launch — the gate
    still fails closed because the launch seed is mandatory.
    """
    monkeypatch.delenv("MEGAPLAN_RUNTIME_LAUNCH_SEED", raising=False)
    monkeypatch.delenv("MEGAPLAN_RUNTIME_PROCESS_ATTESTATION", raising=False)
    monkeypatch.setenv("MEGAPLAN_RUNTIME_ATTESTATION_REQUIRED", "0")

    with pytest.raises(CliError, match="required but missing"):
        attestation.require_configured_runtime_launch("resident")


def test_build_cli_records_explicit_manifest_pointer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Codex consult 0ae19cc17afd (b.1): the `runtime_attestation build` CLI
    accepts --manifest and records the resolved path in input_paths.manifest
    (fixer/rebind parity with the production ensure_runtime_launch_seed path —
    the structural gap that produced the pointerless seed)."""
    _seed, paths = _release_seed(tmp_path, monkeypatch)
    manifest = tmp_path / "runtime-manifest.json"
    _write_json(manifest, {"epic": {"expected_head": "a" * 40}})
    output = tmp_path / "cli-seed.json"
    rc = attestation.main(
        [
            "build",
            "--expected-root",
            str(paths["root"]),
            "--expected-revision",
            "a" * 40,
            "--supervisor-receipt",
            str(paths["receipt"]),
            "--hot-env",
            str(paths["hot_env"]),
            "--marker",
            str(paths["marker"]),
            "--chain-spec",
            str(paths["chain_spec"]),
            "--manifest",
            str(manifest),
            "--output",
            str(output),
        ]
    )
    assert rc == 0
    assert output.exists()
    built = json.loads(output.read_text(encoding="utf-8"))
    assert built["ready"] is True
    assert built["input_paths"]["manifest"] == str(manifest.resolve(strict=False))
    captured = capsys.readouterr()
    assert manifest.resolve(strict=False).as_posix() in captured.out


def test_validate_pointerless_seed_without_manifest_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T-0303 (Codex design): a seed whose revision differs from the live
    head FAILS CLOSED with source_revision_mismatch. Validation NEVER follows
    a manifest/environment head - the seed is immutable evidence and is
    validated exactly as issued (no ARNOLD_ACCEPTED_RUNTIME_HEAD reinterpret).
    """
    original, _paths = _release_seed(tmp_path, monkeypatch)
    seed = dict(original)
    seed["input_paths"] = {**dict(original["input_paths"]), "manifest": ""}
    seed["manifest_identity"] = ""
    seed["manifest_sha256"] = ""
    seed.pop("content_sha256", None)
    seed["content_sha256"] = attestation._canonical_sha256(
        {key: value for key, value in seed.items() if key != "content_sha256"}
    )
    assert seed["input_paths"]["manifest"] == ""
    monkeypatch.delenv("ARNOLD_RUNTIME_MANIFEST", raising=False)
    monkeypatch.delenv("ARNOLD_ACCEPTED_RUNTIME_HEAD", raising=False)

    def _drifted_provenance(**_kwargs: object) -> dict[str, object]:
        return {"ok": False, "errors": ["source_revision_mismatch"]}

    monkeypatch.setattr(attestation, "runtime_provenance", _drifted_provenance)

    with pytest.raises(CliError, match="runtime launch seed manifest identity is missing"):
        attestation.validate_runtime_launch_seed(seed, component="worker")

    # Even with ARNOLD_RUNTIME_MANIFEST pointing at a NEWER accepted head, the
    # stale seed must NOT follow it - the follow behavior is removed.
    new_head = "c" * 40
    manifest = tmp_path / "env-manifest.json"
    _write_json(manifest, {"epic": {"expected_head": new_head}})
    monkeypatch.setenv("ARNOLD_RUNTIME_MANIFEST", str(manifest))

    def _drifted_advanced(**_kwargs: object) -> dict[str, object]:
        prov = dict(seed["runtime_provenance"])  # type: ignore[arg-type]
        prov["source_revision"] = new_head
        prov["ok"] = False
        prov["errors"] = ["source_revision_mismatch"]
        return prov

    monkeypatch.setattr(attestation, "runtime_provenance", _drifted_advanced)
    with pytest.raises(CliError, match="runtime launch seed manifest identity is missing"):
        attestation.validate_runtime_launch_seed(seed, component="worker")
    # No accepted-head env was set by validation (follow removed).
    assert os.environ.get("ARNOLD_ACCEPTED_RUNTIME_HEAD") is None


def test_validate_seed_manifest_pointer_wins_over_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Codex consult 0ae19cc17afd (b.2 precedence): a nonempty seed
    input_paths.manifest is authoritative — a conflicting ARNOLD_RUNTIME_MANIFEST
    is ignored. And a nonempty-but-invalid seed pointer does NOT fall back to
    the environment (seed-first authority preserved)."""
    _seed, paths = _release_seed(tmp_path, monkeypatch)
    seed_head = "a" * 40
    env_head = "d" * 40
    seed_manifest = tmp_path / "seed-manifest.json"
    env_manifest = tmp_path / "env-manifest.json"
    _write_json(seed_manifest, {"epic": {"expected_head": seed_head}})
    _write_json(env_manifest, {"epic": {"expected_head": env_head}})
    monkeypatch.setenv("ARNOLD_RUNTIME_MANIFEST", str(env_manifest))
    monkeypatch.delenv("ARNOLD_ACCEPTED_RUNTIME_HEAD", raising=False)

    seed_with_pointer = attestation.build_runtime_launch_seed(
        expected_root=paths["root"],
        expected_revision=seed_head,
        supervisor_receipt_path=paths["receipt"],
        hot_env_path=paths["hot_env"],
        marker_path=paths["marker"],
        chain_spec_path=paths["chain_spec"],
        manifest_path=seed_manifest,
    )
    assert seed_with_pointer["input_paths"]["manifest"] == str(
        seed_manifest.resolve(strict=False)
    )

    def _stable_provenance(**_kwargs: object) -> dict[str, object]:
        prov = dict(seed_with_pointer["runtime_provenance"])  # type: ignore[arg-type]
        prov["ok"] = True
        return prov

    monkeypatch.setattr(attestation, "runtime_provenance", _stable_provenance)
    result = attestation.validate_runtime_launch_seed(
        seed_with_pointer, component="worker"
    )
    assert result["status"] == "ready"
    # T-0303: validation does NOT set an accepted-head env (follow removed) -
    # the seed is validated exactly as issued against the live provenance.
    assert os.environ.get("ARNOLD_ACCEPTED_RUNTIME_HEAD") is None

    # nonempty-but-invalid seed pointer: must NOT fall through to the env.
    broken = tmp_path / "missing-manifest.json"
    seed_broken = attestation.build_runtime_launch_seed(
        expected_root=paths["root"],
        expected_revision=seed_head,
        supervisor_receipt_path=paths["receipt"],
        hot_env_path=paths["hot_env"],
        marker_path=paths["marker"],
        chain_spec_path=paths["chain_spec"],
        manifest_path=broken,
    )
    assert seed_broken["input_paths"]["manifest"] == str(broken.resolve(strict=False))

    def _env_only_provenance(**_kwargs: object) -> dict[str, object]:
        return {"ok": False, "errors": ["source_revision_mismatch"]}

    monkeypatch.setattr(attestation, "runtime_provenance", _env_only_provenance)
    with pytest.raises(CliError, match="runtime launch seed manifest is unreadable"):
        attestation.validate_runtime_launch_seed(seed_broken, component="worker")


def test_ensure_runtime_launch_seed_rebuilds_pointerless_or_wrong_pointer_seed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Codex consult 0ae19cc17afd (b.3): _launch_seed_current requires the
    seed's input_paths.manifest to resolve to the SAME canonical manifest path.
    A pointerless seed or a wrong-pointer seed (even with a valid recomputed
    digest) is never treated as current and is rebuilt by the next
    ensure_runtime_launch_seed."""
    env = _ensure_seed_env(tmp_path, monkeypatch)
    assert isinstance(env["manifest"], Path)
    manifest = env["manifest"]
    paths = env["paths"]
    assert isinstance(paths, dict)
    state = env["state"]
    assert isinstance(state, dict)
    seed_dir = env["seed_dir"]
    assert isinstance(seed_dir, Path)

    first = attestation.ensure_runtime_launch_seed(
        manifest_path=manifest,
        chain_spec_path=paths["chain_spec"],
        marker_path=paths["marker"],
        chain_runtime_identity=env["identity"],
        seed_dir=seed_dir,
        supervisor_receipt_path=paths["receipt"],
        hot_env_path=paths["hot_env"],
    )
    # T-0303: content-addressed immutable seed + dispatch-current pointer.
    assert first.name != "runtime-test-1.json"
    assert first.parent == seed_dir / "runtime-test-1"
    assert first.exists()
    built = json.loads(first.read_text(encoding="utf-8"))
    assert built["input_paths"]["manifest"] == str(manifest.resolve(strict=False))
    pointer = seed_dir / "runtime-test-1" / "dispatch-current.json"
    assert pointer.exists()
    assert json.loads(pointer.read_text(encoding="utf-8"))["seed_path"] == str(first)

    # rewrite the CURRENT immutable seed with a VALID digest but EMPTY pointer:
    # it is no longer the dispatch-current target (content changed), so the
    # next ensure builds a NEW immutable seed and re-points dispatch-current.
    pointerless = dict(built)
    pointerless["input_paths"] = dict(built["input_paths"])
    pointerless["input_paths"]["manifest"] = ""
    pointerless["content_sha256"] = attestation._canonical_sha256(
        {k: v for k, v in pointerless.items() if k != "content_sha256"}
    )
    _write_json(first, pointerless)
    attestation._verify_seed_digest(
        json.loads(first.read_text(encoding="utf-8"))
    )

    second = attestation.ensure_runtime_launch_seed(
        manifest_path=manifest,
        chain_spec_path=paths["chain_spec"],
        marker_path=paths["marker"],
        chain_runtime_identity=env["identity"],
        seed_dir=seed_dir,
        supervisor_receipt_path=paths["receipt"],
        hot_env_path=paths["hot_env"],
    )
    # The pointerless mutation was rejected: ensure rebuilds the seed with the
    # canonical manifest pointer (content-identical to the original -> may land
    # at the same content-addressed path). The dispatch seed is never the
    # empty-pointer mutation.
    assert second.exists()
    rebuilt = json.loads(second.read_text(encoding="utf-8"))
    assert rebuilt["input_paths"]["manifest"] == str(manifest.resolve(strict=False))
    assert json.loads(pointer.read_text(encoding="utf-8"))["seed_path"] == str(second)

    # wrong pointer (another manifest path) is also not current -> rebuilt
    other = tmp_path / "other-manifest.json"
    _write_json(other, {"epic": {"expected_head": state["revision"]}})
    wrong = dict(rebuilt)
    wrong["input_paths"] = dict(rebuilt["input_paths"])
    wrong["input_paths"]["manifest"] = str(other.resolve(strict=False))
    wrong["content_sha256"] = attestation._canonical_sha256(
        {k: v for k, v in wrong.items() if k != "content_sha256"}
    )
    _write_json(second, wrong)

    third = attestation.ensure_runtime_launch_seed(
        manifest_path=manifest,
        chain_spec_path=paths["chain_spec"],
        marker_path=paths["marker"],
        chain_runtime_identity=env["identity"],
        seed_dir=seed_dir,
        supervisor_receipt_path=paths["receipt"],
        hot_env_path=paths["hot_env"],
    )
    assert third.exists()
    final = json.loads(third.read_text(encoding="utf-8"))
    # The wrong-pointer mutation was rejected: the dispatch seed carries the
    # canonical manifest pointer (rebuilt), never the foreign one.
    assert final["input_paths"]["manifest"] == str(manifest.resolve(strict=False))
    assert final["input_paths"]["manifest"] != str(other.resolve(strict=False))
    assert json.loads(pointer.read_text(encoding="utf-8"))["seed_path"] == str(third)

def test_manifest_matches_tolerates_extra_stored_entries(tmp_path: Path) -> None:
    """Old seeds (built when chain_spec was pinned) carry a 3-entry manifest;
    the post-drop validation shape compares only hot_env + supervisor_receipt.
    Extra stored entries (chain_spec) must be ignored so pre-fix seeds validate
    again — a genuine hot_env edit must still fail (seed schema migration)."""
    hot_env = tmp_path / ".cloud-hot-env"
    receipt = tmp_path / "last-prepare.json"
    chain_spec = tmp_path / "chain.yaml"
    hot_env.write_text("KEY=abc\n", encoding="utf-8")
    receipt.write_text('{"prepared": true}\n', encoding="utf-8")
    chain_spec.write_text("milestones: []\n", encoding="utf-8")

    # Old seed shape: 3 entries including chain_spec.
    old_manifest = attestation._manifest([hot_env, receipt, chain_spec])

    # New validation shape: only hot_env + supervisor_receipt.
    new_paths = [hot_env, receipt]
    assert attestation._manifest_matches(new_paths, old_manifest) is True

    # Genuine hot_env edit is still drift.
    hot_env.write_text("KEY=rotated\n", encoding="utf-8")
    assert attestation._manifest_matches(new_paths, old_manifest) is False
    hot_env.write_text("KEY=abc\n", encoding="utf-8")

    # Missing live path from stored manifest fails closed.
    missing = tmp_path / "nope.json"
    missing.write_text("x\n", encoding="utf-8")
    assert attestation._manifest_matches([missing], old_manifest) is False


def test_adopt_or_refuse_launch_identity_generation_advance() -> None:
    """A manifest generation advance on the same import_root adopts the live
    manifest head (non-event, "JUST RELAUNCH"); a different import_root or a
    downgrade still fails closed. (grok consult 2026-08-18: mid-phase
    manifest cutover must never lock a plan behind repair_phase_contract.)"""
    from arnold_pipelines.megaplan.cloud.runtime_attestation import (
        RUNTIME_ATTESTATION_ERROR,
        _adopt_or_refuse_launch_identity,
    )
    from arnold_pipelines.megaplan.cloud.runtime_cutover import (
        normalize_runtime_identity,
    )

    root = "/workspace/runtime-candidates/arnold-4a830c6ac9a0"
    recorded = {
        "import_root": root,
        "source_revision": "a" * 40,
        "editable_root": None,
        "editable_revision": None,
        "direct_url": None,
        "pth": None,
        "imports": None,
    }
    live = {
        "import_root": root,
        "source_revision": "b" * 40,
        "editable_root": None,
        "editable_revision": None,
        "direct_url": None,
        "pth": None,
        "imports": None,
    }

    # Equal root+rev -> no-op (returns recorded).
    same = dict(live)
    same["source_revision"] = recorded["source_revision"]
    adopted = _adopt_or_refuse_launch_identity(
        recorded, same, recorded_generation=114, live_generation=114
    )
    assert adopted["source_revision"] == recorded["source_revision"]

    # Generation advance gen 114 -> 115 on same root -> adopt live head.
    adopted = _adopt_or_refuse_launch_identity(
        recorded, live, recorded_generation=114, live_generation=115
    )
    assert adopted["source_revision"] == live["source_revision"]

    # Unknown recorded generation + same root -> adopt.
    adopted = _adopt_or_refuse_launch_identity(
        recorded, live, recorded_generation=None, live_generation=115
    )
    assert adopted["source_revision"] == live["source_revision"]

    # Different import_root -> fail closed with diagnostic.
    other_root = dict(live)
    other_root["import_root"] = "/workspace/runtime-candidates/other"
    try:
        _adopt_or_refuse_launch_identity(
            recorded, other_root, recorded_generation=114, live_generation=115
        )
    except Exception as exc:
        assert getattr(exc, "code", None) == RUNTIME_ATTESTATION_ERROR
        msg = str(getattr(exc, "message", getattr(exc, "args", ("",))[0]))
        assert "recorded_identity=import_root=" in msg
        assert "live_identity=import_root=" in msg
        assert "source_revision=" in msg
        assert "generation=114" in msg
        assert "generation=115" in msg
    else:
        raise AssertionError("different import_root must fail closed")

    # Generation downgrade gen 115 -> 114 on same root -> adopt (engine
    # change of ANY direction on the same root is a non-event).
    adopted = _adopt_or_refuse_launch_identity(
        live, recorded, recorded_generation=115, live_generation=114
    )
    assert adopted["source_revision"] == recorded["source_revision"]

    # Same generation but different revision -> adopt (head moved at the
    # same gen is still an engine change; only a root swap fails closed).
    same_gen_other_rev = dict(live)
    same_gen_other_rev["source_revision"] = "c" * 40
    adopted = _adopt_or_refuse_launch_identity(
        recorded, same_gen_other_rev, recorded_generation=114, live_generation=114
    )
    assert adopted["source_revision"] == "c" * 40

    # normalized_runtime_identity round-trips through the helper.
    normalized_recorded = normalize_runtime_identity(recorded)
    adopted = _adopt_or_refuse_launch_identity(
        normalized_recorded, live, recorded_generation=114, live_generation=115
    )
    assert adopted["source_revision"] == live["source_revision"]


def test_validate_seed_adopts_manifest_identity_into_stale_chain_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stale same-root chain projection adopts the immutable seed identity.

    The validation path must treat the seed/manifest as live authority.  This
    guards the argument order at the second enforcement point, where reversing
    the helper arguments silently persisted the stale chain revision.
    """
    seed, _paths = _release_seed(tmp_path, monkeypatch, manifest_generation=1)
    seed_identity = dict(seed["chain_runtime_binding"]["runtime_identity"])
    stale_identity = dict(seed_identity)
    stale_identity["source_revision"] = "z" * 40
    monkeypatch.setattr(
        attestation,
        "_chain_binding_runtime_identity",
        lambda _path: stale_identity,
    )
    monkeypatch.setattr(attestation, "_live_manifest_generation", lambda _path: 1)
    persisted: list[dict[str, object]] = []
    monkeypatch.setattr(
        attestation,
        "_persist_adopted_chain_runtime_identity",
        lambda **kwargs: persisted.append(kwargs),
    )

    result = attestation.validate_runtime_launch_seed(seed, component="worker")

    assert result["status"] == "ready"
    assert len(persisted) == 1
    assert persisted[0]["bound_identity"]["source_revision"] == seed_identity[
        "source_revision"
    ]
    assert persisted[0]["reason"] == "manifest_generation_adopt_validate"

def test_production_worker_dispatch_requires_seed_when_manifest_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Occurrence 12f5e50e0107: a production-bound (ARNOLD_RUNTIME_MANIFEST)
    phase/backend dispatch without a configured launch seed fails closed
    with the typed seed refusal instead of dying later on the first
    ``omp_rpc.host_tools`` import."""
    monkeypatch.delenv("MEGAPLAN_RUNTIME_LAUNCH_SEED", raising=False)
    monkeypatch.setenv("ARNOLD_RUNTIME_MANIFEST", "/tmp/unrelated-manifest.json")

    with pytest.raises(
        CliError, match="canonical runtime launch seed is required but missing"
    ):
        attestation.require_production_worker_dispatch_runtime(component="worker")


def test_production_worker_dispatch_rejects_manifest_generation_interpreter_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Occurrence 12f5e50e0107: under a production binding whose
    dependency-generation interpreter differs from the DISPATCHING
    interpreter, the shared preflight refuses before any provider work —
    naming expected vs actual and pointing at arnold-chain."""
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text("{}\n", encoding="utf-8")
    seed_path = tmp_path / "seed.json"
    _write_json(seed_path, {"schema": "x"})
    monkeypatch.setenv("MEGAPLAN_RUNTIME_LAUNCH_SEED", str(seed_path))
    monkeypatch.setenv("ARNOLD_RUNTIME_MANIFEST", str(manifest_path))

    manifest_dep = str(Path(sys.executable).resolve())
    other_gen = "/opt/other-generation/bin/python"
    monkeypatch.setattr(
        attestation,
        "refresh_runtime_launch_seed_for_worker_dispatch",
        lambda: seed_path,
    )
    monkeypatch.setattr(
        attestation,
        "require_configured_runtime_launch",
        lambda component, **kwargs: {
            "schema": "x",
            "authority": attestation.RUNTIME_LAUNCH_CLOUD_AUTHORITY,
            "ready": True,
            "errors": [],
            "interpreter": {"executable": manifest_dep},
            "dependency_generation": {"interpreter_path": other_gen},
        },
    )

    from arnold_pipelines.megaplan.cloud import runtime_manifest as manifest_module

    class _StubManifest:
        epic = {"dependency_generation": {"interpreter_path": other_gen}}

    monkeypatch.setattr(manifest_module, "load_manifest", lambda _path: _StubManifest())

    with pytest.raises(
        CliError, match="requires the manifest dependency-generation interpreter"
    ) as excinfo:
        attestation.require_production_worker_dispatch_runtime(component="worker")
    assert "arnold-chain" in str(excinfo.value)


def test_production_worker_dispatch_rejects_seed_bound_to_other_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The seed itself must carry the SAME dependency-generation interpreter
    as the live manifest binding; a self-consistent-but-wrong generation
    seed (the 20:16Z dispatch-current.json poison) refuses at admission."""
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text("{}\n", encoding="utf-8")
    seed_path = tmp_path / "seed.json"
    _write_json(seed_path, {"schema": "x"})
    monkeypatch.setenv("MEGAPLAN_RUNTIME_LAUNCH_SEED", str(seed_path))
    monkeypatch.setenv("ARNOLD_RUNTIME_MANIFEST", str(manifest_path))

    here = str(Path(sys.executable).resolve())
    stale_seed_gen = str(Path(sys.executable).resolve()) + "#stale"
    monkeypatch.setattr(
        attestation,
        "refresh_runtime_launch_seed_for_worker_dispatch",
        lambda: seed_path,
    )
    monkeypatch.setattr(
        attestation,
        "require_configured_runtime_launch",
        lambda component, **kwargs: {
            "schema": "x",
            "authority": attestation.RUNTIME_LAUNCH_CLOUD_AUTHORITY,
            "ready": True,
            "errors": [],
            "interpreter": {"executable": here},
            "dependency_generation": {"interpreter_path": stale_seed_gen},
        },
    )

    from arnold_pipelines.megaplan.cloud import runtime_manifest as manifest_module

    class _StubManifest:
        epic = {"dependency_generation": {"interpreter_path": here}}

    monkeypatch.setattr(manifest_module, "load_manifest", lambda _path: _StubManifest())

    with pytest.raises(
        CliError, match="launch seed is bound to a different"
    ):
        attestation.require_production_worker_dispatch_runtime(component="worker")


def test_build_seed_not_ready_when_builder_interpreter_differs_from_dependency_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Occurrence 12f5e50e0107: a seed built by an interpreter other than the
    bound dependency-generation interpreter can never be born ready:true."""
    seed, _paths = _release_seed(
        tmp_path,
        monkeypatch,
        dependency_generation={
            "id": "c" * 64,
            "frozen_spec_sha256": "c" * 64,
            "venv_digest": "d" * 64,
            "interpreter_path": "/opt/other-generation/bin/python",
            "created": "2026-08-26T00:00:00Z",
        },
    )

    assert seed["ready"] is False
    assert any(
        str(error).startswith("dependency_generation_builder_interpreter_mismatch:")
        for error in seed["errors"]
    )


def test_launch_seed_current_rejects_cross_interpreter_ready_seed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A release-ready stored seed whose embedded interpreter vector or
    dependency-generation interpreter no longer matches the current
    dispatcher must never be REUSED — ensure_runtime_launch_seed rebuilds
    instead (the ready:true ambient-executable seed of 2026-08-26T20:16Z)."""
    seed, paths = _release_seed(tmp_path, monkeypatch)
    store_dir = tmp_path / "seeds"
    store_dir.mkdir()
    manifest_pointer = tmp_path / "manifest-pointer.json"
    manifest_pointer.write_bytes(paths["manifest"].read_bytes())
    revision = str(seed["expected_revision"])

    def _materialize(name: str, mutate) -> Path:
        core = {key: value for key, value in seed.items() if key != "content_sha256"}
        input_paths = dict(core.get("input_paths") or {})
        input_paths["manifest"] = str(manifest_pointer)
        core["input_paths"] = input_paths
        mutate(core)
        core["content_sha256"] = attestation._canonical_sha256(core)
        target = store_dir / f"{name}.json"
        target.write_text(json.dumps(core), encoding="utf-8")
        return target

    def _current(core: dict[str, object]) -> None:
        pass

    def _cross_executable(core: dict[str, object]) -> None:
        interp = dict(core["interpreter"])
        interp["executable"] = "/opt/ambient-other/bin/python"
        core["interpreter"] = interp

    def _cross_dep(core: dict[str, object]) -> None:
        core["dependency_generation"] = {
            "id": "c" * 64,
            "frozen_spec_sha256": "c" * 64,
            "venv_digest": "d" * 64,
            "interpreter_path": "/opt/other-generation/bin/python",
            "created": "2026-08-26T00:00:00Z",
        }

    matching = _materialize("matching", _current)
    assert attestation._launch_seed_current(
        matching,
        root=str(paths["root"]),
        expected_revision=revision,
        marker_path=paths["marker"],
        manifest_path=manifest_pointer,
    ) is True

    cross_exe = _materialize("cross-exe", _cross_executable)
    assert attestation._launch_seed_current(
        cross_exe,
        root=str(paths["root"]),
        expected_revision=revision,
        marker_path=paths["marker"],
        manifest_path=manifest_pointer,
    ) is False

    cross_dep = _materialize("cross-dep", _cross_dep)
    assert attestation._launch_seed_current(
        cross_dep,
        root=str(paths["root"]),
        expected_revision=revision,
        marker_path=paths["marker"],
        manifest_path=manifest_pointer,
    ) is False


def test_regenerate_relaunch_command_rebinds_stale_manifest_path() -> None:
    """A marker command that still selects the creation-time session-copy
    manifest is rebound to the authoritative per-slug manifest (occurrence
    c2f73c7ddcef: the gen-19 advance left the gen-13 copy in the command)."""
    command = (
        "cd /ws && env -u MEGAPLAN_RUNTIME_LAUNCH_SEED "
        "ARNOLD_RUNTIME_MANIFEST=/workspace/.megaplan/epic-demo.json "
        f"MEGAPLAN_BOUND_RUNTIME_REVISION={'a' * 40} chain start"
    )
    regenerated = attestation._regenerate_relaunch_command(
        command,
        old_revision="a" * 40,
        new_revision="b" * 40,
        expected_manifest_path="/workspace/.megaplan/runtime-manifests/epic-demo.json",
    )
    assert "ARNOLD_RUNTIME_MANIFEST=/workspace/.megaplan/runtime-manifests/epic-demo.json" in regenerated
    assert "epic-demo.json " not in regenerated.replace(
        "runtime-manifests/epic-demo.json", ""
    )
    assert "MEGAPLAN_BOUND_RUNTIME_REVISION=" + "b" * 40 in regenerated


def test_regenerate_relaunch_command_keeps_authoritative_manifest_path() -> None:
    """A command already binding the authoritative manifest is unchanged in
    that dimension (idempotent rebind)."""
    command = (
        "env ARNOLD_RUNTIME_MANIFEST=/workspace/.megaplan/runtime-manifests/epic-demo.json "
        "chain start"
    )
    assert (
        attestation._regenerate_relaunch_command(
            command,
            old_revision="",
            new_revision="b" * 40,
            expected_manifest_path="/workspace/.megaplan/runtime-manifests/epic-demo.json",
        )
        == command
    )


def test_rebind_marker_stale_command_manifest_path_still_rebinds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Equal root+revision with a STALE manifest selector in the relaunch
    command must NOT early-return: the selector is what fails admission on
    the next marker-only relaunch."""
    from arnold_pipelines.megaplan.cloud import runtime_cutover

    identity = {"import_root": "/ws/runtime", "source_revision": "a" * 40}
    marker = {
        "runtime_binding": {"current_identity": dict(identity)},
        "relaunch_command": (
            "env ARNOLD_RUNTIME_MANIFEST=/legacy/epic-demo.json "
            f"MEGAPLAN_BOUND_RUNTIME_REVISION={'a' * 40} chain start"
        ),
    }
    calls: list[dict[str, object]] = []
    marker_path = tmp_path / "marker.json"
    marker_path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        runtime_cutover,
        "marker_runtime_identity",
        lambda _marker: {**identity, "content_sha256": "d" * 64},
    )

    def fake_update(_path, **kwargs):
        calls.append(kwargs)

    monkeypatch.setattr(runtime_cutover, "update_marker_runtime", fake_update)
    attestation._rebind_marker_if_stale(
        marker_path,
        marker,
        live_identity=dict(identity),
        source_branch="main",
        expected_manifest_path="/auth/epic-demo.json",
    )
    assert len(calls) == 1
    command = calls[0]["relaunch_command"]
    assert "ARNOLD_RUNTIME_MANIFEST=/auth/epic-demo.json" in command
    assert "/legacy/epic-demo.json" not in command


def test_rebind_marker_equal_identity_authoritative_command_noop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Equal root+revision AND the command binding the authoritative manifest
    is the true no-op case — no CAS write is attempted."""
    from arnold_pipelines.megaplan.cloud import runtime_cutover

    identity = {"import_root": "/ws/runtime", "source_revision": "a" * 40}
    marker = {
        "runtime_binding": {"current_identity": dict(identity)},
        "relaunch_command": (
            "env ARNOLD_RUNTIME_MANIFEST=/auth/epic-demo.json chain start"
        ),
    }
    monkeypatch.setattr(
        runtime_cutover,
        "marker_runtime_identity",
        lambda _marker: {**identity, "content_sha256": "d" * 64},
    )

    def fail_update(*_a, **_k):
        raise AssertionError("rebind must not fire for a clean marker")

    monkeypatch.setattr(runtime_cutover, "update_marker_runtime", fail_update)
    attestation._rebind_marker_if_stale(
        tmp_path / "marker.json",
        marker,
        live_identity=dict(identity),
        source_branch="main",
        expected_manifest_path="/auth/epic-demo.json",
    )


def test_rebind_marker_revision_advance_still_rewrites_pins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression guard for the pre-existing behavior: a revision advance on
    the same root still regenerates the revision pin(s) — and now also the
    manifest selector — in one pass."""
    from arnold_pipelines.megaplan.cloud import runtime_cutover

    marker_identity = {
        "import_root": "/ws/runtime",
        "source_revision": "a" * 40,
    }
    live_identity = {
        "import_root": "/ws/runtime",
        "source_revision": "b" * 40,
    }
    marker = {
        "runtime_binding": {"current_identity": dict(marker_identity)},
        "relaunch_command": (
            "env ARNOLD_RUNTIME_MANIFEST=/legacy/epic-demo.json "
            f"MEGAPLAN_BOUND_RUNTIME_REVISION={'a' * 40} chain start"
        ),
    }
    calls: list[dict[str, object]] = []
    marker_path = tmp_path / "marker.json"
    marker_path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        runtime_cutover,
        "marker_runtime_identity",
        lambda _marker: {**marker_identity, "content_sha256": "d" * 64},
    )
    monkeypatch.setattr(
        runtime_cutover,
        "update_marker_runtime",
        lambda _path, **kwargs: calls.append(kwargs),
    )
    attestation._rebind_marker_if_stale(
        marker_path,
        marker,
        live_identity=live_identity,
        source_branch="main",
        expected_manifest_path="/auth/epic-demo.json",
    )
    assert len(calls) == 1
    command = calls[0]["relaunch_command"]
    assert "MEGAPLAN_BOUND_RUNTIME_REVISION=" + "b" * 40 in command
    assert "ARNOLD_RUNTIME_MANIFEST=/auth/epic-demo.json" in command
    assert calls[0]["active_runtime_identity"] == live_identity


def test_regenerate_relaunch_command_rewrites_dependency_interpreter() -> None:
    old = "/workspace/runtime-venvs/old-generation/bin/python"
    new = "/workspace/runtime-venvs/new-generation/bin/python"
    command = (
        "cd /workspace/runtime && "
        f"{old} -P -m arnold_pipelines.megaplan chain start"
    )
    regenerated = attestation._regenerate_relaunch_command(
        command,
        old_revision="",
        new_revision="",
        expected_interpreter_path=new,
    )
    assert old not in regenerated
    assert f"{new} -P -m arnold_pipelines.megaplan" in regenerated


def test_relaunch_matches_runtime_rejects_wrong_dependency_interpreter() -> None:
    from arnold_pipelines.megaplan.cloud.relaunch_resolution import (
        relaunch_matches_runtime,
    )

    command = (
        "env ARNOLD_RUNTIME_MANIFEST=/auth/epic.json "
        "/workspace/runtime-venvs/old-generation/bin/python -P -m "
        "arnold_pipelines.megaplan chain start"
    )
    assert not relaunch_matches_runtime(
        command,
        {"import_root": "/ws/runtime", "source_revision": "a" * 40},
        expected_interpreter_path="/workspace/runtime-venvs/new-generation/bin/python",
    )


def test_rebind_marker_detects_stale_dependency_interpreter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from arnold_pipelines.megaplan.cloud import runtime_cutover, runtime_manifest

    identity = {
        "import_root": "/ws/runtime",
        "source_revision": "a" * 40,
    }
    old = "/workspace/runtime-venvs/old-generation/bin/python"
    new = "/workspace/runtime-venvs/new-generation/bin/python"
    marker = {
        "runtime_binding": {"current_identity": dict(identity)},
        "relaunch_command": f"{old} -P -m arnold_pipelines.megaplan chain start",
    }
    marker_path = tmp_path / "marker.json"
    marker_path.write_text("{}", encoding="utf-8")
    calls: list[dict[str, object]] = []

    class _Manifest:
        epic = {"dependency_generation": {"interpreter_path": new}}

    monkeypatch.setattr(runtime_manifest, "load_manifest", lambda _path: _Manifest())
    monkeypatch.setattr(
        runtime_cutover,
        "marker_runtime_identity",
        lambda _marker: {**identity, "content_sha256": "d" * 64},
    )
    monkeypatch.setattr(
        runtime_cutover,
        "update_marker_runtime",
        lambda _path, **kwargs: calls.append(kwargs),
    )

    attestation._rebind_marker_if_stale(
        marker_path,
        marker,
        live_identity=dict(identity),
        source_branch="main",
        expected_manifest_path="/auth/epic-demo.json",
    )

    assert len(calls) == 1
    assert new in str(calls[0]["relaunch_command"])
    assert old not in str(calls[0]["relaunch_command"])
    assert calls[0]["expected_interpreter_path"] == new
