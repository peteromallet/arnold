"""S2F template discovery and parsing for the non-authoritative shadow engine."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from arnold.workflow.completion.spec import SubjectKind
from arnold.workflow.completion.source_declaration import (
    SourceDeclaration,
    SubjectDeclaration,
)

DEFAULT_S2F_SCAN_DIRS: tuple[str, ...] = (
    "plans",
    "plans/*",
    "s2f_templates",
    "gates/s2f_templates",
)

S2F_SCHEMA_MARKERS: tuple[str, ...] = (
    "GO-FORMAT",
    ".pype",
    "boundary-registry",
    "boundary_registry",
    "arnold.workflow.source_declaration.v1",
    "arnold.workflow.s2f_template.v1",
    "s2f_template",
)


@dataclass(frozen=True)
class S2FMissingTemplateKinds:
    """Typed diagnostic for durable S2F kinds absent from a scan."""

    discovered_kinds: tuple[SubjectKind, ...] = ()
    missing_kinds: tuple[SubjectKind, ...] = ()
    code: str = "S2FMissingTemplateKinds"

    def to_dict(self) -> dict[str, Any]:
        """Return the proof-map-safe diagnostic representation."""
        return {
            "code": self.code,
            "discovered_kinds": [kind.value for kind in self.discovered_kinds],
            "missing_kinds": [kind.value for kind in self.missing_kinds],
        }


@dataclass(frozen=True)
class S2FGapReport:
    """Structured report of S2F discovery and parsing gaps."""

    scan_dirs: tuple[str, ...] = field(default_factory=lambda: DEFAULT_S2F_SCAN_DIRS)
    discovered_files: tuple[Path, ...] = ()
    parsed_declarations: tuple[SubjectDeclaration, ...] = ()
    gaps: tuple[str, ...] = ()
    missing_template_kinds: tuple[SubjectKind, ...] = ()
    diagnostics: tuple[S2FMissingTemplateKinds, ...] = ()

    @property
    def has_gaps(self) -> bool:
        """Return whether parsing or durable-kind coverage has gaps."""
        return bool(self.gaps or self.missing_template_kinds or self.diagnostics)

    @property
    def total_entries_attempted(self) -> int:
        """Return parsed entries plus entry-level gaps."""
        no_template_gap = int(
            "No S2F templates discovered in configured scan directories" in self.gaps
        )
        return len(self.gaps) - no_template_gap + len(self.parsed_declarations)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the complete discovery qualification."""
        return {
            "scan_dirs": list(self.scan_dirs),
            "discovered_files": [str(path) for path in self.discovered_files],
            "parsed_declarations": [
                declaration.to_dict() for declaration in self.parsed_declarations
            ],
            "gaps": list(self.gaps),
            "missing_template_kinds": [kind.value for kind in self.missing_template_kinds],
            "diagnostics": [diagnostic.to_dict() for diagnostic in self.diagnostics],
        }


class S2FTemplatesUnavailable(RuntimeError):
    """Hard stop raised when no S2F templates are discovered."""

    def __init__(self, report: S2FGapReport) -> None:
        super().__init__(
            "No S2F templates were discovered; shadow inventory cannot be built"
        )
        self.report = report


def _matches_marker(path: Path, markers: tuple[str, ...]) -> bool:
    """Return whether a file contains one of the configured schema markers."""
    content = path.read_bytes()
    return any(marker.encode("utf-8") in content for marker in markers)


def _discover_directory(path: Path, markers: tuple[str, ...]) -> tuple[Path, ...]:
    """Discover marker-bearing files beneath one directory."""
    if not path.is_dir():
        return ()
    discovered: list[Path] = []
    for entry in sorted(item for item in path.rglob("*") if item.is_file()):
        try:
            if _matches_marker(entry, markers):
                discovered.append(entry.resolve())
        except (OSError, PermissionError):
            continue
    return tuple(discovered)


def _discover_s2f_files(
    scan_dirs: tuple[str, ...],
    schema_markers: tuple[str, ...],
) -> tuple[Path, ...]:
    """Scan configured directories for marker-bearing S2F files."""
    discovered: list[Path] = []
    for directory in scan_dirs:
        discovered.extend(_discover_directory(Path(directory), schema_markers))
    return tuple(discovered)


def _s2f_kind_to_subject_kind(kind_str: str) -> SubjectKind:
    """Map an S2F kind string to the neutral subject-kind enum."""
    kind_map = {
        "workflow": SubjectKind.WORKFLOW,
        "step": SubjectKind.STEP,
        "human": SubjectKind.HUMAN_BOUNDARY,
        "effect": SubjectKind.EFFECT,
        "child": SubjectKind.DYNAMIC_TASK,
        "rework": SubjectKind.DYNAMIC_TASK,
        "dynamic_task": SubjectKind.DYNAMIC_TASK,
    }
    mapped = kind_map.get(kind_str)
    if mapped is None:
        raise ValueError(
            f"Unrecognised S2F template kind {kind_str!r}. "
            f"Supported kinds: {sorted(kind_map)}"
        )
    return mapped


def _entries_from_document(data: Any) -> list[Any]:
    """Extract candidate declaration entries from one decoded document."""
    if isinstance(data, list):
        return data
    if not isinstance(data, dict):
        return []
    entries = data.get("declarations", data.get("entries", data.get("templates", [])))
    if not entries and any(key in data for key in ("kind", "canonical_name")):
        return [data]
    return entries


def _parse_entry(fp: Path, index: int, entry: Any) -> tuple[SubjectDeclaration | None, str | None]:
    """Parse one candidate entry, returning a declaration or a gap."""
    if not isinstance(entry, dict):
        return None, f"{fp}[{index}]: entry is not a dict"
    kind_str = entry.get("kind") or entry.get("subject_kind") or ""
    if not kind_str:
        return None, f"{fp}[{index}]: missing 'kind' field"
    try:
        subject_kind = _s2f_kind_to_subject_kind(kind_str)
    except ValueError as exc:
        return None, f"{fp}[{index}]: {exc}"
    source_id = entry.get("source_id") or entry.get("id") or f"s2f:{fp.stem}:{index}"
    canonical_name = (
        entry.get("canonical_name") or entry.get("name") or entry.get("identity") or ""
    )
    if not canonical_name:
        return None, f"{fp}[{index}]: missing canonical_name/name/identity"
    source = SourceDeclaration(
        source_id=str(source_id),
        kind=subject_kind,
        canonical_name=str(canonical_name),
        source_path=str(fp),
        template_ref=f"{fp.name}#{index}",
    )
    instance_id = (
        entry.get("subject_instance_id")
        or entry.get("instance_id")
        or f"s2f:{source_id}:inst"
    )
    declaration_id = (
        entry.get("declaration_id") or entry.get("id") or f"s2f:{source_id}:decl"
    )
    return SubjectDeclaration(
        source=source,
        subject_kind=subject_kind,
        subject_instance_id=str(instance_id),
        declaration_id=str(declaration_id),
    ), None


def _parse_s2f_file(fp: Path) -> tuple[list[SubjectDeclaration], list[str]]:
    """Parse one S2F file into declarations and gap descriptions."""
    try:
        data = json.loads(fp.read_bytes())
    except (json.JSONDecodeError, OSError) as exc:
        return [], [f"{fp}: failed to parse JSON: {exc}"]
    declarations: list[SubjectDeclaration] = []
    gaps: list[str] = []
    for index, entry in enumerate(_entries_from_document(data)):
        declaration, gap = _parse_entry(fp, index, entry)
        if declaration is not None:
            declarations.append(declaration)
        if gap is not None:
            gaps.append(gap)
    return declarations, gaps


def _parse_s2f_entries(
    file_paths: tuple[Path, ...],
) -> tuple[tuple[SubjectDeclaration, ...], list[str]]:
    """Parse discovered S2F files into declarations and gaps."""
    declarations: list[SubjectDeclaration] = []
    gaps: list[str] = []
    for file_path in file_paths:
        parsed, file_gaps = _parse_s2f_file(file_path)
        declarations.extend(parsed)
        gaps.extend(file_gaps)
    return tuple(declarations), gaps


def s2f_discovery_gap_report(
    scan_dirs: tuple[str, ...] | None = None,
    schema_markers: tuple[str, ...] | None = None,
) -> S2FGapReport:
    """Produce a structured report for S2F artifact discovery."""
    dirs = scan_dirs if scan_dirs is not None else DEFAULT_S2F_SCAN_DIRS
    markers = schema_markers if schema_markers is not None else S2F_SCHEMA_MARKERS
    file_paths = _discover_s2f_files(dirs, markers)
    declarations, gaps = _parse_s2f_entries(file_paths)
    discovered_kinds = tuple(
        kind for kind in SubjectKind
        if any(declaration.subject_kind == kind for declaration in declarations)
    )
    missing_kinds = tuple(kind for kind in SubjectKind if kind not in discovered_kinds)
    diagnostics = (
        (S2FMissingTemplateKinds(discovered_kinds, missing_kinds),)
        if missing_kinds
        else ()
    )
    if not file_paths:
        gaps.append("No S2F templates discovered in configured scan directories")
    return S2FGapReport(
        scan_dirs=dirs,
        discovered_files=file_paths,
        parsed_declarations=declarations,
        gaps=tuple(gaps),
        missing_template_kinds=missing_kinds,
        diagnostics=diagnostics,
    )


def generate_shadow_specs_from_s2f(
    scan_dirs: tuple[str, ...] | None = None,
    schema_markers: tuple[str, ...] | None = None,
) -> tuple[Any, ...]:
    """Generate shadow specs from the discovered S2F declarations."""
    from arnold.workflow.completion.shadow import generate_shadow_specs

    report = s2f_discovery_gap_report(scan_dirs, schema_markers)
    if not report.discovered_files:
        raise S2FTemplatesUnavailable(report)
    return generate_shadow_specs(report.parsed_declarations)
