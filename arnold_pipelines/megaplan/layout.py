"""Canonical durable Megaplan artifact layout helpers."""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Iterable, Literal

from arnold_pipelines.megaplan.artifacts import slugify as artifact_slugify

LAYOUT_POLICY_VERSION = "megaplan-initiatives-v1"
INITIATIVES_DIR = Path(".megaplan") / "initiatives"
COLLECTION_DIR = Path(".megaplan") / "collection"
COLLECTION_AUTHORITY_PATH = COLLECTION_DIR / "authority.json"
COLLECTION_CHAIN_PATH = COLLECTION_DIR / "chain.yaml"
LEGACY_BRIEFS_DIR = Path(".megaplan") / "briefs"
RUNTIME_PLANS_DIR = Path(".megaplan") / "plans"
RUNTIME_EPICS_DIR = Path(".megaplan") / "epics"
LEGACY_STRATEGY_PATH = Path(".megaplan") / "STRATEGY.md"
STRATEGY_PATH = LEGACY_STRATEGY_PATH  # Backward-compatible public alias.
STRATEGY_FILENAME = "STRATEGY.md"
DEFAULT_STRATEGY_INITIATIVE_SLUG = "repository-strategy"
STRATEGY_PROJECTION_PATH = Path(".megaplan") / "strategy.projection.json"
ALLOWED_INITIATIVE_SUBDIRS = frozenset(
    {"briefs", "research", "decisions", "notes", "assets", "handoff"}
)
ROOT_INITIATIVE_FILES = frozenset(
    {"README.md", "NORTHSTAR.md", "STRATEGY.md", "chain.yaml"}
)
INITIATIVE_RETIREMENT_MARKER = ".retired"

InitiativeDocKind = Literal[
    "briefs",
    "research",
    "decisions",
    "notes",
    "assets",
    "handoff",
]


def render_initiative_readme(title: str, description: str) -> str:
    """Render the initiative front door and canonical working index.

    ``README.md`` is required for agent-obvious discovery.  Readiness anchors
    remain optional: creating an initiative must not imply that a North Star or
    executable chain already exists.
    """

    clean_title = " ".join(str(title).split())
    clean_description = " ".join(str(description).split())
    if not clean_title:
        raise ValueError("initiative title must not be empty")
    if not clean_description:
        raise ValueError("initiative description must not be empty")
    return (
        f"# {clean_title}\n\n"
        f"{clean_description}\n\n"
        "## Current truth and index\n\n"
        "Keep this README current as the initiative front door: state the outcome, boundaries, "
        "success criteria, lifecycle/readiness, and link the canonical documents below. Initiative "
        "creation records commitment to an outcome; it does not launch work.\n\n"
        "- `briefs/` — curated planning inputs and milestone briefs.\n"
        "- `research/` — evidence, investigations, alternatives, and syntheses.\n"
        "- `decisions/` — durable decisions with rationale and consequences.\n"
        "- `notes/` — working notes worth retaining but not yet promoted.\n"
        "- `handoff/` — curated handoffs and canonical syntheses; cite raw agent/subagent run "
        "artifacts instead of copying raw output here.\n"
        "- `assets/` — supporting non-prose files.\n"
        "- `NORTHSTAR.md` — optional durable end-state anchor, added when lifecycle maturity needs it.\n"
        "- `chain.yaml` — optional executable coordination, added only when execution is ready.\n\n"
        "Promote notes/research into decisions or briefs when they become authoritative, and update "
        "this index. Search and reuse related documents, tickets, and initiatives before creating "
        "another artifact.\n"
    )


def slugify_initiative(value: str) -> str:
    """Return the canonical initiative slug."""
    slug = artifact_slugify(value, max_length=96, allow_dots=True)
    if not slug:
        raise ValueError("initiative slug must not be empty")
    return slug


def _matching_strategy_initiative(repo_root: Path) -> Path | None:
    """Return the existing initiative that most clearly owns repo strategy."""
    base = repo_root / INITIATIVES_DIR
    if not base.is_dir():
        return None

    exact = base / DEFAULT_STRATEGY_INITIATIVE_SLUG
    if exact.is_dir():
        return exact

    matches = [
        path
        for path in sorted(base.iterdir())
        if path.is_dir()
        and {"repository", "strategy"}.issubset(set(path.name.split("-")))
    ]
    return matches[0] if len(matches) == 1 else None


def strategy_file_path(
    repo_root: str | Path,
    initiative_slug: str | None = None,
) -> Path:
    """Resolve the authoritative repository strategy Markdown path.

    New strategy documents live at the root of a canonical
    ``megaplan-initiatives-v1`` initiative.  Resolution first honors an
    explicit *initiative_slug*, then an already-adopted initiative strategy,
    then the legacy ``.megaplan/STRATEGY.md`` path for backward compatibility.
    With no existing document, a matching repository-strategy initiative is
    reused; otherwise the canonical ``repository-strategy`` slug is selected.

    This function does not create directories or files.
    """
    root = Path(repo_root)
    base = root / INITIATIVES_DIR
    if initiative_slug is not None:
        return base / slugify_initiative(initiative_slug) / STRATEGY_FILENAME

    legacy = root / LEGACY_STRATEGY_PATH
    adopted = (
        sorted(
            path / STRATEGY_FILENAME
            for path in base.iterdir()
            if path.is_dir() and (path / STRATEGY_FILENAME).is_file()
        )
        if base.is_dir()
        else []
    )
    authorities = [*adopted, *([legacy] if legacy.is_file() else [])]
    if len(authorities) > 1:
        paths = ", ".join(str(path.relative_to(root)) for path in authorities)
        raise ValueError(
            "multiple strategy documents found; keep one canonical repository "
            f"strategy or specify an initiative for initialization: {paths}"
        )
    if adopted:
        return adopted[0]
    if authorities:
        return legacy

    matching = _matching_strategy_initiative(root)
    if matching is not None:
        return matching / STRATEGY_FILENAME
    return base / DEFAULT_STRATEGY_INITIATIVE_SLUG / STRATEGY_FILENAME


def strategy_projection_file_path(repo_root: str | Path) -> Path:
    """Return the absolute path to ``.megaplan/strategy.projection.json``.

    This is a pure path computation — it does not create directories or
    verify that the file exists.
    """
    return Path(repo_root) / STRATEGY_PROJECTION_PATH


def initiatives_dir(repo_root: str | Path) -> Path:
    path = Path(repo_root) / INITIATIVES_DIR
    path.mkdir(parents=True, exist_ok=True)
    return path


def collection_dir(repo_root: str | Path) -> Path:
    """Return the ownerless, placement-only collection namespace."""

    return Path(repo_root) / COLLECTION_DIR


def initiative_root(repo_root: str | Path, slug: str) -> Path:
    return initiatives_dir(repo_root) / slugify_initiative(slug)


def initiative_retirement_marker(repo_root: str | Path, slug: str) -> Path:
    """Return the metadata-only retirement marker for one initiative."""

    return initiative_root(repo_root, slug) / INITIATIVE_RETIREMENT_MARKER


def is_initiative_retired(repo_root: str | Path, slug: str) -> bool:
    """Fail closed when a canonical initiative retirement marker exists."""

    marker = initiative_retirement_marker(repo_root, slug)
    return marker.is_symlink() or marker.is_file()


def retired_chain_marker(spec_path: str | Path, repo_root: str | Path) -> Path | None:
    """Return the retirement marker when *spec_path* is a retired initiative chain."""

    path = Path(spec_path).expanduser().resolve()
    root = Path(repo_root).expanduser().resolve()
    if not is_canonical_chain_spec(path, root):
        return None
    marker = path.parent / INITIATIVE_RETIREMENT_MARKER
    return marker if marker.is_symlink() or marker.is_file() else None


def read_initiative_retirement(repo_root: str | Path, slug: str) -> dict[str, Any] | None:
    """Read JSON retirement evidence, retaining legacy key/value markers."""

    marker = initiative_retirement_marker(repo_root, slug)
    if marker.is_symlink():
        return {"status": "retired", "marker_path": str(marker), "valid": False}
    if not marker.is_file():
        return None
    try:
        text = marker.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return {"status": "retired", "marker_path": str(marker), "valid": False}
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        payload = {}
        for line in text.splitlines():
            key, separator, value = line.partition(":")
            if separator and key.strip():
                payload[key.strip()] = value.strip()
    if not isinstance(payload, dict):
        payload = {}
    return {"status": "retired", "marker_path": str(marker), **payload}


def initiative_doc_dir(repo_root: str | Path, slug: str, kind: InitiativeDocKind) -> Path:
    if kind not in ALLOWED_INITIATIVE_SUBDIRS:
        raise ValueError(f"invalid initiative document kind: {kind}")
    return initiative_root(repo_root, slug) / kind


def is_canonical_chain_spec(path: str | Path, repo_root: str | Path) -> bool:
    try:
        rel = Path(path).expanduser().resolve().relative_to(Path(repo_root).expanduser().resolve())
    except ValueError:
        return False
    parts = rel.parts
    return (
        len(parts) == 4
        and parts[0] == ".megaplan"
        and parts[1] == "initiatives"
        and parts[3] == "chain.yaml"
        and bool(parts[2])
    )


def is_collection_chain_spec(path: str | Path, repo_root: str | Path) -> bool:
    """Recognize the preserved collection chain without granting launch authority."""

    try:
        rel = Path(path).expanduser().resolve().relative_to(Path(repo_root).expanduser().resolve())
    except ValueError:
        return False
    return rel == COLLECTION_CHAIN_PATH


def is_legacy_briefs_chain_spec(path: str | Path, repo_root: str | Path) -> bool:
    try:
        rel = Path(path).expanduser().resolve().relative_to(Path(repo_root).expanduser().resolve())
    except ValueError:
        return False
    parts = rel.parts
    return (
        len(parts) == 4
        and parts[0] == ".megaplan"
        and parts[1] == "briefs"
        and parts[3] == "chain.yaml"
        and bool(parts[2])
    )


def classify_initiative_doc_path(path: str | Path) -> InitiativeDocKind:
    """Classify a legacy initiative artifact into a canonical subdirectory."""
    p = Path(path)
    name = p.name
    lowered = name.lower()
    parts = {part.lower() for part in p.parts}
    if ".megaplan" in parts:
        return "assets"
    if any(part in {"subagent-results", "subagent-briefs", "deferred"} for part in parts):
        return "handoff"
    if re.match(r"^(m\d+|m\d+[a-z]?|m\d+\.\d+|c\d+|ar\d+)[-_ .]", lowered) or re.match(
        r"^(m\d+|c\d+|ar\d+)\.md$", lowered
    ):
        return "briefs"
    if any(token in lowered for token in ("decision", "verdict")):
        return "decisions"
    if any(
        token in lowered
        for token in (
            "research",
            "analysis",
            "audit",
            "review",
            "synthesis",
            "inventory",
            "proposal",
            "spec",
            "contract",
            "plan",
        )
    ):
        return "research"
    if lowered.endswith((".md", ".txt")):
        return "notes"
    return "assets"


def initiative_metadata(repo_root: str | Path, slug: str) -> dict[str, Any]:
    root = initiative_root(repo_root, slug)
    chain_path = root / "chain.yaml"
    docs = recent_initiative_docs(root)
    readme = _read_initiative_readme(root)
    return {
        "slug": root.name,
        "title": readme["title"],
        "description": readme["description"],
        "path": str(root),
        "chain_path": str(chain_path) if chain_path.exists() else None,
        "known_asset_roots": [
            str(root / name)
            for name in sorted(ALLOWED_INITIATIVE_SUBDIRS)
            if (root / name).exists()
        ],
        "recent_docs": docs,
        "layout_policy_version": LAYOUT_POLICY_VERSION,
        "retired": is_initiative_retired(repo_root, slug),
        "retirement": read_initiative_retirement(repo_root, slug),
    }


def initiative_search_text(repo_root: str | Path, slug: str) -> str:
    """Return searchable text for an initiative's lightweight metadata/docs."""
    root = initiative_root(repo_root, slug)
    parts = [root.name]
    for name in ("README.md", "NORTHSTAR.md"):
        path = root / name
        if path.exists():
            try:
                parts.append(path.read_text(encoding="utf-8"))
            except UnicodeDecodeError:
                continue
    return "\n".join(parts)


def initiative_compact_index(repo_root: str | Path, *, limit: int = 50) -> list[dict[str, Any]]:
    """Return compact initiative rows suitable for prompt/context injection."""
    base = Path(repo_root) / INITIATIVES_DIR
    if not base.exists():
        return []
    rows: list[dict[str, Any]] = []
    for path in sorted(base.iterdir()):
        if not path.is_dir():
            continue
        if is_initiative_retired(repo_root, path.name):
            continue
        metadata = initiative_metadata(repo_root, path.name)
        rows.append(
            {
                "slug": metadata["slug"],
                "title": metadata["title"],
                "description": _compact_text(metadata["description"], 180),
                "chain": bool(metadata["chain_path"]),
                "recent_docs": [doc["path"] for doc in metadata["recent_docs"][:4]],
            }
        )
        if len(rows) >= limit:
            break
    return rows


def search_initiatives(
    repo_root: str | Path,
    query: str | Iterable[str],
    *,
    keywords_all: bool = False,
    limit: int = 25,
    include_retired: bool = False,
) -> list[dict[str, Any]]:
    """Search initiatives by slug/title/description with forgiving token matching."""
    terms = _search_terms(query)
    if not terms:
        return []
    base = Path(repo_root) / INITIATIVES_DIR
    if not base.exists():
        return []
    rows: list[dict[str, Any]] = []
    for path in sorted(base.iterdir()):
        if not path.is_dir():
            continue
        if not include_retired and is_initiative_retired(repo_root, path.name):
            continue
        metadata = initiative_metadata(repo_root, path.name)
        searchable = " ".join(
            str(value or "")
            for value in (
                metadata["slug"],
                metadata["title"],
                metadata["description"],
            )
        )
        term_scores = [_term_match_score(term, searchable) for term in terms]
        matched = all(score > 0 for score in term_scores) if keywords_all else any(score > 0 for score in term_scores)
        if not matched:
            continue
        score = sum(term_scores) / max(1, len(terms))
        rows.append(
            {
                **metadata,
                "match_score": round(score, 3),
                "matched_terms": [term for term, term_score in zip(terms, term_scores) if term_score > 0],
            }
        )
    rows.sort(key=lambda row: (row["match_score"], row["slug"]), reverse=True)
    return rows[:limit]


def _read_initiative_readme(root: Path) -> dict[str, str | None]:
    path = root / "README.md"
    if not path.exists():
        return {"title": None, "description": None}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        return {"title": None, "description": None}
    if lines and lines[0].strip() == "---":
        try:
            closing = next(
                index for index, line in enumerate(lines[1:], start=1) if line.strip() == "---"
            )
        except StopIteration:
            return {"title": None, "description": None}
        lines = lines[closing + 1 :]
    title: str | None = None
    description_parts: list[str] = []
    in_description = False
    for line in lines:
        stripped = line.strip()
        if not stripped:
            if in_description and description_parts:
                break
            continue
        if stripped.startswith("# ") and title is None:
            title = stripped[2:].strip() or None
            continue
        if stripped.startswith("---"):
            continue
        if stripped.startswith("#"):
            if in_description:
                break
            continue
        in_description = True
        description_parts.append(stripped)
    description = " ".join(description_parts) or None
    return {"title": title, "description": description}


def _search_terms(query: str | Iterable[str]) -> list[str]:
    raw = [query] if isinstance(query, str) else list(query)
    terms: list[str] = []
    for value in raw:
        terms.extend(_normalize_search_token(part) for part in str(value).split())
    return [term for term in terms if term]


def _normalize_search_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _search_tokens(value: str) -> list[str]:
    return [token for token in (_normalize_search_token(part) for part in re.split(r"[^A-Za-z0-9]+", value)) if token]


def _term_match_score(term: str, searchable: str) -> float:
    normalized = " ".join(_search_tokens(searchable))
    if not normalized:
        return 0.0
    if term in normalized.replace(" ", "") or term in normalized.split():
        return 1.0
    best = max((SequenceMatcher(None, term, token).ratio() for token in normalized.split()), default=0.0)
    if best >= 0.82:
        return best
    if len(term) >= 5 and best >= 0.72:
        return best * 0.85
    return 0.0


def _compact_text(value: Any, limit: int) -> str | None:
    if value is None:
        return None
    text = " ".join(str(value).split())
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)].rstrip() + "..."


def recent_initiative_docs(root: Path, *, limit: int = 12) -> list[dict[str, Any]]:
    if not root.exists():
        return []
    files = [
        path
        for path in root.rglob("*")
        if path.is_file() and ".megaplan" not in path.relative_to(root).parts
    ]
    files.sort(key=lambda path: (path.stat().st_mtime, path.as_posix()), reverse=True)
    out: list[dict[str, Any]] = []
    for path in files[:limit]:
        rel = path.relative_to(root).as_posix()
        out.append({"path": rel, "size_bytes": path.stat().st_size})
    return out


@dataclass(frozen=True)
class LayoutMigrationAction:
    source: str
    destination: str | None
    action: str
    kind: str | None = None
    reason: str | None = None


def migrate_legacy_briefs_layout(repo_root: str | Path, *, apply: bool = False) -> dict[str, Any]:
    """Move legacy ``.megaplan/briefs`` artifacts into initiatives layout."""
    root = Path(repo_root)
    legacy_root = root / LEGACY_BRIEFS_DIR
    actions: list[LayoutMigrationAction] = []
    if not legacy_root.exists():
        return {"applied": apply, "actions": [], "count": 0, "legacy_root_exists": False}

    for child in sorted(legacy_root.iterdir()):
        if child.name == ".DS_Store":
            actions.append(LayoutMigrationAction(_rel(root, child), None, "delete", reason="macOS sidecar"))
            if apply:
                child.unlink(missing_ok=True)
            continue
        if child.is_file():
            slug = _loose_file_holding_slug(child)
            destination = initiative_doc_dir(root, slug, classify_initiative_doc_path(child.name)) / child.name
            _record_move(actions, root, child, destination, apply=apply)
            continue
        if not child.is_dir():
            continue
        slug = slugify_initiative(child.name)
        for path in sorted(child.rglob("*")):
            if not path.is_file():
                continue
            if path.name == ".DS_Store":
                actions.append(LayoutMigrationAction(_rel(root, path), None, "delete", reason="macOS sidecar"))
                if apply:
                    path.unlink(missing_ok=True)
                continue
            rel = path.relative_to(child)
            if rel.parts[:2] == (".megaplan", "plans"):
                destination = root / RUNTIME_PLANS_DIR / "migrated" / slug / Path(*rel.parts[2:])
                _record_move(actions, root, path, destination, apply=apply, kind="runtime")
                continue
            if rel.parts and rel.parts[0] == ".megaplan":
                destination = initiative_doc_dir(root, slug, "assets") / "legacy-megaplan" / Path(*rel.parts[1:])
                _record_move(actions, root, path, destination, apply=apply, kind="assets")
                continue
            if rel.as_posix() == "chain.yaml":
                destination = initiative_root(root, slug) / "chain.yaml"
                _record_move(actions, root, path, destination, apply=apply, kind="chain")
                continue
            if path.name in {"NORTHSTAR.md", "README.md"}:
                destination = initiative_root(root, slug) / path.name
                _record_move(actions, root, path, destination, apply=apply, kind="root")
                continue
            kind = classify_initiative_doc_path(rel)
            destination = initiative_doc_dir(root, slug, kind) / rel
            _record_move(actions, root, path, destination, apply=apply, kind=kind)
    if apply:
        _prune_empty_dirs(legacy_root)
        if legacy_root.exists() and not any(legacy_root.iterdir()):
            legacy_root.rmdir()
        rewritten = _rewrite_legacy_briefs_references(root)
        actions.extend(
            LayoutMigrationAction(path, path, "rewrite", reason="legacy .megaplan/briefs reference")
            for path in rewritten
        )
    return {
        "applied": apply,
        "actions": [action.__dict__ for action in actions],
        "count": len(actions),
        "legacy_root_exists": legacy_root.exists(),
    }


def _loose_file_holding_slug(path: Path) -> str:
    name = path.stem.lower()
    if name.startswith("native-python-pipelines"):
        return "native-python-pipelines"
    if name.startswith(("generalized-pipeline", "aggressive-migration", "pipeline-generalization")):
        return "aggressive-generalized-pipeline-migration"
    if name.startswith("megaplan"):
        return "megaplan-maintenance"
    return "legacy-loose-briefs"


def _record_move(
    actions: list[LayoutMigrationAction],
    root: Path,
    source: Path,
    destination: Path,
    *,
    apply: bool,
    kind: str | None = None,
) -> None:
    final_destination = _unique_destination(destination) if apply else destination
    actions.append(
        LayoutMigrationAction(
            _rel(root, source),
            _rel(root, final_destination),
            "move",
            kind=kind or classify_initiative_doc_path(source),
        )
    )
    if apply:
        final_destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(source), str(final_destination))


def _unique_destination(path: Path) -> Path:
    if not path.exists():
        return path
    stem = path.stem
    suffix = path.suffix
    parent = path.parent
    index = 2
    while True:
        candidate = parent / f"{stem}-{index}{suffix}"
        if not candidate.exists():
            return candidate
        index += 1


def _prune_empty_dirs(path: Path) -> None:
    if not path.exists():
        return
    for child in sorted([p for p in path.rglob("*") if p.is_dir()], reverse=True):
        try:
            child.rmdir()
        except OSError:
            pass


def _rel(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _rewrite_legacy_briefs_references(root: Path) -> list[str]:
    pattern = re.compile(r"\.megaplan/briefs/([^/\s'\"#]+)/([^\s'\"#]+)")
    changed: list[str] = []
    initiatives = root / INITIATIVES_DIR
    if not initiatives.exists():
        return changed
    for path in initiatives.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in {".md", ".yaml", ".yml"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue

        def repl(match: re.Match[str]) -> str:
            slug, remainder = match.group(1), match.group(2)
            return f".megaplan/initiatives/{slug}/briefs/{remainder}"

        new_text = pattern.sub(repl, text)
        new_text = new_text.replace(
            ".megaplan/initiatives/artifact-store/briefs/chain.yaml",
            ".megaplan/initiatives/artifact-store/chain.yaml",
        ).replace(
            ".megaplan/initiatives/artifact-store/briefs/NORTHSTAR.md",
            ".megaplan/initiatives/artifact-store/NORTHSTAR.md",
        )
        if new_text != text:
            path.write_text(new_text, encoding="utf-8")
            changed.append(_rel(root, path))
    return changed
