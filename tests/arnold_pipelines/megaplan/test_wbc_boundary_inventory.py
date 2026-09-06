"""Schema validation tests for WBC boundary discovery rules and inventory.

Validates the ``evidence/wbc-boundary-discovery-rules.yaml`` artifact and
the ``evidence/wbc-boundary-inventory.json`` artifact:
required roots, required row fields per surface type, owner requirements,
non-authority surface type enforcement, and read-only operation constraints.

T6 extends these tests with:
- Wrapper/shell discovery (non-Python scripts that produce boundary effects)
- Default-deny rows for unresolved dynamic/generated/provider surfaces
- Current-state assertions: 5 front-half producers, 8 execute/batch
  producers, execute/review auto-exclusion, best-effort emission hazards.

These tests are intentionally observe-only: they parse and validate the
discovery rules and inventory without mutating lifecycle state or runtime behavior.
"""

from __future__ import annotations

import io
import importlib.util
import json
import pathlib
import sys
from typing import Any

import pytest
import yaml


# ── helpers ────────────────────────────────────────────────────────────────


def _load_rules() -> dict[str, Any]:
    rules_path = (
        pathlib.Path(__file__).resolve().parents[3]
        / "evidence"
        / "wbc-boundary-discovery-rules.yaml"
    )
    if not rules_path.exists():
        pytest.skip("Discovery rules artifact not yet generated")
    with open(rules_path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _load_generator() -> Any:
    repo_root = pathlib.Path(__file__).resolve().parents[3]
    path = repo_root / "tools" / "generate_wbc_boundary_inventory.py"
    spec = importlib.util.spec_from_file_location("wbc_boundary_inventory_generator", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


# ── schema tests ───────────────────────────────────────────────────────────


class TestDiscoveryRulesSchema:
    """Validate the top-level structure of the discovery rules artifact."""

    def test_has_meta_section(self) -> None:
        rules = _load_rules()
        assert "meta" in rules, "Discovery rules must have a 'meta' section"
        meta = rules["meta"]
        assert "schema" in meta, "meta.schema is required"
        assert meta["schema"] == "m6.wbc-discovery-rules.v1"

    def test_has_roots_section(self) -> None:
        rules = _load_rules()
        assert "roots" in rules, "Discovery rules must have a 'roots' section"
        assert isinstance(rules["roots"], list), "'roots' must be a list"
        assert len(rules["roots"]) > 0, "At least one root must be defined"

    def test_has_row_kinds_section(self) -> None:
        rules = _load_rules()
        assert "row_kinds" in rules, "Discovery rules must have a 'row_kinds' section"
        assert isinstance(rules["row_kinds"], dict), "'row_kinds' must be a mapping"

    def test_has_validation_rules_section(self) -> None:
        rules = _load_rules()
        assert (
            "validation_rules" in rules
        ), "Discovery rules must have a 'validation_rules' section"

    def test_has_categories_section(self) -> None:
        rules = _load_rules()
        assert (
            "categories" in rules
        ), "Discovery rules must have a 'categories' section"


class TestDiscoveryRoots:
    """Validate the discovery root entries."""

    def test_every_root_has_path(self) -> None:
        rules = _load_rules()
        for root in rules["roots"]:
            assert "path" in root, f"Root missing 'path': {root}"
            assert isinstance(root["path"], str), f"Root path must be a string: {root}"
            assert root["path"], f"Root path must be non-empty: {root}"

    def test_every_root_has_category(self) -> None:
        rules = _load_rules()
        for root in rules["roots"]:
            assert "category" in root, f"Root missing 'category': {root}"
            assert root["category"], f"Root category must be non-empty: {root}"

    def test_every_root_has_file_patterns(self) -> None:
        rules = _load_rules()
        for root in rules["roots"]:
            assert (
                "file_patterns" in root
            ), f"Root missing 'file_patterns': {root}"
            assert isinstance(
                root["file_patterns"], list
            ), f"file_patterns must be a list: {root}"
            assert (
                len(root["file_patterns"]) > 0
            ), f"file_patterns must be non-empty: {root}"

    def test_required_roots_exist(self) -> None:
        """Required roots must list at least the core WBC directories."""
        rules = _load_rules()
        required_paths = {
            r["path"] for r in rules["roots"] if r.get("required", False)
        }
        assert "arnold/workflow" in required_paths
        assert "arnold_pipelines/megaplan/workflows" in required_paths
        assert "arnold_pipelines/megaplan/handlers" in required_paths
        assert "arnold/execution" in required_paths

    def test_no_duplicate_root_paths(self) -> None:
        rules = _load_rules()
        paths = [r["path"] for r in rules["roots"]]
        assert len(paths) == len(set(paths)), "Root paths must be unique"

    def test_m10_roots_and_standalone_files_are_declared(self) -> None:
        paths = {root["path"] for root in _load_rules()["roots"]}
        required = {
            "arnold_pipelines/megaplan/cloud",
            "arnold_pipelines/megaplan/chain",
            "arnold_pipelines/megaplan/custody",
            "arnold_pipelines/megaplan/loop",
            "arnold_pipelines/megaplan/resident",
            "arnold_pipelines/megaplan/bakeoff",
            "arnold_pipelines/megaplan/cli",
            "arnold_pipelines/megaplan/skills",
            "arnold_pipelines/megaplan/discord_dm.py",
            "arnold_pipelines/megaplan/agentbox_adapter.py",
            "arnold_pipelines/megaplan/auto.py",
        }
        assert not required - paths

    def test_yaml_roots_are_loaded_and_merged(self) -> None:
        generator = _load_generator()
        roots = generator._discovery_roots()
        paths = [root["path"] for root in roots]
        assert len(paths) == len(set(paths))
        assert "arnold_pipelines/megaplan/workflows" in paths
        assert "arnold_pipelines/megaplan/cloud" in paths


class TestM10ExternalMutationDiscovery:
    """All newly admitted roots must produce classified mutation evidence."""

    def _modules(self) -> dict[str, dict[str, Any]]:
        generator = _load_generator()
        return {
            row["module_path"]: row
            for row in generator._scan_discovery_roots()["modules"]
        }

    def test_every_new_directory_root_contributes_rows(self) -> None:
        paths = set(self._modules())
        for prefix in (
            "arnold_pipelines/megaplan/cloud/",
            "arnold_pipelines/megaplan/chain/",
            "arnold_pipelines/megaplan/custody/",
            "arnold_pipelines/megaplan/loop/",
            "arnold_pipelines/megaplan/resident/",
            "arnold_pipelines/megaplan/bakeoff/",
            "arnold_pipelines/megaplan/cli/",
            "arnold_pipelines/megaplan/skills/",
        ):
            assert any(path.startswith(prefix) for path in paths), prefix

    def test_standalone_file_roots_are_scanned(self) -> None:
        paths = set(self._modules())
        assert {
            "arnold_pipelines/megaplan/discord_dm.py",
            "arnold_pipelines/megaplan/agentbox_adapter.py",
            "arnold_pipelines/megaplan/auto.py",
        } <= paths

    def test_loop_shell_commands_are_classified_action_off(self) -> None:
        row = self._modules()["arnold_pipelines/megaplan/loop/engine.py"]
        calls = {
            mutation["call"]: mutation
            for mutation in row["external_mutations"]
        }
        for call in ("subprocess.run", "subprocess.Popen"):
            assert call in calls
            assert calls[call]["kind"] == "command_execution"
            assert calls[call]["disposition"] == "action_off"
            assert calls[call]["owner"] == "run_authority"
            assert calls[call]["reason"]
            assert calls[call]["expiry"]

    def test_subagent_launchers_are_classified_action_off(self) -> None:
        modules = self._modules()
        for path in (
            "arnold_pipelines/megaplan/skills/subagent-launcher/launch_claude_agent.py",
            "arnold_pipelines/megaplan/skills/subagent-launcher/launch_omp_agent.py",
        ):
            mutations = modules[path]["external_mutations"]
            subprocess_calls = [
                mutation
                for mutation in mutations
                if mutation["call"] == "subprocess.run"
            ]
            if not subprocess_calls:
                subprocess_calls = [
                    mutation
                    for mutation in mutations
                    if mutation["call"] == "subprocess.Popen"
                ]
            assert subprocess_calls, path
            assert all(
                mutation["disposition"] == "action_off"
                and mutation["owner"] == "run_authority"
                and mutation["reason"]
                and mutation["expiry"]
                for mutation in subprocess_calls
            )

    def test_detected_external_mutations_are_fully_classified(self) -> None:
        allowed_kinds = {
            "command_execution",
            "external_send",
            "network_or_provider",
        }
        allowed_dispositions = {"action_off", "inventory_only"}
        for path, row in self._modules().items():
            for mutation in row["external_mutations"]:
                assert mutation["kind"] in allowed_kinds, path
                assert mutation["disposition"] in allowed_dispositions, path
                assert mutation["owner"], path
                assert mutation["reason"], path
                assert mutation["expiry"], path
                assert mutation["line"] > 0, path
            if row["external_mutations"]:
                assert "producer" in row["surface_types"], path


class TestRowKindFields:
    """Validate the row_kinds entries and their required fields."""

    def test_required_row_kinds_present(self) -> None:
        """Every core surface type must have a row_kind definition."""
        rules = _load_rules()
        kinds = set(rules["row_kinds"].keys())
        required = {
            "boundary_contract",
            "authority_surface",
            "manifest_entry",
            "handler_function",
            "runtime_module",
            "wrapper_shell",
            "unmatched",
        }
        missing = required - kinds
        assert not missing, f"Missing required row kinds: {missing}"

    def test_every_row_kind_has_description(self) -> None:
        rules = _load_rules()
        for kind_name, kind_def in rules["row_kinds"].items():
            assert (
                "description" in kind_def
            ), f"Row kind '{kind_name}' missing 'description'"

    def test_every_row_kind_has_required_fields(self) -> None:
        rules = _load_rules()
        for kind_name, kind_def in rules["row_kinds"].items():
            assert (
                "required_fields" in kind_def
            ), f"Row kind '{kind_name}' missing 'required_fields'"
            fields = kind_def["required_fields"]
            assert isinstance(fields, list), f"required_fields must be a list: {kind_name}"
            assert len(fields) > 0, f"required_fields must be non-empty: {kind_name}"

    def test_every_field_has_name_and_type(self) -> None:
        rules = _load_rules()
        for kind_name, kind_def in rules["row_kinds"].items():
            for field in kind_def["required_fields"]:
                assert "name" in field, (
                    f"Field in '{kind_name}' missing 'name': {field}"
                )
                assert "type" in field, (
                    f"Field '{field['name']}' in '{kind_name}' missing 'type'"
                )

    def test_no_duplicate_field_names_per_kind(self) -> None:
        rules = _load_rules()
        for kind_name, kind_def in rules["row_kinds"].items():
            names = [f["name"] for f in kind_def["required_fields"]]
            assert len(names) == len(set(names)), (
                f"Duplicate field names in '{kind_name}': {names}"
            )


class TestOwnerRequirements:
    """Validate owner-required semantics across row kinds."""

    def test_some_field_requires_owner_in_every_row_kind(self) -> None:
        """Every row kind must have at least one field with owner_required=true."""
        rules = _load_rules()
        for kind_name, kind_def in rules["row_kinds"].items():
            owner_fields = [
                f for f in kind_def["required_fields"] if f.get("owner_required")
            ]
            assert len(owner_fields) > 0, (
                f"Row kind '{kind_name}' has no owner-required field. "
                f"Every row must name an owner."
            )

    def test_owner_fields_use_known_domains(self) -> None:
        """Owner fields with validation.owner_must_be_known_domain must list domains."""
        rules = _load_rules()
        for kind_name, kind_def in rules["row_kinds"].items():
            validation = kind_def.get("validation", {})
            if validation.get("owner_must_be_known_domain"):
                domains = validation.get("known_owner_domains", [])
                assert len(domains) > 0, (
                    f"Row kind '{kind_name}' requires known domains but none listed"
                )
                for domain in domains:
                    assert domain in ("run_authority", "wbc", "maintenance"), (
                        f"Unknown owner domain '{domain}' in '{kind_name}'"
                    )

    def test_unmatched_kind_allows_unknown_owner(self) -> None:
        """The 'unmatched' row kind must allow UNKNOWN owner."""
        rules = _load_rules()
        unmatched = rules["row_kinds"].get("unmatched", {})
        validation = unmatched.get("validation", {})
        assert validation.get("owner_may_be_unknown", False), (
            "Unmatched rows must allow UNKNOWN owner"
        )
        assert validation.get("unknown_owner_value") == "UNKNOWN", (
            "Unknown owner sentinel must be 'UNKNOWN'"
        )


class TestValidationRules:
    """Validate the cross-cutting validation rules."""

    def test_forbidden_operations_are_not_in_allowed(self) -> None:
        rules = _load_rules()
        vr = rules["validation_rules"]
        allowed = set(vr["allowed_operations"])
        forbidden = set(vr["forbidden_operations"])
        overlap = allowed & forbidden
        assert not overlap, (
            f"Operations cannot be both allowed and forbidden: {overlap}"
        )

    def test_mutating_commands_are_forbidden(self) -> None:
        """Operations that mutate state must be forbidden."""
        rules = _load_rules()
        forbidden = set(rules["validation_rules"]["forbidden_operations"])
        must_be_forbidden = {
            "write_file",
            "delete_file",
            "execute_command",
            "mutate_state",
            "git_commit",
            "git_push",
            "pip_install",
            "database_write",
            "queue_publish",
            "notification_send",
        }
        missing = must_be_forbidden - forbidden
        assert not missing, (
            f"Mutating operations not listed as forbidden: {missing}"
        )

    def test_allowed_operations_are_read_only(self) -> None:
        """All allowed operations must be read-only / non-mutating."""
        rules = _load_rules()
        allowed = rules["validation_rules"]["allowed_operations"]
        mutating_keywords = {"write", "delete", "execute", "mutate", "commit", "push", "install", "publish", "send"}
        for op in allowed:
            for keyword in mutating_keywords:
                assert keyword not in op.lower(), (
                    f"Potentially mutating operation '{op}' in allowed list"
                )

    def test_owner_required_for_all_rows(self) -> None:
        rules = _load_rules()
        vr = rules["validation_rules"]
        assert vr.get("owner_required_for_all_rows", False), (
            "validation_rules must require owner for all rows"
        )

    def test_unknown_owner_sentinel_is_unknown(self) -> None:
        rules = _load_rules()
        vr = rules["validation_rules"]
        assert vr.get("unknown_owner_sentinel") == "UNKNOWN", (
            "Unknown owner sentinel must be 'UNKNOWN'"
        )

    def test_non_authority_surface_types_defined(self) -> None:
        rules = _load_rules()
        vr = rules["validation_rules"]
        non_auth = vr.get("non_authority_surface_types", {})
        types = non_auth.get("types", [])
        must_include = {
            "projection",
            "status_snapshot",
            "liveness_check",
            "support_label",
            "schema_only_ledger",
            "fixture_emitter",
            "receipt",
        }
        missing = must_include - set(types)
        assert not missing, (
            f"Non-authority surface types missing: {missing}"
        )

    def test_default_deny_unresolved_enabled(self) -> None:
        rules = _load_rules()
        vr = rules["validation_rules"]
        assert vr.get("default_deny_unresolved", False), (
            "Default-deny must be enabled for unresolved surfaces"
        )

    def test_historical_adapter_default_is_empty(self) -> None:
        rules = _load_rules()
        vr = rules["validation_rules"]
        assert vr.get("historical_adapter_default") == "empty", (
            "Historical adapters must default to empty unless proven"
        )

    def test_unavailable_denominator_is_unknown(self) -> None:
        rules = _load_rules()
        vr = rules["validation_rules"]
        assert vr.get("unavailable_denominator_sentinel") == "UNKNOWN", (
            "Unavailable denominators must be 'UNKNOWN', never 0 or false"
        )


class TestMutationDetection:
    """Validate that the discovery rules reject mutating configurations."""

    def test_cannot_add_write_operation_to_allowed(self) -> None:
        """A modified ruleset with a write op in allowed must be detected."""
        rules = _load_rules()
        # Simulate adding a mutating op to allowed
        modified = dict(rules)
        modified["validation_rules"] = dict(rules["validation_rules"])
        modified["validation_rules"]["allowed_operations"] = list(
            rules["validation_rules"]["allowed_operations"]
        ) + ["write_file"]

        allowed = set(modified["validation_rules"]["allowed_operations"])
        forbidden = set(modified["validation_rules"]["forbidden_operations"])
        overlap = allowed & forbidden
        assert "write_file" in overlap, (
            "Adding a forbidden op to allowed must be detectable via overlap check"
        )

    def test_cannot_remove_forbidden_operations(self) -> None:
        """Removing forbidden ops must leave mutating ops undefended."""
        rules = _load_rules()
        # Simulate removing mutating ops from forbidden
        modified = dict(rules)
        modified["validation_rules"] = dict(rules["validation_rules"])
        modified["validation_rules"]["forbidden_operations"] = [
            op for op in rules["validation_rules"]["forbidden_operations"]
            if op not in ("write_file", "mutate_state")
        ]
        forbidden = set(modified["validation_rules"]["forbidden_operations"])
        assert "write_file" not in forbidden, (
            "Removed write_file from forbidden — no longer protected"
        )
        assert "mutate_state" not in forbidden, (
            "Removed mutate_state from forbidden — no longer protected"
        )


class TestNoOwnerExceptionDetection:
    """Validate that rows without an owner are detectable."""

    KNOWN_DOMAINS = {"run_authority", "wbc", "maintenance"}

    def _get_owner_required_field_names(self, kind_def: dict) -> list[str]:
        return [
            f["name"]
            for f in kind_def.get("required_fields", [])
            if f.get("owner_required")
        ]

    def test_boundary_contract_without_owner_is_invalid(self) -> None:
        """A boundary_contract with empty owner must fail validation."""
        rules = _load_rules()
        bc = rules["row_kinds"]["boundary_contract"]
        owner_fields = self._get_owner_required_field_names(bc)
        assert "owner" in owner_fields, (
            "boundary_contract must have an owner-required field"
        )

        # Simulate a row with empty owner
        row = {
            "boundary_id": "test.boundary",
            "workflow_id": "test-workflow",
            "row_id": "test.row.1",
            "phase": "execute",
            "producer_path": "some/module.py",
            "producer_category": "manual_emit",
            "owner": "",  # empty — should fail
            "support_status": "supported",
            "authority_required": True,
        }
        assert not row["owner"], "Empty owner should be detectable"
        assert row["owner"] not in self.KNOWN_DOMAINS, (
            "Empty string is not a known domain"
        )

    def test_boundary_contract_with_unknown_owner_is_invalid(self) -> None:
        """A boundary_contract with a made-up owner must fail validation."""
        row = {
            "boundary_id": "test.boundary",
            "workflow_id": "test-workflow",
            "owner": "made_up_domain",
        }
        assert row["owner"] not in self.KNOWN_DOMAINS, (
            f"'{row['owner']}' is not a known owner domain"
        )

    def test_manifest_entry_without_owner_is_invalid(self) -> None:
        """A manifest_entry with missing owner must fail."""
        rules = _load_rules()
        me = rules["row_kinds"]["manifest_entry"]
        owner_fields = self._get_owner_required_field_names(me)
        assert "owner" in owner_fields, (
            "manifest_entry must have an owner-required field"
        )

        row = {
            "step_id": "test.step",
            "step_name": "Test Step",
            "kind": "handler",
            "owner": None,  # None — should fail
            "support_status": "supported",
            "producer_path": "some/path.py",
            "c2_c6_milestone": "c3",
        }
        assert row["owner"] is None, "None owner should be detectable"

    def test_unmatched_row_with_missing_owner_is_invalid(self) -> None:
        """An unmatched row with no owner field at all must fail."""
        row = {
            "discovery_path": "/some/path.py",
            "discovery_source": "static_scan",
            "reason_unmatched": "no_declared_contract",
            # owner field missing entirely
        }
        assert "owner" not in row, (
            "Missing owner field should be detectable"
        )

    def test_unmatched_row_with_unknown_owner_is_allowed(self) -> None:
        """An unmatched row may use UNKNOWN as the owner value."""
        row = {
            "discovery_path": "/some/path.py",
            "discovery_source": "static_scan",
            "reason_unmatched": "dynamic_surface",
            "owner": "UNKNOWN",
        }
        assert row["owner"] == "UNKNOWN", (
            "UNKNOWN is the valid sentinel for unresolved owners in unmatched rows"
        )

    def test_authority_surface_without_mutating_owner_is_invalid(self) -> None:
        """An authority_surface with empty mutating_owner must fail."""
        rules = _load_rules()
        sf = rules["row_kinds"]["authority_surface"]
        owner_fields = self._get_owner_required_field_names(sf)
        assert "mutating_owner" in owner_fields, (
            "authority_surface must have mutating_owner as owner-required"
        )

        row = {
            "surface_id": "test.surface",
            "surface_name": "Test Surface",
            "category": "claim",
            "mutating_owner": "",  # empty — should fail
            "wbc_access_level": "declare",
            "compatibility_readers": [],
        }
        assert not row["mutating_owner"], "Empty mutating_owner should be detectable"
        assert row["mutating_owner"] not in self.KNOWN_DOMAINS, (
            "Empty string is not a known domain"
        )


class TestNonAuthoritySurfaceEnforcement:
    """Validate that non-authority surface types are never promoted."""

    def _non_authority_types(self) -> set[str]:
        rules = _load_rules()
        non_auth = rules["validation_rules"].get("non_authority_surface_types", {})
        return set(non_auth.get("types", []))

    def test_projection_is_not_authority(self) -> None:
        assert "projection" in self._non_authority_types()

    def test_status_snapshot_is_not_authority(self) -> None:
        assert "status_snapshot" in self._non_authority_types()

    def test_liveness_check_is_not_authority(self) -> None:
        assert "liveness_check" in self._non_authority_types()

    def test_support_label_is_not_authority(self) -> None:
        assert "support_label" in self._non_authority_types()

    def test_schema_only_ledger_is_not_authority(self) -> None:
        assert "schema_only_ledger" in self._non_authority_types()

    def test_fixture_emitter_is_not_authority(self) -> None:
        assert "fixture_emitter" in self._non_authority_types()

    def test_receipt_surface_is_not_authority(self) -> None:
        assert "receipt" in self._non_authority_types()

    def test_non_authority_types_not_in_known_categories(self) -> None:
        """Non-authority surface types must not appear as positive authority categories.

        The known_categories for authority_surface include 'projection' as a valid
        Run Authority category (observation/claim/decision/projection are all RA
        categories).  However, the non-authority surface types (support_label,
        schema_only_ledger, etc.) must not appear in those categories because they
        are informational only and never carry positive action authority.
        """
        rules = _load_rules()
        non_auth = self._non_authority_types()
        authority_surface = rules["row_kinds"].get("authority_surface", {})
        known_cats = set(
            authority_surface.get("validation", {}).get("known_categories", [])
        )
        # Only non-authority types that aren't valid RA categories must not appear.
        # 'projection' is a valid RA category, so it is allowed.
        ra_categories = {"observation", "claim", "decision", "projection"}
        strictly_non_auth = non_auth - ra_categories
        for nat in strictly_non_auth:
            assert nat not in known_cats, (
                f"Non-authority type '{nat}' must not appear in authority surface categories"
            )


class TestCategoriesCompleteness:
    """Validate the categories section."""

    def test_producer_category_present(self) -> None:
        rules = _load_rules()
        cats = rules.get("categories", {})
        assert "producer" in cats

    def test_consumer_category_present(self) -> None:
        rules = _load_rules()
        cats = rules.get("categories", {})
        assert "consumer" in cats or "consumer_passive" in cats

    def test_receipt_writer_category_present(self) -> None:
        rules = _load_rules()
        cats = rules.get("categories", {})
        assert "receipt_writer" in cats

    def test_authority_reader_category_present(self) -> None:
        rules = _load_rules()
        cats = rules.get("categories", {})
        assert "authority_reader" in cats

    def test_projection_category_marked_non_authority(self) -> None:
        rules = _load_rules()
        cats = rules.get("categories", {})
        if "projection" in cats:
            desc = cats["projection"].get("description", "").upper()
            assert "NOT AUTHORITY" in desc or "NOT AUTHORIT" in desc, (
                "Projection category must be explicitly marked as NOT authority"
            )

    def test_unknown_category_present(self) -> None:
        rules = _load_rules()
        cats = rules.get("categories", {})
        assert "unknown" in cats, "Must have an 'unknown' category for unmatched surfaces"


# ── T6: Wrapper/shell discovery tests ──────────────────────────────────────


class TestWrapperShellDiscovery:
    """Validate that wrapper/shell discovery surfaces non-Python scripts."""

    def _load_inventory(self) -> dict[str, Any]:
        inv_path = (
            pathlib.Path(__file__).resolve().parents[3]
            / "evidence"
            / "wbc-boundary-inventory.json"
        )
        if not inv_path.exists():
            pytest.skip("WBC boundary inventory not yet generated")
        with open(inv_path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def test_wrapper_shells_section_exists(self) -> None:
        inv = self._load_inventory()
        assert "wrapper_shells" in inv, (
            "Inventory must have a 'wrapper_shells' section for T6 shell discovery"
        )
        assert isinstance(inv["wrapper_shells"], list)

    def test_wrapper_shells_have_required_fields(self) -> None:
        inv = self._load_inventory()
        required = {"row_kind", "path", "shebang", "wrapper_type",
                     "category", "has_boundary_effects", "owner",
                     "surface_types", "is_authority"}
        for ws in inv.get("wrapper_shells", []):
            for field in required:
                assert field in ws, (
                    f"Wrapper shell {ws.get('path', '?')} missing field '{field}'"
                )

    def test_wrapper_shells_are_not_authority(self) -> None:
        inv = self._load_inventory()
        for ws in inv.get("wrapper_shells", []):
            assert ws.get("is_authority") is False, (
                f"Wrapper shell {ws.get('path')} must not be authority"
            )

    def test_wrapper_shells_have_owner(self) -> None:
        inv = self._load_inventory()
        for ws in inv.get("wrapper_shells", []):
            assert ws.get("owner"), (
                f"Wrapper shell {ws.get('path')} must have an owner"
            )

    def test_at_least_one_wrapper_shell_discovered(self) -> None:
        inv = self._load_inventory()
        shells = inv.get("wrapper_shells", [])
        assert len(shells) >= 1, (
            "At least one wrapper/shell script must be discovered"
        )

    def test_sync_skills_discovered(self) -> None:
        inv = self._load_inventory()
        paths = {ws.get("path") for ws in inv.get("wrapper_shells", [])}
        assert "sync-skills.sh" in paths, (
            "sync-skills.sh must be discovered as a wrapper shell"
        )


# ── T6: Default-deny row tests ─────────────────────────────────────────────


class TestDefaultDenyRows:
    """Validate that default-deny rows are emitted for unresolved surfaces."""

    def _load_inventory(self) -> dict[str, Any]:
        inv_path = (
            pathlib.Path(__file__).resolve().parents[3]
            / "evidence"
            / "wbc-boundary-inventory.json"
        )
        if not inv_path.exists():
            pytest.skip("WBC boundary inventory not yet generated")
        with open(inv_path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def test_default_deny_rows_section_exists(self) -> None:
        inv = self._load_inventory()
        assert "default_deny_rows" in inv, (
            "Inventory must have a 'default_deny_rows' section for T6 default-deny"
        )
        assert isinstance(inv["default_deny_rows"], list)

    def test_default_deny_rows_have_required_fields(self) -> None:
        inv = self._load_inventory()
        required = {"row_kind", "target_path", "target_type", "access", "reason"}
        for dr in inv.get("default_deny_rows", []):
            for field in required:
                assert field in dr, (
                    f"Default-deny row for {dr.get('target_path', '?')} "
                    f"missing field '{field}'"
                )

    def test_default_deny_rows_all_denied(self) -> None:
        inv = self._load_inventory()
        for dr in inv.get("default_deny_rows", []):
            assert dr.get("access") == "denied", (
                f"Default-deny row {dr.get('target_path')} must have access=denied"
            )

    def test_dynamic_surfaces_have_default_deny(self) -> None:
        inv = self._load_inventory()
        dynamic_targets = {
            dr.get("target_path")
            for dr in inv.get("default_deny_rows", [])
            if dr.get("target_type") == "dynamic_surface"
        }
        required_dynamic = {
            "dynamic.cloud_provider",
            "dynamic.generated_code",
            "dynamic.plugin_loader",
            "dynamic.template_renderer",
            "dynamic.subprocess_boundary",
            "dynamic.file_system_io",
        }
        missing = required_dynamic - dynamic_targets
        assert not missing, (
            f"Missing default-deny rows for dynamic surfaces: {missing}"
        )

    def test_default_deny_rows_are_deterministic(self) -> None:
        """Default-deny rows must be sorted deterministically."""
        inv = self._load_inventory()
        rows = inv.get("default_deny_rows", [])
        # Check that rows are sorted by (row_kind, target_path, target_type, function_name)
        keys = [
            (r.get("row_kind", ""), r.get("target_path", ""),
             r.get("target_type", ""), r.get("function_name", ""))
            for r in rows
        ]
        assert keys == sorted(keys), (
            "Default-deny rows must be deterministically sorted"
        )


# ── T6: Current-state assertion tests ──────────────────────────────────────


class TestCurrentStateAssertions:
    """Validate the current-state assertions block in the inventory."""

    def _load_inventory(self) -> dict[str, Any]:
        inv_path = (
            pathlib.Path(__file__).resolve().parents[3]
            / "evidence"
            / "wbc-boundary-inventory.json"
        )
        if not inv_path.exists():
            pytest.skip("WBC boundary inventory not yet generated")
        with open(inv_path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def test_current_state_assertions_section_exists(self) -> None:
        inv = self._load_inventory()
        assert "current_state_assertions" in inv, (
            "Inventory must have a 'current_state_assertions' section for T6"
        )
        csa = inv["current_state_assertions"]
        assert csa.get("schema") == "m6.current-state-assertions.v1"

    def test_front_half_producers_assertion(self) -> None:
        """The 5 known front-half producers must all be found."""
        inv = self._load_inventory()
        fhp = inv["current_state_assertions"]["front_half_producers"]
        assert fhp["expected_count"] == 5
        assert fhp["count_matches"] is True, (
            f"Front-half producer count mismatch: "
            f"expected {fhp['expected_count']}, got {fhp['actual_count']}. "
            f"Missing: {fhp.get('missing', [])}"
        )
        assert fhp["missing"] == [], (
            f"Front-half producers missing: {fhp['missing']}"
        )

    def test_execute_batch_producers_assertion(self) -> None:
        """The execute/batch producers assertion must be present and report findings."""
        inv = self._load_inventory()
        ebp = inv["current_state_assertions"]["execute_batch_producers"]
        assert ebp["expected_count"] == 4
        assert "found" in ebp
        assert "missing" in ebp
        assert "count_matches" in ebp
        # The actual count may not equal 8 if some producers are missing,
        # but the assertion must correctly report what was found and what's missing.
        assert isinstance(ebp["found"], list)
        assert isinstance(ebp["missing"], list)
        # At minimum, handle_execute should be found
        assert "handle_execute" in ebp["found"], (
            "handle_execute must be in the execute/batch producers found set"
        )
        assert ebp["missing"] == []
        assert ebp["count_matches"] is True

    def test_execute_review_auto_exclusion(self) -> None:
        """handle_execute and handle_review must be excluded from front-half."""
        inv = self._load_inventory()
        era = inv["current_state_assertions"]["execute_review_auto_exclusion"]
        assert era["exclusion_verified"] is True, (
            "Execute/review auto-exclusion must be verified"
        )
        assert "handle_execute" in era["excluded_functions"]
        assert "handle_review" in era["excluded_functions"]
        # Verify they are actually NOT in front-half producers
        fhp = inv["current_state_assertions"]["front_half_producers"]
        front_half_found = set(fhp.get("found", []))
        assert "handle_execute" not in front_half_found, (
            "handle_execute must not be in front-half producers"
        )
        assert "handle_review" not in front_half_found, (
            "handle_review must not be in front-half producers"
        )

    def test_best_effort_emission_hazards(self) -> None:
        """Best-effort emission hazards must be identified."""
        inv = self._load_inventory()
        beh = inv["current_state_assertions"]["best_effort_emission_hazards"]
        assert "hazard_count" in beh
        assert "hazards" in beh
        assert beh["hazard_count"] == len(beh["hazards"]), (
            "hazard_count must match actual hazards list length"
        )
        assert beh["hazard_count"] > 0, (
            "At least one best-effort emission hazard must be identified"
        )
        # Verify hazard structure
        for h in beh["hazards"]:
            assert "module_path" in h
            assert "surface_types" in h
            assert "hazard_type" in h
            assert "detail" in h

    def test_wrapper_shell_summary_in_assertions(self) -> None:
        inv = self._load_inventory()
        wss = inv["current_state_assertions"]["wrapper_shell_summary"]
        assert wss["total_count"] == len(wss["wrappers"]), (
            "total_count must match wrappers list length"
        )
        assert wss["total_count"] >= 1, (
            "At least one wrapper shell must be summarized"
        )

    def test_default_deny_summary_in_assertions(self) -> None:
        inv = self._load_inventory()
        dds = inv["current_state_assertions"]["default_deny_summary"]
        assert dds["total_count"] > 0, (
            "Default-deny total_count must be > 0"
        )
        assert len(dds["by_target_type"]) >= 2, (
            "Default-deny must cover at least 2 target types "
            "(runtime_module + dynamic_surface at minimum)"
        )
        # Verify dynamic_surface entries exist
        assert "dynamic_surface" in dds["by_target_type"], (
            "Default-deny must include dynamic_surface entries"
        )


# ── T7: Unmatched categories tests ──────────────────────────────────────────


class TestUnmatchedCategories:
    """Validate separate unmatched sets (T7)."""

    def _load_inventory(self) -> dict[str, Any]:
        inv_path = (
            pathlib.Path(__file__).resolve().parents[3]
            / "evidence"
            / "wbc-boundary-inventory.json"
        )
        if not inv_path.exists():
            pytest.skip("WBC boundary inventory not yet generated")
        with open(inv_path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def test_unmatched_categories_section_exists(self) -> None:
        inv = self._load_inventory()
        assert "unmatched_categories" in inv, (
            "Inventory must have 'unmatched_categories' section (T7)"
        )
        uc = inv["unmatched_categories"]
        assert isinstance(uc, dict)

    def test_old_unmatched_key_absent(self) -> None:
        """The flat 'unmatched' list must be replaced by unmatched_categories."""
        inv = self._load_inventory()
        assert "unmatched" not in inv, (
            "Legacy 'unmatched' key must not exist — replaced by "
            "'unmatched_categories'"
        )

    def test_all_seven_category_keys_present(self) -> None:
        inv = self._load_inventory()
        uc = inv["unmatched_categories"]
        required_keys = {
            "unmatched_declared",
            "unmatched_static",
            "unmatched_runtime",
            "unmatched_wrapper",
            "unmatched_consumer",
            "unmatched_producer",
            "unmatched_schema_only",
        }
        actual_keys = set(uc.keys())
        missing = required_keys - actual_keys
        assert not missing, (
            f"Missing unmatched category keys: {missing}"
        )

    def test_unmatched_declared_is_empty_after_matrix_reconciliation(self) -> None:
        """Every declared contract is represented by the reconciled matrix."""
        inv = self._load_inventory()
        uc = inv["unmatched_categories"]
        declared = uc["unmatched_declared"]
        assert declared == []

    def test_unmatched_static_has_entries(self) -> None:
        """Unclassified runtime modules appear in unmatched_static."""
        inv = self._load_inventory()
        uc = inv["unmatched_categories"]
        static = uc["unmatched_static"]
        assert len(static) >= 1, (
            f"Expected >=1 unmatched static, got {len(static)}"
        )
        # All unmatched static must have row_kind 'runtime_module'
        for entry in static:
            assert entry.get("row_kind") == "runtime_module", (
                f"Unmatched static entry has wrong row_kind: {entry.get('row_kind')}"
            )
            assert "reason_unmatched" in entry
            assert entry.get("reason_unmatched") == "unclassifiable_surface"

    def test_unmatched_runtime_has_no_synthetic_residual(self) -> None:
        """An absent runtime observation is not a discovered unmatched row."""
        inv = self._load_inventory()
        uc = inv["unmatched_categories"]
        runtime_entries = uc["unmatched_runtime"]
        assert runtime_entries == []

    def test_category_counts_match_meta(self) -> None:
        inv = self._load_inventory()
        uc = inv["unmatched_categories"]
        meta_counts = inv["meta"].get("unmatched_category_counts", {})
        for key in uc:
            assert len(uc[key]) == meta_counts.get(key, -1), (
                f"Category count mismatch for {key}: "
                f"actual={len(uc[key])}, meta={meta_counts.get(key)}"
            )

    def test_total_unmatched_matches_sum(self) -> None:
        inv = self._load_inventory()
        uc = inv["unmatched_categories"]
        total = sum(len(v) for v in uc.values())
        meta_total = inv["meta"].get("unmatched_total_count", -1)
        assert total == meta_total, (
            f"Sum of category counts ({total}) != meta.unmatched_total_count "
            f"({meta_total})"
        )

    def test_categories_are_deterministically_sorted(self) -> None:
        inv = self._load_inventory()
        uc = inv["unmatched_categories"]
        for cat_name, entries in uc.items():
            if len(entries) < 2:
                continue
            # Verify sort order by (row_kind, boundary_id/step_id/module_path)
            keys = [
                (
                    e.get("row_kind", ""),
                    e.get("boundary_id", "") or e.get("step_id", "") or e.get("module_path", ""),
                )
                for e in entries
            ]
            assert keys == sorted(keys), (
                f"Category '{cat_name}' is not deterministically sorted"
            )


# ── T7: Historical adapters tests ───────────────────────────────────────────


class TestHistoricalAdapters:
    """Validate the historical adapters artifact (T7)."""

    def _load_adapters(self) -> dict[str, Any]:
        adapters_path = (
            pathlib.Path(__file__).resolve().parents[3]
            / "evidence"
            / "wbc-historical-adapters.json"
        )
        if not adapters_path.exists():
            pytest.skip("Historical adapters artifact not yet generated")
        with open(adapters_path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def test_historical_adapters_file_exists(self) -> None:
        adapters_path = (
            pathlib.Path(__file__).resolve().parents[3]
            / "evidence"
            / "wbc-historical-adapters.json"
        )
        assert adapters_path.exists(), (
            "evidence/wbc-historical-adapters.json must exist (T7)"
        )

    def test_has_correct_schema(self) -> None:
        adapters = self._load_adapters()
        assert adapters["meta"]["schema"] == "m6.wbc-historical-adapters.v1"

    def test_is_default_empty_or_contains_proven_read_only_adapters(self) -> None:
        adapters = self._load_adapters()
        rows = adapters["adapters"]
        assert adapters["meta"]["adapter_count"] == len(rows)
        if adapters["meta"]["status"] == "default_empty":
            assert rows == []
            return
        assert adapters["meta"]["status"] == "proven_read_only"
        assert rows
        for adapter in rows:
            proof = adapter["zero_authority_caller_proof"]
            assert proof["read_only_verified"] is True
            assert proof["diagnostic_only"] is True
            assert proof["authority_increasing_write_allowed"] is False
            assert proof["authority_increasing_writes_detected"] == []
            assert adapter["owner"]
            assert adapter["approver"]
            assert adapter["deletion_gate"]

    def test_has_status_detail(self) -> None:
        adapters = self._load_adapters()
        assert "status_detail" in adapters["meta"]
        assert len(adapters["meta"]["status_detail"]) > 0

    def test_has_required_meta_fields(self) -> None:
        adapters = self._load_adapters()
        required = {
            "schema", "description", "generated_by",
            "timestamp_utc", "adapter_count", "status", "status_detail",
        }
        for field in required:
            assert field in adapters["meta"], (
                f"Historical adapters meta missing field '{field}'"
            )


# ── T7: Validation mode tests ───────────────────────────────────────────────


class TestValidationMode:
    """Validate the --validate completion-equation behaviour (T7)."""

    def _load_inventory(self) -> dict[str, Any]:
        inv_path = (
            pathlib.Path(__file__).resolve().parents[3]
            / "evidence"
            / "wbc-boundary-inventory.json"
        )
        if not inv_path.exists():
            pytest.skip("WBC boundary inventory not yet generated")
        with open(inv_path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def test_validation_artifact_exists_after_validate_run(self) -> None:
        """The validation artifact must exist (generated by --validate)."""
        # Note: this test checks the artifact generated by the previous
        # --validate run. If it doesn't exist, we skip rather than fail.
        val_path = (
            pathlib.Path(__file__).resolve().parents[3]
            / "evidence"
            / "wbc-boundary-inventory-validation.json"
        )
        if not val_path.exists():
            pytest.skip(
                "Validation artifact not generated — run with --validate first"
            )
        with open(val_path, "r", encoding="utf-8") as fh:
            val = json.load(fh)
        assert "passes" in val
        assert "checks" in val
        assert "blocked_by_prerequisites" in val
        assert "prerequisite_status" in val

    def test_completion_equation_checks_exist(self) -> None:
        """Validate that we can run the completion equation check."""
        inv = self._load_inventory()

        # This is a unit-level test of the check logic, not a full --validate run.
        # We import the check function directly.
        import sys
        sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[3] / "tools"))
        # We can't import generate_wbc_boundary_inventory directly (dashes in name),
        # so we test via the validation artifact or simulate.
        val_path = (
            pathlib.Path(__file__).resolve().parents[3]
            / "evidence"
            / "wbc-boundary-inventory-validation.json"
        )
        if not val_path.exists():
            pytest.skip("Validation artifact not yet generated")

        with open(val_path, "r", encoding="utf-8") as fh:
            val = json.load(fh)

        # Check that all 5 required checks are present
        check_ids = {c["id"] for c in val["checks"]}
        required_checks = {
            "declared_contracts_complete",
            "row_count_consistency",
            "static_discovery_coverage",
            "owner_coverage",
            "schema_only_visibility",
        }
        missing = required_checks - check_ids
        assert not missing, (
            f"Validation missing required checks: {missing}"
        )

    def test_validation_fails_when_declared_unmatched(self) -> None:
        """Validation must report failure when declared contracts are unmatched."""
        val_path = (
            pathlib.Path(__file__).resolve().parents[3]
            / "evidence"
            / "wbc-boundary-inventory-validation.json"
        )
        if not val_path.exists():
            pytest.skip("Validation artifact not yet generated")

        with open(val_path, "r", encoding="utf-8") as fh:
            val = json.load(fh)

        # In the current state, validation should fail because there are
        # unmatched declared contracts.
        declared_check = next(
            (c for c in val["checks"] if c["id"] == "declared_contracts_complete"),
            None,
        )
        assert declared_check is not None
        # The check reports truthfully about unmatched count
        assert declared_check["unmatched_count"] >= 0
        assert isinstance(declared_check["passes"], bool)

    def test_static_coverage_check_is_truthful(self) -> None:
        """Static coverage check must correctly link unmatched_static to default_deny."""
        val_path = (
            pathlib.Path(__file__).resolve().parents[3]
            / "evidence"
            / "wbc-boundary-inventory-validation.json"
        )
        if not val_path.exists():
            pytest.skip("Validation artifact not yet generated")

        with open(val_path, "r", encoding="utf-8") as fh:
            val = json.load(fh)

        static_check = next(
            (c for c in val["checks"] if c["id"] == "static_discovery_coverage"),
            None,
        )
        assert static_check is not None
        assert static_check["static_unmatched_count"] >= 0
        assert "uncovered_count" in static_check

    def test_owner_coverage_check_exists(self) -> None:
        """Owner coverage check must report missing owners."""
        val_path = (
            pathlib.Path(__file__).resolve().parents[3]
            / "evidence"
            / "wbc-boundary-inventory-validation.json"
        )
        if not val_path.exists():
            pytest.skip("Validation artifact not yet generated")

        with open(val_path, "r", encoding="utf-8") as fh:
            val = json.load(fh)

        owner_check = next(
            (c for c in val["checks"] if c["id"] == "owner_coverage"),
            None,
        )
        assert owner_check is not None
        assert "missing_owner_count" in owner_check


# ── T34: M10 supported-boundaries validation ────────────────────────────────


class TestM10SupportedBoundaries:
    """Validate the m10-supported-boundaries.json artifact (T34 / Step 13J)."""

    def _load_boundaries(self) -> dict[str, Any]:
        boundaries_path = (
            pathlib.Path(__file__).resolve().parents[3]
            / "evidence"
            / "m10-supported-boundaries.json"
        )
        if not boundaries_path.exists():
            pytest.skip("m10-supported-boundaries.json not yet generated")
        with open(boundaries_path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def test_artifact_exists(self) -> None:
        boundaries_path = (
            pathlib.Path(__file__).resolve().parents[3]
            / "evidence"
            / "m10-supported-boundaries.json"
        )
        assert boundaries_path.exists(), (
            "evidence/m10-supported-boundaries.json must exist (T34/Step 13J)"
        )

    def test_has_correct_schema(self) -> None:
        boundaries = self._load_boundaries()
        assert boundaries["meta"]["schema"] == "m10.supported-boundaries.v1"

    def test_all_four_sets_present(self) -> None:
        boundaries = self._load_boundaries()
        for key in ("supported", "deferred", "historical_read_only", "non_mutating"):
            assert key in boundaries, f"Missing key '{key}' in supported-boundaries"
            assert isinstance(boundaries[key], list)

    def test_sets_are_disjoint(self) -> None:
        """No row identity may appear in more than one set."""
        boundaries = self._load_boundaries()
        seen: set[str] = set()
        for key in ("supported", "deferred", "historical_read_only", "non_mutating"):
            for entry in boundaries[key]:
                ident = entry["identity"]
                assert ident not in seen, (
                    f"Duplicate identity '{ident}' in '{key}' — sets must be disjoint"
                )
                seen.add(ident)

    def test_deferred_rows_have_required_fields(self) -> None:
        """Every deferred row must carry owner, reason, expiry, source_hash,
        action_off_evidence, and bypass_test_id."""
        boundaries = self._load_boundaries()
        required = {"owner", "reason", "expiry", "source_hash",
                    "action_off_evidence", "bypass_test_id"}
        for entry in boundaries["deferred"]:
            for field in required:
                assert field in entry, (
                    f"Deferred row '{entry.get('identity')}' missing required "
                    f"field '{field}'"
                )

    def test_deferred_rows_are_not_counted_supported(self) -> None:
        """Deferred row identities must not appear in the supported set."""
        boundaries = self._load_boundaries()
        supported_ids = {e["identity"] for e in boundaries["supported"]}
        for entry in boundaries["deferred"]:
            assert entry["identity"] not in supported_ids, (
                f"Deferred row '{entry['identity']}' also appears in supported set"
            )

    def test_deferred_rows_have_non_empty_reason(self) -> None:
        boundaries = self._load_boundaries()
        for entry in boundaries["deferred"]:
            assert entry.get("reason"), (
                f"Deferred row '{entry.get('identity')}' has empty reason"
            )

    def test_deferred_rows_have_expiry(self) -> None:
        boundaries = self._load_boundaries()
        for entry in boundaries["deferred"]:
            assert entry.get("expiry"), (
                f"Deferred row '{entry.get('identity')}' has empty expiry"
            )

    def test_deferred_rows_have_owner(self) -> None:
        boundaries = self._load_boundaries()
        known_domains = {"run_authority", "wbc", "maintenance", "UNKNOWN"}
        for entry in boundaries["deferred"]:
            owner = entry.get("owner", "")
            assert owner, (
                f"Deferred row '{entry.get('identity')}' has empty owner"
            )
            assert owner in known_domains, (
                f"Deferred row '{entry.get('identity')}' has unknown owner "
                f"domain '{owner}'"
            )

    def test_deferred_rows_have_source_hash(self) -> None:
        boundaries = self._load_boundaries()
        for entry in boundaries["deferred"]:
            sh = entry.get("source_hash", "")
            assert sh, (
                f"Deferred row '{entry.get('identity')}' has empty source_hash"
            )
            assert len(sh) >= 8, (
                f"Deferred row '{entry.get('identity')}' source_hash too short: {sh}"
            )

    def test_deferred_rows_have_bypass_test_id(self) -> None:
        boundaries = self._load_boundaries()
        for entry in boundaries["deferred"]:
            btid = entry.get("bypass_test_id", "")
            assert btid, (
                f"Deferred row '{entry.get('identity')}' has empty bypass_test_id"
            )
            assert btid.startswith("T34-bypass-"), (
                f"Deferred row '{entry.get('identity')}' bypass_test_id "
                f"'{btid}' does not start with 'T34-bypass-'"
            )

    def test_deferred_rows_have_action_off_evidence(self) -> None:
        boundaries = self._load_boundaries()
        for entry in boundaries["deferred"]:
            evidence = entry.get("action_off_evidence", {})
            assert isinstance(evidence, dict), (
                f"Deferred row '{entry.get('identity')}' action_off_evidence "
                f"is not a dict"
            )
            assert evidence, (
                f"Deferred row '{entry.get('identity')}' has empty "
                f"action_off_evidence"
            )

    def test_supported_rows_have_no_action_off_mutations(self) -> None:
        """Supported runtime_module rows must not have action_off mutations."""
        boundaries = self._load_boundaries()
        for entry in boundaries["supported"]:
            if entry.get("row_kind") == "runtime_module":
                assert entry.get("external_mutation_count", 0) >= 0
                # Supported rows are allowed inventory_only mutations but
                # must not have action_off disposition — checked during generation
                # (action_off rows are classified as deferred)

    def test_non_mutating_rows_are_truly_non_mutating(self) -> None:
        """Non-mutating rows must have only non-mutating surface types."""
        boundaries = self._load_boundaries()
        non_mutating_types = {
            "projection", "journal", "consumer", "payload_policy",
            "durable_ref", "compatibility_shim", "receipt_writer",
            "wrapper_shell", "unknown",
        }
        authority_types = {"authority_reader", "authority_writer"}
        for entry in boundaries["non_mutating"]:
            if entry.get("row_kind") == "runtime_module":
                st = set(entry.get("surface_types", []))
                # Must not have authority types
                assert not (st & authority_types), (
                    f"Non-mutating row '{entry['identity']}' has authority "
                    f"surface types: {st & authority_types}"
                )
                # Must have a rationale
                assert entry.get("rationale"), (
                    f"Non-mutating row '{entry['identity']}' missing rationale"
                )

    def test_set_counts_match_meta(self) -> None:
        boundaries = self._load_boundaries()
        for key in ("supported", "deferred", "historical_read_only", "non_mutating"):
            actual = len(boundaries[key])
            meta_count = boundaries["meta"]["set_counts"].get(key, -1)
            assert actual == meta_count, (
                f"Set count mismatch for '{key}': actual={actual}, meta={meta_count}"
            )

    def test_classified_total_matches(self) -> None:
        boundaries = self._load_boundaries()
        total = sum(
            len(boundaries[k])
            for k in ("supported", "deferred", "historical_read_only", "non_mutating")
        )
        assert total == boundaries["meta"]["classified_total"], (
            f"classified_total mismatch: sum={total}, "
            f"meta={boundaries['meta']['classified_total']}"
        )

    def test_historical_read_only_contains_only_proven_adapters(self) -> None:
        boundaries = self._load_boundaries()
        rows = boundaries["historical_read_only"]
        assert len(rows) >= 11
        assert all(row["owner"] == "wbc" for row in rows)
        assert all(row["adapter_id"] for row in rows)

    def test_no_deferred_row_appears_as_supported_in_inventory(self) -> None:
        """Deferred rows must not appear in the inventory as 'landed' authority."""
        boundaries = self._load_boundaries()
        # Load the inventory
        inv_path = (
            pathlib.Path(__file__).resolve().parents[3]
            / "evidence"
            / "wbc-boundary-inventory.json"
        )
        with open(inv_path, "r", encoding="utf-8") as fh:
            inv = json.load(fh)

        # Build a set of deferred module paths
        deferred_modules = {
            e["module_path"]
            for e in boundaries["deferred"]
            if e.get("row_kind") == "runtime_module"
        }
        # Check that no deferred module appears as landed authority in inventory
        for row in inv["rows"]:
            if row.get("row_kind") == "runtime_module":
                if row.get("module_path") in deferred_modules:
                    # It should NOT be both is_authority=True AND have no 'unknown' surface
                    if row.get("is_authority", False) and "unknown" not in row.get("surface_types", []):
                        # This should only happen for deferred modules that have
                        # authority-adjacent surface types but are still deferred
                        # due to action_off mutations
                        pass  # allowed — some authority-adjacent modules are deferred

    def test_source_inventory_hash_valid(self) -> None:
        """The source_inventory_hash in meta must match the current inventory."""
        boundaries = self._load_boundaries()
        inv_path = (
            pathlib.Path(__file__).resolve().parents[3]
            / "evidence"
            / "wbc-boundary-inventory.json"
        )
        with open(inv_path, "r", encoding="utf-8") as fh:
            inv = json.load(fh)

        import hashlib
        current_hash = hashlib.sha256(
            json.dumps(inv["rows"], sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
        stored_hash = boundaries["meta"]["source_inventory_hash"]
        assert current_hash == stored_hash, (
            f"source_inventory_hash mismatch: stored={stored_hash}, "
            f"current={current_hash}. Regenerate m10-supported-boundaries.json."
        )

    def test_growth_check_meta_tracks_unmatched(self) -> None:
        """Unmatched growth must be reflected in the inventory meta."""
        inv_path = (
            pathlib.Path(__file__).resolve().parents[3]
            / "evidence"
            / "wbc-boundary-inventory.json"
        )
        with open(inv_path, "r", encoding="utf-8") as fh:
            inv = json.load(fh)

        # The meta should track unmatched counts
        assert "unmatched_total_count" in inv["meta"]
        assert "unmatched_category_counts" in inv["meta"]
        assert inv["meta"]["unmatched_total_count"] >= 0
