"""Tests for :mod:`arnold_pipelines.megaplan.workflows.override_matrix`.

Covers:
* Every legacy-handler or control-only canonical action is present in the matrix.
* Every matrix entry is classified as either ``terminal_route`` or
  ``additive_config``.
* Classification sets are disjoint and cover all 14 canonical keys.
* No key is double-classified or misclassified as ``additive_config`` when
  it has explicit route bindings in the OVERRIDE step component.
* Convenience exports (``TERMINAL_ROUTE_ACTIONS``, ``ADDITIVE_CONFIG_ACTIONS``)
  are consistent with the matrix.
* ``get_entry`` returns the correct entry for every key.
* The matrix raises :class:`OverrideActionClassificationError` when a key
  in ``_OVERRIDE_ACTIONS`` is not classified.
* The CL5 cutover action is a terminal, control-routed, ``workflow.route_binding``
  action declaring combined run_authority + maintenance authority.

.. versionadded:: M6
"""

from __future__ import annotations

import pytest

from arnold_pipelines.megaplan.handlers.override import _OVERRIDE_ACTIONS
from arnold_pipelines.megaplan.workflows import planning
from arnold_pipelines.megaplan.workflows.override_matrix import (
    ADDITIVE_CONFIG_ACTIONS,
    CONTROL_ROUTED_ACTIONS,
    OverrideActionClassificationError,
    OVERRIDE_ACTION_MATRIX,
    ROUTE_SIGNAL_BY_ACTION,
    TERMINAL_ROUTE_ACTIONS,
    get_entry,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ALL_KEYS = frozenset(_OVERRIDE_ACTIONS.keys()) | frozenset(CONTROL_ROUTED_ACTIONS)

# Actions with explicit native source route bindings in the override interface
# (abort→halt, force-proceed→finalize, replan/cap-revise-once→revise).
_OVERRIDE_ROUTE_BINDING_ACTIONS = frozenset({"abort", "force-proceed", "replan", "cap-revise-once"})


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestOverrideActionMatrixCompleteness:
    """Every canonical override key participates in the matrix."""

    def test_all_14_keys_present(self) -> None:
        matrix_keys = frozenset(entry.action for entry in OVERRIDE_ACTION_MATRIX)
        assert len(matrix_keys) == 14, f"Expected 14 keys, got {len(matrix_keys)}: {sorted(matrix_keys)}"
        assert matrix_keys == _ALL_KEYS, (
            f"Matrix keys do not match canonical dispatch registries.\n"
            f"  Missing from matrix: {sorted(_ALL_KEYS - matrix_keys)}\n"
            f"  Extra in matrix:    {sorted(matrix_keys - _ALL_KEYS)}"
        )

    def test_every_entry_has_a_family(self) -> None:
        for entry in OVERRIDE_ACTION_MATRIX:
            assert entry.family in {"terminal_route", "additive_config"}, (
                f"Entry '{entry.action}' has unknown family: {entry.family}"
            )

    def test_every_entry_has_a_description(self) -> None:
        for entry in OVERRIDE_ACTION_MATRIX:
            assert isinstance(entry.description, str) and len(entry.description) > 10, (
                f"Entry '{entry.action}' has insufficient description: {entry.description!r}"
            )

    def test_every_entry_declares_dispatch_surface(self) -> None:
        for entry in OVERRIDE_ACTION_MATRIX:
            assert entry.dispatch_surface in {
                "workflow.route_binding",
                "workflow.native_policy",
                "policy.effect",
            }
            assert entry.route_signal is not None, f"{entry.action} is missing a route signal"
            if entry.dispatch_surface == "policy.effect":
                assert (
                    entry.effect_id is not None
                    and entry.target_ref is None
                    and entry.declared_target_ref is None
                    and entry.policy_route_ref is None
                )
            elif entry.dispatch_surface == "workflow.native_policy":
                assert (
                    entry.effect_id is None
                    and entry.policy_route_ref is not None
                    and entry.declared_target_ref is not None
                )
            else:
                assert (
                    entry.target_ref is not None
                    and entry.declared_target_ref is not None
                    and entry.effect_id is None
                    and entry.policy_route_ref is None
                )


class TestOverrideActionMatrixDisjointClassification:
    """Terminal-route and additive-config sets are disjoint and complete."""

    def test_no_overlap_between_families(self) -> None:
        terminal = frozenset(TERMINAL_ROUTE_ACTIONS)
        additive = frozenset(ADDITIVE_CONFIG_ACTIONS)
        overlap = terminal & additive
        assert not overlap, f"Keys in both families: {sorted(overlap)}"

    def test_families_cover_all_keys(self) -> None:
        terminal = frozenset(TERMINAL_ROUTE_ACTIONS)
        additive = frozenset(ADDITIVE_CONFIG_ACTIONS)
        covered = terminal | additive
        assert covered == _ALL_KEYS, (
            f"Families do not cover all keys.\n"
            f"  Missing: {sorted(_ALL_KEYS - covered)}\n"
        )

    def test_terminal_route_count(self) -> None:
        assert len(TERMINAL_ROUTE_ACTIONS) == 9, (
            f"Expected 9 terminal-route actions, got {len(TERMINAL_ROUTE_ACTIONS)}: "
            f"{TERMINAL_ROUTE_ACTIONS}"
        )

    def test_additive_config_count(self) -> None:
        assert len(ADDITIVE_CONFIG_ACTIONS) == 5, (
            f"Expected 5 additive/config actions, got {len(ADDITIVE_CONFIG_ACTIONS)}: "
            f"{ADDITIVE_CONFIG_ACTIONS}"
        )


class TestOverrideActionMatrixRouteBindingConsistency:
    """Actions with explicit native override route bindings MUST be terminal-route."""

    def test_native_override_route_bindings_match_terminal_actions(self) -> None:
        labels = {
            binding["label"]
            for binding in planning.declared_step_route_bindings("override")
            if binding.get("target_ref") in {"halt", "finalize", "revise"}
        }
        assert labels == {"abort", "force_proceed", "replan", "cap_revise_once"}

    def test_route_binding_actions_are_terminal(self) -> None:
        for action in _OVERRIDE_ROUTE_BINDING_ACTIONS:
            entry = get_entry(action)
            assert entry.family == "terminal_route", (
                f"'{action}' has an explicit native route binding but is "
                f"classified as '{entry.family}'"
            )

    def test_config_actions_dont_have_route_bindings(self) -> None:
        """Additive/config actions must NOT be in _OVERRIDE_ROUTE_BINDING_ACTIONS."""
        for action in ADDITIVE_CONFIG_ACTIONS:
            assert action not in _OVERRIDE_ROUTE_BINDING_ACTIONS, (
                f"'{action}' is classified as additive_config but has explicit "
                f"native route bindings in the override interface"
            )

    def test_control_routed_actions_match_matrix_flag(self) -> None:
        expected = frozenset(
            entry.action for entry in OVERRIDE_ACTION_MATRIX if entry.control_routed
        )
        assert CONTROL_ROUTED_ACTIONS == expected


class TestOverrideActionMatrixConvenienceExports:
    """Convenience tuples match the matrix and are stable."""

    def test_terminal_route_actions_match_matrix(self) -> None:
        from_matrix = tuple(
            sorted(
                entry.action
                for entry in OVERRIDE_ACTION_MATRIX
                if entry.family == "terminal_route"
            )
        )
        from_export = tuple(sorted(TERMINAL_ROUTE_ACTIONS))
        assert from_export == from_matrix

    def test_additive_config_actions_match_matrix(self) -> None:
        from_matrix = tuple(
            sorted(
                entry.action
                for entry in OVERRIDE_ACTION_MATRIX
                if entry.family == "additive_config"
            )
        )
        from_export = tuple(sorted(ADDITIVE_CONFIG_ACTIONS))
        assert from_export == from_matrix

    def test_get_entry_works_for_all_keys(self) -> None:
        for action in _ALL_KEYS:
            entry = get_entry(action)
            assert entry.action == action
            assert ROUTE_SIGNAL_BY_ACTION[action] == entry.route_signal

    def test_get_entry_raises_key_error_for_unknown(self) -> None:
        with pytest.raises(KeyError):
            get_entry("nonexistent-action")


class TestOverrideActionMatrixClassificationError:
    """The matrix raises when a key lacks a declared route or effect."""

    def test_unclassified_key_raises(self) -> None:
        """Simulate a scenario where a key is added to _OVERRIDE_ACTIONS but
        not classified in either family."""
        import importlib

        from arnold_pipelines.megaplan.workflows import override_matrix as om

        original = dict(om._DECLARED_OVERRIDE_AUTHORITY)

        try:
            reduced = dict(original)
            reduced.pop("abort")
            om._DECLARED_OVERRIDE_AUTHORITY = reduced
            with pytest.raises(OverrideActionClassificationError) as exc_info:
                om._build_matrix()
            assert "abort" in str(exc_info.value)
        finally:
            om._DECLARED_OVERRIDE_AUTHORITY = original
            importlib.reload(om)


class TestCutoverOverrideAction:
    """The CL5 cutover action declares its route/authority contract (Step 8a).

    These are Phase-1 matrix data-structure assertions: they do NOT invoke the
    cutover handler (whose dispatch is wired in Step 8b and exercised in Phase 3).
    """

    def test_cutover_is_a_declared_key(self) -> None:
        from arnold_pipelines.megaplan.workflows.override_matrix import (
            _OVERRIDE_ACTION_KEYS,
        )

        assert "cutover" in _OVERRIDE_ACTION_KEYS
        assert "cutover" in {entry.action for entry in OVERRIDE_ACTION_MATRIX}

    def test_cutover_is_terminal_route(self) -> None:
        entry = get_entry("cutover")
        assert entry.family == "terminal_route"
        assert "cutover" in TERMINAL_ROUTE_ACTIONS
        assert "cutover" not in ADDITIVE_CONFIG_ACTIONS

    def test_cutover_uses_workflow_route_binding(self) -> None:
        entry = get_entry("cutover")
        assert entry.dispatch_surface == "workflow.route_binding"
        # workflow.route_binding invariant: route-bound target, no effect/policy refs
        assert entry.route_signal == "cutover"
        assert entry.target_ref == "cutover"
        assert entry.declared_target_ref == "cutover"
        assert entry.effect_id is None
        assert entry.policy_route_ref is None

    def test_cutover_is_control_routed(self) -> None:
        entry = get_entry("cutover")
        assert entry.control_routed is True
        assert "cutover" in CONTROL_ROUTED_ACTIONS
        assert ROUTE_SIGNAL_BY_ACTION["cutover"] == "cutover"

    def test_cutover_description_records_combined_authority(self) -> None:
        """The cutover action requires combined run_authority (human-gate) AND
        maintenance (repair_queue) authority — documented in its description."""
        entry = get_entry("cutover")
        description = entry.description.lower()
        assert "human-gate" in description or "human_gate" in description
        assert "repair_queue" in description or "repair-queue" in description
        assert "run_authority" in description
        assert "maintenance" in description
