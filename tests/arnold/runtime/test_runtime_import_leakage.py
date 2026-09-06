"""Import-leak gate: ``arnold.runtime`` must not pull in Megaplan policy.

This test spawns a hermetic subprocess with a ``sys.meta_path`` finder
that blocks any import of ``megaplan`` or ``arnold_pipelines.megaplan``
by raising ``ModuleNotFoundError``.  Inside that subprocess we import
the key Arnold runtime modules (and one cross-package consumer).  If any
of those imports transitively trigger a megaplan import, the subprocess
will fail — proving that the runtime boundary is not hermetic.

Design decision (per plan SD1 + gate sign-off)
    Using a ``MetaPathFinder`` in a subprocess (~100ms) gives the same
    empirical guarantee as a real megaplan-absent virtualenv (minutes)
    and is reusable for future milestones (m7, m8).
"""

from __future__ import annotations

import subprocess
import sys
import textwrap

# ---------------------------------------------------------------------------
# Subprocess script — installed as the ``-c`` argument
# ---------------------------------------------------------------------------

_IMPORT_CHECK_SCRIPT = textwrap.dedent("""\
import sys

# ── meta_path blocker: refuse any megaplan import ──────────────────────
class _BlockMegaplanFinder:
    def find_spec(self, fullname, path, target=None):
        if fullname == "megaplan" or fullname.startswith("arnold_pipelines.megaplan."):
            raise ModuleNotFoundError(
                f"megaplan import blocked by leak gate: {fullname}"
            )
        if fullname == "arnold_pipelines.megaplan" or fullname.startswith(
            "arnold_pipelines.megaplan."
        ):
            raise ModuleNotFoundError(
                f"arnold_pipelines.megaplan import blocked by leak gate: {fullname}"
            )
        return None  # let other finders handle it

sys.meta_path.insert(0, _BlockMegaplanFinder())

# ── import the target modules ─────────────────────────────────────────
import arnold.runtime                # noqa: E402
import arnold.runtime.durable_ops    # noqa: E402
import arnold.runtime.envelope       # noqa: E402
import arnold.runtime.errors         # noqa: E402
import arnold.pipeline.types         # noqa: E402

expected_durable_ops_exports = {
    "ApprovalLink",
    "BROKER_APPROVAL_SUSPENSION_KIND",
    "BrokerApprovalDecision",
    "DurableOpsStore",
    "FileBackedDurableOpsStore",
    "InvalidOperationTransition",
    "InvalidScheduledTaskTransition",
    "OperationAlreadyExists",
    "OperationEvent",
    "OperationEventAlreadyExists",
    "OperationHandler",
    "OperationLockConflict",
    "OperationNotFound",
    "OperationRun",
    "OperationState",
    "ResourceType",
    "RetryMetadata",
    "ScheduledTask",
    "ScheduledTaskAlreadyExists",
    "ScheduledTaskLeaseConflict",
    "ScheduledTaskLeaseTokenMismatch",
    "ScheduledTaskNotFound",
    "ScheduledTaskState",
    "TypedResource",
    "TypedResourceAlreadyExists",
    "LAUNCH_ENVELOPE_FIELDS",
    "LAUNCH_ENVELOPE_VERSION",
    "LAUNCH_SPEC_FIELDS",
    "LaunchEnvelope",
    "LaunchEnvelopeError",
    "LaunchDispatchRejected",
    "LaunchInspection",
    "LaunchMethodResult",
    "LaunchOutcome",
    "LaunchReason",
    "LaunchResult",
    "LaunchTransactionResult",
    "UnknownLaunchEnvelopeVersion",
    "LaunchStoreResult",
    "PREFLIGHT_SCHEMA",
    "PREFLIGHT_SECTIONS",
    "LaunchPreflightReport",
    "PreflightReason",
    "PreflightResult",
    "apply_broker_approval_decision",
    "broker_approval_effect_metadata",
    "can_transition_operation",
    "can_transition_scheduled_task",
    "ensure_operation_transition",
    "ensure_scheduled_task_transition",
    "is_terminal_operation_state",
    "is_terminal_scheduled_task_state",
    "canonical_launch_envelope",
    "evaluate_launch_request",
    "launch_envelope_digest",
    "launch_once",
    "launch_transaction",
    "inspect_launch",
    "reconcile_launch",
    "observation_only_preflight",
    "preflight_launch",
    "read_only_capacity_observation",
    "read_only_network_observation",
    "run_launch_preflight",
}
actual_durable_ops_exports = set(arnold.runtime.durable_ops.__all__)
if actual_durable_ops_exports != expected_durable_ops_exports:
    raise AssertionError(
        "durable_ops exports drifted from the neutral runtime boundary: "
        f"missing={sorted(expected_durable_ops_exports - actual_durable_ops_exports)} "
        f"extra={sorted(actual_durable_ops_exports - expected_durable_ops_exports)}"
    )
""")


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

class TestRuntimeImportLeakage:
    """Importing Arnold runtime modules must succeed without megaplan."""

    def test_imports_succeed_with_megaplan_blocked(self) -> None:
        """Subprocess with meta_path blocker imports core modules with exit 0."""
        result = subprocess.run(
            [sys.executable, "-c", _IMPORT_CHECK_SCRIPT],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

        # If any import triggered a megaplan dependency the subprocess fails.
        assert result.returncode == 0, (
            f"Subprocess exited {result.returncode}.\n"
            f"--- stdout ---\n{result.stdout}\n"
            f"--- stderr ---\n{result.stderr}"
        )
        assert result.stderr == "", (
            f"Subprocess stderr expected empty but got:\n{result.stderr}"
        )
