# Workflow Manifest Amendment Protocol

The M1 manifest/kernel contract is versioned deliberately. Downstream
milestones must not widen the contract silently.

## Version Bumps

Bump `arnold.workflow.manifest.v1` only when a serialized manifest meaning
changes, a required field is added, a hash input changes, or replay cannot
interpret old events without an alias gate. Additive optional metadata that
does not affect hashes may stay within v1 if validation remains deterministic.

## Proposal Requirements

Every amendment must name:

- The contract field or kernel event family being changed.
- Whether `manifest_hash`, `topology_hash`, or both change.
- How in-flight runs behave: replay with original manifest, replay through an
  explicit compatibility alias, or quarantine with operator-visible rationale.
- Any new volatile golden field and its canonical normalization transform.
- The milestone that owns implementation and the tests proving compatibility.

## M2 Clarifications

M2 does not replace the M1 dataclass manifest with a new schema layer. The
compile target remains `WorkflowManifest` and its nested dataclasses in
`arnold.workflow.manifests`.

The M2 explicit-node DSL lowers to the existing v1 fields:

- Authored steps become `WorkflowNode` entries with explicit stable `id`
  values.
- Authored control routes become `WorkflowEdge` entries where they describe
  forward topology, and `WorkflowPolicy` / `SuspensionRoute` entries where they
  describe policy, suspension, or reentry.
- Authored hook, condition, reducer, and stop-condition references become
  durable string refs such as `condition_ref`, `until_ref`, or `reducer_ref`;
  live callables and runtime objects are not manifest fields.
- Package `build_pipeline()` returns the M2 authoring pipeline object. A
  `WorkflowManifest` is compiler output.

The implementation lives in `arnold/manifest/manifests.py`.

Loop-back behavior is a semantic tightening, not a new v1 field.  Arbitrary graph cycles are not valid M2 topology; intentional recursive behavior must be expressed with explicit bounded loop/reentry carriers:

- `WorkflowPolicy.loop.max_iterations` supplies the finite bound.
- `WorkflowPolicy.loop.until_ref` may name the durable stop condition.
- `SuspensionRoute.reentry_id` supplies the stable reentry cursor segment used
  by resume/replay.
- `ManifestCursor.reentry_id` names the runtime position for a specific manifest
  coordinate.

If later compiler work proves those carriers insufficient, the change must be a
separate manifest amendment that states whether `manifest_hash`,
`topology_hash`, or both change.

## M3 Runtime Reserved Slots

M3 adds optional runtime-reserved policy carriers to the v1 manifest contract
without changing topology identity. These carriers are serialized manifest
fields and therefore change `manifest_hash` when present or edited:

- `WorkflowPolicy.timing`
- `WorkflowPolicy.idempotency`
- `WorkflowPolicy.effects`
- `WorkflowPolicy.reducers`
- `WorkflowPolicy.compensation`
- `WorkflowPolicy.escalation`
- `WorkflowPolicy.control_transitions`
- `WorkflowPolicy.topology_overlays`
- `WorkflowPolicy.authority`
- `SuspensionRoute.resume_schema_hash`, `resume_schema_ref`, and
  `resume_payload_ref`

These fields do not change `topology_hash` because the static graph remains the
same: nodes, edges, stable inputs/outputs, subpipeline refs, and edge
conditions are unchanged.

Dynamic topology overlays are represented by `TopologyOverlaySlot` manifest
metadata plus later runtime control-transition events. The runtime event records
the applied overlay and projects it into views, but it does not rewrite the
canonical manifest or replace the original `manifest_hash` carried by replay
events. Planned topology variants remain separate compiled manifests.

## Fixture Changes

Behavioral goldens cannot change for import/package-only moves. Legitimate
behavior changes need a sibling `.explanation.md` artifact that names the
behavioral reason and references the milestone.

## M4 Megaplan Product Migration

The M4 milestone relocates the Megaplan planning product from
``arnold.pipelines.megaplan`` to ``arnold_pipelines.megaplan`` and introduces
the canonical explicit-node manifest for the Megaplan pipeline.

* Contract field: canonical Megaplan manifest topology.
* ``manifest_hash`` changes: yes — the explicit-node DSL adds runtime policy
  carriers (timing, control transitions, suspension routes) that are serialized.
* ``topology_hash`` changes: yes — the explicit node and edge IDs are now
  authored directly rather than derived from the legacy typed-port pipeline.
* In-flight runs: legacy runs resume through a journal-derived cursor and an
  explicit alias mapping; they do not silently replay against the new manifest.
* New volatile golden fields: none; normalization follows
  ``tests/fixtures/workflow/README.md``.
* Current canonical identity: ``manifest_hash`` is
  ``sha256:962e57e7f8bb15761cc2a6a2e2bb64924eb6681bc86ed5fbf0de295df1ab5504``
  and ``topology_hash`` is
  ``sha256:295e0ad28430ff465334a36c6ff5add25fba1d21d7ba2449da6b081150098260``.
  The fourteen-action override matrix includes the CAS-fenced
  ``cap-revise-once`` route to ``revise``; its typed route, authority row,
  normalized shape, and golden overlay are part of the same canonical
  reconciliation.
* Owner: ``m4-megaplan-product-migration``.
* Tests: ``tests/arnold_pipelines/megaplan/test_topology_amendment.py``,
  ``tests/arnold_pipelines/megaplan/test_parity_harness.py``.

## Replay Rule

The original manifest reference carried by journaled events is authoritative.
If a newer manifest version cannot resolve a historical event, the resolver
must return an explicit alias or quarantine decision; it must not infer runtime
state from Python object graphs or product package internals.
