# Native Build Forward continuation handoff

This is a fresh, unlaunched continuation of the Native Build Forward epic.
It begins at `native-c2-completion-evaluation` and contains that milestone plus
the original unexecuted suffix, in order. Its completion history is empty: it
must not replay P0, P1, P2, Native S1, Native S2F, or Native C1.

## Historical authority

The predecessor remains paused and immutable. It is the authority for the six
completed labels and their accepted receipts; this continuation is not a
rewrite or a release of that chain.

| item | authoritative location / identity |
| --- | --- |
| old chain spec | `/workspace/runtime-candidates/native-build-forward/.megaplan/initiatives/native-build-forward/chain.yaml` — SHA-256 `60a6cfc151e935de8308f4bee2316b5948827d5e9610e3a11adc93a1e5ef99b1` |
| old chain state | `/workspace/runtime-candidates/native-build-forward/.megaplan/plans/.chains/chain-672f8a08988a.json` — SHA-256 `fb4c58d491a1c47c7f744d2fc8c344b1656ea012f9b4a53d6f935d9f21808ad6`; cursor 6, paused, no current plan |
| old runtime checkout | branch `fixer/native-build-forward-nbf08-final-20260901`, head `57ce08b200df95323f77538acc81484353051479` |
| retired C2 plan | `native-c2-completion-binding-20260831-2100/state.json` — `65a32e32a74f27ba534fb62a2e15f9551af8944ba8d42e34c655625c1836d7a6` |
| retired C2 binding | `canonical_source_binding.json` — `98ba17eb1490cefbe9b2ee2999d420226560f6075a450a8a05af404b774c0df2` |
| retired C2 execution artifact | `execution.json` — `16a9bca8cf53e22636a98fae43a5eb8f0550a1268d141bbfca12b9db88018e3b` |

Completed plan state receipts (each also has immutable
`completion_verdict.json` and `review_evidence.json`):

| label | plan | state SHA-256 |
| --- | --- | --- |
| p0-mrc-intake-crosswalk | `p0-mrc-closeout-intake-and-20260826-0049` | `b1ae731f68f9c0ffed155d9b3afd854c2f8f319fdb3035d146ed4b9de93fc697` |
| p1-custody-m11-admission | `p1-custody-m11-admission-20260827-0329` | `bbf878a2f27a875b9899eb885d2e74a938feed5b03cb443d8263d5be3b5cf3e0` |
| p2-milestone-gate-bootstrap | `p2-milestone-gate-bootstrap-20260827-1501` | `952f3b216016d85c44b89a3b99601753dc790f6498001d48ad37cae1a5721fb5` |
| native-s1-baseline | `native-s1-custody-admission-20260829-0358` | `3a6b0861c8492f8757bb372489cfb9b4cebf51661bf0f64179deaa6fffa1ac67` |
| native-s2f-pype-format | `native-s2f-pype-compiler-20260829-0604` | `29a1c646a0a20096462e9c120e0679f38d66ab4e6c328cb0f350c0f79ecc7f47` |
| native-c1-completion-contract | `native-c1-completion-contract-20260829-1141` | `2147b6a85cc8c3a28d2b9ed8893489c4598109e77d2c5aa39849f2ec33411992` |

Cutover custody references recorded by the predecessor inventory are
promotion receipt `7f14d25a`, custody manifest `c06bc802`, and archived ledger
`e5d8c648`. The independently verified operational-refresh archive is
`/workspace/.megaplan/custody/native-build-forward/operational-refresh-20260902T163544Z/manifest.json`
(`b82e8e1916165bd95d7f22f7ad47296c1c05a11bc2ee90d79eea7723ec75e4c6`) with
ledger `.../.megaplan/incident-ledger/events.jsonl`
(`693170b7ae1837646a06ceea621192cc057516bea842df7a66315bac5eaff33c`).
The full promotion/custody digests must be re-read from that immutable archive
at launch; no caller-supplied abbreviated value is authoritative.

## New continuation identity

Canonical source is `main@2a47196196c5eae72c6cd92491ee300eb48605f3`, the asset-bearing commit whose content
is pinned by the continuation chain.
The intended branch is `fixer/native-build-forward-c2-9707ce4a-20260903-r8`.
The cloud workspace, runtime candidate, and session all use the unique
namespace `native-build-forward-c2-9707ce4a-20260903-r8`:

- runtime candidate: `/workspace/runtime-candidates/native-build-forward-c2-9707ce4a-20260903-r8`
- chain session: `native-build-forward-c2-9707ce4a-20260903-r8`
- supported marker directory: `/workspace/.megaplan/cloud-sessions`; expected marker filename: `native-build-forward-c2-9707ce4a-20260903-r8.json`
- chain spec: `.megaplan/initiatives/native-build-forward-continuation-20260903-r8/chain.yaml`
- configured bootstrap interpreter: `/root/.pyenv/versions/3.13.6/bin/python`

The earlier unlaunched identity and any failed partial runtime under
`/workspace/runtime-candidates/native-build-forward-c2-a8286d28-20260902`
remain immutable historical evidence and are not reused by this continuation.
The superseded r2 continuation identity
`native-build-forward-c2-c4b0c102-20260902-r2` is likewise preserved as
historical evidence. Its failed WBC launch receipt and partial runtime remain
under the r2 namespace; they are not deleted, imported, or replayed by r8.
The superseded r3 launch was invoked once and stopped before chain startup at
the typed `engine_ref_probe_failed` authentication guard. Its failed runtime
and marker remain immutable evidence at
`/workspace/runtime-candidates/native-build-forward-c2-ec69ede3-20260902-r3`
and `/workspace/.megaplan/cloud-sessions/native-build-forward-c2-ec69ede3-20260902-r3.json`;
they are not reused by r8.

The superseded r4 launch was invoked once and stopped before chain startup at
the guarded partial-runtime recovery boundary: its manifest was bound to bbe1
while the reviewed source advanced to 7801, and its runtime origin still
pointed at the local r3 custody checkout rather than the canonical GitHub
repository. The r4 runtime, manifest, pointer, and launch evidence remain
immutable and are not reused by r8.

The r5 launch was invoked once and stopped before chain startup at the typed
`chain_runtime_create_failed` boundary caused by a stale installed runtime
wrapper. Its clean partial runtime and active per-epic manifest remain
immutable at `/workspace/runtime-candidates/native-build-forward-continuation-20260903-r5`
and `/workspace/.megaplan/native-build-forward-continuation-20260903-r5.json`;
no r5 marker, chain state, owner, or provider receipt was created, and r8
does not reuse that evidence.

The r6 launch was invoked once and stopped before chain startup at the typed
`chain_runtime_create_failed` boundary. Launch canonicalization rewrote the
reviewed r6 chain YAML in place, making the source checkout dirty before the
source-bound runtime guard; no r6 marker, chain state, owner, provider receipt,
or fixer was created. The r6 partial runtime and WBC evidence remain immutable
historical evidence and are not reused by r8.

The r7 launch was invoked once and stopped before chain startup at the typed
`chain_runtime_probe_unreadable` boundary. The on-box provider classified the
compound probe as an authenticated Git operation because its unreachable
manifest-creation branch contained an inline fetch, then suppressed the
otherwise valid JSON binding stdout for credential safety. The r7 runtime,
manifest, and 46-event WBC receipt remain immutable historical evidence and
are not reused by r8; the stdout classification repair is included in this
continuation's source.

All workflow, preparation, nested tier, execution, critique, and review
routes resolve through `all-muse-spark-openrouter` to the exact
`omp:openrouter/meta/muse-spark-1.3-contributor` route. The adapter forces
`thinking=high` for this provider/model. The closed continuation contract
normalizes every caller-supplied thinking value to `high`.

## Supported launch preconditions

This artifact does not launch or resume anything. Before a future launch,
the operator must:

1. publish this branch (or an equivalent content-addressed commit) and make
   the remote `main`/`megaplan.ref` resolve the exact canonical source;
2. verify that the chain driver's content-addressed revision pin and the
   remote checkout agree, then verify the 19 launch assets (chain spec, North
   Star, cloud configuration, and all 16 briefs) are present and tracked
   byte-for-byte at that revision, together with the bound Muse profile;
3. run the supported `cloud preflight` against `cloud.yaml`, then
   `chain verify`/`doctor` as available, and confirm the new workspace,
   session, marker, and clean editable runtime are unique and not
   `/workspace/arnold`;
4. confirm the new chain has no persisted state and starts at C2, while the
   old chain's pause and durable hold remain unchanged. Only then is the exact
   next action supported: `uv run python -m arnold_pipelines.megaplan cloud chain .megaplan/initiatives/native-build-forward-continuation-20260903-r8/chain.yaml --cloud-yaml .megaplan/initiatives/native-build-forward-continuation-20260903-r8/cloud.yaml`.

No `chain_completed` predecessor marker is invented, no old state is copied,
and no old hold is released by this handoff.
