# NBF paused-chain → fresh-continuation handoff

## Historical source (immutable; not adopted)

The original AgentBox chain remains ownerless, `should_run=false`, paused, and
held. It is preserved as evidence and is never rewritten, deleted, rebound, or
resumed by this continuation.

| Field | Value |
|---|---|
| old checkout | `/workspace/runtime-candidates/native-build-forward` |
| old branch/HEAD | `fixer/native-build-forward-nbf08-final-20260901` / `57ce08b200df95323f77538acc81484353051479` |
| old chain state SHA-256 | `fb4c58d491a1c47c7f744d2fc8c344b1656ea012f9b4a53d6f935d9f21808ad6` |
| old chain spec SHA-256 | `60a6cfc151e935de8308f4bee2316b5948827d5e9610e3a11adc93a1e5ef99b1` |
| old aborted C2 plan SHA-256 | `65a32e32a74f27ba534fb62a2e15f9551af8944ba8d42e34c655625c1836d7a6` |
| old session marker SHA-256 | `5ccc3b477f09f712cb5aded03a97324ac8741d4dd8d4859e7a0349b60a268017` |
| old runtime manifest SHA-256 | `8d358ba8e31699db4d568009a4a40ed61bf39e2991d50c0274c69bcd80b8af80` |
| old cursor/projection | cursor/index `6`, `current_plan_name=null`, `last_state=paused` |
| old ownership | no owner, fixer, provider, PID, lease, or fence |
| old hold | operator pause and resume hold active; `should_run=false` |

The old persisted rows use `status=done`, not canonical `completed`; its
`chain_session`, `metadata.chain_id`, and project source binding are null, and
its recorded spec digest is stale. These are preserved facts, not normalized.
This manifest therefore proves a six-label historical prefix, but explicitly
does **not** assert that the old chain is `chain_completed`.

## Six-prefix evidence

The historical labels, in exact order, are:

1. `p0-mrc-intake-crosswalk`
2. `p1-custody-m11-admission`
3. `p2-milestone-gate-bootstrap`
4. `native-s1-baseline`
5. `native-s2f-pype-format`
6. `native-c1-completion-contract`

The source-side reviewed evidence is retained in the durable-start run:

- `.otto/runs/nbf-durable-start-20260903/evidence/batch-1-manifest.md`
- `.otto/runs/nbf-durable-start-20260903/evidence/batch-1-final-oracle-sol.md`
- `.otto/runs/nbf-durable-start-20260903/findings/batch-2-final-source-stability-oracle-grok.md`
- `.otto/runs/nbf-durable-start-20260903/receipts/batch-2-live-paused-checkout-cutover.md`

The reviewed continuation source is the published `main` branch at the
post-port SHA recorded by the launch run (the source is always revalidated by
its immutable tree before deployment). Fresh admission must rehash every old
and new authority and must refuse on drift; the deployment receipt and runtime
manifest are the sole exact SHA/tree authority.

## Fresh continuation contract

The new chain/session/runtime/operation identities above are unique and have
no shared ownership with the old chain. A supported launch must first create a
new content-addressed runtime manifest and handoff receipt, verify all six
labels and evidence without turning them into new completed rows, and prove
the candidate branch/ref/object/package/profile closure. It may then create
one fresh C2 plan, acquire one new owner reservation, and route supported chain
  lifecycle phases, fixer, oracle, researcher, and superfixer roles through the
  canonical Muse Spark 1.3 Contributor high profile. The exact-output provider
  receipt and preflight must prove this binding before dispatch; no fallback to
  resident defaults is permitted. Hold release, plan creation, and dispatch are
separate guarded actions; any mismatch leaves the old chain untouched and the
new continuation paused.
