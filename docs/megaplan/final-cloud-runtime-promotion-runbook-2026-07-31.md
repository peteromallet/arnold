# Final cloud runtime promotion runbook — 2026-07-31

This is the fail-closed operator procedure for promoting one reviewed Arnold
commit to the Hetzner Megaplan cloud runner. It changes no secrets and does not
declare Custody, Superpom, Withings, or the release complete merely because a
process is alive. Completion requires the terminal projections and live probes
below.

> **Authority status (M11):** The `docker exec` invocations below are
> non-authoritative transport for checkpointing, selector mutation, and
> read-only probes inside the already selected container. They do not grant
> repair authority or replace the canonical recovery delegation path.

The procedure deliberately separates four identities:

1. the reviewed Git commit;
2. its immutable source checkout and virtual environment;
3. the immutable Docker image used for the cloud runner;
4. the selectors and launch attestation actually inherited by live processes.

Do not replace this sequence with an in-place pull, editable-install refresh,
manual container restart, or a hand-written `done` marker.

## 1. Operator parameters and hard stop rules

Set these in the operator shell. `FINAL_SHA` must be the full 40-character
reviewed commit, not a branch or abbreviated hash. No secret value belongs in
this file or the receipt directory.

```bash
set -euo pipefail

export CLOUD_CONFIG="${CLOUD_CONFIG:?absolute path to the reviewed cloud.yaml}"
export SSH_TARGET="${SSH_TARGET:?user@host from the approved SSH config}"
export CONTAINER="${CONTAINER:-megaplan-cloud-agent}"
# The SSH provider intentionally uses ssh.container as both the running
# container name and mutable docker-build tag (providers/ssh.py).
export DEPLOY_IMAGE="${DEPLOY_IMAGE:-$CONTAINER}"
export FINAL_SHA="${FINAL_SHA:?full reviewed 40-character Git SHA}"
export FINAL_TAG="${FINAL_TAG:-post-m11-consolidation-${FINAL_SHA:0:12}}"
export IMAGE_TAG="${IMAGE_TAG:-megaplan-cloud-agent:${FINAL_SHA}}"
export WORKSPACE_HOST="${WORKSPACE_HOST:-/opt/megaplan-cloud/workspace}"
export RUNTIME_SRC="/workspace/runtime-candidates/arnold-${FINAL_SHA}"
export RUNTIME_VENV="/workspace/runtime-venvs/arnold-${FINAL_SHA}"
export RUNTIME_PYTHON="${RUNTIME_VENV}/bin/python3"
export HOT_ENV="/workspace/.cloud-hot-env"
export RESIDENT_ENV="/workspace/.megaplan/resident-runtime.env"
export SIMPLE_FIXER_DROPIN="${SIMPLE_FIXER_DROPIN:-/etc/systemd/system/megaplan-progress-audit.service.d/95-post-m11-runtime.conf}"
export RECEIPT_ID="$(date -u +%Y%m%dT%H%M%SZ)-${FINAL_SHA:0:12}"
export RECEIPT_HOST="${WORKSPACE_HOST}/.megaplan/release-receipts/${RECEIPT_ID}"
export RECEIPT_CONTAINER="/workspace/.megaplan/release-receipts/${RECEIPT_ID}"
export RELEASE_EVIDENCE_DOCUMENT="${RECEIPT_CONTAINER}/public/post-m11-release-evidence.candidate-ready.json"
export RELEASE_EVIDENCE_SHA256="${RELEASE_EVIDENCE_DOCUMENT}.sha256"
export RUNTIME_IDENTITY="${RECEIPT_CONTAINER}/private/candidate-runtime-identity.json"
export RUNTIME_PROVENANCE_RECEIPT="${RECEIPT_CONTAINER}/private/candidate-runtime-provenance.json"
export AUTHORITATIVE_MARKER="${AUTHORITATIVE_MARKER:?current marker path in container}"
export AUTHORITATIVE_MANIFEST="${AUTHORITATIVE_MANIFEST:?authoritative pinned runtime manifest path in container}"
export AUTHORITATIVE_CHAIN_SPEC="${AUTHORITATIVE_CHAIN_SPEC:?current chain spec path in container}"
export AUTHORITATIVE_CHAIN_STATE="${AUTHORITATIVE_CHAIN_STATE:?current chain state path in container}"
export CHAIN_PREVIOUS_RUNTIME_SHA256="${CHAIN_PREVIOUS_RUNTIME_SHA256:?current chain runtime digest}"
export MARKER_PREVIOUS_RUNTIME_SHA256="${MARKER_PREVIOUS_RUNTIME_SHA256:?current marker runtime digest}"
export CHAIN_PREVIOUS_RUNTIME_IDENTITY="${CHAIN_PREVIOUS_RUNTIME_IDENTITY:?independently receipted old chain runtime identity}"
export CHAIN_PREVIOUS_RUNTIME_PROVENANCE="${CHAIN_PREVIOUS_RUNTIME_PROVENANCE:?independent old chain runtime provenance receipt}"

case "$FINAL_SHA" in
  [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
  *) echo "FINAL_SHA must be a full lowercase 40-character SHA" >&2; exit 2 ;;
esac
```

Abort before mutation unless all of these are true:

- the direct-promotion policy override is present, the ordinary fast-forward
  compare-and-swap push succeeded, and `FINAL_SHA` is the exact validated
  `main` commit;
- the source tag peels to `FINAL_SHA`; the separate acceptance tag is created
  only after the final external receipt exists;
- the final frozen validation manifest is green at that exact commit;
- the local checkout and cloud source remote agree on the same commit;
- no active chain is in an external-effect critical section;
- Custody has an authoritative terminal projection, not just a historical
  marker or a manufactured label;
- the current runtime, container, selector files, systemd units, and image ID
  have been checkpointed and hashed;
- rollback keeps the old immutable runtime and image available for at least
  24 hours and one later watchdog/auditor cycle.

Two consecutive missed expected heartbeats, any critical probe failure, any
source/interpreter/selector mismatch, or a new current repairable failure
aborts the promotion and invokes rollback.

## 2. Pre-mutation checkpoint

Create a private receipt directory and capture state without printing
environment contents to the terminal. The copies may contain secret-bearing
configuration and therefore remain mode `0700`/`0600`; the published receipt
contains only hashes and redacted projections.

```bash
ssh "$SSH_TARGET" bash -s -- \
  "$CONTAINER" "$DEPLOY_IMAGE" "$RECEIPT_HOST" "$RECEIPT_CONTAINER" "$HOT_ENV" "$RESIDENT_ENV" \
  "$SIMPLE_FIXER_DROPIN" <<'REMOTE'
set -euo pipefail
container="$1"
deploy_image="$2"
receipt="$3"
receipt_container="$4"
hot_env="$5"
resident_env="$6"
dropin="$7"

install -d -m 700 "$receipt/private" "$receipt/public"
docker inspect "$container" >"$receipt/private/container-inspect.before.json"
docker image inspect "$(docker inspect -f '{{.Image}}' "$container")" \
  >"$receipt/private/image-inspect.before.json"
docker image inspect "$deploy_image" \
  >"$receipt/private/deploy-image-tag.before.json"
systemctl cat megaplan-repair-trigger.service \
  >"$receipt/private/megaplan-repair-trigger.before.txt" 2>&1 || true
systemctl cat megaplan-progress-audit.service \
  >"$receipt/private/megaplan-progress-audit.before.txt" 2>&1 || true
systemctl cat megaplan-watchdog-ensure.service \
  >"$receipt/private/megaplan-watchdog-ensure.before.txt" 2>&1 || true
systemctl cat megaplan-resident-ensure.service \
  >"$receipt/private/megaplan-resident-ensure.before.txt" 2>&1 || true
if [[ -f "$dropin" ]]; then
  cp -a "$dropin" "$receipt/private/simple-fixer-dropin.before"
else
  : >"$receipt/private/simple-fixer-dropin.before.absent"
fi

docker exec "$container" bash -s -- "$receipt_container" "$hot_env" "$resident_env" <<'INNER'
set -euo pipefail
receipt="$1"
hot_env="$2"
resident_env="$3"
umask 077
for path in "$hot_env" "$resident_env"; do
  if [[ -f "$path" ]]; then
    cp -a "$path" "$receipt/private/$(basename "$path").before"
  else
    : >"$receipt/private/$(basename "$path").before.absent"
  fi
done
git -C /workspace/arnold rev-parse HEAD \
  >"$receipt/public/legacy-source-head.before.txt" 2>/dev/null || true
tmux list-sessions -F '#{session_name} #{session_created} #{session_attached}' \
  >"$receipt/public/tmux.before.txt" 2>/dev/null || true
ps -eo pid,ppid,lstart,args --sort=pid >"$receipt/private/processes.before.txt"
INNER

(
  cd "$receipt"
  find private public -type f -print0 |
    sort -z |
    xargs -0 sha256sum >public/checkpoint.sha256
)
chmod -R go-rwx "$receipt"
REMOTE
```

Capture the canonical status projection before cutover:

```bash
python -m arnold_pipelines.megaplan cloud chains \
  --cloud-yaml "$CLOUD_CONFIG" --compact --since 24h \
  >"/tmp/cloud-chains-${RECEIPT_ID}.json"
scp "/tmp/cloud-chains-${RECEIPT_ID}.json" \
  "${SSH_TARGET}:${RECEIPT_HOST}/public/cloud-chains.before.json"
```

Treat old markers as historical evidence, not current authority. Never edit an
old marker to manufacture completion. A marker may be archived only after the
canonical projection proves it is terminal, its runner and repair processes are
absent, its workspace is not selected by any live process, and its content hash
is in the receipt. A newer non-terminal chain state always defeats an older
`complete` or watchdog marker.

## 3. Build the immutable runtime

Create the candidate from the exact remote commit in a new path. Refuse an
existing path unless it already has the exact clean identity. Build a new
virtual environment with the frozen lock; do not reuse the production editable
install.

```bash
python -m arnold_pipelines.megaplan cloud exec \
  --cloud-yaml "$CLOUD_CONFIG" \
  "set -euo pipefail
   test \"\$(git -C /workspace/arnold rev-parse '${FINAL_TAG}^{commit}')\" = '${FINAL_SHA}'
   if test -e '${RUNTIME_SRC}'; then
     test \"\$(git -C '${RUNTIME_SRC}' rev-parse HEAD)\" = '${FINAL_SHA}'
     test -z \"\$(git -C '${RUNTIME_SRC}' status --porcelain)\"
   else
     git clone --no-checkout /workspace/arnold '${RUNTIME_SRC}'
     git -C '${RUNTIME_SRC}' checkout --detach '${FINAL_SHA}'
   fi
   test \"\$(git -C '${RUNTIME_SRC}' rev-parse HEAD)\" = '${FINAL_SHA}'
   test -z \"\$(git -C '${RUNTIME_SRC}' status --porcelain)\"
   python3 -m venv --copies '${RUNTIME_VENV}'
   '${RUNTIME_PYTHON}' -m pip install --upgrade pip uv
   cd '${RUNTIME_SRC}'
   VIRTUAL_ENV='${RUNTIME_VENV}' PATH='${RUNTIME_VENV}/bin':\"\$PATH\" \
     '${RUNTIME_PYTHON}' -m uv sync --all-extras --frozen --active
   '${RUNTIME_PYTHON}' -P -c 'import pathlib,arnold,arnold_pipelines; root=pathlib.Path(\"${RUNTIME_SRC}\").resolve(); assert pathlib.Path(arnold.__file__).resolve().is_relative_to(root); assert pathlib.Path(arnold_pipelines.__file__).resolve().is_relative_to(root)'
   PYTHONSAFEPATH=1 PYTHONPATH='${RUNTIME_SRC}' '${RUNTIME_PYTHON}' -P -m arnold_pipelines.megaplan.cloud.runtime_provenance \
     --expected-root '${RUNTIME_SRC}' --expected-revision '${FINAL_SHA}' \
     --emit-receipt --identity-out '${RUNTIME_IDENTITY}' \
     --receipt-out '${RUNTIME_PROVENANCE_RECEIPT}'
   test -s '${RUNTIME_IDENTITY}'
   test -s '${RUNTIME_PROVENANCE_RECEIPT}'
   git -C '${RUNTIME_SRC}' status --porcelain | test ! -s /dev/stdin"
```

Prepare the isolated supervisor runtime from the candidate and require its
receipt to bind the candidate source and commit:

```bash
python -m arnold_pipelines.megaplan cloud exec \
  --cloud-yaml "$CLOUD_CONFIG" \
  "set -euo pipefail
   export MEGAPLAN_SUPERVISOR_SOURCE='${RUNTIME_SRC}'
   export MEGAPLAN_SUPERVISOR_RUNTIME_ROOT='${RUNTIME_VENV}/supervisor'
   export MEGAPLAN_SUPERVISOR_PYTHON='${RUNTIME_VENV}/supervisor/current/bin/python3'
   export MEGAPLAN_SUPERVISOR_RUNTIME_REQUIRED=1
   '${RUNTIME_SRC}/arnold_pipelines/megaplan/cloud/wrappers/arnold-supervisor-runtime' --prepare
   test -s '${RUNTIME_VENV}/supervisor/last-prepare.json'
   jq -e --arg src '${RUNTIME_SRC}' --arg sha '${FINAL_SHA}' \
     '.source == \$src and .source_revision == \$sha' \
     '${RUNTIME_VENV}/supervisor/last-prepare.json'"
```

Build the thin image through the supported provider path, then record and tag
the resulting immutable image. `cloud deploy` is intentionally not run yet.

```bash
python -m arnold_pipelines.megaplan cloud build --cloud-yaml "$CLOUD_CONFIG"
ssh "$SSH_TARGET" bash -s -- \
  "$DEPLOY_IMAGE" "$IMAGE_TAG" "$RECEIPT_HOST" <<'REMOTE'
set -euo pipefail
deploy_image="$1"
image_tag="$2"
receipt="$3"
image_id="$(docker image inspect -f '{{.Id}}' "$deploy_image")"
docker tag "$image_id" "$image_tag"
docker image inspect "$image_tag" >"$receipt/private/image-inspect.candidate.json"
printf '%s\n' "$image_id" >"$receipt/public/candidate-image-id.txt"
sha256sum "$receipt/private/image-inspect.candidate.json" \
  >"$receipt/public/candidate-image-inspect.sha256"
REMOTE
```

## 4. Isolated canary

The first canary must not mount the production workspace read/write, use the
production container name or port, consume Discord credentials, or start
watchdog/fixer/resident processes. It verifies the new image against a
read-only view of the content-addressed runtime.

```bash
ssh "$SSH_TARGET" bash -s -- \
  "$IMAGE_TAG" "$WORKSPACE_HOST" "$RUNTIME_SRC" "$RUNTIME_PYTHON" "$FINAL_SHA" <<'REMOTE'
set -euo pipefail
image_tag="$1"
workspace_host="$2"
runtime_src="$3"
runtime_python="$4"
final_sha="$5"
canary="megaplan-runtime-canary-${final_sha:0:12}"
docker rm -f "$canary" >/dev/null 2>&1 || true
docker run --rm --name "$canary" \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=256m \
  -v "${workspace_host}:/workspace:ro" \
  --entrypoint bash "$image_tag" -lc "
    set -euo pipefail
    test \"\$(git -C '$runtime_src' rev-parse HEAD)\" = '$final_sha'
    test -z \"\$(git -C '$runtime_src' status --porcelain)\"
    PYTHONSAFEPATH=1 PYTHONPATH='$runtime_src' '$runtime_python' -P -c \
      'import arnold, arnold_pipelines, agentbox'
    PYTHONSAFEPATH=1 PYTHONPATH='$runtime_src' '$runtime_python' -P -m \
      arnold_pipelines.megaplan.cloud.runtime_provenance \
      --expected-root '$runtime_src' --expected-revision '$final_sha'
  "
REMOTE
```

Failure here stops the release. It does not justify mutating selectors or
trying the same candidate directly in production.

## 5. Atomic selector transaction

The selector transaction has three durable surfaces:

1. `.cloud-hot-env` for watchdog, heartbeat, audit, meta-repair, chain launch,
   and supervisor source;
2. `resident-runtime.env` for the resident source, interpreter, launch seed,
   and fail-closed attestation requirement;
3. the host systemd drop-in pinning `MEGAPLAN_SIMPLE_FIXER_SOURCE_ROOT`.

All source selectors must name `RUNTIME_SRC`; all execution selectors must name
`RUNTIME_PYTHON` or its prepared supervisor child. Build the launch seed from
the exact current authoritative marker and chain spec before enabling
`MEGAPLAN_RUNTIME_ATTESTATION_REQUIRED=1`. The seed command is:

```text
python -P -m arnold_pipelines.megaplan.cloud.runtime_attestation build
  --expected-root RUNTIME_SRC --expected-revision FINAL_SHA
  --supervisor-receipt SUPERVISOR_RECEIPT --hot-env HOT_ENV
  --marker AUTHORITATIVE_MARKER --chain-spec AUTHORITATIVE_CHAIN_SPEC
  --seed-doc RELEASE_EVIDENCE_DOCUMENT --output RUNTIME_LAUNCH_SEED
```

Use the actual authoritative marker/spec paths from the terminal projection;
never guess them or bind a stale historical marker.

### 5.1 Freeze and validate the existing release-evidence authority

Resolve these three paths and both previous runtime identities from the current
terminal projection before continuing:

```bash
export AUTHORITATIVE_MARKER="${AUTHORITATIVE_MARKER:?current marker path in container}"
export AUTHORITATIVE_CHAIN_SPEC="${AUTHORITATIVE_CHAIN_SPEC:?current chain spec path in container}"
export AUTHORITATIVE_CHAIN_STATE="${AUTHORITATIVE_CHAIN_STATE:?current chain state path in container}"
export CHAIN_PREVIOUS_RUNTIME_SHA256="${CHAIN_PREVIOUS_RUNTIME_SHA256:?current chain runtime digest}"
export MARKER_PREVIOUS_RUNTIME_SHA256="${MARKER_PREVIOUS_RUNTIME_SHA256:?current marker runtime digest}"
```

For the 2026-07-31 Custody preflight these were, respectively,
`3d482370707a0a7f9d806a38ff270b986f646b2e4595b1ede57cedc1cb52b6fd`
and `b7ec04a77bc6ef47adfafbcc6482cf2e5734be9b372541cf11c08e4c57e22e8f`.
They are historical observations, not defaults: re-read and compare them
immediately before mutation.

Checkpoint both authorities and the independently receipted chain rollback
runtime. This happens before either rebind and is included in the receipt hash:

```bash
python -m arnold_pipelines.megaplan cloud exec \
  --cloud-yaml "$CLOUD_CONFIG" \
  "set -euo pipefail
   umask 077
   cp -a '${AUTHORITATIVE_MARKER}' '${RECEIPT_CONTAINER}/private/marker.before.json'
   cp -a '${AUTHORITATIVE_CHAIN_SPEC}' '${RECEIPT_CONTAINER}/private/chain-spec.before.yaml'
   cp -a '${AUTHORITATIVE_CHAIN_STATE}' '${RECEIPT_CONTAINER}/private/chain-state.before.json'
   cp -a '${CHAIN_PREVIOUS_RUNTIME_IDENTITY}' '${RECEIPT_CONTAINER}/private/chain-previous-runtime-identity.json'
   cp -a '${CHAIN_PREVIOUS_RUNTIME_PROVENANCE}' '${RECEIPT_CONTAINER}/private/chain-previous-runtime-provenance.json'
   sha256sum \
     '${RECEIPT_CONTAINER}/private/marker.before.json' \
     '${RECEIPT_CONTAINER}/private/chain-spec.before.yaml' \
     '${RECEIPT_CONTAINER}/private/chain-state.before.json' \
     '${RECEIPT_CONTAINER}/private/chain-previous-runtime-identity.json' \
     '${RECEIPT_CONTAINER}/private/chain-previous-runtime-provenance.json' \
     >'${RECEIPT_CONTAINER}/public/runtime-authorities.before.sha256'"
```

`RELEASE_EVIDENCE_DOCUMENT` is not an arbitrary seed manifest and is not the
checked-out `in_progress` template. It is the durable receipt-directory
snapshot of
`docs/megaplan/post-m11-release-evidence-20260731.json`, after the final proof
aggregation has bound the exact `FINAL_SHA`, its tree, `RUNTIME_IDENTITY`, the
no-debt inventory, and every pre-deploy residual receipt. The checked-in
record cannot contain the identity of a runtime built from its own eventual
commit without a content-identity cycle, so the immutable candidate snapshot
lives beside the release receipts and retains the same schema and authority.

The snapshot must have `record_status: candidate_ready`. That status is a
hard validator state: all pre-deploy residuals are complete and immutably
receipted; only runtime-selector promotion, production canary, the acceptance
tag, and Critique rebind/launch may remain pending. Cleanup approval is outside
release completeness. `in_progress`, a hand-edited `done` label, a hash without
a green validation, or an otherwise valid JSON document is not seed authority.

Run this exact validation with the candidate code before any chain, marker, or
selector mutation:

```bash
python -m arnold_pipelines.megaplan cloud exec \
  --cloud-yaml "$CLOUD_CONFIG" \
  "set -euo pipefail
   test -s '${RELEASE_EVIDENCE_DOCUMENT}'
   test -s '${RELEASE_EVIDENCE_SHA256}'
   jq -e --arg sha '${FINAL_SHA}' \
     '.schema == \"arnold.post_m11_release_evidence.v1\"
      and .record_status == \"candidate_ready\"
      and .authority.evidence_cut_commit == \$sha' \
     '${RELEASE_EVIDENCE_DOCUMENT}' >/dev/null
   test \"\$(git -C '${RUNTIME_SRC}' rev-parse HEAD^{tree})\" = \
     \"\$(jq -r '.authority.evidence_cut_tree' '${RELEASE_EVIDENCE_DOCUMENT}')\"
   PYTHONSAFEPATH=1 PYTHONPATH='${RUNTIME_SRC}' '${RUNTIME_PYTHON}' -P \
     '${RUNTIME_SRC}/scripts/validate_post_m11_release_evidence.py' \
     '${RELEASE_EVIDENCE_DOCUMENT}' --print-sha256 \
     >'${RECEIPT_CONTAINER}/public/candidate-ready.validation.sha256'
   test \"\$(cut -d' ' -f1 '${RELEASE_EVIDENCE_SHA256}')\" = \
     \"\$(cat '${RECEIPT_CONTAINER}/public/candidate-ready.validation.sha256')\""
```

### 5.2 Rebind the terminal chain and marker before seed construction

The launch-seed builder correctly rejects old marker or chain runtime
identities. Rebind both durable authorities directly to the candidate before
rewriting selectors. Their previous identities need not be equal: each is its
own compare-and-swap guard. Manufacturing an intermediate equality would erase
the mismatch rather than explain it. The completed Custody chain uses the
explicit terminal guards shown below. `runtime-rebind` additionally
requires cursor index equal to milestone count, no active plan, canonical
`last_state: done`, and the exact ordered set of `done` milestone records.

```bash
python -m arnold_pipelines.megaplan cloud exec \
  --cloud-yaml "$CLOUD_CONFIG" \
  "set -euo pipefail
   exec 9>/workspace/.megaplan/runtime-cutover.lock
   flock -x 9
   test \"\$(sha256sum '${AUTHORITATIVE_CHAIN_STATE}' | cut -d' ' -f1)\" = \
     \"\$(sha256sum '${RECEIPT_CONTAINER}/private/chain-state.before.json' | cut -d' ' -f1)\"
   test \"\$(jq -r '.metadata.execution_binding.runtime_binding.current_identity.content_sha256' '${AUTHORITATIVE_CHAIN_STATE}')\" = \
     '${CHAIN_PREVIOUS_RUNTIME_SHA256}'
   test \"\$(jq -r '.runtime_binding.current_identity.content_sha256' '${AUTHORITATIVE_MARKER}')\" = \
     '${MARKER_PREVIOUS_RUNTIME_SHA256}'
   test \"\$(jq -r '.last_state' '${AUTHORITATIVE_CHAIN_STATE}')\" = done
   test -z \"\$(jq -r '.current_plan_name // empty' '${AUTHORITATIVE_CHAIN_STATE}')\"
   candidate_runtime=\"\$(jq -r '.content_sha256' '${RUNTIME_IDENTITY}')\"
   PYTHONSAFEPATH=1 PYTHONPATH='${RUNTIME_SRC}' '${RUNTIME_PYTHON}' -P -m \
     arnold_pipelines.megaplan chain runtime-rebind \
     --spec '${AUTHORITATIVE_CHAIN_SPEC}' \
     --from-runtime-sha256 '${CHAIN_PREVIOUS_RUNTIME_SHA256}' \
     --to-runtime-sha256 \"\$candidate_runtime\" \
     --expected-current-milestone @terminal \
     --expected-current-plan @none \
     --direction cutover \
     --reason 'post-M11 content-addressed production promotion' \
     --actor release-operator \
     >'${RECEIPT_CONTAINER}/public/chain-runtime-rebind.json'

   marker_sha=\"\$(sha256sum '${AUTHORITATIVE_MARKER}' | cut -d' ' -f1)\"
   jq -er '.relaunch_command // .launch_command // empty' \
     '${AUTHORITATIVE_MARKER}' \
     >'${RECEIPT_CONTAINER}/private/relaunch-command.txt'
   PYTHONSAFEPATH=1 PYTHONPATH='${RUNTIME_SRC}' '${RUNTIME_PYTHON}' -P -m \
     arnold_pipelines.megaplan.cloud.runtime_cutover \
     --marker '${AUTHORITATIVE_MARKER}' \
     --manifest '${AUTHORITATIVE_MANIFEST}' \
     --expect-marker-sha256 \"\$marker_sha\" \
     --from-runtime-sha256 '${MARKER_PREVIOUS_RUNTIME_SHA256}' \
     --runtime-identity '${RUNTIME_IDENTITY}' \
     --relaunch-command-file '${RECEIPT_CONTAINER}/private/relaunch-command.txt' \
     --direction cutover \
     --reason 'post-M11 content-addressed production promotion' \
     --actor release-operator \
     >'${RECEIPT_CONTAINER}/public/marker-runtime-rebind.json'
   test \"\$(jq -r '.metadata.execution_binding.runtime_binding.current_identity.content_sha256' '${AUTHORITATIVE_CHAIN_STATE}')\" = \
     \"\$candidate_runtime\"
   test \"\$(jq -r '.runtime_binding.current_identity.content_sha256' '${AUTHORITATIVE_MARKER}')\" = \
     \"\$candidate_runtime\""
```

Both operations preserve operational cursor fields. The marker has a file-SHA
CAS and lock. The chain has exact terminal, plan, and previous-runtime guards
but currently lacks a state-file-SHA CLI guard. This terminal release therefore
also holds the release lock, compares the checkpoint hash, and requires proof
that no runner, repairer, or other chain-state writer is live.

If marker rebind fails after chain rebind, stop before selector mutation or
process restart. Roll the chain from the candidate digest back to
`CHAIN_PREVIOUS_RUNTIME_SHA256` through `runtime-rebind --direction rollback`,
supplying the checkpointed `chain-previous-runtime-identity.json` and
`chain-previous-runtime-provenance.json`. If a later operation fails, roll the
marker back separately to `MARKER_PREVIOUS_RUNTIME_SHA256` using the exact
checkpointed marker identity and relaunch command, then roll the chain back as
above. Verify both restored identities and receipt hashes. Never repair the
mismatch by editing either JSON file.

Acquire one host cutover lock. Write all three replacements to temporary files,
`fsync` and rename them, then reload systemd. If any write fails, restore all
three checkpoints before restarting a process.

Required `.cloud-hot-env` bindings:

```text
MEGAPLAN_RUNTIME_SRC=RUNTIME_SRC
MEGAPLAN_LAUNCH_RUNTIME_SRC=RUNTIME_SRC
CLOUD_WATCHDOG_ARNOLD_SRC=RUNTIME_SRC
MEGAPLAN_AUDIT_ARNOLD_SRC=RUNTIME_SRC
MEGAPLAN_META_ARNOLD_SRC=RUNTIME_SRC
MEGAPLAN_SUPERVISOR_SOURCE=RUNTIME_SRC
MEGAPLAN_SUPERVISOR_RUNTIME_ROOT=RUNTIME_VENV/supervisor
MEGAPLAN_SUPERVISOR_PYTHON=RUNTIME_VENV/supervisor/current/bin/python3
MEGAPLAN_SUPERVISOR_RUNTIME_REQUIRED=1
```

Required `resident-runtime.env` bindings:

```text
MEGAPLAN_RUNTIME_SRC=RUNTIME_SRC
MEGAPLAN_RUNTIME_PYTHON=RUNTIME_PYTHON
MEGAPLAN_RUNTIME_LAUNCH_SEED=RUNTIME_LAUNCH_SEED
MEGAPLAN_RUNTIME_ATTESTATION_REQUIRED=1
```

Preserve unrelated existing settings. Do not source either file into the
operator shell or log their contents. The transaction receipt records their
SHA-256 hashes and the redacted selector names, never secret values.

The following transaction performs those rewrites. Set the three authoritative
input paths from the current canonical projection; each must exist inside the
container and belong to the intended current chain.

```bash
export SUPERVISOR_RECEIPT="${RUNTIME_VENV}/supervisor/last-prepare.json"
export RUNTIME_LAUNCH_SEED="${RUNTIME_VENV}/runtime-launch-seed.json"

ssh "$SSH_TARGET" bash -s -- \
  "$CONTAINER" "$RECEIPT_HOST" "$RECEIPT_CONTAINER" \
  "$HOT_ENV" "$RESIDENT_ENV" "$SIMPLE_FIXER_DROPIN" \
  "$RUNTIME_SRC" "$RUNTIME_VENV" "$RUNTIME_PYTHON" "$FINAL_SHA" \
  "$AUTHORITATIVE_MARKER" "$AUTHORITATIVE_CHAIN_SPEC" \
  "$RELEASE_EVIDENCE_DOCUMENT" "$SUPERVISOR_RECEIPT" \
  "$RUNTIME_LAUNCH_SEED" <<'REMOTE'
set -euo pipefail
container="$1"; receipt_host="$2"; receipt_container="$3"
hot_env="$4"; resident_env="$5"; dropin="$6"
runtime_src="$7"; runtime_venv="$8"; runtime_python="$9"; final_sha="${10}"
marker="${11}"; chain_spec="${12}"; seed_doc="${13}"
supervisor_receipt="${14}"; launch_seed="${15}"

# Same inode as /workspace/.megaplan/runtime-cutover.lock inside the container.
# Reacquire it for the selector phase and revalidate the candidate bindings;
# no writer may run in the short interval between terminal rebind and here.
exec 9>/opt/megaplan-cloud/workspace/.megaplan/runtime-cutover.lock
flock -x 9

rollback_selectors() {
  docker exec "$container" bash -s -- \
    "$receipt_container" "$hot_env" "$resident_env" <<'INNER'
set -euo pipefail
receipt="$1"; hot="$2"; resident="$3"
for item in "$hot:.cloud-hot-env" "$resident:resident-runtime.env"; do
  target="${item%%:*}"; name="${item#*:}"
  if [[ -f "$receipt/private/${name}.before" ]]; then
    install -m 600 "$receipt/private/${name}.before" "${target}.rollback"
    mv -f "${target}.rollback" "$target"
  elif [[ -f "$receipt/private/${name}.before.absent" ]]; then
    rm -f "$target"
  fi
done
INNER
  if [[ -f "$receipt_host/private/simple-fixer-dropin.before" ]]; then
    install -D -m 644 \
      "$receipt_host/private/simple-fixer-dropin.before" "$dropin"
  elif [[ -f "$receipt_host/private/simple-fixer-dropin.before.absent" ]]; then
    rm -f "$dropin"
  fi
  systemctl daemon-reload
}
trap 'rollback_selectors' ERR

docker exec -i "$container" bash -s -- \
  "$hot_env" "$resident_env" "$runtime_src" "$runtime_venv" \
  "$runtime_python" "$final_sha" "$marker" "$chain_spec" "$seed_doc" \
  "$supervisor_receipt" "$launch_seed" <<'INNER'
set -euo pipefail
hot="$1"; resident="$2"; src="$3"; venv="$4"; runtime_python="$5"
sha="$6"; marker="$7"; chain_spec="$8"; seed_doc="$9"
supervisor_receipt="${10}"; launch_seed="${11}"
supervisor_root="$venv/supervisor"
supervisor_python="$supervisor_root/current/bin/python3"

for required in "$marker" "$chain_spec" "$seed_doc" "$supervisor_receipt"; do
  [[ -s "$required" ]] || {
    echo "required launch binding is missing: $required" >&2
    exit 1
  }
done

rewrite_env() {
  local source="$1"; target="$2"; shift 2
  python3 - "$source" "$target" "$@" <<'PY'
import os
import re
import sys
from pathlib import Path

source, target, *pairs = sys.argv[1:]
updates = dict(pair.split("=", 1) for pair in pairs)
lines = Path(source).read_text(encoding="utf-8").splitlines() if Path(source).exists() else []
seen = set()
out = []
pattern = re.compile(r"^(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)=")
for line in lines:
    match = pattern.match(line)
    if match and match.group(1) in updates:
        key = match.group(1)
        if key not in seen:
            out.append(f"{key}={updates[key]}")
            seen.add(key)
    else:
        out.append(line)
for key, value in updates.items():
    if key not in seen:
        out.append(f"{key}={value}")
path = Path(target)
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text("\n".join(out) + "\n", encoding="utf-8")
os.chmod(path, 0o600)
with path.open("rb") as handle:
    os.fsync(handle.fileno())
PY
}

hot_next="${hot}.next.$$"
rewrite_env "$hot" "$hot_next" \
  "MEGAPLAN_RUNTIME_SRC=$src" \
  "MEGAPLAN_LAUNCH_RUNTIME_SRC=$src" \
  "CLOUD_WATCHDOG_ARNOLD_SRC=$src" \
  "MEGAPLAN_AUDIT_ARNOLD_SRC=$src" \
  "MEGAPLAN_META_ARNOLD_SRC=$src" \
  "MEGAPLAN_SUPERVISOR_SOURCE=$src" \
  "MEGAPLAN_SUPERVISOR_RUNTIME_ROOT=$supervisor_root" \
  "MEGAPLAN_SUPERVISOR_PYTHON=$supervisor_python" \
  "MEGAPLAN_SUPERVISOR_RUNTIME_REQUIRED=1"
mv -f "$hot_next" "$hot"

PYTHONSAFEPATH=1 PYTHONPATH="$src" "$runtime_python" -P -m \
  arnold_pipelines.megaplan.cloud.runtime_attestation build \
  --expected-root "$src" \
  --expected-revision "$sha" \
  --supervisor-receipt "$supervisor_receipt" \
  --hot-env "$hot" \
  --marker "$marker" \
  --chain-spec "$chain_spec" \
  --seed-doc "$seed_doc" \
  --output "$launch_seed"
jq -e '.ready == true and (.errors | length == 0)' "$launch_seed" >/dev/null

resident_next="${resident}.next.$$"
rewrite_env "$resident" "$resident_next" \
  "MEGAPLAN_RUNTIME_SRC=$src" \
  "MEGAPLAN_RUNTIME_PYTHON=$runtime_python" \
  "MEGAPLAN_RUNTIME_LAUNCH_SEED=$launch_seed" \
  "MEGAPLAN_RUNTIME_ATTESTATION_REQUIRED=1"
mv -f "$resident_next" "$resident"
INNER

install -d -m 755 "$(dirname "$dropin")"
dropin_next="${dropin}.next.$$"
printf '[Service]\nEnvironment="MEGAPLAN_SIMPLE_FIXER_SOURCE_ROOT=%s"\n' \
  "$runtime_src" >"$dropin_next"
chmod 644 "$dropin_next"
sync "$dropin_next"
mv -f "$dropin_next" "$dropin"
systemctl daemon-reload

docker exec "$container" sha256sum \
  "$hot_env" "$resident_env" "$supervisor_receipt" "$launch_seed" \
  >"$receipt_host/public/selector-transaction.sha256"
sha256sum "$dropin" >>"$receipt_host/public/selector-transaction.sha256"
trap - ERR
REMOTE
```

## 6. Supported deploy and process restart

Only after the selector transaction and seed validation succeed, point the
provider's mutable image name at the immutable candidate image and use the
supported deployment command:

```bash
ssh "$SSH_TARGET" bash -s -- "$IMAGE_TAG" "$DEPLOY_IMAGE" <<'REMOTE'
set -euo pipefail
docker tag "$1" "$2"
REMOTE
python -m arnold_pipelines.megaplan cloud deploy --cloud-yaml "$CLOUD_CONFIG"
```

Then restart/reconcile only through the installed custody mechanisms:

```bash
ssh "$SSH_TARGET" bash -s -- "$CONTAINER" <<'REMOTE'
set -euo pipefail
container="$1"
systemctl daemon-reload
systemctl restart megaplan-watchdog-ensure.service
systemctl restart megaplan-resident-ensure.service
systemctl start megaplan-progress-audit.service
systemctl start megaplan-repair-trigger.service
docker inspect -f '{{.State.Running}} {{.Image}}' "$container"
REMOTE
```

Do not start a second resident, watchdog, repairer, or auditor by hand. The
entrypoint and systemd ensure units own singleton recovery.

## 7. Production acceptance: cycles 0, 5, and 10

Run this probe immediately, after five minutes, and after ten minutes. If the
expected heartbeat interval is longer, continue until three complete expected
cycles have occurred. The acceptance window is therefore at least ten
continuous minutes **and** three expected cycles, whichever is longer.

```bash
for minute in 0 5 10; do
  if (( minute > 0 )); then sleep 300; fi
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  python -m arnold_pipelines.megaplan cloud chains \
    --cloud-yaml "$CLOUD_CONFIG" --compact --since 24h \
    >"/tmp/cloud-chains-${RECEIPT_ID}-${minute}.json"
  scp "/tmp/cloud-chains-${RECEIPT_ID}-${minute}.json" \
    "${SSH_TARGET}:${RECEIPT_HOST}/public/cloud-chains.${minute}m.${stamp}.json"
  ssh "$SSH_TARGET" bash -s -- \
    "$CONTAINER" "$RUNTIME_SRC" "$RUNTIME_PYTHON" "$FINAL_SHA" "$RECEIPT_HOST" "$minute" <<'REMOTE'
set -euo pipefail
container="$1"
runtime_src="$2"
runtime_python="$3"
final_sha="$4"
receipt="$5"
minute="$6"
docker exec "$container" bash -s -- \
  "$runtime_src" "$runtime_python" "$final_sha" "$receipt" "$minute" <<'INNER'
set -euo pipefail
runtime_src="$1"
runtime_python="$2"
final_sha="$3"
receipt="$4"
minute="$5"
test "$(git -C "$runtime_src" rev-parse HEAD)" = "$final_sha"
test -z "$(git -C "$runtime_src" status --porcelain)"
tmux has-session -t heartbeat
tmux has-session -t watchdog
tmux has-session -t megaplan-resident-discord
PYTHONSAFEPATH=1 PYTHONPATH="$runtime_src" "$runtime_python" -P -m \
  arnold_pipelines.megaplan resident health \
  --mode production \
  --store-root "${MEGAPLAN_RESIDENT_STORE_ROOT:-/workspace/arnold/.megaplan/resident}"
{
  tmux list-sessions -F '#{session_name} #{session_created} #{session_attached}'
  ps -eo pid,ppid,lstart,args --sort=pid
} >"$receipt/private/process-probe.${minute}m.txt"
INNER
systemctl is-active megaplan-watchdog-ensure.timer
systemctl is-active megaplan-resident-ensure.timer
systemctl is-active megaplan-progress-audit.timer
REMOTE
done
```

At every cycle verify:

- the resident, watchdog, progress auditor, three-hour fixer/repair trigger, and
  their child processes import only from `RUNTIME_SRC`;
- their interpreters resolve to `RUNTIME_PYTHON` or the pinned prepared
  supervisor interpreter;
- their process launch attestations validate against the same launch seed;
- no duplicate owner, dead worker PID, stale active step, current repairable
  failure, repeated attempt without new evidence, or selector drift appears;
- heartbeat/report timestamps advance between cycles.

Send an actual `/whats-cooking` command through the approved Discord client
after cycle 0 and again after cycle 10. Record the request and response UTC
timestamps, Discord message IDs, bot role, and a SHA-256 of the redacted
response. The response must be a fresh successful outcome produced by the
production resident; seeing the resident process or a cached status file is not
an outcome probe. Do not put the Discord token or raw secret configuration in a
receipt.

The exact terminal projection gate is:

| Subject | Required authoritative result |
| --- | --- |
| Custody | terminal `complete`; no newer non-terminal state; no live runner; no current repairable failure; final accepted code reachable from `FINAL_SHA` |
| Superpom | its designated production session/service reports its accepted terminal/healthy outcome; no missing Discord credential classification; runtime/process attestation equals `FINAL_SHA` |
| Withings | its designated recovery session reports accepted terminal completion; no current recovery attempt, stale worker, or repairable failure; runtime/process attestation equals `FINAL_SHA` |

Record the exact session/service identifiers in the receipt before evaluation.
Do not accept name similarity, percentage progress, `runner running`,
`finalized`, `alive_but_failed`, an old watchdog `complete`, or a manually
created `done` label as a substitute for these results.

### 7.1 Deployed workflow canary

The old credential-gated `test_live_smoke.py` placeholders were not live
evidence: they skipped when credentials were absent and otherwise asserted
only that a temporary directory existed. They are retired. A release now
requires a separately admitted job against the exact deployed target,
deployment ID, `FINAL_SHA`, and strict runtime-identity receipt.

Create one private root named
`/workspace/.megaplan/m11-canaries/m11-workflow-${RECEIPT_ID}`. Copy the strict
runtime-identity receipt produced for the deployed process into that root.
Before launching any scenario, run:

```text
RUNTIME_PYTHON -P -m arnold_pipelines.megaplan.cloud.m11_workflow_canary admit
  --root WORKFLOW_CANARY_ROOT
  --config WORKFLOW_CANARY_ROOT/admission-config.json
```

The config supplies `job_id`, `deployment_target`, `deployment_id`,
`expected_revision` (the full `FINAL_SHA`), and `runtime_receipt_path`.
The strict runtime receipt's target-marker component must
contain exactly the admitted `deployment_target` and `deployment_id`; an older
receipt without those fields is unsupported and cannot be admitted. The
runtime identity is derived from the receipt digest, never supplied separately
by the caller.

Run the producer against the immutable deployed checkout. The deterministic
decision adapter replaces model inference only; every custody, WBC, boundary,
suspension, tiebreaker, suite and acceptance write comes from the canonical
production handler or acceptance entrypoint:

```text
RUNTIME_PYTHON -P -m arnold_pipelines.megaplan.cloud.m11_workflow_canary run
  --root WORKFLOW_CANARY_ROOT
  --project-dir RUNTIME_SRC
```

The producer checkpoints the current SQLite backend, removes only successfully
checkpointed WAL bookkeeping sidecars, and writes an exact append-only frozen
manifest. It cannot write `verdict.json`. Run the separate verifier:

```text
RUNTIME_PYTHON -P -m arnold_pipelines.megaplan.cloud.m11_workflow_canary verify
  --root WORKFLOW_CANARY_ROOT
```

Before a complete frozen run, `verify` exits nonzero and writes no verdict.
Afterward it opens SQLite read-only/immutable and independently re-derives the
exact inventory, producer provenance, lifecycle order, boundary histories,
committed acceptance snapshots/transactions, source/runtime joins, and:

1. a genuinely fresh plan through accepted terminal completion;
2. a durable suspension followed by a distinct resume and accepted terminal
   completion;
3. at least three observed gate iterations before accepted terminal
   completion;
4. the tiebreaker path, including its decision, before accepted terminal
   completion.

Any changed, missing, or extra frozen artifact; reused attempt identity;
malformed event order; missing canonical producer provenance; stale
source/runtime binding; uncommitted acceptance; or structured-output schema
parity error fails closed. Arbitrary observations, labels, booleans,
timestamps, and recomputed self-hashes cannot become release proof.
Conformance accepts `deployed_proof_status: verified` only by rerunning this
independent derivation against the stored `workflow-canary/verdict.json`.

## 8. Final receipts

After the last successful cycle, hash every public and private artifact, then
write a redacted manifest containing the final commit, annotated tag, candidate
image ID, old image ID, selector-file hashes, supervisor receipt hash, launch
seed hash, projection hashes, probe timestamps, Discord outcome hashes, and the
three cycle verdicts. It must also contain the deployed workflow-canary
admission digest, semantic-verdict digest, and an explicit true gate
for each of the four required workflow scenarios.

```bash
ssh "$SSH_TARGET" bash -s -- "$RECEIPT_HOST" <<'REMOTE'
set -euo pipefail
receipt="$1"
(
  cd "$receipt"
  find private public -type f ! -name 'final.sha256' -print0 |
    sort -z |
    xargs -0 sha256sum >public/final.sha256
  sha256sum public/final.sha256 >public/final.sha256.sha256
)
chmod -R go-rwx "$receipt"
REMOTE
```

A release is `done` only when the redacted manifest says every gate is true,
including all four deployed workflow-canary gates, and its
`final.sha256.sha256` is durable. A label may then project that fact; it must
not create it.

## 9. Rollback

Rollback is one transaction. Stop the batch, reacquire the cutover lock, restore
the checkpointed `.cloud-hot-env`, `resident-runtime.env`, systemd drop-in, and
old image selector, then use the supported deploy path. Never restore only one
selector or reuse a contaminated mutable checkout.

```bash
ssh "$SSH_TARGET" bash -s -- \
  "$CONTAINER" "$DEPLOY_IMAGE" "$RECEIPT_HOST" "$RECEIPT_CONTAINER" "$HOT_ENV" "$RESIDENT_ENV" \
  "$SIMPLE_FIXER_DROPIN" <<'REMOTE'
set -euo pipefail
container="$1"
deploy_image="$2"
receipt="$3"
receipt_container="$4"
hot_env="$5"
resident_env="$6"
dropin="$7"

# Same host/container mounted release lock used by the forward cutover.
exec 9>/opt/megaplan-cloud/workspace/.megaplan/runtime-cutover.lock
flock -x 9
old_image="$(jq -r '.[0].Image' "$receipt/private/container-inspect.before.json")"

restore_inside_container() {
  docker exec -i "$container" bash -s -- "$@" <<'INNER'
set -euo pipefail
receipt="$1"
hot_env="$2"
resident_env="$3"
for item in "$hot_env:.cloud-hot-env" "$resident_env:resident-runtime.env"; do
  target="${item%%:*}"
  name="${item#*:}"
  if [[ -f "$receipt/private/${name}.before" ]]; then
    tmp="${target}.rollback.$$"
    install -m 600 "$receipt/private/${name}.before" "$tmp"
    sync "$tmp"
    mv -f "$tmp" "$target"
  elif [[ -f "$receipt/private/${name}.before.absent" ]]; then
    rm -f "$target"
  else
    echo "missing rollback checkpoint for $target" >&2
    exit 1
  fi
done
INNER
}
restore_inside_container "$receipt_container" "$hot_env" "$resident_env"

if [[ -f "$receipt/private/simple-fixer-dropin.before" ]]; then
  install -D -m 644 "$receipt/private/simple-fixer-dropin.before" "$dropin"
elif [[ -f "$receipt/private/simple-fixer-dropin.before.absent" ]]; then
  rm -f "$dropin"
else
  echo "missing systemd drop-in rollback checkpoint" >&2
  exit 1
fi
docker tag "$old_image" "$deploy_image"
systemctl daemon-reload
REMOTE

python -m arnold_pipelines.megaplan cloud deploy --cloud-yaml "$CLOUD_CONFIG"
```

Re-run the same resident, watchdog, three-hour fixer, `/whats-cooking`,
Custody, Superpom, Withings, provenance, and three-cycle probes against the old
immutable identity. Rollback is not successful until all of them pass. Keep the
failed candidate and receipts for diagnosis; do not rewrite its failed history.

## 10. Post-cutover retention

Keep both immutable runtimes, both image IDs, all selector checkpoints, the
launch seed, and receipt hashes for at least 24 hours after the final successful
cycle and through one subsequent scheduled watchdog/auditor cycle. Only then
may the normal loose-work cleanup inventory classify an old runtime or
historical marker as deletion-ready, and deletion still requires explicit
per-item approval.
