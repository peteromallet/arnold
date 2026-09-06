# Megaplan Cloud Configs

Cloud runner configs are per-initiative local files named:

```bash
.megaplan/initiatives/<initiative>/cloud.yaml
```

These files contain machine-specific runner details and are intentionally ignored by git. Keep durable chain inputs in the initiative directory, and use the matching local `cloud.yaml` only to launch, observe, or relaunch that initiative.

Current Arnold runner config on the Hetzner agentbox:

| Initiative | Config | Status on 2026-07-04 |
| --- | --- | --- |
| `sequential-model-fallbacks` | `.megaplan/initiatives/sequential-model-fallbacks/cloud.yaml` | active / should run |

For shared runner status, use the active config:

```bash
python -m arnold_pipelines.megaplan cloud status --all --compact --since 12h \
  --cloud-yaml .megaplan/initiatives/sequential-model-fallbacks/cloud.yaml
```

Do not add root-level `cloud.<name>.yaml` files. They duplicate initiative state and make it unclear which config owns a chain.

Completed sessions are still visible through the shared runner marker directory via `cloud status --all`; they do not need local launch configs unless they are intentionally being relaunched. Use `--compact --since <duration>` for recent-activity checks, because it filters on real plan `state.json` timestamps instead of watchdog report mtimes.
