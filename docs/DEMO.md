# ProofOps Demo Foundation (M00.6 foundation; full demo owned by M22)

Authoritative spec: `docs/PS03_FINAL_SPEC_V2.md` §55 (5:00 demo), §56 (demo
fallback), §57 (judge traceability), §05 (non-goals), §40 (`POST /demo/seed`).

Owning module: M22 for the demo itself; the M00.1–M00.4 surface below is owned by
M00. Operator instructions live in [`QUICKSTART.md`](QUICKSTART.md).

Status: the mode vocabulary and the views **are** implemented; the demo *script*
is not. An earlier revision of this doc described all four operating modes as
"spec-defined, not implemented" and referred to "the five UI views". Both were
stale: the mode badge ships in five of six views, and there are six views. The
corrections are noted inline so the change is auditable.

Nothing here claims production readiness or certification.

## What runs today, verified

Six views at <http://localhost:5173>: Command Center, Incident Detail, Safety
Gate, Execution, RCA and Eval, Agents. Five of the six carry a mode badge.

## Mode vocabulary (spec-defined, and now implemented)

`ModeBadge` (`frontend/src/components/badges.tsx:22`) renders the operating
mode. Its value comes from `useMode` → `GET /meta`, so it is derived from server
state rather than hardcoded, and `PROBING` is rendered while the probe is in
flight so a slow load never reads as an outage.

| Badge | Source condition | Meaning |
|-------|------------------|---------|
| `LIVE` | `executor_tier === "docker"` | Actions execute against a real executor, not the in-memory sandbox |
| `MOCK` | `executor_tier === "mock"` | Actions execute against the deterministic in-memory sandbox |
| `REPLAY` | `executor_tier === "replay"` | Recorded agent trace replayed against live policy and sandbox |
| `OFFLINE` | any other tier, or the probe threw | Fail-closed. No execution is claimed |
| `PROBING` | probe in flight | Unknown, not yet claimed |

Binding honesty rule, spec §56: never present REPLAY as LIVE; the active mode is
always on screen. `OFFLINE` is the fail-closed default, which is why a failed
probe cannot be mistaken for a working system.

A second, independent tier readout exists at `GET /meta/engines` and is
documented in [`API.md`](API.md). It reports four engines (database,
Kubernetes, Prometheus, LLM provider) rather than one executor mode. Do not
conflate the two: `prometheus.tier` describes the verifier, not the executor.

**Known gap.** `AgentsView` is the one view without a mode badge, and the one
view not covered by the rendered browser check. Owning module: M19, PLANNED.

## Reproducible today (M00.1–M00.4, no demo script)

```bash
cp .env.example .env    # once; set POSTGRES_PASSWORD and a real APPROVAL_SECRET
docker compose up -d    # ordered, health-gated start
docker compose ps       # expect 3x healthy
curl http://localhost:8000/healthz
curl http://localhost:8000/readyz
curl http://localhost:8000/meta/engines
```

`GET /meta/engines` is the single most useful pre-demo check, because it tells
you honestly whether you are on a real tier or a mock one before you start. Full
instructions, including troubleshooting, are in [`QUICKSTART.md`](QUICKSTART.md).

The seed trio `SEED_SCENARIO=bad-deploy` / `SEED_VARIANT=NORMAL` / `SEED_SEED=42`
is reserved via config (M00.2).

## How to get an incident today (no seed endpoint)

There is **no `POST /demo/seed`** in this tree. It is spec §40 surface, still
PLANNED. Two real paths exist instead:

1. **The orchestrator seeds itself.** The worker generates incidents on an
   interval, so a fresh stack usually shows one in the Command Center within
   about 45 seconds. `GET /orchestrator` reports whether the counter is moving.
2. **Submit explicitly.** `POST /alerts/ingest` with a scenario and
   `process: true` hands the bundle to the worker, which runs triage, evidence,
   diagnosis, planning, validation, and policy, then parks a reversible action at
   `AWAITING_APPROVAL`. The request body is in [`QUICKSTART.md`](QUICKSTART.md).

The worker can never approve anything. A human does that in the Safety Gate.

## The 5:00 spec target (quoted direction, not implemented as a script)

Seed `bad-deploy/NORMAL` → N alerts collapse to 1 P1 → evidence chips →
hypotheses with ruled-out plus runbook pin → live RED block of a destructive
action with zero-diff proof → approved YELLOW rollback → BEFORE/AFTER state
diff → VERIFIED badge → gated RCA → six-gate scorecard → Lyzr-vs-custom table →
"Agent reasons. Control plane decides."

Full beat map: spec §55. Every element except the scripted ordering is present
in the product today; what is missing is the deterministic walkthrough and its
timing.

## Optional live tier for the demo

`bash scripts/live_tier.sh up` provisions a real kind cluster, an instrumented
demo workload, kube-state-metrics, and a real Prometheus, writing credentials to
`var/live/`. Set `LIVE_CLUSTER=true` to execute and verify against it. With that
flag on, a live failure is reported as a live failure and is **not** downgraded
to the mock, because a success from a sandbox that never touched the cluster
would be an audit entry for a remediation that did not happen.

Details, including the teardown caveat about the external `kind` network, are in
[`QUICKSTART.md`](QUICKSTART.md). The credential-handling argument for the
read-only mount is in [`SECURITY.md`](SECURITY.md).

## PLANNED (M22 demo hardening, not implemented)

- `scripts/demo.sh --check` validating seeds, policies, runbooks, and one
  end-to-end pass in under 5 minutes. Neither the script nor the `--check` gate
  exists; `scripts/` has no `demo.sh`, `seed.sh`, or `eval.sh`.
- `POST /demo/seed`, so a demo does not depend on the generator interval.
- REPLAY pack, fallback triggers, 3× rehearsal logs, and a final evidence
  package (M22.3–M22.7 in `docs/MODULE_REGISTRY.md`).
- An RCA document renderer. The RCA view renders the audit chain and the
  six-gate scorecard, and says so on screen; it does not render an RCA document.
- Eval scorecard feed into the 4:00 board moment (M16).

## Honest demo risks

Things that will go wrong in front of a judge, named in advance:

- **Mode badge reads `MOCK` on a stock start.** That is correct, not a failure.
  Announce it rather than hiding it; a demo that claims LIVE while running a
  dict is the failure this project argues against.
- **The live tier takes minutes to provision and needs `kind` on `PATH`.** If
  `kind` is missing, `live_tier.sh` refuses with a clear message. Have the mock
  path ready.
- **Prometheus reports `standby-sandbox` unless the live tier is up**, so the SLO
  signal is unmeasured. The verifier refuses to assert `RESOLVED` from
  unmeasured state rather than guessing, which means a live demo without
  Prometheus escalates instead of claiming success. Say that out loud; it is the
  point.
- **No committed baseline JSONL run.** Every C1–C6 number available today is a
  mock-harness pass rate. See [`EVALUATION.md`](EVALUATION.md).
- **Rollback and RESOLVED on the live tier are not yet demonstrated.** The
  rollback target and the instrumented workload are separate objects in the
  current provisioning, so a live run is expected to escalate. Do not narrate
  RESOLVED as the expected live outcome.

## Non-goals (spec §05, restated so no reader expects them)

No real paging, no prod credentials, no autonomous prod-DB writes, no live vendor
integrations. Simulated telemetry and execution by default; HMAC demo roles, no
SSO. The live tier is a local kind cluster, not a cloud account.
