# ProofOps Demo Foundation (M00.6 foundation; full demo owned by M22)

Authoritative spec: `docs/PS03_FINAL_SPEC_V2.md` §55 (5:00 demo), §56 (demo
fallback), §57 (judge traceability), §05 (non-goals).

Status: no demo script exists today. There is no `scripts/demo.sh`, no
`--check` gate, no rehearsal log, and no evidence package in this tree — this
doc states the spec target and the reproducible surface that exists now.
Nothing here claims production readiness or certification.

## Reproducible today (M00.1–M00.4, no script)

```bash
cp .env.example .env   # once; fill secrets (never commit .env)
docker compose up -d                  # ordered, health-gated start
docker compose ps                     # expect 3x healthy
curl http://localhost:8000/healthz    # {"status":"ok",...}
curl http://localhost:8000/readyz     # {"status":"ready",...} when db serves
```

Seed trio `SEED_SCENARIO=bad-deploy` / `SEED_VARIANT=NORMAL` / `SEED_SEED=42`
is reserved via config (M00.2) for the future seeded flow; no seeding endpoint
exists today (`POST /demo/seed` is spec §40, PLANNED with the API modules).

## Spec target (quoted direction, not implemented)

Seed `bad-deploy/NORMAL` → N alerts collapse to 1 P1 → evidence chips →
hypotheses with ruled-out plus runbook pin → live RED block of a destructive
action with zero-diff proof → approved YELLOW rollback → BEFORE/AFTER state
diff → VERIFIED badge → gated RCA → six-gate scorecard → Lyzr-vs-custom table
→ "Agent reasons. Control plane decides." Full beat map: spec §55.

## Mode vocabulary (spec-defined, not implemented)

LIVE (full) / REPLAY (recorded agent trace with live policy/sandbox/verify on
a cached Action) / MOCK (executor forced mock) / OFFLINE (short video last
resort). Binding honesty rule, spec §56: never present REPLAY as LIVE; the
active mode is always announced on screen.

## PLANNED (M22 demo hardening, not implemented)

- `scripts/demo.sh --check` validating seeds, policies, runbooks, and one
  end-to-end pass in under 5 minutes.
- REPLAY pack, fallback triggers, 3× rehearsal logs, final evidence package
  (M22.3–M22.7 in `docs/MODULE_REGISTRY.md`).
- Eval scorecard feed into the 4:00 board moment (M16); the five UI views
  (M19); seeded scenario reseed support (M22.1).

## Non-goals (spec §05, restated so no reader expects them)

No real paging, no prod credentials, no autonomous prod-DB writes, no live
vendor integrations. Simulated telemetry/execution; HMAC demo roles (no SSO).

