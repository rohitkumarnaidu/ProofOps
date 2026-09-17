# M00–M06 Safety Crossing Plan (DRAFT — no implementation until human approval)

Authoritative spec: `docs/PS03_FINAL_SPEC_V2.md`. Naming truth:
`docs/MODULE_REGISTRY.md`. Operating constitution: `AGENTS.md`
(§14 build-first + scoring rubric + gates, §15 waves). Method: zero-trust
audit → verify → plan → implement → re-verify → rescore, per unit, repeat
until gates pass; then human verification + approval.

Status: DRAFT. Implementing anything under this plan before a human APPROVE
at the gate (§10) violates the plan itself. Precondition (§5): this campaign
may start only on explicit human declaration of FINAL TRUST PHASE for the
M00–M06 scope (build-first forbids perfecting early modules otherwise).

## 1. Objective and gates (project gates, quoted — never redefined here)

- Overall ≥ 90 every unit (90 passes; gates use ≥, per registry + AGENTS).
- Safety ≥ 95 where REQUIRED (all of M06).
- Grounding ≥ 95 where REQUIRED (all of M05).
- Universal conditions per unit: zero P0 · no unresolved safety-critical
  P1 · all required tests green · evidence reproducible · human approval ·
  no hidden regressions.
- Scoring uses the frozen 10-dimension rubric (Functional /20,
  Verification /15, Security /15, Reliability /10, Specification /10,
  Integration /10, Performance /5, Observability /5, Maintainability /5,
  Hackathon Value /5). No custom rubric, no caps, no averaged-away children:
  scores below are per-unit tables only (no grand or phase averages —
  averaging hides children).
- Zero P0 globally or everything stops (§3 STOP).

## 2. Starting scores (recorded verdicts under test — re-derive, don't trust)

Why re-proof is required (verified in git, not asserted): M00–M04 verdict
rows predate the M12–M19 merges sitting in `master` today (e.g. M19 merge
`9357678` landed after those rows; M05/M06 verdicts postdate the merges).
Code the verdicts depend on (contracts, normalizer, correlator, compose,
frontend, shared tests) has moved since. Prior numbers:

- M00: .1 93 · .2 92 · .3 92 · .4 92 · .5 91 · .6 90 · .7 92
- M01: .1 92 · .2 95 · .3 95 · .4 91 · .5 92 · .6 91 · .7 92 · .8 91 · .9 91 · .10 91 · .11 91 · .12 91 · .13 91 · .14 91 · .15 91
- M02: .1 91 · .2 91 · .3 91 · .4 92 · .5 91 · .6 91 · .7 91 · .8 91 · .9 91 · .10 92
- M03: .1 92 · .2 92 · .3 92 · .4 92 · .5 91 · .6 92
- M04: .1 91 · .2 92 · .3 92 · .4 92 · .5 91 · .6 91
- M05: .1 91 · .2 91 · .3 91 · .4 91 · .5 92 · .6 92
- M06: .1 91 · .2 91 · .3 91 · .4 92 · .5 92 · .6 92 · .7 91 · .8 91 · .9 91 · .10 91

No unit is assumed below-bar on entry — not even M00.6 (90 passes the ≥90
gate; it is re-audited like everything else, lifted only on evidence).

## 3. The loop (per unit, in wave order M00 → M06)

```text
BASELINE (status; branch; HEAD; log -20 — required every unit)
  → AUDIT (from zero, prior scores inadmissible; spec-reconcile the unit
     against its spec section refs; record deviations in DECISIONS.md)
  → VERIFY (run §6 gates on the unit slice + adversarial probes)
  → PLAN (fix list with file:line, or "holds" with proof)
  → IMPLEMENT (owner files only; frozen surfaces need freeze process;
     read-only re-proof preferred — touch code only on evidence)
  → RE-VERIFY (unit slice + full host-safe suite + gates + targeted probes)
  → RESCORE (10-dimension rubric + universal conditions, from zero)
  → HOLD (gates pass) or REPEAT; any P0/P1 resets to AUDIT
```

Probes that prove a scored property MUST be committed as tests (temp-only
probe transcripts never support a score). One unit at a time for trust
decisions; parallel probes allowed. Per MODULE (not per campaign): full
regression + secret-scan + freeze-check, then exactly one merge with
regression between merges; registry flips ride the module merge. No merge,
push, amend, registry flip, or new module without explicit human approval
(one approval covers exactly what it names). Mid-campaign `master` moves:
rebase-check + full regression before continuing (never merge stale).

STOP conditions (progress BLOCKED, surface immediately): unsafe execution,
policy bypass, secret exposure/leak, ground-truth leak to model paths,
approval replay/tamper accepted, destructive action escaping the boundary,
falsified metric, broken authorization, critical regression, rewritten
trusted history, unapproved merge/push.

## 4. Per-module work lists (starting points, not conclusions)

- **M00**: re-prove at current tree (M19 rebuilt frontend/compose/ui).
  Residuals: M00.3 caps P2 (daemon test when available); TESTING-number
  freshness (manual process); sensitive IDs in snapshots (classified).
- **M01**: re-prove single-validation path (rivalry test), all fast-paths
  identical, no prod `schemas` imports, bounds sample. Residual: helper
  duplication (maintainability only — no churn on green gates).
- **M02**: re-prove determinism incl. cross-process sample, seal +
  per-section tamper, GT strip, payload rules. Residual: ~11-min metric
  series (documented shape boundary).
- **M03**: re-prove env/ts fail-closed matrix, inert DATA, None-sweep,
  joint severity pair, full-chain matrix. Residuals: open kind/reason/
  level sets, free-form versions (documented vendor-drift boundaries).
- **M04**: re-prove pairwise split, cpu-gate, per-service attribution,
  storm cap + perf, FP table, e2e matrix. Residual: triage proposal
  divergences are M13-owned (other lane's file — never touch; verify M04
  authority holds).
- **M05**: re-prove grounded coverage incl. empty-deny, computed trust,
  pack determinism + verifier, capture edges. Grounding ≥95 re-measured.
- **M06**: re-prove regex/nested/SQL gates, None-explicit, rule
  attribution per DENY rule, GREEN-mut blast, env-context, seals +
  live `pip-audit`. Safety ≥95 re-measured. Adjudicated non-issues
  (TTL-on-DENY, GREEN-reads blast, severity inputs) are re-verified, not
  re-litigated, unless new evidence appears.

## 5. Dependencies, frozen surfaces, preconditions

- Wave order M00 → M01 → M02 → M03 → M04 → M05 → M06 (data flows forward;
  M06 last as the boundary everything leans on).
- `backend/app/contracts/` frozen (M01.1 surface): read-only unless the
  freeze process runs (change request + impact + human review + bump).
- `backend/app/config.py`, logging/health enums: M00-frozen, same rule.
- Other lanes' files (agents/, routers/, eval…): read-only. A probe
  failure implicating them is reported for reconciliation, never fixed
  unilaterally.
- `tests/test_docs.py` pins the doc set: this file is registered in its
  allowlist (explicit entry + justification); no other root/doc additions
  without the same treatment.
- Shared lane discipline: feature branches from current trusted master,
  worktrees under the temp dir, PARALLEL BUILD / SERIAL TRUST, one merge
  at a time with regression between, never touch another lane's files,
  never rewrite trusted history.
- PRECONDITION: campaign starts only on human FINAL TRUST declaration
  for M00–M06 (build-first forbids this work otherwise; see gate §10).

## 6. Verification commands (canonical gates + campaign pins)

```powershell
python -m pytest tests/ -q -p no:warnings --ignore=tests/test_compose_runtime.py --ignore=tests/test_config_runtime.py --ignore=tests/test_health_runtime.py --ignore=tests/test_logging_runtime.py
python -m ruff check backend tests scripts telemetry   # telemetry scope widened vs AGENTS snippet; pinned in test_ci.py
python -m mypy backend/app
python scripts/secret_scan.py
python scripts/freeze.py --check
```

`freeze.py --audit` runs in CI and locally only where `pip-audit` is
installed (else `scripts/ci.sh`, which encodes the honest-SKIP rule).
Daemon-available additions: the 4 `*_runtime.py` files, `docker compose
ps` (3× healthy, left UP+healthy). CI (`ci` workflow, 5 jobs incl.
lockfile+audit) must be green on every landing push; a red push is worked
like any P0 (diagnose from the failed log, never memory → fix-forward on
branch → re-verify → push → watch green).

## 7. Evidence standard (per unit, no exceptions)

Implementation path · test path · sample output · failure case · security
behavior where applicable · commit · known limitation. Numbers link to a
run, a committed test assertion, or a pasted probe transcript that a
committed test now covers. A skipped check is reported SKIP, never PASS.

## 8. Scoring (frozen rubric, from zero every round)

AGENTS §14.3 ten dimensions + universal conditions (§1). No custom
deduction schemes, no score caps, no averaging across units. A rescore
that moves a prior APPROVED number down is a P1-class event: fix or
escalate with evidence; history keeps the old row, the new verdict
supersedes with rationale.

## 9. Failure modes registry

| # | Failure | Response |
|---|---|---|
| F1 | Unit will not cross gates after 2 fix rounds | STOP unit, escalate to human with evidence; never lower the gate, never polish around it |
| F2 | CI red on push | Diagnose from failed log (not memory) → fix-forward on branch → re-verify → push → watch green |
| F3 | Lane collision (shared master moved / foreign worktree holds a ref) | Never force; rebase-check + full regression; queue behind integration lane; reconcile, don't overwrite |
| F4 | Daemon-dependent proof with daemon down | BLOCKS the requiring item only (not the campaign): record P2 with owner + TTL; DONE needs the proof or an explicit human waiver naming owner + TTL |
| F5 | Re-audit drops a prior score below gate | Treat as P1: fix or escalate; prior APPROVED stays in history, new verdict supersedes with rationale |
| F6 | Tool lies (misreported edit/test result) | Diff-verify every edit; one edit per file per batch; read real output, never memory |
| F7 | Mid-campaign master moves under the branch | Rebase-check + full regression before continuing; never merge stale |

## 10. Human gate (real state transition, never inferred)

Reviews run in batches of ≤5 units, each with pasted evidence (not
summaries). Per unit: code inspected · tests reproduced · negative
reproduced · security reproduced · output verified · metrics verified ·
spec matched · no unexpected files · no secrets · no bypass. Verdict per
unit: APPROVE / REJECT / FIX REQUIRED with file:line. If a later unit's
fix touches shared files, affected earlier units are re-verified and
re-stated (regression output attached). Registry flips and pushes only on
explicit approval naming exactly what it covers. "Project complete" and
"submission ready" stay banned until their §14.8 gates pass.

Gate questions for THIS plan: (Q1) approve the plan as amended +
declare FINAL TRUST PHASE for the M00–M06 scope? (Q2) approve
push-after-local-green per module (push → CI-watch → fix-forward on red),
or require a separate push approval each time?

## 11. DONE definition

All 60 units at/above gates at one master commit + full regression green
+ daemon proofs from the pre-enumerated set below (or human waivers with
owner + TTL) + CI green on the landing push(es) + registry per-row truth
+ this plan marked SUPERSEDED (not deleted) with a pointer to the closing
report. Daemon-required subset (complete on entry, extend only with
human approval): M00.3 auto-resurrection re-confirm on Linux dockerd;
`test_*_runtime.py` ×4 green; image build for any Dockerfile change.
Then — and only then — the next wave.

## 12. Decision Audit Trail

| # | Phase | Decision | Classification | Principle | Rationale | Rejected |
|---|-------|----------|-----------|-----------|----------|---|
| D1 | setup | Proceed without gstack-skill-start preamble (degraded mode) | Mechanical | Pragmatic | Bash-script infra on a PowerShell host with no verified runner; skill's own degraded rule says proceed | Blocking the task on infra |
| D2 | setup | No UI scope, no DX scope for this plan | Mechanical | Pragmatic | Process plan, not product: no views (UI), not a developer tool (DX); keyword hits would be false positives | Running design/devex reviews on process prose |
| D3 | setup | Single primary + one Task-subagent second voice; no codex | Mechanical | Pragmatic | Codex CLI absent; jq absent; subagent is the only available second model voice, honestly labeled | Faking dual voices |
| D4 | review | Accept second voice's 5 premise corrections + 7 holes + scope + risks | Taste | Completeness | Each verified against registry/AGENTS/git (details in review message); plan rewritten, not patched | Patching the flawed draft (would leave structure incoherent) |
| D5 | review | FINAL TRUST declaration as plan precondition + gate Q1 | Taste | Completeness | Build-first forbids this campaign otherwise; self-authorizing it would violate the constitution | Starting on agent authority |
| D6 | review | Restore frozen 10-dimension rubric + universal conditions | Mechanical | DRY | Rubric already frozen in AGENTS; custom scheme was a silent gate change | Keeping the invented scheme |
| D7 | review | Drop grand/phase averages; per-unit tables only | Mechanical | Completeness | No-average-hiding rule; nothing hidden behind a mean | Informational averages |
| D8 | review | Probes must be committed as tests to support scores | Taste | Completeness | Temp-only evidence is irreproducible by definition | Score-on-transcript |
| D9 | review | Per-module merges + registry-per-module + rebase discipline | Mechanical | DRY | Existing serial-trust rules already require it; plan had deferred integration wrongly | End-of-campaign big-bang merge |
| D10 | review | Daemon waiver = human decision with owner+TTL; subset pre-enumerated | Taste | Explicit | Resolves F4/DONE contradiction without weakening DONE | Agent-side silent deferral |
| D11 | review | No forced M00.6 lift; re-audit decides on evidence | Mechanical | Pragmatic | ≥90 passes; churning a passing unit violates breadth rules | 91+ mandate |
| D12 | gate | Code only via dedicated file tools (Read/Write/Edit); never shell heredocs, python -c source surgery, or shell string replacement for code — human standing rule | Taste | Explicit | Shell-written code caused real corruption before (mojibake); file tools are diff-verifiable | Shell code-writing for speed |
| D13 | gate | Agent may invoke any available skill where the task matches its triggers; skill use pre-approved, reported in review messages | Mechanical | Pragmatic | Per-skill permission round-trips would stall the loop; misuse is visible in review | Asking first every time |
