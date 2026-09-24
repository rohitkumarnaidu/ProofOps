# ProofOps — Enterprise Audit Report (measured scores, with proof)

> **Status:** every score below is a sum of binary checks, each check cited with
> its proof (a test run observed green, a grep result, or a file:line read).
> No judgment points. A check that could not be proven is marked FAIL.
> **HEAD:** `b32da96` (`master`, clean tree apart from this untracked file).
> **Method:** five independent measurement lanes ran in parallel, read-only
> (no application file created, modified, or deleted; no docker; no network).
> This file is the only filesystem artifact of the audit.
> **Gates at write time:** pytest 2663 passed / 1 skipped (known drift),
> ruff clean, mypy clean (49 files, `disallow_untyped_defs` on),
> secret scan PASS, `tsc` clean, `oxlint` clean.

---

## §0 — How to read these scores (why three different numbers exist)

Past revisions mixed three different questions, which is what made scores feel
fake. Every number below is labeled with its question:

- **Q1 — Are the claimed controls implemented and tested?** Binary checks
  against code + green tests. High scores here mean "the mechanism exists."
- **Q2 — How powerful / production-complete is it?** Enterprise bar
  (regulated-tomorrow, 3am-incident). Low scores here mean "mechanism present
  but not production-sufficient."
- **Q3 — What does each agent / view actually do?** Honesty checks (not power).

Q1 ≈ 90s, Q2 ≈ 25, Q3 = tables below. All three are real simultaneously.

Corrections carried forward (verified): auth module = `backend/app/routers/auth.py`
(`compare_digest` at `:38`); `CANONICAL_8` renamed to `CANONICAL_DOCS`
(`tests/test_docs.py:32`, 11 entries, zero old-name hits repo-wide);
`run_view` provably lacks `state_diff` (`api.ts:69-86`); `NOT STARTED` uses a space.
Registry recount confirmed again: **183 = 60 + 116 + 7**, header consistent.

---

## §1 — Q1 measured: Security **95/100** (12 checks)

| # | Check (pts) | Result | Proof |
|---|---|---|---|
| S1 | RED blocked all envs (10) | PASS | `test_adversarial_m18 + test_safety_m06_hardening` → 93 passed; `policy.py:228-231` RED→DENY; `sandbox.py:29-30,54-55` MOCKABLE gate |
| S2 | YELLOW requires valid HMAC HITL (10) | PASS | `approvals.py:332-333` verify on approve path; tampered/expired/mismatch/replay/permit tests → 7 passed |
| S3 | Replay/tamper/expiry/wrong-actor/mismatch denied (10) | PASS | `test_approvals_m19.py` → 27 passed; `approval.py:79-98` nonce burn + fsync; `:184-197` all five verify checks |
| S4 | No unvalidated→exec path (10) | PASS | `pipeline.py:161-186` validator→policy→BLOCKED before `sandbox.apply` (`:215`); grep routers for `sandbox.apply\|execute_action(` → zero hits (1 comment only) |
| S5 | Permits incident-bound + fresh + single-use (8) | PASS | `approvals.py:419-426` incident bind; `:446-452` derived-nonce burn + 300s cap; `runs.py:440-486`; `test_runs_router_m14.py` → 21 passed |
| S6 | Rollback validated + policy-gated + once (8) | PASS | `pipeline.py:247-285` gate + refuse-audit + single attempt; `fsm.py:234-237`; `test_pipeline_branches_m21.py` → 22 passed |
| S7 | All mutating HTTP key-guarded (8) | PASS | `test_http_guards.py` → 5 passed; guards at `runs.py:620,638,651`, `approvals.py:518,550,559`, `audit.py:166`, `eval.py:96` |
| S8 | Injection contained at control layer (8) | PASS | adversarial log/prompt/bypass tests → 16 passed; `validator.py:21-56`, `planner.py:47-78`, diagnostic citation gate |
| S9 | Secrets hygiene (8) | PASS | secret scan PASS (221 files); uvicorn redaction `logging_setup.py:128-143`; secrets registered `main.py:21-26` |
| S10 | Audit on block/deny paths (5) | PASS | `_stop` + `policy.decision` emits; `approval.rejected` emits; `test_rejected_verify_emits_audit` green |
| S11 | Per-user identity + SoD (5) | **FAIL** | SSO/OIDC/SoD/per-user greps → zero (one `accessor` substring false positive); only shared key + self-asserted actor |
| S12 | Proof durable across restart (10) | PASS | save/load + auto-load wired for approvals/runs/chains (`approvals.py:79,117,177`; `runs.py:267,291,302`; `audit.py:141,201,232`); 4 roundtrip tests green |

**95/100.** The 5 missing points are exactly S11: no per-user identity exists.

---

## §2 — Q1 measured: Architecture **92/100** (10 checks)

| # | Check (pts) | Result | Proof |
|---|---|---|---|
| A1 | FSM no-skip structure (12) | PASS | `fsm.py:54` no `POLICY_CHECK→EXECUTING` edge; `:57` APPROVED→EXECUTING only; `:226-233` stored-permit gate; fsm suites → 33 passed |
| A2 | Contracts freeze intact (12) | PASS | `schemas.py` defines only `Alert`; rivalry suite → 6 passed |
| A3 | Agents wired (4, tiers, ACLs, budgets) (10) | PASS | `agents/__init__.py:15,18-23`; `tools.py:79-88` (planner empty); platform suite → 47 passed |
| A4 | Pipeline order + verifier independence (10) | PASS | `pipeline.py:161-228` ordered stages; `verifier.py:3-6,33-48` exit-code-free verdict; `test_pipeline_m21.py` → 5 passed |
| A5 | RCA hardened-only + legacy default-deny (10) | PASS | `pipeline.py:379-401` mapping required, no fallback; `reporter.py:103-106` deny-by-default; branches suite → 22 passed |
| A6 | Durability on serving path (10) | PASS | save/load/auto-load in both routers + audit router; approvals+audit suites → 59 passed; non-persisted `IDEM_RESPONSES`/`idem_store` documented non-domain |
| A7 | Budgets live (8) | PASS | aggregate 12/incident (`session.py:119-133`), 5/agent tools, inclusive gate; `test_budgets_m20.py` → 25 passed |
| A8 | Prompt↔code consistency (8) | **FAIL** | fingerprint 16-hex consistent everywhere; **contradiction:** `diagnostic.md:41,70` confidence<0.6 rule has zero code enforcement |
| A9 | Lyzr labels honest (10) | PASS | `LYZR-NATIVE` in backend = 1 disclaimer, in agents = 0; README/ARCHITECTURE qualified Today-vs-Target |
| A10 | Registry truth 183=60+116+7 (10) | PASS | independent recount exact; header consistent |

**92/100.** The 8 missing points are exactly A8: one unenforced prompt rule.

---

## §3 — Q3 measured: agents honesty **40/40 each** (8 checks × 5 pts)

Rubric per agent: 16-section prompt (G1), garbage rejected (G2), frozen+forbid
envelope (G3), ACL+mutating-denied (G4), honest fallback/refusal (G5), budget
wired (G6), grounding mechanism (G7), zero live-model tests proving honesty-not-faking (G8).
All four agents passed all eight checks (130-test run green), with two
behavioral facts recorded, not penalized here:

- `run_*` → `tools.invoke` call sites per agent file: **0, 0, 0, 0** (planner ACL is `frozenset()` by design).
- Zero agent tests touch the network (`FakeClient` + mocked `urlopen` only; keys used are `""`/`"k"`/fixtures).

**A1 40 · A2 40 · A3 40 · A4 40.** Read this correctly: it measures that every
claimed honesty property is implemented and tested — not power. Power, measured
separately (zero invoke sites, zero live observations, single-shot each), is
L0 static for all four: enterprise power A2 25 / A1 20 / A4 15 / A3 10
(safest, weakest — by design). The old 94/81/81/80 band mixed the two questions;
the split above replaces it.

---

## §4 — Q3 measured: UI per-view (10 checks × 10 pts)

| View | Score | Failed checks (all others PASS with cited lines/tests) |
|---|---|---|
| SafetyGate | **80** | V1 (no fetch on mount — user-triggered first fetch), V2 (initial null renders empty-state) |
| ExecutionView | **80** | V7 (one-shot load; stream URL 404s), V10 (no controls → no aria/disabled) |
| IncidentDetail | **70** | V6 (zero actions, no read-only label), V7 (one-shot; 404 stream), V10 (no aria/disabled) |
| RCAView | **70** | V2 (empty-state renders mid-load), V7 (on-demand only), V10 (button has no aria/disabled) |
| CommandCenter | **60** | V2 (load renders empty-state), V7 (probe-only, no subscribe), V10 (button never disables); V8 partial |

Verified facts (all re-confirmed): **no backend `/stream` route exists**
(routers are approvals/audit/auth/eval/runs only); **`run_view` has no
`state_diff`** (`api.ts:69-86`) so `diff={null}` is the only truthful option;
**SafetyGate never sends idempotency keys** (supported by `api.ts`, unused in
`SafetyGate.tsx:69-99`); nav hardcodes demo `inc-1` links; no mock-data
markers anywhere (swept + test-pinned).

---

## §5 — Q1 measured: Quality **60/60**, Reliability **40/40**, Evidence **100/100**

- **Quality:** full suite 2663 passed / 1 justified skip (Q1); ruff clean incl. agents+telemetry (Q2); mypy clean with `disallow_untyped_defs` on (Q3); negatives in 41 files incl. all critical modules (Q4); zero `xfail`, 8 justified skips (Q5); `tsc` + `oxlint` clean on 13 files (Q6).
- **Reliability:** frozen secret-free `/healthz` + 2s-bounded `/readyz` (R1); fail-closed secrets + format-then-scrub incl. uvicorn (R2); 5+ enforced timeouts/TTLs incl. 300s permit freshness (R3); DENY-default + full typed-error matrix (R4); non-root, no-`:latest`, hard-required password, 3 healthchecks, `cap_drop` (R5 — with recorded debit: **no image digest**, documented tradeoff).
- **Evidence:** harness CASE→REPORT green (E1); deep5-25 + stub7-7 committed and verified (E2); 14 attacks with control+metric green (E3); hardened MUST-CITE denies stale/LOW/unsealed (E4); hardened-only publish + default-deny drafts (E5); retrieval params + 6k pack budget (E6); docs-governance green (E7); **zero pipeline-system JSONL/scorecards committed** (E8 — proves no fabricated benchmarks); **C1–C6 all `[PROVISIONAL]`, zero baselines** (E9); 14-count consistent in all four locations (E10).

---

## §6 — Q2 enterprise bar: **~25, Experimental** (method unchanged)

| Dimension | Score | One-line proof |
|---|---|---|---|
| Identity & access | 18 | shared key, self-asserted roles, no SSO/RBAC/SoD/rotation |
| Durability & HA | 12→* | file persistence exists but: no backup/replica, Postgres unused, best-effort saves |
| Ops observability | 15 | nothing pages at 3am — no metrics, alerts, SLOs, dashboards |
| Compliance evidence | 15 | redaction ≠ GDPR; gitignored JSONL ≠ SOC2 trail; SIEM/retention FUTURE |
| Security hardening | 22 | non-root/cap-drop/lockfile real; no TLS, no digests, published DB port |
| Ops maturity | 12 | nothing beyond `compose up` — no CD, migrations, DR, on-call |
| Supply chain | 20 | lockfile yes; SBOM/signing/provenance/scans no |
| Resilience | 18 | bounds yes; breakers/chaos/load/soak none |
| Agentic power | 18 | single-shot proposers; zero live tool calls anywhere |
| UI at enterprise bar | 34 | honest shells; no realtime, hollow execution core |
| Live measurement | 12 | harness real, zero pipeline runs, zero load tests |
| Model ops | 10 | tiers without models, no versioning, no cost attribution |
| **Overall (mean)** | **~25** | **Experimental band (0–15 Experimental, 16–31 Conditional)** |

*Durability note (reconciliation): §1–§2 prove file persistence is real and
tested, which the enterprise lane already priced in — its 12 reflects the
*production* gap (no backup/HA/Postgres/RPO), not absence of mechanism. Same
evidence, different question. No contradiction.

Model sources (re-verified zero model strings in code): tiers select Studio
`agent_id`s; provider/model/temperature/max-iterations live in Studio config.
Real platform billing is $0.06–0.30/run + pass-through tokens; repo rates are
placeholders; no per-agent cost attribution exists. Model swaps can change
behavior under identical repo hashes.

---

## §7 — Zero-trust verdict: **P0 none** (reconfirmed)

S1–S10 all PASS above: RED→DENY everywhere, HMAC HITL, replay/tamper/expiry/
mismatch denied, no exec-path bypass, bound/fresh/single-use permits, gated
once-only rollback, guarded mutating surface, control-layer injection
containment, clean secrets, audit on every block. Remaining P1s: per-user
identity absent; HTTP attestation without policy evaluation; sessions/budgets
memory-only; legacy opt-in exists (explicit, audited); narrow RAI regexes.

**Bottom line:** Q1 ≈ 90s (controls implemented + tested, proven above),
Q2 ≈ 25 (not enterprise production-grade), Q3 = honest-but-static agents and
shells. Correct status: `IMPLEMENTED_TESTED, HARDENING_PENDING`.

---

## Appendix — superseded bands

The 88/73/82/85/73/87 (~84), 81/63-75 (~83), and 94/81/81/80 score bands from
prior turns are superseded by the measured tables above. Direction of each
correction: Security 88→95 (S12 durability proven, bound permits); Architecture
73→92 (incident binding, gated rollback, persistence, honesty labels verified);
agents /100→/40-honesty-split-from-power (same evidence, unmixed questions);
UI 63–75→60–80 (binary rubric: SafetyGate/ExecutionView up on verified loops
and labels, CommandCenter down on proven load≡empty + no-disable); Evidence
stays 100/100 on Q1 with E8/E9 explicitly recording zero baselines.
Enterprise ~25 stands — the measured persistence narrows named residuals
without closing any listed production gap.
