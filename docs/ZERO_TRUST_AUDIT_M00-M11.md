# Zero-Trust Audit — M00 → M11 (Build-First Interim)

**Date:** 2026-09-16 · **Mode:** BUILD → zero-trust audit (serial phases, parallel lenses) · **Auditor:** build lane, model muse-spark-1.2
**Scope:** 93 implemented units (M00.1–M11.6 per `docs/MODULE_REGISTRY.md`). 90 units M12–M22 NOT STARTED, not scored.
**Method:** 12 phases audited serially, 2 parallel lenses per phase (A=Correctness/Spec, B=Verification/Security). Scored from ZERO against `AGENTS.md` §14.3 (10 dimensions, /100). Read-only, registry statuses distrusted. Static inspection + measured suite runs (no fabricated metrics).
**Operational note:** `<system-reminder> plan → build` received 2026-09-16; this report is the first build-mode artifact. No code changed by the audit itself.

> Authoritative: `docs/PS03_FINAL_SPEC_V2.md` · `docs/MODULE_REGISTRY.md` (naming truth) · `AGENTS.md` §1.1 invariants, §14–15 build-first policy · Detail companion `docs/ProofOps_PS03_Master_Winning_Implementation_Trust_Submission_Checklist.md` + `docs/BUILD_FIRST_MASTER_PLAN.md`

---

## 0. Baseline (measured, not claimed)

- **10 APPROVED** (human verdict, locked): M00.1, M00.3–M00.7, M01.1–M01.4
- **1 IMPLEMENTED awaiting verdict:** M00.2
- **82 IMPLEMENTED_TESTED** (hardening pending): M01.5 → M11.6 (M11 lives in worktree `Temp/opencode/w11-runbooks` branch `feature/m11-runbooks` commit `3d19432`, not yet merged to master)
- **90 NOT STARTED:** M12 → M22
- **Suite (main tree, 2026-09-16):** `1573 passed, 1 skipped` (`python -m pytest tests/ -q --ignore runtime`) · `ruff check` pass · `mypy backend/app` pass · `secret_scan.py` PASS (112 files)
- **M11 worktree suite:** `57 passed` (`tests/test_runbooks_m11.py`) + full suite `1573 passed` re-confirmed in worktree

---

## 1. Overall verdict

- **Overall ≥90:** **4 / 93 pass** — M01.2 (95), M01.3 (95), M01.4 (90), M01.7 (91)
- **Safety ≥95 where REQUIRED (M06–M11):** **0 pass** (best Sec 14/15 but Overall <90)
- **Grounding ≥95 where REQUIRED (M05):** **0 pass** — MUST-CITE gate is measure-only (see P1 #5)
- **P0 (unsafe exec / bypass / secret leak / ground-truth leak to live model):** **0 found** — no model-visible path exists yet (M13 not started), no bypass proven, no secret in logs
- **Build-complete gate:** FAIL (89 below Overall gate) — expected under build-first breadth; hardening pass required. System would **NOT survive final zero-trust audit today**.

---

## 2. Scorecard — /100 = lens A (/50 Correctness/Spec/Rel/Maint/Hack) + lens B (/50 Verification/Security/Int/Perf/Obs)

> Each cell is independently scored from zero; Perf/Obs dings largely reflect correctly-deferred instrumentation, not defects.

| Phase | Units | Avg |
|---|---|---|
| **M00** Foundation | M00.1 79 · M00.2 86 · M00.3 83 · M00.4 87 · M00.5 81 · M00.6 66 · M00.7 71 | **79.0** |
| **M01** Contracts | M01.1 86 · M01.2 **95** ✓ · M01.3 **95** ✓ · M01.4 **90** ✓ · M01.5 85 · M01.6 89 · M01.7 **91** ✓ · M01.8 87 · M01.9 86 · M01.10 87 · M01.11 87 · M01.12 85 · M01.13 83 · M01.14 86 · M01.15 86 | **87.9** |
| **M02** Telemetry | M02.1 51 · M02.2 56 · M02.3 51 · M02.4 55 · M02.5 35 · M02.6 25 · M02.7 44 · M02.8 44 · M02.9 33 · M02.10 52 | **44.6** |
| **M03** Normalization | M03.1 66 · M03.2 47 · M03.3 55 · M03.4 44 · M03.5 46 · M03.6 59 | **52.8** |
| **M04** Correlation | M04.1 58 · M04.2 56 · M04.3 68 · M04.4 54 · M04.5 44 · M04.6 48 | **54.7** |
| **M05** Evidence | M05.1 65 · M05.2 48 · M05.3 38 · M05.4 33 · M05.5 47 · M05.6 35 | **44.3** |
| **M06** Policy/Safety | M06.1 64 · M06.2 72 · M06.3 71 · M06.4 75 · M06.5 73 · M06.6 71 · M06.7 49 · M06.8 51 · M06.9 72 · M06.10 57 | **65.5** |
| **M07** HITL | M07.1 49 · M07.2 61 · M07.3 44 · M07.4 51 · M07.5 53 · M07.6 35 · M07.7 42 · M07.8 12 | **43.4** |
| **M08** Sandbox | M08.1 55 · M08.2 52 · M08.3 61 · M08.4 52 · M08.5 35 · M08.6 19 | **45.7** |
| **M09** Verification | M09.1 55 · M09.2 45 · M09.3 35 · M09.4 64 · M09.5 48 · M09.6 37 · M09.7 41 · M09.8 57 | **47.8** |
| **M10** Rollback | M10.1 51 · M10.2 45 · M10.3 32 · M10.4 24 · M10.5 35 | **37.4** |
| **M11** Runbooks | M11.1 58 · M11.2 63 · M11.3 66 · M11.4 57 · M11.5 62 · M11.6 63 | **61.5** |
| **Overall (93 units)** | | **58.5** |

Full per-lens breakdown and subagent raw outputs retained in audit session (24 subagent runs, 2 retries: M02B, M09A).

---

## 3. P1 findings — fix before any HUMAN_APPROVED claim (fail-closed defects)

| # | Phase | File:line | What | Severity |
|---|---|---|---|---|
| 1 | M06.1 | `backend/app/services/validator.py:19` | `SHELL_META=r"[;&|`$()\\n]"` matches literal `n` not newline → false-positive rejects `nginx`/`green`, false-negative on real `\n`/`\r`/`>`/`<` injection. Fixtures avoid `n` so tests pass (`tests/test_safety_m05_06.py:278-282`). | P1 |
| 2 | M06.1 | `validator.py:60-65` | Metachar/SQL scan is top-level strings only; nested `{"cfg":{"cmd":"a;evil"}}` bypasses. `policy.py:134-137` re-checks type only. | P1 |
| 3 | M07 | `backend/app/services/approval.py:88-107` | `verify()` never compares `req.incident_id` vs `action.incident_id` → cross-incident reuse with same action_id/params passes. | P1 |
| 4 | M07 | `approval.py:95-96` | Actor check is string equality only; no role check (viewer vs approver). `services/policy.py:164` role map unwired. | P1 |
| 5 | M07 | `approval.py:32-42` | `NonceStore` in-memory `set` only; restart wipes burns → replay after restart succeeds. No persistence/lock/cap. | P1 |
| 6 | M07 | `approval.py:88-107` + `backend/app/main.py:1-44` | Zero audit emission on approve/deny/expire/replay; invariant §1.1 #14 violated. | P1 |
| 7 | M07 | `approval.py:88-107` | `verify()` accepts empty/None secret (computes `_mac("",…)`) — fail-open if miswired; only `config.py:119-124` startup gate saves it. | P1 |
| 8 | M05 | `backend/app/services/predigest.py:40,45,52` | All pack evidence hardcoded `TrustLevel.HIGH`; no corroboration check — trust inflation vs `services/evidence.py:88-90` + `contracts/evidence.py:53-60`. | P1 |
| 9 | M05 | `services/evidence.py:109-121` | `must_cite_coverage` is ID-membership only; ignores freshness/trust/hash validity; `contracts/rca.py:11` gate promise has no `publish_rca` implementation — gate is measure-only. | P1 |
| 10 | M05 | `services/evidence.py:116-117` | Zero MUST-CITE claims → `1.0` vacuous-open; empty RCA passes grounding gate. | P1 |
| 11 | M09 | `services/verifier.py:58-63` | `FAILED` verdict unreachable — `reversible=True` hardcodes `ROLLBACK_REQUIRED` shadowing; `return FAILED` is dead code. Masked by `in ("FAILED","ROLLBACK_REQUIRED")` asserts (`test_execution.py:130`, `test_execution_m07_10.py:215`). | P1 |
| 12 | M09 | `services/verifier.py:50-63` | `ESCALATE` never emitted (enum has 6, verifier emits 5). Spec V2 §29 requires 6-way. | P1 |
| 13 | M09 | `services/verifier.py:38` + `services/sandbox.py:45-84` | CrashLoop `after.get("crashloop",False)` defaults missing→pass; sandbox never sets `crashloop`/`latency_p95_ms` — 60s-window semantics absent. | P1 |
| 14 | M09 | `services/verifier.py:29,36-37` | `expected` omittable → skips version check; planner can satisfy degraded `after` by crafting `expected["version"]`. No provenance auth on `before`/`after`/`slo`; `execution_id` free string. | P1 |
| 15 | M10 | `services/rollback.py:34-62` vs `services/validator.py:70-71` | No executor exists; `rollback_for()` inverse Action omits `rollback_action` → fails own validator (reversible YELLOW requires it). Auto-rollback cannot pass validation. | P1 |
| 16 | M10 | `services/rollback.py:10-18` | Rollback unwired to validator/policy/HITL/audit — if wired directly to sandbox it is an ungoverned mutation path. | P1 |
| 17 | M02 | `telemetry/gen.py:207-219` + `services/predigest.py:25-65` | Ground truth (`expected_cause/allowed/forbidden/slo`) co-packaged in same bundle with no allowlist-strip; isolation is incidental (no model path yet, M13 not started) — blocks opening Wave 4 until fixed. | P1 |
| 18 | M03 | `services/normalizer.py:135,142` | Missing `environment` defaults to `mock` → prod alert missing env mis-grouped as mock/P3; drives grouping (`correlator.py:87,139`) + severity. | P1 |
| 19 | M03 | `services/normalizer.py:153` vs `services/correlator.py:179-189` | Dual severity authority — normalizer P3 vs correlator P2 for same WARNING/prod input; no canonical mapping. | P1 |
| 20 | M03 | `services/normalizer.py:173-180,228-234,247-251` | `ts` passthrough unvalidated in logs/traces/deployments/k8s (`None`/`NaN`/`str` accepted) vs strict `_coerce_ts` for alerts + finite-check for metrics — inconsistent fail-closed. | P1 |
| 21 | M04 | `services/correlator.py:146-147` | Dependency merge is flat-membership (`svc in depends_on or g[svc] in depends_on`) not pairwise edge — any service in flat list merges with any group when time+sim pass. Ignores `topology["service"]`. | P1 |
| 22 | M04 | `services/correlator.py:125-130` | P1 gate `max_err>0.05` over any metric value with no name/SLO filter — any `cpu` metric trips P1; SLO breach never an input. | P1 |
| 23 | M01 | `backend/app/schemas.py:54-289` | `schemas.py` defines 15 rival models with weaker validation; docstring "defines no vocabulary" false. `contracts/__init__.py:3-4` repeats false claim. Latent — no prod importer today, but any future `schemas.*` validation bypasses canonical hardening. | P1 |

---

## 4. P2/P3 bench — recorded for Phase-B hardening (not gating the interim, but must not hide)

- **Contracts (M01 P2/P3):** `hypothesis.py:80-81` MAX_ARGS 32 vs doc 16, depth 4 never enforced; `action.py:326-335` rollback_action unbounded vs parameters bounded; `rca.py:91-108` row checks untyped; `rollback.py:176-188` succeeded/attempted inconsistency; `audit.py:251-261` policy map no key/depth check; `alert.py:448-454` `str()`-coercion laundering; `approval.py:63-64` nonce 8 chars weak (deferred to M07).
- **M00:** secret scanner misses generic `sk-*` (`scripts/secret_scan.py:31-37`); daemon resurrection + runtime parity unproven on this host (Desktop 29.6.2 Restarts=0).
- **M02:** per-(scenario,variant,seed) matrix untested beyond one combo; metrics single `error_rate` 11-min not pre/post 15m delta; K8s event field mismatch + no ts-index test; topology minimal; no persisted sha-log/seeds.
- **M04:** fingerprint hashes `deploy_id` not window bucket (`correlator.py:35-37`, `[:16]` undocumented); severity keyword-substrings fragile; P4 only 2 sigs; global suppressed count mis-attributed; storm >100 same-fp crashes `Incident` max 100; fail-open auxiliary inputs.
- **M05:** `PACK_MAX_ITEMS/REF_LEN` dead constants, no 6k enforcement; freshness `is_stale` unwired; corroboration unwired; custody hash covers summaries not source blobs; windowing missing.
- **M06:** missing `>`/`<`/`\r`/real newline, UPDATE/INSERT/etc. SQL not covered, `image_tag` exact-key bypass, `bundle or load_bundle()` falsy loads disk not DENY, `_rule_matches` unknown `when` keys fall through, `severity`/`freshness`/`runbook_version` inputs unevaluated, blast override YELLOW-only (GREEN huge-blast stays ALLOW), `reversible` sets drift, bundle unpinned, TTL on DENY 600.
- **M08:** no flap on restart, scale unbounded, patch_config hardcoded non-idempotent, docker tier refusal-only, `DOCKER_CONSTRAINTS` declaration-only.
- **M09:** deploy availability only `replicas>0`, latency skip-absent can RESOLVE, WORSENED 1.2x undocumented, `float()`/`int()` raises unmapped, `reversible=True` stub.
- **M11:** YAML syntax escapes as `YAMLError` not `ValueError`; no `version` arg on load (wrong-version-silent); string dialect no regex cap; inverted `integer-10-1` not rejected; non-string YAML keys → `TypeError`; forbidden lists non-exhaustive; `stamp_hashes` crash on non-mapping.

---

## 5. What is strong (keep)

- **M01 contracts:** `model_construct` blocked + `model_copy(update)` re-validates across all 15 contracts, proven by 1071 tests; frozen + `extra=forbid`; no rival enums; M01.2+ imports canonical.
- **M06:** 72-case policy sweep exceeds 40-test claim; RED→DENY proven (9 cases + sweep + LLM-GREEN-on-delete still DENY); fail-closed (`evaluate()` never raises).
- **M08:** RED never executable at `apply()` boundary (ValueError pre-copy, deepcopied snapshot, 8 RED excluded from `MOCKABLE`).
- **M11:** traversal/non-mapping/swap/tamper/float/bool-as-int/unknown-token/quarantine-with-params all proven rejected; worktree fixes glob-injection + bad sys.path.

---

## 6. Evidence gaps (unproven, do not credit)

Ground-truth strip test · `generate("nope")` reject · variant count matrix · metric delta · trace span-ref / deploy-window ±15m · storm fixtures (30) · severity boundary (0.049/0.051) · SLO severity · publish-gate DENY+audit · pack overflow · stale→ESCALATE e2e · nonce persistence/role/concurrency · docker/isolation enforcement · latency/budget · audit emission across M05/M07/M08/M09/M10.

---

## 7. Next hardening queue (proposed order by blast radius)

1. M06.1 validator regex + nested scan (smallest, highest leverage)
2. M07 `incident_id` bind + role check + `NonceStore` persistence/cap + empty-secret fail-closed + audit emission
3. M05 trust inflation fix + enforce `publish_rca` gate (close empty-claims hole)
4. M09 `FAILED`/`ESCALATE` verdicts + versioned `slo.yaml` + CrashLoop provenance + `expected` binding
5. M10 executor wiring (validate+policy+HITL+audit) + inverse Action passing own validator
6. M02 ground-truth strip + seed persistence
7. M03 env default + severity canonicalization + ts validation parity
8. M04 pairwise edge + metric-name filter for P1 gate

---

*This audit covers 93/183 units. 90 units M12→M22 remain NOT STARTED per `docs/BUILD_FIRST_MASTER_PLAN.md` Wave 4–7. Overall avg 58.5/100; harness pending. No fabricated metrics — every score links to a file:line and a test assertion (or its absence) above.*
