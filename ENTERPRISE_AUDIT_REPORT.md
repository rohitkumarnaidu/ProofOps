# ProofOps — Enterprise Audit Report (loop F, re-measured from zero)

> **Supersedes** every score in the previous revision of this file. That
> revision reported `Security 95/100` and `Q2 enterprise ~25`. Re-auditing
> from zero **disproved** the 95: at `6af0f5e` the resolved identity was
> discarded at every HTTP guard, self-approval was the default, and no
> server-side role gate existed on any route. The old number measured the
> presence of a mechanism, not its enforcement. Every number below is a sum
> of binary checks, each cited to a file:line and, where a test exists, to a
> test that fails if the property regresses.
>
> **Audited state:** `master` @ `6af0f5e` **plus the loop-F working tree**
> (now committed as `b859c92`..`18d038a`). Nothing in this report is inferred
> where it could be measured.
> **Gates at write time (measured, this pass):** pytest **2858 passed, 1
> skipped** (the documented host starlette drift), ruff clean over 134 files,
> mypy clean over 52 source files with `disallow_untyped_defs`, secret scan
> PASS over 239 tracked files, `tsc -b` clean under `strict`, `oxlint` clean
> over 14 frontend files.
> **Runtime evidence (this pass, `python:3.12-slim` via compose):** all three
> services healthy; `/healthz` and `/readyz` 200 with the DB probe passing;
> every state writer resolving to `/app/var`; files landing on the volume
> owned by `appuser`; the full request→approve HITL flow over HTTP; the
> chain and the approval queue both surviving `docker compose restart`;
> `/metrics` emitting live counters; `/alerts` evaluating four SLOs; the SSE
> replay stream returning real chained frames; the UI serving its bundle.
> **Browser evidence (this pass, headless Chrome via CDP, cache disabled):**
> all five views mounted with **zero** console errors or warnings, rendering two
> real incidents in both the selector and the queue table; the Safety Gate
> truthfully surfacing its own `HTTP 401` instead of faking an identity; SSE
> streaming through the same-origin proxy and reporting `replay` rather than a
> false disconnect; and no horizontal overflow at 360px or 390px on any view.
> A standing sweep covers 5 views × 3 viewports (360/768/1440) = 15
> combinations, asserting mount, one `h1`, named regions, no overflow, and no
> rendered failure banners — 15/15 clean. This pass is what caught the §1.3
> white-screen P0 that every static test and the dev server had passed, plus
> the §4.1 spread-order and false-disconnect defects.
> **Still not proven:** anything needing a live Lyzr key, a browser, a second
> user identity, or external infrastructure. Marked `[UNVERIFIED]` at the
> point of use.

---

## §0 — Three questions, three numbers (why earlier scores felt fake)

Past revisions mixed three different questions. Every number below is tagged
with the question it answers, and they are not comparable:

- **Q1 — are the claimed controls implemented AND enforced?** Binary checks
  against code, with a negative test per control. High here means "you cannot
  ship the obvious bypass."
- **Q2 — is this deployable to a regulated enterprise tomorrow?** Includes
  SSO, backup, paging, HA, supply chain, and live load evidence. This is the
  question the user's own 29/100 was answering.
- **Q3 — what does each agent / view actually do?** Honesty, not power.

Q1 is now materially higher than before. **Q2 is still ~30 and is capped by
things this repository cannot contain** (SSO provider, managed HA Postgres,
paging, certs, SIEM, live load). Claiming a Q2 of 80 would be false.

---

## §1 — Q1 measured: Security / identity

Three independent audit rounds; the last one was adversarial specifically to
disprove the previous round's fixes. Scores are not comparable to the old
"95/100" because the rubric changed: the old one scored *mechanisms present*,
this one scores *bypasses closed*.

| # | Control | Result | Proof (code + the test that fails on regression) |
|---|---|---|---|
| S1 | Every mutation enforces a **server-side** role from the key's stored roles, never a client claim | **PASS** | `require_role()` `auth.py:222-249`; gates at `approvals.py:759,777,747`, `runs.py:684,702,715`, `audit.py:201`, `eval.py:101`. No mutating body carries a role field. `test_viewer_key_cannot_mutate_runs_even_claiming_admin`, `test_audit_append_requires_a_write_role` |
| S2 | Actor is **server-derived**; a client cannot act as another named actor | **PASS** | `_actor_for` `approvals.py:711-727`, `_assert_owner:663-680`; audit append `_emit_actor` `audit.py:134-151`. `test_body_actor_cannot_impersonate_another_key_owner` |
| S3 | Four-eyes: requester key ≠ approver key, no self-approval override | **PASS** | `approvals.py:416-429` (no override branch); key store refuses two keys per owner `auth.py:181-190`. `test_per_key_self_approval_denied_and_distinct_approver_allowed`, `test_key_store_refuses_two_keys_for_one_owner` |
| S4 | Two-principal verify weakens **nothing**: expiry, exact params hash, scope, action_id, signature, single-use nonce burn all still enforced | **PASS** | `verify_actor = req.actor` only in per-key mode `approvals.py:454-457`; `approval.py:174-198` recomputes the MAC from the **stored** request, so the actor argument was always an assertion check, never integrity. `test_approval_m07.py` (27), `test_approvals_m19.py` (27) |
| S5 | A per-key approval must record the principal that decided it, else no execution permit is minted | **PASS** | `verified_permit` `approvals.py:566-571`. `test_per_key_permit_requires_a_deciding_principal` |
| S6 | Audit actor is the immutable key id; the client's claim is annotation, never the record | **PASS** | `principal()` `auth.py:206-217`; approvals write the principal via `audit_actor` and keep the claim in `result` `approvals.py:309-315,480-490`. `test_audit_m15.py:282-297` |
| S7 | The request's identity mode cannot be laundered by the approver | **PASS** | approve writes only `status` + `decided_by` `approvals.py:508-512`. `test_request_mode_is_not_laundered_by_the_approver` |
| S8 | A corrupt key store fails closed for every request | **PASS** | `auth.py:156-190` raises `ValueError` → HTTP 500 `auth.py:300-302`. `test_identity_corrupt_store_fails_closed` |
| S9 | Every audit emit on the serving path is flushed to disk | **PASS** (was FAIL) | `persist_chain` after each HTTP decision `approvals.py:637-651`; FSM records `runs.py:443-459`. Previously only the direct-append route persisted, so after a restart the queue and the exported chain disagreed. |
| S10 | `bootstrap` mode is labelled, never presented as an identity | **PASS** | `identity_view` always emits `mode` + `server_enforced` `auth.py:335-340`; `approval_view` emits `identity_mode` + `sod` `approvals.py:340-352`; UI states it verbatim `SafetyGate.tsx:558-568`. `test_bootstrap_identity_is_labeled_not_enforced` |
| S11 | Per-user identity, SSO/OIDC, key expiry/revocation | **FAIL** | No SSO, no expiry, no revocation list, no remote identity provider. `auth.py:46-49` documents this as `[FUTURE]`. |
| S12 | Rate limiting / lockout / abuse control | **FAIL** | No limiter, throttle, quota, or request-concurrency cap anywhere in `backend/`. Unbounded idempotency caches in `approvals.py`, `runs.py`. |
| S13 | Read routes authenticated | **FAIL** | `GET /runs`, `GET /approvals/{id}`, audit view/export, `GET /stream/incidents/{id}`, `/metrics`, `/alerts` are open by design; documented as such in `docs/API.md`. |
| S14 | The shared API key is not shipped in the browser bundle | **FAIL** | `frontend/src/api.ts:6` reads `VITE_PROOFOPS_API_KEY` and the Safety Gate instructs the operator to set it. Unchanged and unfixed. |

**Q1 security/identity: 62/100.** Earned on S1-S10 (mechanisms now *enforced*
and pinned by negative tests). The 38-point debit is S11-S14, of which three
are external-provider work.

### §1.1 The finding that mattered most

At `6af0f5e` this was true and is not obvious from reading a single file:
every handler called the auth guard and **threw the result away**. The
per-key identity store, `check_key_role`, and the separation-of-duties flag
all existed, all had tests, and none of them was on the request path. A
`viewer` key could call the approval endpoint with `role: "admin"` in the body
and be approved. That is why the previous report's 95/100 was wrong: it cited
`approvals.py:332-333` (HMAC verify) as proof of identity safety while the
authorization decision two lines above it was client-supplied.

### §1.2 The bug this loop introduced, and then caught

Lane B added `backend/app/paths.py` and the Dockerfile/compose changes, but
the routers kept their own `Path(__file__).resolve().parents[3] / "var"`. In
the source tree `parents[3]` **is** the repo root, so every test passed. In
the image the module path is `/app/app/routers/...`, so `parents[3]` is `/`:
the key store resolved to `/var/api_keys.json`, which does not exist and is
not writable by uid 10001. **Consequence: in the shipped container the
per-key store was never found, so every request fell back to the
full-authority `bootstrap` identity — no server-side roles, no separation of
duties** — while the source, the tests, and the Dockerfile comments all
asserted per-key identity was live. Re-audit round 2 found it; it is fixed and
now structurally unpinnable (`tests/test_paths_state_m22.py`: an AST check that
rejects any hand-rolled `parents[...]` path, plus a synthetic image-layout
replay proving the resolver lands on the WORKDIR while the old guess does not).

**This one is now measured, not reasoned.** In the running container:
`repo_root=/app`, `state_dir=/app/var`, all seven writers agree,
`missing_assets=[]`, and the files land on the volume owned by `appuser`
(uid 10001). The first host-only guard for it was tautological — in the
source tree `parents[3]` *is* the repo root, so a constant-equality test
could never fail. The AST rewrite is what makes it a real guard.

**A second bug was found only by running it.** `get_chain` read memory only,
so after a restart every read 404'd a chain that demonstrably existed on the
volume: the operator would be told there was no proof of a decision that had
been decided and recorded. Fixed, with a memory-wipe reload test, and re-verified
live — `valid=True checked=2` after `docker compose restart`.

### §1.3 A third bug that only a real browser could find: the blank white screen

**Severity: P0 — the shipped UI rendered nothing at all.** `#root` had zero
children and the console showed `Uncaught TypeError: r.map is not a function`.
Every deep link, at every viewport, on every page. The API was healthy the whole
time, so no server-side check would ever have found it.

The chain, each step verified in the built artifact:

1. `frontend/Dockerfile` declared `ARG VITE_API_URL=""`. Vite inlines that as the
   empty **string**, not `undefined`.
2. `api.ts` resolved it with `?.trim() ?? "/api"`. `??` falls back only on
   null/undefined, so `API_URL` stayed `""`.
3. Every call became same-origin and prefix-less: `fetch("/runs")`.
4. nginx serves the SPA fallback for unknown paths, so `/runs` answered
   `index.html` with **HTTP 200**.
5. `request()` does `await response.json().catch(() => ({}))` and raises only on
   `!response.ok`. So 200 + HTML returned `{}` — a *success*, not an error.
6. `setRuns({})` rendered `{}.map(...)` → TypeError → uncaught → blank page.

The minified bundle proved it directly: `var Gn=``,Kn=``; … fetch(\`${Gn}${e}\`)`,
i.e. the API base compiled to an empty string. After the fix the same probe
reports ``var Gn=`/api` ``.

**Why every existing test missed it.** The four `test_frontend_m19*.py` files are
source-substring assertions. Steps 2–6 are runtime data flow; no amount of
grepping evaluates them. The dev server also *passed*, because the env var is
`undefined` there and `??` did fire — so "it works in dev" was actively
misleading evidence. The new `tests/test_frontend_api_base.py` therefore
**executes** the shipped resolution logic in Node across seven env shapes
(unset / empty / whitespace / `/api` / trailing slashes / explicit override),
stripping only TS annotations. Reintroducing `??` was verified to turn that suite
red, so it is not a tautological guard.

**Two defects, not one.** The cross-origin default (`http://localhost:8000` in a
browser served from `:5173`, against an API with no CORS middleware and a `405`
on OPTIONS preflight) was the trigger; the empty-string fallback was what made
the same-origin repair silently ship as a white screen. Fixing only the first
would have looked correct in review and been worse than the original in the
browser. Fixed in both places, deliberately: the code coerces falsy → `/api`,
and the `ARG` now *defaults to* `/api` so doing nothing is correct.

### §1.4 A prior claim, measured and REFUTED

The four-lane frontend audit asserted that layouts break at 360px from unwrapped
long tokens and flex/grid children lacking `min-w-0`. **Not reproducible.** With
cache disabled and a fresh profile, measuring `documentElement.scrollWidth`
against `clientWidth` on all five views at 360×800 and 390×844:

| view | viewport | scrollWidth | overflow |
|---|---|---|---|
| Command Center | 360 | 360 | no |
| Incident | 360 | 360 | no |
| Safety Gate | 360 | 360 | no |
| Execution | 360 | 360 | no |
| Audit & Eval | 360 | 360 | no |

Recorded rather than quietly dropped: the static-analysis finding was plausible
and wrong, and only a measurement could tell the difference. The *real* layout
defects from that audit (no design tokens, a 610-line `SafetyGate`, missing
state primitives) stand unrefuted and remain open work. One genuine gap this
pass did confirm: the UI ships no JavaScript test runner, so nothing automated
would have caught the white screen either — that is now recorded as Q2 debt
alongside the per-key browser-key exposure.

---

## §2 — Q1 measured: Architecture and control plane

| # | Control | Result | Proof |
|---|---|---|---|
| A1 | FSM has no `POLICY_CHECK → EXECUTING` edge; `APPROVED` requires a permit | **PASS** | `fsm.py:46-65,226-246`; fsm suites green |
| A2 | Contracts freeze intact; no rival model | **PASS** | `tests/test_contracts_m01_rivalry.py` (6) |
| A3 | Validator → policy → approval → sandbox ordering; verifier independent of planner | **PASS** | `pipeline.py:161-228`; `verifier.py` exit-code-free |
| A4 | RCA publish hardened-only; legacy drafts explicit opt-in | **PASS** | `pipeline.py:379-410`; `reporter.py:98-106` |
| A5 | Loop bounds enforced: ≤3 hypotheses, ≤2 replans, ≤5 tools/agent, ≤12 calls/incident | **PASS** | `schemas.py:26-30`, `fsm.py:216-219`, `tools.py:93-105`, `session.py:119-133`; `test_budgets_m20.py` (25) |
| A6 | A single path resolver owns every runtime asset/state path | **PASS** | `paths.py`; all 6 state writers + 3 asset loaders on it; `test_paths_state_m22.py` (13) |
| A7 | Image and compose provision what the code resolves | **PASS** | `Dockerfile:39-45` (`COPY policies`, `COPY runbooks`, `mkdir+chown /app/var`), `docker-compose.yml:46-52` (`api_state:/app/var`) |
| A8 | The Dockerfile parity pin is not weakened | **PASS** | Four literal-match exceptions in `tests/test_repo_structure.py:170-179`, each root-context-only for the same reason as the existing `agents`/`telemetry` exceptions; every safety directive still asserted |
| A9 | Prompt ↔ code consistency | **FAIL** | `prompts/diagnostic.md:41,70` states a confidence < 0.6 → `INSUFFICIENT_EVIDENCE` rule with no enforcement in `diagnostic.py:131-144` |
| A10 | A live server-side orchestration route exists | **FAIL** | `runs.py` exposes create/list/get/advance/sweep only; the four agents are invoked by `pipeline.run_pipeline` and by `scripts/run_baseline.py` with scripted clients, never over HTTP |
| A11 | A4 runs inside the main pipeline | **FAIL** | `pipeline.py:134-158` calls A1/A2/A3 and returns at `:305-319`; RCA helpers are separate. `to_eval_trace` reports the report stage successful without running it |
| A12 | `CORRELATED` is reached with a deterministic correlation result | **FAIL** | `pipeline.py:137-140` advances without calling `correlator.correlate`; A1's fingerprint is never compared to the deterministic one |

**Q1 architecture: 75/100.** A6-A8 are new this loop. A9-A12 are honest gaps,
three of them pre-existing and previously unreported.

---

## §3 — Q3 measured: agents (honesty, not power)

| Agent | Honesty controls | Power | Autonomy | Blocker to the next level |
|---|---|---|---|---|
| A1 Triage | 16-section prompt, garbage rejected, ACL has read tools, mutating denied, honest fallback, budget wired | 22/100 | **L0** — 0 tool invocations, 1 LLM call | 5 of its 6 ACL read tools have **no provider**; only `fetch_runbook` is implemented |
| A2 Diagnostic | as above + citation IDs validated against the pack | 35/100 | **L1 (weak)** — 1 real `fetch_runbook` read, but the tool is hard-coded, not model-selected, and there is no second reasoning turn | needs a model-directed tool loop; the Lyzr client sends no tool-call protocol (`lyzr_client.py:146-168`) |
| A3 Planner | emits data only, no shell, empty ACL by design, `validate_action` re-run | 12/100 | **L0** — 0 tool invocations | its ACL is `frozenset()`; it loads the runbook server-side but the rendered prompt does not include the runbook text |
| A4 Reporter | blameless lint, citation coverage gate, server-side publish | 17/100 | **L0** — 0 tool invocations, live response is **not** parsed through `RCAReport`; only `summary` is extracted | needs a verified case file; `draft_rca` discards the `run` and `diagnosis` it is given |

All four pass every claimed honesty property; that is not in dispute and is
not what a power score measures. **No agent has ever been observed talking to
Lyzr in this repository** — no `LYZR_API_KEY` is available here, so every
"live" claim is `[UNVERIFIED]`.

---

## §4 — Q3 measured: UI per view

Binary checks, 10 points each, 15 checks per view. Round 3 re-scored all five
against the *current* code and found the previous lane's fixes had introduced
three defects of its own; those are fixed and re-pinned.

| View | Prior | Now | What moved |
|---|---|---|---|
| Command Center | 60 | 67 | Real incident ids (no hardcoded `inc-1`), a11y wholesale, event-driven refresh. Held back: no live queue stream, no manual refresh |
| Incident Detail | 70 | 87 | Contextual links to the same incident's Safety Gate/Execution/Audit, event-driven refresh, focus-to-heading, live regions |
| Safety Gate | 80 | 67 | **Up:** client role `<select>` deleted (it was client-side authorization fiction), one idempotency key per approval reused across retries, 410 becomes a terminal expired state, `/identity` is the only role source, load-another-operator's-approval added so four-eyes is demonstrable. **Down (round-2 defect, now fixed):** it was blocking Approve/Deny on an empty role list, which is always true in `bootstrap` mode — the product's headline control was undemonstrable in the default deployment |
| Execution / Verification | 80 | 87 | Event-driven refresh, honest 404, a11y. Still shows no state diff because **no endpoint exists** — the copy says so explicitly rather than rendering a fake |
| Audit & Evaluation | 70 | 67 | **Up:** a11y, event-driven refresh, relabeled accurately ("Audit & Evaluation … does not render an RCA document"). Round 2 read `chain.items` from an endpoint that returns `events`, which threw in render and blanked the SPA with no error boundary; round 2 also deleted the chain-validity badge and its test marker together, which hid it. Both fixed, badge restored and cross-pinned. |

Three UI P0s found and fixed this loop, none of them visible to `tsc`:
a render-time crash on a response-shape mismatch, a polling fallback that read
a field the server never sends and then reported a healthy backend as
`OFFLINE`, and a role gate stricter than the server. The terminal-state set
was also wrong in a way that **a test had been made to assert** — the UI
stopped streaming at `RESOLVED` while the FSM still routes
`RESOLVED|ESCALATED → RCA_PENDING → RCA_PUBLISHED → AUDITED`. The test now
reads the Python `TERMINAL` constant so the two languages cannot drift.

### §4.1 Round 4 — the design system, and three more defects measurement found

A four-lane static audit of the UI returned: no design system (~34 raw colour
literals across 199 `className` sites, 115 distinct utility tokens, 674 raw
token occurrences), a 610-line `SafetyGate` re-implementing the same
panel/button/field/table/error markup as every other view, absent loading /
empty / error / permission states, and a claim that layouts break at 360px.
Three of those were real. One was not. All four changed what got built.

**Shipped.** A semantic token layer under Tailwind v4 `@theme` (elevation,
borders, text hierarchy, accent, five state colours each paired with its own
foreground), a primitive set (Panel, Button, StatusPill, TextField /
TextAreaField / SelectField, DataTable, Notice, LoadingState, EmptyState,
ErrorState, KeyValue, Well), and all five views plus the shell refactored onto
it. The Safety Gate's eight hand-written inline warnings — four of which had
no `role` and so were invisible to a screen reader — now go through `Notice`
with an explicit tone and an opt-in assertive live region.

**Contrast is asserted, not assumed.** `tests/test_frontend_design_system.py`
parses the tokens back out of `index.css` and computes real WCAG 2.x ratios for
the 13 text pairs the UI renders. All pass AA. That immediately caught a
genuine defect in the new primitives: form-control borders were **1.30:1**,
because they used the decorative separator token. SC 1.4.11 requires 3:1 for
anything that identifies a component and explicitly exempts decorative
separators, so the palette now carries `line-control` (3.11:1) for control
boundaries and keeps `line` quiet. A test asserts both directions, so the
distinction cannot rot unnoticed.

**A gate that could only pass.** `npx tsc --noEmit` typechecks **nothing** in
this repo: `frontend/tsconfig.json` is solution-style (empty `files`, project
references, no `include`), so `--noEmit` compiled zero sources and reported a
confident exit 0 — across the entire design-system commit. The real gate is
`tsc -b`, and it immediately caught two type errors. `npm run build` already
used `tsc -b`, so the image build was never at risk; the danger was the ad-hoc
verification command, which is the worse shape: a check that always succeeds.
`tests/test_frontend_typecheck_gate.py` now pins the arrangement and fails if
any test or script bakes in the vacuous form. Separately, `tsconfig.app.json`
had **no `strict` key at all** — the frontend was never type-checked in strict
mode. Added; the tree was already clean.

**A class of bug TypeScript cannot see.** Spreading `{...rest}` *after*
`className` in a primitive let a view's own `className` replace the
primitive's classes outright, so the incident-id input rendered with
`border=0px` and a transparent fill. Found by reading computed styles in a
real browser; `tsc` was satisfied and so was every source-grep test. Primitives
now spread caller props first, and a test pins that ordering — verified to fail
with a precise message when the spread is moved back.

**A fourth honesty defect, in the opposite direction.** Every incident view
showed a red "Event stream update failed: incident event stream disconnected"
while the backend was healthy in MOCK mode, having just delivered its full
audit backlog. The stream is replay-only: the server sends the backlog and
closes, and `EventSource` reports that close through `onerror`,
indistinguishable from a real drop. Normal termination was not observable, so
the client inferred failure. The server now emits a named `replay-complete`
sentinel after the last frame and the client reports a distinct `replay`
state — no error, no `OFFLINE` — while keeping the polling fallback and
backoff reconnect, since new events can appear after the window closes. Tests
cover both halves plus the opposite failure (a stream that never sent the
sentinel did fail and must still be reported), because over-correcting into
silence would be its own lie.

**The 360px claim: refuted, and the refutation kept.** Measured
`scrollWidth` against `clientWidth` on all five views: no overflow at 360 or
390. The static finding was plausible and wrong. The sweep now runs 5 views ×
3 viewports (360 / 768 / 1440) = 15 combinations, asserting mount, a single
`h1`, named regions, `scrollWidth == clientWidth`, and **absence of rendered
failure banners** — added after the SSE bug proved that "no console errors"
and "no failures on screen" are different claims. All 15 clean.

**What this round did not fix.** The UI still ships no JavaScript test runner,
so everything above is host-side source assertions plus manual CDP browser
verification. The browser harness that found four of these five defects lives
outside the repo. That is the single highest-value piece of remaining Q2 debt:
it is the difference between a UI whose tests can all pass while it is blank
and one whose tests cannot.

---

## §5 — Q1 measured: Quality, Reliability, Evidence

- **Quality:** 2858 passed / 1 justified skip; ruff clean over 134 files; mypy
  clean with `disallow_untyped_defs`; `tsc -b` + `oxlint` clean over 14 files
  (`tsc --noEmit` is a no-op here — see §4.1); negatives present in every
  critical module; zero `xfail`.
- **Reliability:** frozen secret-free `/healthz`, 2s-bounded `/readyz`,
  fail-closed config, 5+ enforced timeouts, DENY-by-default, non-root +
  `cap_drop: ALL` + `no-new-privileges`, 3 healthchecks. Debits: no image
  digest (documented tradeoff), no resource limits, single replica, no CD job
  in CI, no migration tooling.
- **Evidence:** 25 deep5 + 7 stub7 golden rows committed and rebuild-verified;
  14 attacks with control + metric + audit assertion green; the evaluation
  header contradiction is fixed; `docs/EVALUATION.md` now separates
  SCRIPTED-ORACLE SIMULATION / MEASURED SYSTEM RUN / PERSISTED EVIDENCE /
  UNMEASURED and states plainly that all six C1-C6 gates in the first baseline
  are fed from `mock_trace()` or hard-coded trace values, so "1.000" is a
  mock-harness pass rate and not a measured quality result.

### §5.1 Numbers a clean-clone reviewer cannot verify

Named here rather than left to be discovered: the `runs/` artifact is
gitignored, so the 2026-09-24 baseline is re-runnable but not verifiable as a
historical run; there are **zero** live-model runs (no `LYZR_API_KEY` here),
zero load or chaos campaigns, zero browser-level accessibility results, and
**zero second-identity tests against a running server** — the per-key
separation-of-duties path is proven by unit tests with a real key store, not
by two operators on two keys. Every UI claim in §4 is source-level, proven by
Python source assertions plus a live bundle serving; that is not browser
verification.

**What the container run did and did not exercise:** it proved the deployment
wiring, the state model, the auth gate behavior at the HTTP boundary, the
HITL flow, the chain, the metrics and alerts endpoints, and the SSE replay. It
did not run the four agents (no Lyzr key), the policy→sandbox execution path
(no pipeline was triggered), or anything involving a second key.

---

## §6 — Q2 enterprise bar: **~30, Conditional**

This is the question the user's 29/100 was answering. Unchanged in direction
from the previous revision, and the reason is structural, not effort-based.

| Dimension | Before | Now | Why it cannot move much in-repo |
|---|---|---|---|
| Identity & access | 18 | **34** | per-key identity + server roles + SoD + owner binding are real and tested; SSO/OIDC, key lifecycle, and revoking the browser-shipped key are provider work |
| Durability & HA | 12 | **24** | every state writer now persists to a provisioned, volume-backed path and the chain is flushed; single replica, no backup/restore, Postgres unused, RPO/RTO unstated |
| Ops observability | 15 | **26** | `/metrics` + `/alerts` + versioned SLOs + a metrics middleware; 6 declared counters still unwired, no paging, no dashboards, no log shipping |
| Compliance evidence | 15 | **18** | hash chain + redaction + provenance; no retention policy, no SIEM, no WORM, no attestation |
| Security hardening | 22 | **30** | non-root, caps dropped, healthchecks, live RBAC; no TLS, no digests/SBOM/signing, DB port published, key in the browser |
| Ops maturity | 12 | **18** | compose up + `--check`; no CD, no migrations, no DR drill, no on-call runbook |
| Supply chain | 20 | **22** | lockfile + `pip-audit` + secret scan; no SBOM, no signing, no image provenance |
| Resilience | 18 | **22** | bounds, timeouts, reconnect backoff; no circuit breaker, no chaos, no load, no soak |
| Agentic power | 18 | **20** | A2 reached weak L1; A1/A3/A4 are L0, 5 of 6 read tools have no provider, no live traffic ever observed |
| UI at enterprise bar | 34 | **46** | real navigation, server identity, a11y basics, honest labels; replay-only stream, no state diff, no browser-verified a11y, no execution surface |
| Live measurement | 12 | **30** | 25-row scripted run with a real control-plane path; zero live-model runs, zero load tests, gates still mock-fed |
| Model ops | 10 | **12** | tiers + `MODEL_IDS` recorded; nothing routed, no per-agent cost attribution, Studio-side config invisible |
| **Mean** | ~17 (arithmetic) | **~30** | previous revision reported "~25" against a dimension list summing to 17.2; the arithmetic is corrected here |

**Q2 = ~30/100, Conditional band (16-31).** The honest reason it is not 60:
roughly 40 of the missing points need a person with a cloud account, an
identity provider, a pager, and a load generator. The honest reason it is not
15: the controls that a security engineer would actually try to break — RBAC,
actor provenance, four-eyes, permit binding, audit durability, injection
containment — are now implemented, enforced, and pinned by negative tests.

### §6.1 What would actually move the number

In-repo, next: rate limiting; wire the 6 counters; a read-path auth decision
for `/approvals/{id}` and the stream; a real execution/state-diff endpoint so
Execution View stops rendering nothing; promote A1/A3/A4 to L1 with real read
providers; enforce the unenforced prompt rule in A8; pull `CORRELATED` onto
the deterministic correlator.
Requires infrastructure: SSO/OIDC, managed HA Postgres + backup drill, TLS
termination, paging, SIEM, image signing, load/chaos infra, browser E2E.

---

## §7 — Zero-trust verdict

**P0: none open in the source.** The two P0 classes that were open at
`6af0f5e` — client-asserted identity with no role enforcement, and the
container resolving state to an unusable path — are closed and pinned. One
deployment-level P0 **remains and is not closable in this repository**: the
shipped default is `bootstrap` identity, because `var/` ships only
`api_keys.json.example` and `.gitignore` excludes the real store. Until an
operator creates `var/api_keys.json` with two distinct owners, the deployment
runs as one shared credential with no separation of duties. The code labels
this honestly everywhere; the deployment is one file-copy away from hardening,
and that is the single most important thing to fix first.

**Open P1s:** no rate limiting; open read routes; browser-shipped API key; no
key expiry/revocation; nonce store soft-fails to memory on `OSError` while
`/meta` still reports `persistent=true`; 6 unwired metric counters; replay-only
stream; no live-model or load evidence.

**Correct status: `IMPLEMENTED_TESTED, HARDENING_PENDING`.** Not
"production-ready", and this report does not claim it.

---

## Appendix A — Superseded numbers, and why they moved

| Prior claim | Now | Direction and reason |
|---|---|---|
| Security 95/100 | 62/100 (different rubric) | **Down, and that is an improvement in honesty.** The old score counted mechanisms; it cited HMAC verify as identity proof while authorization was client-asserted. The new score counts closed bypasses and admits three open controls. |
| Architecture 92/100 | 75/100 | Down for the same reason: three unreported gaps (A9-A12) are now named. Up on the path/state and image-provisioning checks, which are new. |
| Q2 enterprise ~25 | ~30 | Up slightly, with the arithmetic error in the old table (dimensions summed to 17.2 against a stated 25) corrected. |
| Agents "40/40 honesty" | unchanged | Not restated as power. A2 is the only agent above L0. |
| UI 60-80 | 67-87 | Up on a11y, navigation, identity, and lifecycle honesty; down where round 2 introduced defects this loop had to fix. |
| "zero baselines" (Evidence E8/E9) | removed | Contradicted by `docs/EVALUATION.md`. The run exists; it is scripted and its gates are mock-fed, which is now said plainly instead. |

## Appendix B — How this was produced

Three audit rounds, each read-only, each followed by implementation and a
full gate run before the next round:

1. **Round 1** — five parallel lanes (security/identity, observability/ops,
   agentic power, UI/UX, measurement/provenance). Found 5 P0s and
   invalidated the previous security score.
2. **Implementation** — identity/RBAC wiring, server-derived actor and role,
   per-key separation of duties, the two-principal token fix, the
   `parents[N] → app.paths` migration, Dockerfile/compose provisioning, and
   the UI/UX truthfulness pass (three parallel lanes: backend security,
   paths/packaging, frontend).
3. **Round 2** — two parallel lanes re-audited the result adversarially. Found
   that the paths fix was incomplete (the P0 in §1.2), that the audit chain
   was memory-only on the product path, that `POST /approvals` still had no
   role gate, and three UI P0s including one that a test had been made to
   assert.
4. **Round 3** — a verification pass targeting every finding. Ten of twelve
   were closed; the three blockers were fixed and pinned. The pass explicitly
   warned that three of the fixes would regress with a green suite, which is
   why the invariant tests were rewritten rather than the code re-reviewed.
