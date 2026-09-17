# ProofOps Architecture Decisions (M00.6 foundation log)

Authoritative spec: `docs/PS03_FINAL_SPEC_V2.md` (per-ADR section refs below).

Status: this log records decisions taken in M00.1–M00.5 plus the M00.6
documentation-scope decision. Future ADRs are listed as PLANNED slots with
owners, not taken here.
Nothing here claims production readiness or certification.

## ADR-001 — Container is the source of truth (M00.1)

Context: host Python (3.13/3.14) drifts from the pinned image
(`python:3.12-slim`, Starlette v1 ABI break).
Decision: `Dockerfile`/`backend/Dockerfile` pin `python:3.12-slim`; host may
run offline structure tests only. Spec: §43, §47.
Consequences: live FastAPI checks run in the container; host skips report
SKIP, never PASS (`tests/test_repo_structure.py`).

## ADR-002 — Unknown-env typo policy: ignore, documented (M00.2)

Context: `extra='forbid'` provably ignores both system env and planted typo
vars under pydantic-settings 2.13, buying zero protection while suggesting it.
Decision: `extra=ignore` plus template completeness, AST code/template parity
tests, and the machine-readable `Settings.inventory()` contract — a
misspelled key fails visibly as "required key missing".
Spec: §43. Detail: `docs/CONFIGURATION.md`.

## ADR-003 — DB password fails closed at two layers (M00.2/M00.3)

Context: a soft dev default for the DB password could silently cross into
demo/prod use.
Decision: `Settings` requires the secret AND compose uses the `:?`
hard-require form so `docker compose config` aborts with an actionable
message when unset. Note postgres semantics: the password applies at volume
initialization only (see stickiness note in `docs/COMPOSE.md`).
Spec: §39, §43.

## ADR-004 — Liveness vs readiness split; readiness is NOT the healthcheck (M00.4)

Context: the M00.3 skeleton answered `/healthz` even with the database down;
a flapping database must never restart the api container.
Decision: `/healthz` stays liveness-only (always 200 while the process
lives); new `/readyz` reports dependency depth (200 ready / 503 not-ready,
2s bounded probe, secret-free static errors). Only liveness drives the image
`HEALTHCHECK` and compose `service_healthy`.
Spec: §29 (verification independence reads the same split). Detail:
`docs/HEALTH.md`. Reconciliation: the M00.3-era "M00.4 scope/gap" wording for
the db-down behavior was closed by M00.4; the `docs/COMPOSE.md` db-down line
was updated in M00.6 (single authorized line edit, human-assigned).

## ADR-005 — Format-then-scrub logging with a stated boundary (M00.5)

Context: secrets can arrive via message, args, or tracebacks; taking over
uvicorn's boot formatter would need deprecated hooks.
Decision: `RedactingFormatter` scrubs the fully rendered line (message, args,
tracebacks) for registered values plus generic credential patterns; uvicorn
boot lines keep the stock formatter (secret-free by nature, asserted hygienic
live). Detail: `docs/LOGGING.md`. Spec: §37 (secret-leak control).

## ADR-006 — M00.6 documentation scope and README reconciliation (this module,
hardened to 11-docs in 90+ pass)

Context: `README.md` lists `docs/EVALUATION.md`, `docs/SECURITY.md`,
`docs/DECISIONS.md`, `docs/DEMO.md` as PLANNED "in M00.6/M22", while spec §44
additionally names `ARCHITECTURE.md`, `API.md`, `TESTING.md`.
Decision: the canonical M00.6 set is the 4 frozen foundation docs
(`CONFIGURATION`, `COMPOSE`, `HEALTH`, `LOGGING`) plus foundation versions of
the 4 README-planned docs created here (honest status, spec links, owning
modules for the unbuilt remainder) plus foundation versions of the 3 spec-§44
docs (`ARCHITECTURE.md`, `API.md`, `TESTING.md`) added in the 90+ hardening
pass so spec §44 has no gap. "M00.6/M22" means: M00.6 creates the
foundation skeleton; M22 owns full demo hardening (`demo.sh --check`,
rehearsals, evidence package) and M16 owns the eval runner. No full
implementation is claimed in foundation docs — every unbuilt remainder is
marked PLANNED with its owning module.

## ADR-007 — M00 90+ hardening (this pass, owns M00.1–M00.7 lift to ≥90)

Decision: additive hardening only — no frozen-body changes (`/healthz` body
byte-frozen, `Settings` trust boundary preserved, liveness vs readiness split
preserved). New tests in new files where the original file is frozen; edits to
frozen docs/compose/logging are minimal, reviewed, and re-tested. Registry
status flips only on human APPROVE.

## ADR-008 — Adversarial re-audit lacks + boundaries (this pass)

Context: adversarial re-audit after the 90+ pass reproduced 13 concrete lacks
with file:line proof. Fixed now (each with tests): UTC-vs-localtime lie
(`logging_setup.py`, converter pinned to `gmtime`); DSN corruption on
`+psycopg` passwords (`health.py`, scheme-prefix replace); stale TESTING
baseline (refreshed + refresh rule); scanner PGP/`github_pat_`/`xoxe-` gaps;
logging quoted-space passwords + PGP + `github_pat_` + extended Slack;
implicit compose healthchecks (now explicit, mirroring images); vacuous
canonical-set test (now governs the real tree); weak CI echo assert
(tightened). Recorded boundaries (P2, owned, non-blocking): `SEED_SCENARIO`
accepts empty (frozen `config.py`; validation owned by a future contracts
pass); DB passwords must be URL-safe (no raw `@/:?#% ` — derived and compose
URLs interpolate without quoting; quoting owned by M00.2 future work);
`/readyz` carries no timestamp and no auth (M00.4 scope is liveness/readiness
split only; freshness/auth owned by API phase); bearer tokens <20 chars and
exact values <8 chars rely on URI/assignment paths (documented in
`docs/LOGGING.md`); CI has no daemon build/smoke or vuln scan yet
(`docs/TESTING.md` PLANNED, owners M16/M20/M22).

## ADR-009 — Submodule re-audit lacks + boundaries (this pass)

Context: submodule-level re-audit (every M00 sub from zero) reproduced 8 more
lacks. Fixed now (each with tests): `scripts/ci.sh` CRLF on Windows checkouts
broke the bash shebang — new `.gitattributes` (`*.sh text eol=lf`) + LF
conversion + LF/shebang test; workflow had no `permissions:`/`concurrency:`
(added least-privilege + cancel-duplicates); template `POSTGRES_PASSWORD`
emptiness unpinned (now asserted — no silent shared default); README
fabrication hygiene untested (now gated like the 11 docs); `os.getenv("X")`
form missed by BOTH parity detectors (regex needs `os.environ`, AST missed
attribute-getenv — prospective fail-loud test added, zero hits today).
Recorded boundaries (P2, owned, non-blocking with evidence): compose `$`
in passwords collides with `${VAR}` interpolation (passwords must avoid raw
`$` — noted in `docs/COMPOSE.md` stickiness); `pyproject.toml` lint scope is
narrow (E4/E7/E9/F) so some `noqa` markers are inert decorations (widening
owned by M00.7 with a full-violation triage).
CORRECTED here (was wrong in ADR-009): `python-dotenv` is NOT unused —
`pydantic-settings` hard-requires it (`Requires-Dist: python-dotenv>=0.21.0`,
verified via importlib metadata) and uses it for `.env` parsing
(`test_env_beats_dotenv_file` exercises it). Removal is REJECTED, and a
presence test pins it. (Lesson: "grep shows no import" missed transitive
library use — check metadata, not just imports.)
CLOSED here: `Settings(env_file=".env")` stays CWD-relative BY DECISION
(investigated anchoring, REJECTED with proof): anchoring to the repo root
would couple every bare process to the repo `.env` (present on dev boxes),
so the hermetic fail-closed proof (`test_process_fails_closed_actionable`:
scrubbed env + foreign CWD must raise naming the key) would go green-by-
accident locally while staying red on clean clones — the worst kind of
environment-dependent test. CWD-relative fails loud and safe everywhere, and
the contract is now pinned by test + documented in CONFIGURATION.md.
CLOSED here: action SHAs pinned (verified live via api.github.com, `# vN`
comments) and runner pinned `ubuntu-24.04` (was "floats" in ADR-009).
Spec: §43–§46. Detail: `docs/TESTING.md`, `docs/ARCHITECTURE.md`, `docs/API.md`.

## ADR-010 — No lockfile yet (recorded gap, not a decision)

Context: `backend/requirements.txt:9` promises "M00.7 CI foundation adds pip
freeze / hash check" — that piece never landed. Today there is no
`requirements.lock`, freeze gate, or `--require-hashes`; only narrow bounded
ranges + `pip check` (consistency, not CVEs, not drift) + the
`python:3.12-slim` container convention. Two fresh installs weeks apart can
resolve different versions inside the ranges (the starlette v1.x breakage was
fixed reactively with an upper bound — a lockfile prevents the class, not one
instance). "Reproducible" currently means constrained-float, not locked; docs
must not claim more.
Decision: resolve + freeze on the source of truth (`python:3.12-slim`, never
the drifted 3.13/3.14 host) → commit `backend/requirements.lock` → CI
installs from the lock + a stale-lock check job. A hand-written lock with
unresolved versions is forbidden (false precision is worse than honest
ranges). Interim guard (this pass): every requirements line must carry BOTH a
lower and an upper bound, pinned by test — nobody silently adds a floating
dep while the lock is missing. Owner: M00.7 (needs a daemon/container run +
human review of the resolved set).

## ADR-010b — Lock LANDED (this pass, closes ADR-010)

Resolution: live `pip install --dry-run --report` against PyPI with
`--python-version 3.12 --implementation cp --abi cp312
--platform manylinux_2_17_x86_64 --only-binary=:all:` → 36 resolved, minus
win32-only `colorama`/`tzdata` (false on linux per resolver `requires_dist`
markers) → committed `backend/requirements.lock` (34 exact pins,
name-sorted, every pin inside its declared range — proven by
`scripts/freeze.py --check` + `tests/test_freeze.py`, including a real-files
pass and a win32-exclusion pin). Enforcer: `scripts/freeze.py` (stdlib-only;
strict `--check` for CI, `--generate` that REFUSES non-3.12 interpreters so a
drifted host can never bake the lock). CI now installs from the lock and runs
a 5th `lockfile` job (`needs: [security]`); the Windows-local runner keeps
portable ranges with the split documented + tested (manylinux wheels cannot
install on Windows). CLOSED after landing (this pass): both Dockerfiles now
install from `requirements.lock` — proven by a clean `--no-cache` build
(`proofops-api:lockproof`) + container smoke (`/healthz` 200 frozen body,
`/readyz` 503 with no DB) on Docker Desktop 29.6.2. CLOSED after landing
(this pass): `pip-audit` gates the lock in CI with 8 documented per-ID
exceptions (7 starlette: no in-bounds fix under fastapi<0.120, zero
exploitable surface proven by grep; 1 pytest: local-only) — live scan
evidence from a 3.12-slim run, unknown IDs fail loud. REMAINING (owned,
next): `--require-hashes` still open (M00.7).

## ADR-011 — M01 rival-models closure + freeze-surface assessment (this pass)

Context: interim-audit P1 — `app/schemas.py` defined 15 weak rival models
beside the canonical 16 (any future `schemas.*` validation would bypass
canonical hardening; `contracts/__init__.py` + `test_contracts_m01_1.py`
already documented the single-source intent the code violated).
Decision: 15 models are now TRUE aliases (`S.X is C.X`, pinned by
`tests/test_contracts_m01_rivalry.py`); `schemas.py` defines exactly one
class (`Alert`, raw-telemetry input shape for the tested `from_legacy`
migration bridge — different stage, not a rival validator), zero enums;
any future backend/scripts/telemetry import of `app.schemas` fails CI (AST
test enforcing the existing contracts-ONLY rule). `to_legacy` methods now
pass canonical immutable containers (fixes 33 mypy arg-type errors the weak
shapes had masked); `Hypothesis` bridges are lossless both directions
(`test_args` truncation removed); `Alert.from_legacy` is strict-typed
(no `str()` laundering).
Freeze assessment (CONTRACT_VERSION stays 1.0): JSON wire output is
byte-identical (tuples/FrozenDicts serialize as JSON arrays/objects, proven
by round-trip tests); only Python-level container types strengthened, and
the sole consumers are in-repo tests, all updated with justification in
`docs/CONTRACTS.md`. No external caller exists (proven: zero non-test
importers of `app.schemas`, zero non-test `from_legacy`/`to_legacy`
callers). Any future WIRE change still needs the full 1.0 process (change
request + impact + human review + bump + migration).
Bounds closed in the same pass: `test_args` depth<=4 + doc 16→32;
`Action.rollback_action` caps; RCA timeline ts+actor+hash keys;
`Rollback` outcome-consistency; `AuditEvent.policy` version+rule+result
keys. Defect-pinning test updates (15 single-definition, 2 duck-typed
invalid, 1 list-compare) remove no coverage.

## ADR-012 — M01 adversarial round-2: nesting crash, row caps, fast-paths

Context: submodule re-audit reproduced 7 more lacks with file:line proof.
Fixed: adversarial nesting (2000-deep mappings crashed with
`RecursionError` past the trust boundary in hypothesis/rca-impact/audit-
policy — proven) now fails closed as `ValidationError` via a net in
`FrozenDict._validate_full` (per-field depth caps still apply after it);
`_check_rows` coercion wrapped the same way; `RCA.impact` enforces its
declared `MAX_IMPACT_DEPTH=5` (constant existed, check did not); timeline/
remediation rows get `MAX_ROW_JSON_BYTES=16384` each (family-consistent with
params/impact/policy caps); `confidence_bucket` rejects bool/str;
`from_legacy` fast-paths (`type(legacy) is cls` → exact return) on all 15
bridges so the only real input skips coercion entirely.
Verified NON-lacks (evidence overrules suspicion, recorded so nobody
"fixes" them): `ttl_seconds` bool already rejected (strict validator);
`utcnow` tz-aware; `params_hash` order-stable; shipped runbooks name only
allowlisted actions (17/17 ⊆ ACTION_TYPES, now pinned by test).
Boundaries: `from_legacy` foreign-duck input (untested shapes beyond
scalars) may raise `TypeError` on exotic coercions — never silently
accepted; constructors remain THE trust boundary. `Alert.from_legacy`
takes legacy-shaped OBJECTS, not raw dicts (raw dicts → normalizer, M02).

## ADR-013 — M02 telemetry hardening (this pass)
Context: M02 scored 44.6 (thinnest phase: 70 tests for 10 units, one golden
combo). Zero-trust re-audit found: answers co-packaged without a sanctioned
model-visible view (P1, downgraded by evidence — retrieval guards queries
and predigest never packs answers, but no primitive existed); bare-ID
traces with dangling log refs (t-*-3..6 unresolvable); list-aliased
CONTRADICTORY rows (one object ×5); ruff gate blind to telemetry/ (an
orphaned dead fragment from this pass proved it).
Decision: `public_bundle()` (drops exactly `GROUND_TRUTH_KEYS` + seal,
one-line change surface, pinned); span-shaped traces with pure-arithmetic
ids/durations (never `hash()`, separate from legacy rng streams so golden
bytes hold); log groups 0..2 resolving to trace objects (specials first so
3-exemplars include them); `topology_edges` + `events_in_window` helpers
(fail-closed); aliasing fix; ruff scope widened to telemetry/ (CI + local +
test pinned). Full 12×5 matrix determinism incl. cross-process
(PYTHONHASHSEED 0 vs 12345), per-combo counts, deploy ±15m window,
pre/post metric shapes, per-section tamper seal, payload present-once /
absent-where-clean rules.
Boundaries: `slo` thresholds STAY in the public view (policy config, not
answers — one-line change if human disagrees); metrics cover ~11 min at 60s
(pre/post SHAPE for delta, not a 15m series); stub-7 stay minimal by design.

## ADR-014 — M03 normalization hardening (this pass)

Context: M03 scored 52.8 with three P1s. All three closed with file:line
proof, plus a None-hole sweep and span preservation.
Decision:
- P1 #18 (environment mock-default): missing/null environment now REJECTS
  before the fingerprint binds it (blank still rejects in the model). No
  test pinned the default; gen and all fixtures always set env.
- P1 #19 (dual severity): documented as TWO deliberate levels, not a
  contradiction — signal severity on Alert (indicator strength) vs triage
  severity on Incident (env+error+signature). WARNING/prod = P3-signal but
  P2-incident by design (degraded prod pages); pinned jointly with M04.
  Neither mapping changed (both pinned by pre-existing tests).
- P1 #20 (ts parity): TWO rules, not one (uniformity was impossible — an
  existing k8s test pins missing-ts→reject while an existing log test pins
  missing-ts→fill). Observations (alert/log/trace): missing/null takes
  arrival time, malformed rejects. Anchored events (metric/deploy/k8s):
  missing/null rejects, malformed rejects. Shared strict core
  (bool/NaN/negative/unparseable/naive rejected).
- Identity-fallback doctrine (visible-noise over silent-blindness): missing
  ids take unique/generated markers, never colliding placeholders; grouping
  keys with no safe default (signature, environment) reject.
- None-hole sweep: every `str(raw.get(...))` now routes through `_raw_str`
  (present-None used to stringify into "None" groups/versions).
- Traces carry spans through normalization (M02.6 enrichment survives;
  non-mapping spans reject).
- Verified NON-lack: blank resource stays "" (canonical allows absent
  resource); blank from_v/to_v stay (content-level, visible).

## ADR-015 — M03 adversarial round-2: range crash, time types, full chain
Context: end-to-end re-audit (gen→normalize→correlate→predigest matrix)
reproduced 4 more lacks. Fixed: `fromtimestamp` on out-of-range magnitudes
(`1e20`) escaped as raw `OverflowError` — now `ValueError` in the shared
strict core (all six normalizers inherit); canonical `ts` is now ONE type
(tz-aware UTC datetime everywhere — metric/deploy/k8s float passthrough is
gone); alert metadata `trace_id`/`pod` extras are strict-typed (non-str
rejected, was `str()`-laundered); full-chain matrix test (6 scenarios ×
normalize→correlate→predigest, raw AND normalized inputs, adversarial
payload-truncation pinned) proves the pipeline composes.
Verified NON-lacks: labels int-keys/values already rejected by the model;
`str(None)` fallbacks already guarded by `_raw_str` where used; predigest
80-char truncation is by design (evil line stays recognizable).
Boundaries: `from_v`/`to_v` content unvalidated (free-form tags, visible);
k8s kind/reason open sets (vendor drift risk if closed); log `level` open
set (same reason).
- Methodology note: test-count arithmetic is verified via isolated
  worktree baselines, never memory (a stale 2174 figure was caught and
  corrected to a measured 2248+21 this pass).

## ADR-016 — CI caught a Windows-only assumption (ts ceiling)

Context: the M03 push went red on ubuntu with exactly 1 failure in 2337 —
`test_out_of_range_rejected_everywhere[99999999999]`: year 5138 raises on
Windows but is VALID under Linux 64-bit time_t. A platform-delegated range
check can never be uniform.
Decision: explicit admissible range 1970..2100 (`MAX_TS`/`MAX_TS_YEAR`) —
numeric compare before conversion (no conversion to overflow), year compare
for ISO/datetime shapes (no `timestamp()` round-trip to overflow). The
conversion guard (`OverflowError`/`OSError` → `ValueError`) stays as the
second net. Boundary tests pin both sides on every platform. Lesson recorded:
range edges must be asserted constants, never delegated to the CRT.

## ADR-017 — M04 correlation hardening (this pass)
Context: M04 scored 54.7 with two P1s, both reproduced live before fixing.
Decision:
- P1 #21 (flat-membership merge): cross-service merge is now PAIRWISE — the
  pair must equal {topology.service, dep} in either direction (proven: a
  payments+unrelated pair with identical signatures merged under the old
  rule). `topology["service"]` is read again (was ignored); malformed
  topology (non-object, non-list deps, non-str entries, deps without a
  service) fails closed — the old code applied substring semantics to
  strings and TypeError'd on non-lists.
- P1 #22 (any-metric P1 gate): max is over `error_rate` readings only
  (proven: cpu_percent=95 paged P1); non-finite and boolean readings skip
  (garbage in, no signal out). Same family as predigest uses; documented.
- Suppression attribution: `deduplicate` returns (unique, total, by_key) and
  each incident stamps its OWN count (the global total on every incident was
  a data-integrity bug); the 4 unpack sites updated, no coverage lost.
- Storm survival: 200-alert storms yield one incident (first 100 ids, full
  count in `alert_count`, `source_alert_ids_capped` flag) instead of
  ValidationError'ing the whole correlation (proven crash).
- Fingerprint: `[:16]` rationale + deploy-window encoding documented (in-
  window id vs "none" splits groups; pinned behaviorally); width frozen
  (agents pin 16-hex independently — signature and output unchanged).
- Keyword arms kept deliberately (fail-closed heuristic: data gaps
  escalate; removing them downgrades real spikes on missing metrics) and
  pinned; FP set pinned (2 members + non-member control); `_sig_sim` empty
  guard; `_deploy_in_window` bool-ts skip.
- Non-goals recorded: agents/triage.py owns a PROPOSAL-grade severity copy
  with known edge divergences (security-always-P1, slo_breach arm) — M13
  lane's file, not touched; M04 remains the deciding authority.

## ADR-018 — M04 round-2: per-service severity + end-to-end matrix

Context: end-to-end re-audit (full bundles through correlate) reproduced one
high-value lack the unit tests couldn't see: the error gate was computed
GLOBALLY, so a web spike at 0.18 paged an unrelated search blip (own
error_rate 0.001) to P1 — and NOISY junk groups (cpu_blip) paged P1/P2
beside real spikes, defeating the FP gate they were designed for.
Decision: `_service_max_err` attributes readings per service (tagged
readings count for their service; untagged-but-named count globally as
bundle evidence; nameless/non-finite/bool readings skip). Post-fix matrix
(12 scenarios × NORMAL/NOISY/INCOMPLETE/CONTRADICTORY/ADVERSARIAL, pinned):
junk is P4 everywhere, FP scenario P4, staging P3, prod spikes/security P1,
INCOMPLETE/CONTRADICTORY/ADVERSARIAL hold severity. Storm perf smoke (<2s
for 200 alerts). Same-id-different-content keeps first-wins (id-uniqueness
invariant, documented in code).
Boundaries: agents/triage.py keeps a proposal-grade severity copy (M13
lane's file, untouched); M04 decides. Topology stays single-service-context
(multi-service callers merge per-context maps first).

## ADR-019 — Zero-trust re-audit round-3 (M00–M04): hunt, don't confirm

Context: a re-audit that holds every prior score is indistinguishable from
trusting old reports. This round assumed guilt: 16/16 fast-paths probed
(found Evidence missing its own — fixed), bool-typed ints probed
(`APPROVAL_TTL_SECONDS=True` coerced to a 1-second window — fixed with a
before-validator + string-numeral regression test), scanner suffixes
audited (blind to .ts/.tsx/.js/.css/.json/.conf despite the M19 frontend —
widened, clean tree still PASS), README wave-status audited (claimed
"M12–M22 NOT STARTED" after M12–M19 landed — refreshed + pinned),
spec §15 counted (says "14", enumerates 18 — code follows the enumerated
list; the label is spec's own inconsistency, not a code defect).
Process lesson (repeat offense, now enforced): never batch two edits to the
SAME file in one parallel block (results misreport; caught twice by
diff-verify), and never hand-write oldString from memory (phantom anchors
fail — read first). Diff-verify every edit before committing.

## PLANNED ADR slots (not taken in M00.6)

- FSM-primary over SuperFlow mirror (owning module: orchestration phase).
- 4-agent split plus session_id=incident_id (M13).
- No-pgvector retrieval freeze: Classic KB plus local pre-digestion (M12/M13).
- RAI per-agent placement, policy engine as authz boundary (M06/M13).
- HMAC token crypto shape: scope hash, nonce burn, TTL (M07).
- mock-default executor with docker/kind tiers (M08).
