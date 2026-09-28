#!/usr/bin/env node
// End-to-end FLOW gate: does the operator's path actually work in a browser?
//
// The existing ui_browser_check.mjs answers "does every view render cleanly".
// It cannot answer the question this script exists for: "can an operator drive
// the control plane from the UI, and does the UI then show what really
// happened?" Every view can render perfectly while the product is unusable --
// the incident form submits to a route that never drives the pipeline, the
// Safety Gate shows a blank hand-written template, and the Execution view has
// no evidence to show. All of that is invisible to a render check.
//
// So this drives the real path against the real stack:
//   1. type a new incident id into the Command Center and submit the ingest
//      form, asserting the server accepted and queued it;
//   2. wait for the orchestrator to drive it to AWAITING_APPROVAL;
//   3. assert the Safety Gate lists the PIPELINE'S OWN parked proposal, with a
//      real risk tier, and that loading it fills the request form;
//   4. request approval, approve it, and wait for RESOLVED;
//   5. assert the Execution view shows the real tier, the real state diff and
//      the real verifier verdict with its per-check results -- the evidence
//      that only exists if the backend attached it;
//   6. assert the Audit view shows event timestamps, the policy decision, and
//      a chain that verifies.
//
// Zero dependencies, same CDP-over-WebSocket approach as ui_browser_check.mjs.
//
// Usage:
//   node scripts/ui_flow_check.mjs
//   PROOFOPS_UI_URL=http://127.0.0.1:5173 node scripts/ui_flow_check.mjs
//   node scripts/ui_flow_check.mjs --shots ./artifacts
//
// Exit 0 = the whole operator path works. 1 = a step failed. 2 = the
// environment could not support a run.

import { spawn } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const BASE = (process.env.PROOFOPS_UI_URL || "http://127.0.0.1:5173").replace(/\/+$/, "");
const API = (process.env.PROOFOPS_API_URL || BASE).replace(/\/+$/, "");
const shotIndex = process.argv.indexOf("--shots");
const SHOTS = shotIndex === -1 ? null : process.argv[shotIndex + 1];
const CHROME = process.env.PROOFOPS_CHROME
  || [
    "C:/Program Files/Google/Chrome/Application/chrome.exe",
    "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
  ].find((p) => existsSync(p));
const DEBUG_PORT = Number(process.env.PROOFOPS_CDP_PORT || 9412);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function fail(message, code = 2) {
  process.stderr.write(`ui_flow_check: ${message}\n`);
  process.exit(code);
}

async function fetchJson(url, attempts = 40) {
  for (let i = 0; i < attempts; i += 1) {
    try {
      const res = await fetch(url);
      if (res.ok) return await res.json();
    } catch { /* retry */ }
    await sleep(250);
  }
  return null;
}

/**
 * Wait until the API is genuinely ready to serve a write.
 *
 * Liveness (/healthz) alone is not enough: it answers with dependencies down by
 * design, which is correct for a liveness probe and useless as a gate
 * precondition. /readyz is the dependency-aware probe, and /meta/engines
 * confirms the database reports healthy. All three, so the gate never asserts
 * against a half-initialised control plane.
 */
async function waitForApiReady(attempts) {
  let detail = "no attempt made";
  for (let i = 0; i < attempts; i += 1) {
    try {
      const live = await fetch(`${API}/api/healthz`);
      if (!live.ok) { detail = `/healthz answered ${live.status}`; await sleep(2000); continue; }
      const readyRes = await fetch(`${API}/api/readyz`);
      if (readyRes.status !== 200) {
        const body = await readyRes.json().catch(() => ({}));
        detail = `/readyz answered ${readyRes.status}: ${JSON.stringify(body).slice(0, 120)}`;
        await sleep(2000);
        continue;
      }
      const engines = await fetch(`${API}/api/meta/engines`);
      const engineBody = engines.ok ? await engines.json() : null;
      if (!engineBody?.database?.healthy) {
        detail = `database not healthy: ${JSON.stringify(engineBody?.database ?? null).slice(0, 120)}`;
        await sleep(2000);
        continue;
      }
      return { ok: true, detail: "ready" };
    } catch (e) {
      detail = String(e);
      await sleep(2000);
    }
  }
  return { ok: false, detail };
}

// The UI is same-origin behind nginx, so these go through the UI, not :8000.
// The bearer token is read out of the BROWSER's own storage, so the approval
// request and decision are made with exactly the credential the sign-in in the
// UI obtained. Inventing a second credential here would test a path no
// operator takes.
let browserToken = "";
const authHeaders = () => (browserToken ? { Authorization: `Bearer ${browserToken}` } : {});

const apiGet = async (p) => {
  try {
    const res = await fetch(`${API}/api${p}`, { headers: authHeaders() });
    return res.ok ? await res.json() : null;
  } catch { return null; }
};
const apiPost = async (p, body) => {
  try {
    const res = await fetch(`${API}/api${p}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify(body),
    });
    return { status: res.status, body: await res.json().catch(() => ({})) };
  } catch (e) {
    return { status: 0, body: { detail: String(e) } };
  }
};

async function main() {
  if (!CHROME) fail("no Chrome/Chromium binary found; set PROOFOPS_CHROME");
  try {
    const res = await fetch(`${BASE}/`);
    if (!res.ok) fail(`UI at ${BASE} answered HTTP ${res.status}`);
  } catch {
    fail(`UI not reachable at ${BASE}; start the stack first`);
  }

  // Readiness pre-flight. The UI answers as soon as nginx is up, but the API
  // behind it is still initialising its schema and starting the orchestrator.
  // Driving the flow into that window produced a 500/502 on the first write,
  // which reads as a product failure when it is a cold stack -- and a gate that
  // fails intermittently is a gate people learn to ignore, which is worse than
  // no gate at all. So: wait for /healthz AND /readyz, and for the DB to be
  // reported healthy, before asserting anything.
  const ready = await waitForApiReady(60);
  if (!ready.ok) {
    fail(`API never became ready at ${API} (${ready.detail}); `
      + "the stack is not up, so the flow cannot be driven");
  }

  // A unique id per run so the flow never collides with an existing incident,
  // and so a stale persisted run cannot make a broken flow look like it works.
  const stamp = Date.now().toString(36);
  const incidentId = `ui-flow-${stamp}`;

  const profile = join(tmpdir(), `proofops-ui-flow-${process.pid}`);
  const chrome = spawn(CHROME, [
    "--headless=new", "--disable-gpu", "--no-sandbox", "--hide-scrollbars",
    `--remote-debugging-port=${DEBUG_PORT}`,
    `--user-data-dir=${profile}`,
    "--window-size=1440,1400",
    "about:blank",
  ], { stdio: "ignore" });

  const targets = await fetchJson(`http://127.0.0.1:${DEBUG_PORT}/json/list`);
  if (!targets?.length) { chrome.kill(); fail("could not attach to Chrome via CDP"); }

  const page = targets.find((t) => t.type === "page") || targets[0];
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  let nextId = 0;
  const pending = new Map();
  const problems = [];
  let shot = 0;

  const send = (method, params = {}) =>
    new Promise((resolve_) => {
      nextId += 1;
      pending.set(nextId, resolve_);
      ws.send(JSON.stringify({ id: nextId, method, params }));
    });

  ws.addEventListener("message", (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.id && pending.has(msg.id)) {
      pending.get(msg.id)(msg.result);
      pending.delete(msg.id);
      return;
    }
    if (msg.method === "Runtime.exceptionThrown") {
      const d = msg.params.exceptionDetails;
      problems.push(`uncaught ${d.exception?.description || d.text}`);
    }
  });

  await new Promise((r) => ws.addEventListener("open", r, { once: true }));
  await send("Page.enable");
  await send("Runtime.enable");
  await send("Network.enable");
  await send("Network.setCacheDisabled", { cacheDisabled: true });
  await send("Emulation.setDeviceMetricsOverride", {
    width: 1440, height: 1400, deviceScaleFactor: 1, mobile: false,
  });

  const evaluate = async (expression) => {
    const r = await send("Runtime.evaluate", {
      expression, awaitPromise: true, returnByValue: true,
    });
    if (r?.exceptionDetails) {
      problems.push(`evaluate threw: ${r.exceptionDetails.exception?.description
        || r.exceptionDetails.text}`);
      return null;
    }
    return r?.result?.value ?? null;
  };

  const goto = async (route) => {
    await send("Page.navigate", { url: BASE + route });
    await sleep(1400);
  };

  const screenshot = async (label) => {
    if (!SHOTS) return;
    mkdirSync(SHOTS, { recursive: true });
    const { data } = await send("Page.captureScreenshot", { format: "png" });
    shot += 1;
    writeFileSync(join(SHOTS, `${String(shot).padStart(2, "0")}-${label}.png`),
      Buffer.from(data, "base64"));
  };

  const text = () => evaluate("document.body.innerText");

  const results = [];
  const check = (name, ok, detail = "") => {
    results.push({ name, ok: Boolean(ok), detail });
    if (!ok) problems.push(`FLOW ${name}: ${detail}`);
  };

  // ---------------------------------------------------------------- step 0
  // Sign in through the UI. Every write is server-gated, so without a
  // credential the ingest form submits and gets 401 -- which is the default
  // deployment unless a key was baked into the bundle at build time. The key
  // comes from the environment; it is never written into the repo.
  //
  // Retried: a fresh API container can still be finishing warm-up when the
  // first request lands, and a transient 500 there is a cold stack, not a
  // broken sign-in. Retrying a bounded number of times separates the two
  // without masking a real failure (a bad key is rejected 401 every time and
  // the retries all burn).
  if (process.env.PROOFOPS_API_KEY) {
    await goto("/");
    const keyField = await evaluate(
      '!!document.getElementById("operator-api-key")'
    );
    if (!keyField) {
      check("the UI offers a sign-in control", false,
        "no operator-api-key field: a signed-out operator cannot enable any write");
      // Without the field there is nothing to retry; stop here rather than
      // burning four attempts against a control that does not exist.
      problems.push("FLOW the operator can sign in from the UI: no sign-in field");
    }
    let signedIn = false;
    for (let attempt = 0; attempt < 4 && !signedIn && keyField; attempt += 1) {
      await evaluate(`(() => {
        const el = document.getElementById("operator-api-key");
        if (!el) return false;
        Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")
          .set.call(el, ${JSON.stringify(process.env.PROOFOPS_API_KEY)});
        el.dispatchEvent(new Event("input", { bubbles: true }));
        el.dispatchEvent(new Event("change", { bubbles: true }));
        return true;
      })()`);
      await sleep(500);
      await evaluate(`(() => {
        const btn = [...document.querySelectorAll("button")]
          .find((b) => /^sign in$/i.test((b.textContent || "").trim()));
        if (btn) { btn.click(); return true; }
        return false;
      })()`);
      for (let i = 0; i < 6; i += 1) {
        await sleep(1000);
        signedIn = await evaluate(
          '!!document.querySelector("[data-testid=\'identity-summary\']")'
        );
        if (signedIn) break;
        const issue = await evaluate(
          'document.querySelector("[data-testid=\'identity-issue\']")?.innerText || ""'
        );
        // A credential rejection is final; do not burn retries on it.
        if (/rejected/i.test(issue || "")) {
          results.push({
            name: "the operator can sign in from the UI", ok: false,
            detail: `the server rejected the key: ${issue}`,
          });
          signedIn = "rejected";
          break;
        }
      }
    }
    if (signedIn === "rejected") {
      signedIn = false;
    } else if (keyField) {
      check("the operator can sign in from the UI", signedIn,
        "sign-in did not produce an identity after 4 attempts; "
        + "every write will answer 401");
    }
    browserToken = (await evaluate(
      'localStorage.getItem("proofops_jwt_token") || ""'
    )) || "";
    check("sign-in issued a bearer token", browserToken !== "",
      "no token in the page's storage, so later writes cannot authenticate");
    await screenshot("signed-in");
  } else {
    process.stderr.write(
      "ui_flow_check: PROOFOPS_API_KEY not set; the write path will 401 and the\n"
      + "              flow checks that need a credential will fail.\n");
  }

  // ---------------------------------------------------------------- step 1
  // The operator's first action: type an id and submit the ingest form.
  await goto("/");
  const formReady = await evaluate(
    '!!document.getElementById("new-incident") && !!document.getElementById("new-scenario")'
  );
  check("ingest form is present", formReady,
    "the Command Center has no incident-ingest form; the operator cannot start anything");
  await screenshot("command-center");

  const filled = await evaluate(`(() => {
    const set = (id, value) => {
      const el = document.getElementById(id);
      if (!el) return false;
      const proto = el instanceof HTMLTextAreaElement
        ? HTMLTextAreaElement : (el instanceof HTMLSelectElement
          ? HTMLSelectElement : HTMLInputElement);
      Object.getOwnPropertyDescriptor(proto.prototype, "value")
        .set.call(el, value);
      el.dispatchEvent(new Event("input", { bubbles: true }));
      el.dispatchEvent(new Event("change", { bubbles: true }));
      return true;
    };
    const ok = set("new-incident", ${JSON.stringify(incidentId)});
    set("new-scenario", "bad-deploy");
    set("new-service", "checkout-api");
    set("new-env", "prod");
    set("new-signature", "HTTP5xx");
    set("new-error-rate", "0.42");
    return ok;
  })()`);
  check("ingest form is fillable", filled, "could not set the incident id field");

  // Submit, retried. The form is filled the same way each attempt; only the
  // submission is repeated, because a cold API that 500s on the first write
  // would otherwise fail the run AND every step downstream of it, turning one
  // transient fault into six reported defects.
  let ingested = false;
  for (let attempt = 0; attempt < 3 && !ingested; attempt += 1) {
    await evaluate(`(() => {
      const form = document.getElementById("new-incident")?.closest("form");
      if (form) form.requestSubmit ? form.requestSubmit() : form.dispatchEvent(
        new Event("submit", { bubbles: true, cancelable: true }));
      return true;
    })()`);
    for (let i = 0; i < 8; i += 1) {
      await sleep(1000);
      const body = await text();
      if (/queued|accepted|not processed/i.test(body || "")) { ingested = true; break; }
    }
  }
  check("ingest was acknowledged in the UI", ingested,
    "no server acknowledgement rendered after submitting the ingest form");
  await screenshot("after-ingest");

  // The run must exist server-side, or nothing was actually submitted.
  let run = null;
  for (let i = 0; i < 30; i += 1) {
    run = await apiGet(`/runs/${encodeURIComponent(incidentId)}`);
    if (run) break;
    await sleep(1000);
  }
  check("submitted incident exists server-side", Boolean(run),
    `GET /runs/${incidentId} did not return a run`);

  // ---------------------------------------------------------------- step 2
  // The orchestrator must drive it to the human gate.
  for (let i = 0; i < 60; i += 1) {
    run = await apiGet(`/runs/${encodeURIComponent(incidentId)}`);
    if (run && run.state === "AWAITING_APPROVAL") break;
    await sleep(1000);
  }
  check("orchestrator drove the run to AWAITING_APPROVAL",
    run && run.state === "AWAITING_APPROVAL",
    `run ended in ${run?.state} instead of parking for approval`);

  // ---------------------------------------------------------------- step 3
  // The Safety Gate must show the PIPELINE'S proposal, not a blank template.
  await goto(`/#/safety?incident_id=${encodeURIComponent(incidentId)}`);
  await sleep(2200);
  const gateText = (await text()) || "";
  check("Safety Gate lists the pipeline's own proposal",
    /awaiting a decision|rollback_deployment|parked/i.test(gateText),
    "the gate lists no parked action, so the operator cannot obtain what they are authorising");
  check("Safety Gate shows a real risk tier",
    /GREEN|YELLOW|RED|UNCLASSIFIED/.test(gateText),
    "no risk tier rendered; the tier must come from the parked proposal");
  await screenshot("safety-gate-proposals");

  const loaded = await evaluate(`(() => {
    const btn = [...document.querySelectorAll("button")]
      .find((b) => /load this action/i.test(b.textContent || ""));
    if (!btn) return false;
    btn.click();
    return true;
  })()`);
  check("a proposal can be loaded into the request form", loaded,
    "no 'Load this action' control on the gate");

  await sleep(900);
  const actionJson = await evaluate(
    'document.getElementById("action-json")?.value || ""'
  );
  check("loading a proposal fills the real action",
    actionJson.includes("rollback_deployment") && actionJson.includes("evidence_ids"),
    `the request form did not receive the planned action (got ${actionJson.length} chars)`);

  // ---------------------------------------------------------------- step 4
  // Raise the approval and decide it, exactly as an operator would.
  const requested = await apiPost("/approvals", {
    action: JSON.parse(actionJson),
  });
  check("the proposed action is acceptable to the server",
    requested.status === 200 || requested.status === 201,
    `POST /approvals returned ${requested.status}: ${JSON.stringify(requested.body).slice(0, 160)}`);

  if (requested.body?.approval_id && requested.body?.token) {
    const approved = await apiPost(
      `/approvals/${encodeURIComponent(requested.body.approval_id)}/approve`,
      { token: requested.body.token, idempotency_key: `ui-flow-${stamp}` },
    );
    check("the approval can be granted",
      approved.status === 200 && approved.body?.status === "approved",
      `approve returned ${approved.status}: ${JSON.stringify(approved.body).slice(0, 160)}`);

    for (let i = 0; i < 60; i += 1) {
      run = await apiGet(`/runs/${encodeURIComponent(incidentId)}`);
      if (run && ["RESOLVED", "AUDITED", "ESCALATED", "ROLLBACK", "BLOCKED"]
        .includes(run.state)) break;
      await sleep(1000);
    }
    // Terminal state, with the target named rather than demanded.
    //
    // AUDITED is the honest destination: the FSM declares
    // RESOLVED -> RCA_PENDING -> RCA_PUBLISHED -> AUDITED, and only publishing a
    // gated postmortem gets there. Requiring it today would make this gate red
    // for a feature that is not built -- the resume path after a human approval
    // finishes at RESOLVED and never drives the post-incident stage -- and a
    // gate that is always red is a gate people switch off. So the terminal state
    // is asserted, and the shortfall is named in the detail so it is visible in
    // the report rather than hidden or promoted into a false failure.
    const reached = run?.state;
    const shortOfAudited = Boolean(reached) && reached !== "AUDITED";
    check("the approved run reached a terminal state",
      Boolean(reached) && ["RESOLVED", "AUDITED", "ESCALATED", "ROLLBACK", "BLOCKED"].includes(reached),
      shortOfAudited
        ? `run ended in ${reached}. AUDITED is the target: the resume path does not yet drive the post-incident stage, so no gated postmortem was published. Owner: RCA renderer lane.`
        : `run ended in ${reached}`);

    // ---------------------------------------------------------------- step 4b
    // The post-incident stage. The run must not merely finish at RESOLVED: the
    // FSM's declared terminal state is AUDITED, reached only by publishing a
    // gated postmortem, and before this stage was driven no run ever got there.
    for (let i = 0; i < 40; i += 1) {
      run = await apiGet(`/runs/${encodeURIComponent(incidentId)}`);
      if (run && run.state === "AUDITED") break;
      await sleep(1000);
    }
    check("the run reached the terminal AUDITED state", run?.state === "AUDITED",
      `run is in ${run?.state}; AUDITED requires a published postmortem`);

    const postmortem = await apiGet(
      `/incidents/${encodeURIComponent(incidentId)}/rca`);
    check("the postmortem is published and ungated",
      postmortem?.published === true && postmortem?.report?.gated === false,
      `GET /rca reported published=${postmortem?.published} `
      + `gated=${postmortem?.report?.gated}`);
    check("the postmortem carries grounded claims",
      Array.isArray(postmortem?.report?.claim_ids)
        && postmortem.report.claim_ids.length > 0,
      "a published postmortem with no claims would mean the coverage gate was vacuous");
    check("the postmortem carries a remediation and approval record",
      Array.isArray(postmortem?.report?.remediation_log)
        && postmortem.report.remediation_log.length > 0,
      "the postmortem has no remediation/approval/verification record");
    check("the postmortem carries blameless prevention notes",
      Array.isArray(postmortem?.report?.prevention)
        && postmortem.report.prevention.length > 0,
      "the postmortem has no prevention notes");

    // ---------------------------------------------------------------- step 5
    // The evidence the Execution view exists to show.
    check("the executed run reports its real executor tier",
      ["mock", "docker", "k8s"].includes(run?.execution_tier),
      `execution_tier is ${JSON.stringify(run?.execution_tier)}`);
    check("the executed run carries a real state diff",
      Boolean(run?.state_diff?.changed && Object.keys(run.state_diff.changed).length),
      "no state diff on a run that executed");
    check("the executed run carries executor output",
      Array.isArray(run?.execution_logs) && run.execution_logs.length > 0,
      "no executor output on a run that executed");
    const verdicts = run?.verification_results || [];
    check("the executed run carries a real verifier verdict",
      verdicts.length > 0 && Boolean(verdicts[0].verdict),
      "no verification verdict banked on a run that executed");
    check("the verdict carries its per-check results",
      verdicts.length > 0 && verdicts[0].checks
        && Object.keys(verdicts[0].checks).length > 0,
      "the banked verdict has no checks, so it is a label rather than evidence");

    await goto(`/#/execution/${encodeURIComponent(incidentId)}`);
    await sleep(2200);
    const execText = (await text()) || "";
    check("Execution view shows the real verdict", /RESOLVED|PARTIAL|FAILED|WORSENED|ROLLBACK_REQUIRED|ESCALATED/.test(execText),
      "the Execution view rendered no verifier verdict");
    check("Execution view shows the per-check results", /PASS|FAIL/.test(execText),
      "the Execution view rendered no per-check pass/fail");
    check("Execution view shows the state diff",
      /deployment_version|error_rate|replicas|config_rev|restarts/.test(execText),
      "the Execution view rendered no state diff");
    check("Execution view does not claim an exit code",
      !/EXIT CODE/.test(execText),
      "the Execution view still shows a fabricated process status");
    await screenshot("execution");

    // ---------------------------------------------------------------- step 6
    // The audit surface.
    await goto(`/#/rca/${encodeURIComponent(incidentId)}`);
    await sleep(2500);
    const auditText = (await text()) || "";
    check("Audit view shows a verifying chain", /chain valid/i.test(auditText),
      "the audit chain did not report itself valid");
    check("Audit view shows event timestamps",
      /\d{1,2}:\d{2}/.test(auditText),
      "the audit list has no time axis");
    check("Audit view shows the policy decision",
      /policy/i.test(auditText) && /YELLOW|GREEN|RED|DENY|ALLOW|ESCALATE/.test(auditText),
      "the authorization outcome is invisible in the audit surface");

    // The postmortem must be RENDERED, not merely served. An operator
    // reconstructing an incident needs the cause, the record and the prevention
    // notes on the page.
    const showsPostmortem = await evaluate(
      '!!document.querySelector("[data-testid=\'rca-document\']")'
    );
    check("the postmortem is rendered on the page", showsPostmortem,
      "the RCA view served no postmortem document; the operator path ends "
      + "without a usable incident record");
    check("the rendered postmortem shows a verified root cause",
      /Verified root cause/i.test(auditText) || /root cause/i.test(auditText),
      "no root-cause section rendered");
    check("the rendered postmortem shows the prevention notes",
      /Prevention notes/i.test(auditText),
      "no prevention notes rendered");
    check("the view no longer claims it cannot render an RCA",
      !/does not render an RCA document/i.test(auditText),
      "the view still states it renders no postmortem, which is now false");

    const verified = await apiPost(`/incidents/${encodeURIComponent(incidentId)}/audit/verify`);
    check("the chain recomputes as valid",
      verified.status === 200 && verified.body?.valid === true,
      `audit verify returned ${verified.status}: ${JSON.stringify(verified.body).slice(0, 160)}`);
    await screenshot("audit");
  }

  chrome.kill();

  const failed = results.filter((r) => !r.ok);
  const report = {
    incident_id: incidentId,
    final_state: run?.state ?? null,
    checks: results,
    problems,
  };
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (problems.length || failed.length) {
    process.stderr.write(`\nui_flow_check: ${failed.length}/${results.length} checks failed\n`);
    process.exit(1);
  }
  process.stderr.write(`ui_flow_check: all ${results.length} checks passed\n`);
  process.exit(0);
}

main().catch((e) => fail(`unexpected: ${e && e.stack ? e.stack : e}`));
