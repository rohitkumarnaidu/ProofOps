#!/usr/bin/env node
// Browser QA gate for the ProofOps UI (M19).
//
// Why this exists, and why it is not a test-runner dependency:
//
// Every one of the four defects found in the frontend pass was invisible to
// the static suite. A blank white screen from an empty API base, an input
// rendering with no border because a spread order dropped its classes, and a
// red "stream disconnected" banner on a perfectly healthy backend all passed
// every source-grep test, `tsc`, and the dev server. A gate that only reads
// source cannot see a runtime defect, and the one thing this project must not
// get wrong is what the UI claims about itself.
//
// So this drives a real browser over the Chrome DevTools Protocol and asserts
// on the RENDERED result. It uses Node's built-in WebSocket (Node >= 22) and
// nothing else -- no Playwright, no Puppeteer, no new dependency in
// package.json. The alternative was letting the only tool that can catch these
// bugs live in a temp directory, which is the same as not having it.
//
// Usage:
//   node scripts/ui_browser_check.mjs                     # against :5173
//   PROOFOPS_UI_URL=http://127.0.0.1:5173 node scripts/ui_browser_check.mjs
//   node scripts/ui_browser_check.mjs --json              # machine-readable
//   node scripts/ui_browser_check.mjs --shots ./artifacts # keep screenshots
//
// Exit code 0 = every view/viewport combination clean, 1 = at least one is not,
// 2 = the environment could not support a run (no browser, no server).

import { spawn } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const BASE = (process.env.PROOFOPS_UI_URL || "http://127.0.0.1:5173").replace(/\/+$/, "");
const API = (process.env.PROOFOPS_API_URL || BASE).replace(/\/+$/, "");
const AS_JSON = process.argv.includes("--json");
const shotIndex = process.argv.indexOf("--shots");
const SHOTS = shotIndex === -1 ? null : process.argv[shotIndex + 1];
const CHROME = process.env.PROOFOPS_CHROME
  || [
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
  ].find((p) => existsSync(p));

const DEBUG_PORT = Number(process.env.PROOFOPS_CDP_PORT || 9411);

// The five MVP views. `%INCIDENT%` is substituted at run time.
//
// The incident id is DISCOVERED, never hardcoded. Pinning a literal id made
// this gate report 15 failures on a perfectly healthy system the moment that
// one run aged out of the store -- a gate that fails for reasons unrelated to
// the code under test trains people to ignore it, which is worse than not
// having it.
const VIEW_TEMPLATES = [
  ["command-center", "/"],
  ["incident", "/#/incidents/%INCIDENT%"],
  ["safety-gate", "/#/safety?incident_id=%INCIDENT%"],
  ["execution", "/#/execution/%INCIDENT%"],
  ["audit-eval", "/#/rca/%INCIDENT%"],
];

async function discoverIncident() {
  // Prefer a run that actually has history: a brand-new NEW run renders mostly
  // empty states, which would weaken what the sweep can see.
  try {
    const res = await fetch(`${API}/api/runs`);
    if (res.ok) {
      const runs = await res.json();
      if (Array.isArray(runs) && runs.length) {
        const rich = runs.find((r) => (r.history_len ?? 0) > 0) || runs[0];
        if (rich?.incident_id) return String(rich.incident_id);
      }
    }
  } catch { /* fall through */ }
  return "unknown-incident";
}

const VIEWPORTS = [
  [360, 800, "mobile"],
  [768, 1024, "tablet"],
  [1440, 1000, "desktop"],
];

// Rendered text that means the UI is telling the operator something untrue.
// A 401 on a key-gated endpoint is the CORRECT behaviour for the
// unauthenticated demo, so it is excluded -- the point of this gate is
// dishonesty, not the absence of authentication.
const FALSE_CLAIMS = [
  /Event stream update failed/i,
  /stream disconnected/i,
  /backend unreachable/i,
  /chain INVALID/i,
];

// Minimum rendered characters for a view to count as mounted. The shortest
// real view (Command Center, two incidents, MOCK badge) renders ~390, so 200
// is a wide margin that still cannot be met by a shell-only or half-rendered
// tree. Calibrated by measurement, not guessed at exactly.
const MIN_TEXT = 200;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function fetchJson(url, attempts = 40) {
  for (let i = 0; i < attempts; i += 1) {
    try {
      const res = await fetch(url);
      if (res.ok) return await res.json();
    } catch {
      /* not up yet */
    }
    await sleep(500);
  }
  return null;
}

function fail(message, code = 2) {
  if (AS_JSON) console.log(JSON.stringify({ ok: false, error: message }, null, 2));
  else console.error(`ui_browser_check: ${message}`);
  process.exit(code);
}

async function main() {
  if (!CHROME) fail("no Chrome/Chromium binary found; set PROOFOPS_CHROME");
  // Reachability only. Deliberately does not parse the body: the root returns
  // HTML, and a JSON parse failure swallowed here reads as "not reachable",
  // which reports an environment problem when the stack is actually fine.
  try {
    const res = await fetch(`${BASE}/`);
    if (!res.ok) fail(`UI at ${BASE} answered HTTP ${res.status}`, 2);
  } catch {
    fail(`UI not reachable at ${BASE}; start the stack first`, 2);
  }

  const profile = join(tmpdir(), `proofops-ui-qa-${process.pid}`);
  const chrome = spawn(CHROME, [
    "--headless=new",
    "--disable-gpu",
    "--no-sandbox",
    "--hide-scrollbars",
    `--remote-debugging-port=${DEBUG_PORT}`,
    `--user-data-dir=${profile}`,
    "--window-size=1440,1000",
    "about:blank",
  ], { stdio: "ignore" });

  const targets = await fetchJson(`http://127.0.0.1:${DEBUG_PORT}/json/list`);
  if (!targets?.length) {
    chrome.kill();
    fail("could not attach to Chrome via CDP");
  }

  const page = targets.find((t) => t.type === "page") || targets[0];
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  let nextId = 0;
  const pending = new Map();
  let problems = [];

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
    if (msg.method === "Log.entryAdded" && msg.params.entry.level === "error") {
      const text = msg.params.entry.text || "";
      if (!/status of 401/.test(text)) problems.push(`console ${text.slice(0, 140)}`);
    }
  });

  await new Promise((r) => ws.addEventListener("open", r, { once: true }));
  await send("Page.enable");
  await send("Runtime.enable");
  await send("Log.enable");
  await send("Network.enable");
  // A reused profile will happily serve a STALE bundle, which reads as "the
  // build is broken" when the truth is "you are testing the previous build".
  await send("Network.setCacheDisabled", { cacheDisabled: true });

  const incidentId = await discoverIncident();
  const views = VIEW_TEMPLATES.map(([name, tpl]) => [
    name, tpl.replaceAll("%INCIDENT%", encodeURIComponent(incidentId)),
  ]);
  const rows = [];
  for (const [width, height, vpName] of VIEWPORTS) {
    for (const [viewName, route] of views) {
      problems = [];
      await send("Emulation.setDeviceMetricsOverride", {
        width, height, deviceScaleFactor: 1, mobile: width < 500,
      });
      await send("Page.navigate", { url: BASE + route });
      await sleep(3000);

      const probe = await send("Runtime.evaluate", {
        returnByValue: true,
        expression: `(() => {
          const de = document.documentElement;
          const root = document.getElementById('root');
          return {
            kids: root ? root.childElementCount : -1,
            text: root ? root.innerText : '',
            len: root ? root.innerText.trim().length : -1,
            vw: de.clientWidth,
            sw: de.scrollWidth,
            h1: document.querySelectorAll('h1').length,
            regions: document.querySelectorAll('section[aria-labelledby]').length,
            sections: document.querySelectorAll('section').length,
            unlabeled: Array.from(
              document.querySelectorAll('input, select, textarea')
            ).filter((el) => {
              if (el.type === 'hidden' || el.type === 'submit') return false;
              const byFor = el.id && document.querySelector(
                'label[for="' + CSS.escape(el.id) + '"]'
              );
              return !(byFor || el.getAttribute('aria-label')
                       || el.getAttribute('aria-labelledby'));
            }).length,
          };
        })()`,
      });
      const r = probe.result?.value || {};
      const falseClaims = FALSE_CLAIMS.filter((re) => re.test(r.text || "")).map(
        (re) => re.source
      );
      const issues = [...problems, ...falseClaims.map((c) => `false claim: ${c}`)];
      // A child-count check alone is far too weak. When a view throws during
      // render, React can leave the shell's skip link mounted while the entire
      // operator UI is gone -- #root still had exactly one child in that state.
      // Content length is the check that actually distinguishes "mounted" from
      // "mounted the skip link and nothing else".
      if (!(r.kids > 0)) {
        issues.push(`#root has ${r.kids} children (view did not mount)`);
      } else if (r.len < MIN_TEXT) {
        issues.push(
          `only ${r.len} chars rendered (expected >= ${MIN_TEXT}); ` +
            "the view is likely blank or half-rendered"
        );
      }
      if (r.sw > r.vw + 1) issues.push(`horizontal overflow ${r.sw}>${r.vw}`);
      if (r.h1 !== 1) issues.push(`expected exactly one h1, found ${r.h1}`);
      if (r.sections < 1) issues.push("no content sections rendered");
      if (r.unlabeled > 0) issues.push(`${r.unlabeled} form control(s) without a label`);

      if (SHOTS) {
        const dir = resolve(SHOTS);
        mkdirSync(dir, { recursive: true });
        const { data } = await send("Page.captureScreenshot", { format: "png" });
        writeFileSync(join(dir, `${vpName}-${viewName}.png`), Buffer.from(data, "base64"));
      }

      rows.push({ view: viewName, viewport: vpName, ok: issues.length === 0, issues });
    }
  }

  ws.close();
  chrome.kill();

  const failed = rows.filter((r) => !r.ok);
  const report = { ok: failed.length === 0, base: BASE, incident: incidentId, total: rows.length, rows };
  if (AS_JSON) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log("view           viewport  result  issues");
    console.log("-".repeat(72));
    for (const r of rows) {
      console.log(
        `${r.view.padEnd(14)} ${r.viewport.padEnd(9)} ${(r.ok ? "ok" : "FAIL").padEnd(7)} ${r.issues.join("; ")}`
      );
    }
    console.log("-".repeat(72));
    console.log(
      report.ok
        ? `ALL CLEAN (${rows.length} view/viewport combinations)`
        : `${failed.length} of ${rows.length} combinations need attention`
    );
  }
  process.exit(report.ok ? 0 : 1);
}

main().catch((e) => fail(e.message));
