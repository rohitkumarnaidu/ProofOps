"""ProofOps Step 1 — Lyzr connectivity verification (stdlib only, no deps).

Checks, per PS03_FINAL_SPEC_V2 §10:
  LYZR_CONNECTIVITY · AGENT_TEST · STRUCTURED_OUTPUT_TEST · SESSION_TEST
  STREAM_TEST · RAI_TEST · KB_TEST · TRACE_TEST

Each result: AVAILABLE | UNAVAILABLE | UNVERIFIED (+ detail).
Missing key / agent id => agent-dependent tests report UNVERIFIED (approved fallback:
local mock agent client) — never faked as AVAILABLE.

Usage:
  set LYZR_API_KEY=...        (required for agent tests)
  set LYZR_AGENT_ID=...       (optional; triage agent id for live tests)
  python scripts/verify_lyzr.py
"""
from __future__ import annotations

import json
import os
import socket
import sys
import urllib.error
import urllib.request

OK, FAIL, NA = "AVAILABLE", "UNAVAILABLE", "UNVERIFIED"
BASES = [
    "https://studio.lyzr.ai",
    "https://agent-prod.studio.lyzr.ai",
]
TIMEOUT = 15
results: list[tuple[str, str, str]] = []


def put(name: str, status: str, detail: str) -> None:
    results.append((name, status, detail))
    print(f"[{status:11}] {name}: {detail}")


def check_dns(host: str) -> bool:
    try:
        socket.getaddrinfo(host, 443)
        return True
    except OSError:
        return False


def http_get(url: str) -> tuple[int | None, str]:
    req = urllib.request.Request(url, method="GET",
                                 headers={"User-Agent": "ProofOps-verify/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status, "ok"
    except urllib.error.HTTPError as e:
        return e.code, f"HTTP {e.code}"
    except Exception as e:  # network down, DNS, TLS, ...
        return None, f"{type(e).__name__}: {e}"


def http_post(url: str, payload: dict, headers: dict) -> tuple[int | None, str, str]:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, "ok", r.read(2000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            body = e.read(2000).decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, f"HTTP {e.code}", body
    except Exception as e:
        return None, f"{type(e).__name__}: {e}", ""


def main() -> int:
    key = os.environ.get("LYZR_API_KEY", "").strip()
    agent_id = os.environ.get("LYZR_AGENT_ID", "").strip()

    # 1. Raw network path to Lyzr control plane hosts.
    dns_ok = any(check_dns(h.split("://")[1]) for h in BASES)
    if not dns_ok:
        put("LYZR_CONNECTIVITY", FAIL, "DNS resolution failed for Lyzr hosts")
    else:
        codes = {b: http_get(b)[0] for b in BASES}
        if any(c is not None for c in codes.values()):
            put("LYZR_CONNECTIVITY", OK, f"hosts reachable {codes}")
        else:
            put("LYZR_CONNECTIVITY", FAIL, f"hosts unreachable {codes}")

    # 2-8. Agent-level tests need key + agent id.
    if not key:
        for t, why in [
            ("AGENT_TEST", "LYZR_API_KEY not set"),
            ("STRUCTURED_OUTPUT_TEST", "LYZR_API_KEY not set"),
            ("SESSION_TEST", "LYZR_API_KEY not set"),
            ("STREAM_TEST", "LYZR_API_KEY not set"),
            ("RAI_TEST", "LYZR_API_KEY not set; RAI is Studio-side config anyway"),
            ("KB_TEST", "LYZR_API_KEY not set; KB is Studio-side config anyway"),
            ("TRACE_TEST", "LYZR_API_KEY not set; trace is Studio-side, verify in UI"),
        ]:
            put(t, NA, why + " -> fallback: local mock agent client")
        return 0 if dns_ok else 1

    if not agent_id:
        for t in ["AGENT_TEST", "STRUCTURED_OUTPUT_TEST", "SESSION_TEST",
                  "STREAM_TEST", "RAI_TEST", "KB_TEST", "TRACE_TEST"]:
            put(t, NA, "LYZR_AGENT_ID not set -> fallback: local mock agent client")
        return 0

    headers = {"Content-Type": "application/json", "x-api-key": key,
               "User-Agent": "ProofOps-verify/1.0"}
    chat_url = f"https://agent-prod.studio.lyzr.ai/v3/agent/{agent_id}/chat"

    # 2. Basic chat round-trip.
    st, msg, body = http_post(chat_url, {"message": "Reply with exactly: PONG",
                                         "session_id": "proofops-verify-1"}, headers)
    if st == 200 and "PONG" in body:
        put("AGENT_TEST", OK, "chat round-trip ok")
    elif st in (401, 403):
        put("AGENT_TEST", FAIL, f"auth rejected ({msg}); check key/agent id")
        for t in ["STRUCTURED_OUTPUT_TEST", "SESSION_TEST", "STREAM_TEST"]:
            put(t, NA, "blocked on auth")
        for t in ["RAI_TEST", "KB_TEST", "TRACE_TEST"]:
            put(t, NA, "verify in Studio UI (Safety and Evaluations / Tracing)")
        return 1
    else:
        put("AGENT_TEST", FAIL, f"{msg} {body[:200]}")
        for t in ["STRUCTURED_OUTPUT_TEST", "SESSION_TEST", "STREAM_TEST"]:
            put(t, NA, "blocked on chat failure")
        for t in ["RAI_TEST", "KB_TEST", "TRACE_TEST"]:
            put(t, NA, "verify in Studio UI")
        return 1

    # 3. Structured output: agent must return JSON with required keys
    #    (requires Structured Output schema configured on the agent in Studio).
    st, msg, body = http_post(
        chat_url,
        {"message": 'Return JSON only: {"action_type": "read", "resource_id": "x"}',
         "session_id": "proofops-verify-2"}, headers)
    try:
        obj = json.loads(body[body.index("{"):body.rindex("}") + 1])
        if isinstance(obj, dict) and "action_type" in obj:
            put("STRUCTURED_OUTPUT_TEST", OK, f"JSON keys={sorted(obj)[:5]}")
        else:
            put("STRUCTURED_OUTPUT_TEST", FAIL, "JSON missing required keys")
    except Exception:
        put("STRUCTURED_OUTPUT_TEST", FAIL,
            "non-JSON response; configure Structured Output schema in Studio")

    # 4. Session persistence: same session_id must retain context.
    sid = "proofops-verify-session"
    http_post(chat_url, {"message": "Remember the codeword BRAVO.", "session_id": sid}, headers)
    st, msg, body = http_post(
        chat_url, {"message": "What was the codeword?", "session_id": sid}, headers)
    put("SESSION_TEST", OK if "BRAVO" in body else FAIL,
        "session retained codeword" if "BRAVO" in body else f"no recall: {body[:160]}")

    # 5. Streaming endpoint reachable (SSE).
    stream_url = f"https://agent-prod.studio.lyzr.ai/v3/agent/{agent_id}/stream-chat"
    st, msg, body = http_post(stream_url, {"message": "hi", "session_id": sid}, headers)
    put("STREAM_TEST",
        OK if st == 200 and ("text/event-stream" in body or "data:" in body) else
        (NA if st in (404, 405, 422) else FAIL),
        f"{msg} (SSE stream-chat)")

    # 6-8. Studio-side config: can only be asserted live with a policy/KB/trace
    # wired to this agent; report UNVERIFIED with the UI path.
    for t, path in [
        ("RAI_TEST", "Studio > agent > Responsible AI card > policy PS03-Governed"),
        ("KB_TEST", "Studio > agent > Knowledge Base > runbooks-v* attached"),
        ("TRACE_TEST", "Studio > Tracing/Transcripts for session proofops-verify-*"),
    ]:
        put(t, NA, f"assert in Studio UI: {path}")

    failed = [r for r in results if r[1] == FAIL]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks non-failing "
          f"({len(failed)} FAIL).")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
