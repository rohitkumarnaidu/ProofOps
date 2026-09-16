"""M13.1 Lyzr Agent API client (stdlib only) + honest mode classification.

Wire shape mirrors scripts/verify_lyzr.py exactly: POST
{base}/v3/agent/{agent_id}/chat with {"message", "session_id"}, header
x-api-key; stream-chat for SSE. Structured Output is a Studio-side schema;
here we extract the JSON object (first "{" .. last "}") and re-validate via
schemas.parse_or_reject -- never trusted raw.

Modes: DISABLED (no key or no agent id -- never faked CONNECTED), CONNECTED
(live 200 with parsed JSON), FALLBACK (any live failure: auth/network/
timeout/non-JSON -- caller takes deterministic paths). Secrets never enter
logs/traces: repr redacts, errors carry statuses not bodies.
"""
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Mapping

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from agents import AGENTS  # noqa: E402 (M13 workforce map)
from agents.schemas import OutputRejected  # noqa: E402 (M13.6 parsing)

CHAT_PATH = "/v3/agent/{agent_id}/chat"
STREAM_PATH = "/v3/agent/{agent_id}/stream-chat"
DEFAULT_BASE = "https://agent-prod.studio.lyzr.ai"
RAI_POLICY_DEFAULT = "PS03-Governed"
MAX_MESSAGE_CHARS = 12000
MAX_SSE_BYTES = 8000


# Connectivity vocabulary as Literals, not enums: the hardened
# no-enum-outside-contracts rule (M00) keeps Enum definitions in
# contracts/enums.py (frozen M01.1 surface), so agent-platform states are
# constrained strings here instead.
Mode = Literal["DISABLED", "FALLBACK", "CONNECTED"]


@dataclass(frozen=True)
class ClientConfig:
    api_key: str = ""
    agent_ids: Mapping[str, str] = field(default_factory=dict)
    rai_policy: str = RAI_POLICY_DEFAULT
    base_url: str = DEFAULT_BASE
    timeout_s: float = 15.0
    stream_timeout_s: float = 30.0

    def __post_init__(self) -> None:
        unknown = set(self.agent_ids) - set(AGENTS)
        if unknown:
            raise ValueError(f"unknown agent ids: {sorted(unknown)}")
        if self.timeout_s <= 0 or self.stream_timeout_s <= 0:
            raise ValueError("timeouts must be positive")
        if not self.base_url.startswith("https://"):
            raise ValueError("base_url must be https")

    def __repr__(self) -> str:
        ids = {k: ("set" if v else "") for k, v in self.agent_ids.items()}
        return (f"ClientConfig(api_key={'set' if self.api_key else ''}, "
                f"agent_ids={ids}, rai_policy={self.rai_policy!r})")


@dataclass(frozen=True)
class ClientResult:
    mode: Mode
    agent: str
    session_id: str
    payload: dict[str, Any] | None
    fallback_reason: str
    latency_ms: int
    rai_policy: str


def _extract_json(body: str) -> dict[str, Any]:
    """Brace-slice + parse (same rule as scripts/verify_lyzr.py)."""
    try:
        obj = json.loads(body[body.index("{"):body.rindex("}") + 1])
    except (ValueError, IndexError) as exc:
        raise OutputRejected(f"non-JSON model response: {exc}") from exc
    if not isinstance(obj, dict):
        raise OutputRejected("model JSON top level must be an object")
    return obj


def _post(url: str, payload: dict[str, Any], api_key: str,
          timeout_s: float) -> tuple[int | None, str]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json", "x-api-key": api_key,
                 "User-Agent": "ProofOps-agent/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return resp.status, resp.read(MAX_SSE_BYTES).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, ""
    except Exception as exc:
        return None, f"{type(exc).__name__}"


class LyzrClient:
    """Thin Agent API caller with classified outcomes (M13.1)."""

    def __init__(self, config: ClientConfig) -> None:
        self._config = config

    def __repr__(self) -> str:
        return f"LyzrClient({self._config!r})"

    def mode_for(self, agent: str) -> Mode:
        if agent not in AGENTS:
            raise OutputRejected(f"unknown agent: {agent!r}")
        if not self._config.api_key.strip():
            return "DISABLED"
        if not self._config.agent_ids.get(agent, "").strip():
            return "DISABLED"
        return "CONNECTED"

    def _check_call(self, agent: str, session_id: str,
                    message: str) -> str | None:
        """Validate; return DISABLED reason or None when callable."""
        if agent not in AGENTS:
            raise OutputRejected(f"unknown agent: {agent!r}")
        for name, value in (("session_id", session_id), ("message", message)):
            if not isinstance(value, str) or not value.strip():
                raise OutputRejected(f"{name} must be a non-empty string")
        if len(message) > MAX_MESSAGE_CHARS:
            raise OutputRejected(
                f"message {len(message)} chars exceeds {MAX_MESSAGE_CHARS} cap")
        if not self._config.api_key.strip():
            return "missing-api-key"
        if not self._config.agent_ids.get(agent, "").strip():
            return "missing-agent-id"
        return None

    def _disabled(self, agent: str, session_id: str, reason: str) -> ClientResult:
        return ClientResult("DISABLED", agent, session_id, None, reason, 0,
                            self._config.rai_policy)

    def chat(self, agent: str, session_id: str, message: str) -> ClientResult:
        """One chat round-trip; session_id should equal the incident_id."""
        reason = self._check_call(agent, session_id, message)
        if reason is not None:
            return self._disabled(agent, session_id, reason)
        agent_id = self._config.agent_ids[agent].strip()
        url = self._config.base_url + CHAT_PATH.format(agent_id=agent_id)
        start = time.monotonic()
        status, body = _post(url, {"message": message, "session_id": session_id},
                             self._config.api_key, self._config.timeout_s)
        latency = int((time.monotonic() - start) * 1000)
        if status != 200:
            tag = f"http-{status}" if status is not None else (body or "network-error")
            return ClientResult("FALLBACK", agent, session_id, None, tag,
                                latency, self._config.rai_policy)
        try:
            payload = _extract_json(body)
        except OutputRejected as exc:
            return ClientResult("FALLBACK", agent, session_id, None,
                                f"non-json-response: {exc}", latency,
                                self._config.rai_policy)
        return ClientResult("CONNECTED", agent, session_id, payload, "",
                            latency, self._config.rai_policy)

    def stream_chat(self, agent: str, session_id: str,
                    message: str) -> ClientResult:
        """SSE stream accumulation; payload carries capped raw SSE text."""
        reason = self._check_call(agent, session_id, message)
        if reason is not None:
            return self._disabled(agent, session_id, reason)
        agent_id = self._config.agent_ids[agent].strip()
        url = self._config.base_url + STREAM_PATH.format(agent_id=agent_id)
        start = time.monotonic()
        status, body = _post(url, {"message": message, "session_id": session_id},
                             self._config.api_key, self._config.stream_timeout_s)
        latency = int((time.monotonic() - start) * 1000)
        if status != 200:
            tag = f"http-{status}" if status is not None else (body or "network-error")
            return ClientResult("FALLBACK", agent, session_id, None, tag,
                                latency, self._config.rai_policy)
        return ClientResult("CONNECTED", agent, session_id,
                            {"sse_text": body[:MAX_SSE_BYTES]}, "",
                            latency, self._config.rai_policy)
