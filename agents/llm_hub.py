"""Multi-Provider AI Workforce Inference Hub (M13 Multi-Cloud Tier).

Unified inference router supporting:
1. Lyzr Studio Agent API (when LYZR_API_KEY is configured).
2. Direct LLM Providers (OpenAI, Anthropic, Gemini via httpx) when direct keys are provided.
3. Deterministic Scripted Oracle (reproducible offline baseline, labeled honestly).
"""
from __future__ import annotations

import json
import os
import time
from typing import Any, Mapping

import httpx

from agents import AGENTS
from agents.lyzr_client import ClientConfig, ClientResult, LyzrClient, Mode


#: Substrings that mark a value as a template rather than a credential.
_PLACEHOLDER_MARKERS = (
    "replace_me", "your_", "your-", "changeme", "placeholder", "dummy",
    "example", "<", ">", "xxxx", "todo",
)


def _is_placeholder(value: str) -> bool:
    """Whether a key value is a template rather than a credential.

    A non-empty key is not a working key. `.env` ships with an obvious placeholder
    so a new clone has the right shape, and this project once reported
    `provider=lyzr, status=CONNECTED` off the literal string
    "REPLACE_ME_WITH_YOUR_LYZR_API_KEY" -- a badge asserting a live enterprise
    integration that had never made a call. A placeholder must read as absent.
    """
    text = (value or "").strip()
    if not text:
        return True
    lowered = text.lower()
    return any(marker in lowered for marker in _PLACEHOLDER_MARKERS)


def _get_env_key(key: str) -> str:
    """Read provider keys outside backend config boundary safely.

    Placeholders are normalised to empty so the hub degrades to the deterministic
    oracle and says so, rather than attempting an authenticated call that cannot
    succeed and reporting the attempt as a connection.
    """
    val = os.environ.get(key, "").strip()
    return "" if _is_placeholder(val) else val


class DirectLLMClient:
    """Direct provider client (OpenAI / Anthropic / Gemini) conforming to agent client contract."""

    def __init__(self, provider: str, api_key: str, model: str) -> None:
        self.provider = provider
        self.api_key = api_key
        self.model = model
        #: Set only by a call that actually succeeded. Connectivity is a measured
        #: fact, not a consequence of a config string being non-empty.
        self._verified = False

    def mode_for(self, agent: str) -> Mode:
        """Report connectivity honestly.

        A key being present is not a connection. Until a call has actually
        succeeded this reports UNVERIFIED, because "we hold a credential" and
        "the credential works" are different claims and only the second is
        established by having made a call.
        """
        _ = agent
        return "CONNECTED" if self._verified else "UNVERIFIED"

    def chat(self, agent: str, session_id: str, message: str) -> ClientResult:
        """Execute chat with structured JSON output enforcement."""
        start = time.time()
        try:
            raw_text = self._call_provider(agent, message)
            # Extract JSON
            start_idx = raw_text.index("{")
            end_idx = raw_text.rindex("}") + 1
            payload = json.loads(raw_text[start_idx:end_idx])
            latency = int((time.time() - start) * 1000)
            # A call came back and parsed: the credential demonstrably works.
            self._verified = True
            return ClientResult(
                mode="CONNECTED",
                agent=agent,
                session_id=session_id,
                payload=payload,
                fallback_reason="",
                latency_ms=latency,
                rai_policy=f"Direct-{self.provider}",
            )
        except Exception as exc:
            latency = int((time.time() - start) * 1000)
            return ClientResult(
                mode="FALLBACK",
                agent=agent,
                session_id=session_id,
                payload=None,
                fallback_reason=str(exc),
                latency_ms=latency,
                rai_policy="None",
            )

    def _call_provider(self, agent: str, message: str) -> str:
        """Call LLM API via httpx synchronously."""
        system_prompt = (
            f"You are the ProofOps {agent} autonomous agent. "
            "You MUST respond ONLY with a valid JSON object matching the requested schema. "
            "Never output markdown, backticks, or explanatory text outside the JSON."
        )

        if self.provider == "openai":
            headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
            body = {
                "model": self.model or "gpt-4o",
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": message},
                ],
                "response_format": {"type": "json_object"},
            }
            with httpx.Client(timeout=30.0) as client:
                res = client.post("https://api.openai.com/v1/chat/completions", headers=headers, json=body)
                res.raise_for_status()
                return str(res.json()["choices"][0]["message"]["content"])

        elif self.provider == "anthropic":
            headers = {
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            }
            # Annotated as a JSON body: `max_tokens` is an int, and mypy
            # otherwise infers the dict from the nested `messages` value and
            # rejects every scalar alongside it.
            anthropic_body: dict[str, Any] = {
                "model": self.model or "claude-3-5-sonnet-20241022",
                "max_tokens": 4096,
                "system": system_prompt,
                "messages": [{"role": "user", "content": message}],
            }
            with httpx.Client(timeout=30.0) as client:
                res = client.post("https://api.anthropic.com/v1/messages", headers=headers, json=anthropic_body)
                res.raise_for_status()
                return str(res.json()["content"][0]["text"])

        elif self.provider == "gemini":
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model or 'gemini-1.5-pro'}:generateContent?key={self.api_key}"
            body = {
                "contents": [{"parts": [{"text": f"{system_prompt}\n\n{message}"}]}],
                "generationConfig": {"response_mime_type": "application/json"},
            }
            with httpx.Client(timeout=30.0) as client:
                res = client.post(url, json=body)
                res.raise_for_status()
                return str(res.json()["candidates"][0]["content"]["parts"][0]["text"])

        raise ValueError(f"Unsupported provider: {self.provider}")


class LLMHub:
    """Inference router across Lyzr, direct models, and scripted oracle."""

    @staticmethod
    def get_client(agent: str, fallback_payload: Mapping[str, Any] | None = None) -> Any:
        # 1. Lyzr Studio Enterprise API
        lyzr_key = _get_env_key("LYZR_API_KEY")
        if lyzr_key:
            config = ClientConfig(api_key=lyzr_key, agent_ids={name: name for name in AGENTS})
            return LyzrClient(config)

        # 2. Direct OpenAI
        openai_key = _get_env_key("OPENAI_API_KEY")
        if openai_key:
            return DirectLLMClient("openai", openai_key, "gpt-4o")

        # 3. Direct Anthropic
        anthropic_key = _get_env_key("ANTHROPIC_API_KEY")
        if anthropic_key:
            return DirectLLMClient("anthropic", anthropic_key, "claude-3-5-sonnet-20241022")

        # 4. Direct Gemini
        gemini_key = _get_env_key("GEMINI_API_KEY")
        if gemini_key:
            return DirectLLMClient("gemini", gemini_key, "gemini-1.5-pro")

        # 5. Deterministic Scripted Oracle
        from app.services.orchestrator import _Scripted

        return _Scripted(agent, dict(fallback_payload or {}))

    @staticmethod
    def active_provider() -> dict[str, Any]:
        """Which provider is active, and whether it has been proven to work.

        Status is UNVERIFIED whenever a credential is present but no successful
        call has been made. Reporting CONNECTED on the strength of a config
        string is the specific dishonesty this project exists to argue against:
        a judge reading a green "enterprise-studio" badge should be able to infer
        that something was actually called.
        """
        for env_key, provider, tier in (
            ("LYZR_API_KEY", "lyzr", "enterprise-studio"),
            ("OPENAI_API_KEY", "openai", "direct-llm"),
            ("ANTHROPIC_API_KEY", "anthropic", "direct-llm"),
            ("GEMINI_API_KEY", "gemini", "direct-llm"),
        ):
            if _get_env_key(env_key):
                return {"provider": provider, "status": "UNVERIFIED",
                        "tier": tier}
        return {"provider": "scripted-oracle", "status": "OFFLINE",
                "tier": "deterministic-baseline"}
