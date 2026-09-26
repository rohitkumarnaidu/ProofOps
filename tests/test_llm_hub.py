"""Tests for Multi-Provider AI Workforce Inference Hub."""
import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from agents.llm_hub import LLMHub, DirectLLMClient, _get_env_key
from agents.lyzr_client import LyzrClient


def test_llm_hub_active_provider_default():
    with patch.dict(os.environ, {}, clear=True):
        info = LLMHub.active_provider()
        assert info["provider"] == "scripted-oracle"
        assert info["status"] == "OFFLINE"
        assert info["tier"] == "deterministic-baseline"


def test_llm_hub_active_provider_lyzr():
    with patch.dict(os.environ, {"LYZR_API_KEY": "lyzr-secret-key"}):
        info = LLMHub.active_provider()
        assert info["provider"] == "lyzr"
        assert info["status"] == "CONNECTED"
        assert info["tier"] == "enterprise-studio"


def test_llm_hub_active_provider_openai():
    with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-openai-key"}, clear=True):
        info = LLMHub.active_provider()
        assert info["provider"] == "openai"
        assert info["status"] == "CONNECTED"
        assert info["tier"] == "direct-llm"


def test_llm_hub_active_provider_anthropic():
    with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-key"}, clear=True):
        info = LLMHub.active_provider()
        assert info["provider"] == "anthropic"
        assert info["status"] == "CONNECTED"


def test_llm_hub_active_provider_gemini():
    with patch.dict(os.environ, {"GEMINI_API_KEY": "ai-gemini-key"}, clear=True):
        info = LLMHub.active_provider()
        assert info["provider"] == "gemini"
        assert info["status"] == "CONNECTED"


def test_llm_hub_get_client_fallback_to_scripted():
    with patch.dict(os.environ, {}, clear=True):
        client = LLMHub.get_client("A1_triage", {"severity": "P1"})
        result = client.chat("A1_triage", "sess-1", "normalize alert")
        assert result.mode in ("MOCK", "FALLBACK", "CONNECTED")
        assert result.payload["severity"] == "P1"


def test_llm_hub_get_client_openai():
    with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-openai-key"}, clear=True):
        client = LLMHub.get_client("A1_triage")
        assert isinstance(client, DirectLLMClient)
        assert client.provider == "openai"
        assert client.model == "gpt-4o"


def test_direct_llm_client_chat_json_parsing():
    client = DirectLLMClient("openai", "test-key", "gpt-4o")
    with patch.object(client, "_call_provider", return_value='```json\n{"status": "ok", "action": "restart"}\n```'):
        res = client.chat("A3_remediation", "sess-10", "plan fix")
        assert res.mode == "CONNECTED"
        assert res.payload == {"status": "ok", "action": "restart"}
        assert res.rai_policy == "Direct-openai"
        assert res.latency_ms >= 0


def test_direct_llm_client_chat_error_fallback():
    client = DirectLLMClient("openai", "test-key", "gpt-4o")
    with patch.object(client, "_call_provider", side_effect=RuntimeError("Rate limit exceeded")):
        res = client.chat("A3_remediation", "sess-10", "plan fix")
        assert res.mode == "FALLBACK"
        assert res.payload is None
        assert "Rate limit exceeded" in res.fallback_reason
