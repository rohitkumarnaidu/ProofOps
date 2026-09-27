"""Zero-trust tests for LLM provider honesty.

The specific failure this exists to prevent: a green "CONNECTED /
enterprise-studio" badge on a system that has never made a call.

It happened here. `.env` ships an obvious placeholder so a new clone has the
right shape, the hub inferred connectivity from the key being *non-empty*, and
`/api/meta/engines` cheerfully reported a live enterprise integration off the
literal string "REPLACE_ME_WITH_YOUR_LYZR_API_KEY". Everything else in this project
is careful to distinguish measured from assumed; the badge a judge is most
likely to read was the one that assumed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HUB = ROOT / "agents" / "llm_hub.py"
CLIENT = ROOT / "agents" / "lyzr_client.py"

import sys  # noqa: E402
sys.path.insert(0, str(ROOT))

from agents.llm_hub import (  # noqa: E402
    DirectLLMClient,
    LLMHub,
    _get_env_key,
    _is_placeholder,
)


# ---------------------------------------------------------------------------
# A placeholder is not a credential
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "REPLACE_ME_WITH_YOUR_LYZR_API_KEY",
        "replace_me",
        "your-api-key-here",
        "changeme",
        "placeholder",
        "dummy",
        "example",
        "<your-key>",
        "xxxxxxxx",
        "TODO",
    ],
)
def test_placeholder_values_read_as_absent(value):
    assert _is_placeholder(value), (
        f"{value!r} is a template, not a credential, and must read as absent")


@pytest.mark.parametrize(
    "value",
    ["sk-live-abc123", "lyzr_9f3c2b1a", "a" * 40],
)
def test_real_shaped_keys_are_not_treated_as_placeholders(value):
    assert not _is_placeholder(value), (
        f"{value!r} looks like a real credential and must be honoured")


def test_env_lookup_normalises_a_placeholder_to_empty(monkeypatch):
    """The hub must not attempt an authenticated call it knows cannot work."""
    monkeypatch.setenv("LYZR_API_KEY", "REPLACE_ME_WITH_YOUR_LYZR_API_KEY")
    assert _get_env_key("LYZR_API_KEY") == ""


# ---------------------------------------------------------------------------
# Presence is not connectivity
# ---------------------------------------------------------------------------

def test_a_key_present_but_unproven_reads_as_unverified(monkeypatch):
    """Having a credential and having used it are different claims."""
    monkeypatch.setenv("LYZR_API_KEY", "sk-real-looking-value-123")
    for other in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY"):
        monkeypatch.delenv(other, raising=False)
    st = LLMHub.active_provider()
    assert st["provider"] == "lyzr"
    assert st["status"] == "UNVERIFIED", (
        "a configured-but-uncalled provider must not claim CONNECTED")
    assert st["status"] != "CONNECTED"


def test_a_placeholder_leaves_the_deterministic_oracle_in_charge(monkeypatch):
    monkeypatch.setenv("LYZR_API_KEY", "REPLACE_ME_WITH_YOUR_LYZR_API_KEY")
    st = LLMHub.active_provider()
    assert st["provider"] == "scripted-oracle", (
        "a placeholder key must not select a provider that cannot be called")
    assert st["status"] == "OFFLINE"
    assert st["tier"] == "deterministic-baseline"


def test_no_key_at_all_also_falls_back(monkeypatch):
    for key in ("LYZR_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
                "GEMINI_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    assert LLMHub.active_provider()["provider"] == "scripted-oracle"


def test_direct_client_starts_unverified_and_only_verifies_on_success():
    """UNVERIFIED until a call demonstrably succeeds."""
    client = DirectLLMClient("openai", "sk-x", "gpt-x")
    assert client.mode_for("triage") == "UNVERIFIED", (
        "a fresh client has made no call, so it has proven nothing")
    client._verified = True  # noqa: SLF001 - simulating a successful call
    assert client.mode_for("triage") == "CONNECTED"


def test_mode_literal_admits_unverified():
    """The type must allow the honest state, or mypy forces the dishonest one."""
    text = CLIENT.read_text(encoding="utf-8")
    assert "UNVERIFIED" in text, (
        "Mode must include UNVERIFIED; without it the only expressible states "
        "are DISABLED, FALLBACK and CONNECTED, and 'configured but unproven' "
        "has nowhere honest to go")


def test_hub_source_never_hardcodes_connected_for_key_presence():
    """Structural guard against the exact bug regressing.

    Asserted on the absence of the pattern rather than on behaviour, because the
    behaviour depends on environment the test should not have to arrange.
    """
    src = HUB.read_text(encoding="utf-8")
    assert '"status": "CONNECTED"' not in src, (
        "active_provider must not hardcode CONNECTED; a provider's status is a "
        "measured fact, not a config-derived claim")
