"""Offline checks for the real-LLM live suite's skip gate.

``tests/live/test_live_scenarios_real_llm.py`` bills a real provider, so it must
stay skipped unless BOTH the explicit opt-in flag is set AND the configured
provider's key is present. These run in the plain offline suite (no network,
no LLM): they only exercise the gate function.
"""

from __future__ import annotations

import pytest

from playground.config import Settings
from tests.live.test_live_scenarios_real_llm import real_llm_skip_reason


def _settings(**kw) -> Settings:
    base = {"openai_api_key": "", "anthropic_api_key": ""}
    base.update(kw)
    return Settings(_env_file=None, **base)


@pytest.mark.parametrize("flag", [None, ""])
def test_no_flag_skips_even_with_a_key(flag):
    reason = real_llm_skip_reason(flag, _settings(llm_provider="openai", openai_api_key="x"))
    assert reason and "ACDP_LIVE_REAL_LLM=1" in reason


@pytest.mark.parametrize(
    ("provider", "var"), [("openai", "OPENAI_API_KEY"), ("anthropic", "ANTHROPIC_API_KEY")]
)
def test_flag_without_matching_key_skips(provider, var):
    reason = real_llm_skip_reason("1", _settings(llm_provider=provider))
    assert reason and var in reason


def test_key_for_the_other_provider_does_not_count():
    reason = real_llm_skip_reason("1", _settings(llm_provider="openai", anthropic_api_key="x"))
    assert reason and "OPENAI_API_KEY" in reason


def test_whitespace_key_counts_as_missing():
    assert real_llm_skip_reason("1", _settings(llm_provider="openai", openai_api_key="  "))


def test_flag_and_key_runs():
    assert real_llm_skip_reason("1", _settings(llm_provider="openai", openai_api_key="x")) is None
    assert (
        real_llm_skip_reason("1", _settings(llm_provider="anthropic", anthropic_api_key="x"))
        is None
    )


def test_mock_provider_needs_no_key():
    assert real_llm_skip_reason("1", _settings(llm_provider="mock")) is None
