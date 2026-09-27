"""Tests for reliability: provider precedence and the honest fallback path.

The core promise is: the engine owns the verdict; if a live AI is configured
and fails for any reason, the result still comes back as a complete, correctly
labeled deterministic verdict — the demo never breaks.
"""

import pytest

from app.ai.provider import AIError, BaseProvider, get_provider
from app.data.seed_alerts import seed_alerts
from app.services import analyzer


def test_no_keys_means_demo_mock(monkeypatch):
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    provider = get_provider()
    assert provider.name == "fallback"
    assert not provider.is_live()


def test_nvidia_takes_precedence(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-test")
    monkeypatch.setenv("GEMINI_API_KEY", "gemini-test")
    provider = get_provider()
    assert provider.name == "nvidia"
    assert provider.model_name == "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning"


def test_env_model_overrides_default(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-test")
    monkeypatch.setenv("NVIDIA_MODEL", "custom/nim-model")
    assert get_provider().model_name == "custom/nim-model"


def test_gemini_used_when_nvidia_absent(monkeypatch):
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "gemini-test")
    assert get_provider().name == "gemini"


def fake_alert():
    a = seed_alerts()[0]  # AL-2024-0001 SSH brute force, HIGH
    a.status = "NEW"
    return a


def test_deterministic_result_when_ai_rejects_verdict(monkeypatch):
    """A live provider that FAILS must yield a labeled fallback, not a crash."""

    class BrokenProvider(BaseProvider):
        name = "broken"
        model_name = "broken/nim"

        def is_configured(self):
            return True

        def is_live(self):
            return True

        def enrich(self, alert, result):
            raise AIError("simulated outage")

        def answer(self, alert, result, question):
            raise AIError("simulated outage")

        def incident_overview(self, facts):
            raise AIError("simulated outage")

        def audit_insight(self, facts):
            raise AIError("simulated outage")

    from app.services.analyzer import analyze_alert

    monkeypatch.setattr(analyzer, "get_provider", lambda: BrokenProvider())
    result = analyze_alert(fake_alert())
    assert result.analysis_mode == "fallback"
    assert result.model_used == "broken/nim"
    # the engine's verdict survives the outage untouched
    assert result.severity == "HIGH"
    assert result.confidence > 0
    assert result.summary  # still a complete, readable answer


def test_no_key_marks_fallback_deterministic(monkeypatch):
    from app.services.analyzer import analyze_alert

    result = analyze_alert(fake_alert())
    assert result.analysis_mode == "fallback"
    assert result.model_used == "deterministic"
    assert result.severity == "HIGH"