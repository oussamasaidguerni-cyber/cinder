"""AI provider abstraction.

CINDER treats the AI as a narrative helper, NOT a decision-maker. The
deterministic engine produces the verdict; the AI only phrases the summary,
recommended actions, false-positive indicators, and incident report.

`enrich()` returns NarrativeEnrichment; any failure raises AIError so the
caller can fall back to deterministic output.
"""

import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

from ..schemas.analysis import AnalysisResult
from .prompts import build_enrichment_prompt, build_incident_prompt, build_question_prompt

GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models"
NVIDIA_API_URL = "https://integrate.api.nvidia.com/v1/chat/completions"
DEFAULT_NVIDIA_MODEL = "openai/gpt-oss-20b"


class AIError(Exception):
    """Raised when the AI provider fails for any reason."""


@dataclass
class NarrativeEnrichment:
    summary: str
    recommended_actions: list[str]
    false_positive_indicators: list[str]
    incident_report: str


class BaseProvider:
    name = "base"
    model_name = "base"

    def is_configured(self) -> bool:
        raise NotImplementedError

    def is_live(self) -> bool:
        """True when the provider makes real remote AI calls that can fail.

        Non-live providers (the demo Mock) cannot meaningfully fail, so
        callers skip the AI-attempt / deterministic-fallback dance for them.
        """
        raise NotImplementedError

    def enrich(self, alert, result: AnalysisResult) -> NarrativeEnrichment:
        raise NotImplementedError

    def answer(self, alert, result: AnalysisResult, question: str) -> str:
        raise NotImplementedError

    def incident_overview(self, facts: str) -> str:
        raise NotImplementedError


class GeminiProvider(BaseProvider):
    """Calls the Gemini REST API via urllib (no SDK dependency)."""

    name = "gemini"

    def __init__(self, api_key: str, model: str) -> None:
        self._api_key = api_key
        self._model = model
        self.model_name = model

    def is_configured(self) -> bool:
        return bool(self._api_key)

    def is_live(self) -> bool:
        return True

    def enrich(self, alert, result: AnalysisResult) -> NarrativeEnrichment:
        prompt = build_enrichment_prompt(alert, result)
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.3,
                "maxOutputTokens": 1024,
                "responseMimeType": "application/json",
            },
        }
        body = self._call_gemini(payload)
        try:
            text = body["candidates"][0]["content"]["parts"][0]["text"]
            parsed = json.loads(text)
        except (KeyError, IndexError, json.JSONDecodeError) as exc:
            raise AIError("Gemini returned an unexpected or non-JSON payload.") from exc

        return _validate_enrichment(parsed)

    def answer(self, alert, result: AnalysisResult, question: str) -> str:
        payload = {
            "contents": [{"parts": [{"text": build_question_prompt(alert, result, question)}]}],
            "generationConfig": {
                "temperature": 0.4,
                "maxOutputTokens": 512,
            },
        }
        body = self._call_gemini(payload)
        try:
            text = body["candidates"][0]["content"]["parts"][0]["text"].strip()
        except (KeyError, IndexError) as exc:
            raise AIError("Gemini returned an unexpected or non-JSON payload.") from exc
        if not text:
            raise AIError("Gemini returned an empty answer.")
        return text

    def incident_overview(self, facts: str) -> str:
        payload = {
            "contents": [{"parts": [{"text": build_incident_prompt(facts)}]}],
            "generationConfig": {
                "temperature": 0.3,
                "maxOutputTokens": 512,
            },
        }
        body = self._call_gemini(payload)
        try:
            text = body["candidates"][0]["content"]["parts"][0]["text"].strip()
        except (KeyError, IndexError) as exc:
            raise AIError("Gemini returned an unexpected or non-JSON payload.") from exc
        if not text:
            raise AIError("Gemini returned an empty incident overview.")
        return text

    def _call_gemini(self, payload: dict) -> dict:
        """POST to Gemini, retrying transient 429/5xx responses with backoff.

        Gemini is known to return 429 (rate limit) and 503 (throttled spike)
        under load. Retrying a few times with short backoff gives the demo a
        much higher chance of a live result instead of an instant fallback.
        """
        url = f"{GEMINI_API_URL}/{self._model}:generateContent"
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                "x-goog-api-key": self._api_key,
            },
        )
        last_error: Exception | None = None
        for attempt in range(4):
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    return json.loads(resp.read().decode())
            except urllib.error.HTTPError as exc:
                # 429 and 5xx are transient; 4xx (except 429) is a real error.
                if exc.code in (429, 500, 502, 503) and attempt < 3:
                    last_error = exc
                    time.sleep(1.5 * (attempt + 1))
                    continue
                raise AIError(f"Gemini HTTP {exc.code}: {exc.read().decode()[:200]}") from exc
            except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
                raise AIError(f"Gemini request failed: {exc}") from exc
        raise AIError(f"Gemini request failed: {last_error}") from last_error

    @staticmethod
    def _validate(parsed: dict) -> NarrativeEnrichment:
        return _validate_enrichment(parsed)


def _strip_thinking(text: str) -> str:
    """Drop an optional leading <thinking> ... </thinking> block if present.

    NVIDIA reasoning models (e.g. Llama Nemotron Nano) sometimes prepend a
    'thinking' section before the real answer. We keep every character except
    that explicit block so question answers and incident overviews stay clean.
    """
    t = text.strip()
    start_marker, end_marker = "<thinking>", "</thinking>"
    if t.startswith(start_marker) and end_marker in t:
        after = t[t.find(end_marker) + len(end_marker) :].strip()
        if after:
            return after
    return t


def _extract_json_object(text: str) -> dict:
    """Leniently pull a JSON object out of a model's text response.

    NVIDIA-hosted models occasionally wrap JSON in markdown fences or add
    prose around it; we find the first { ... } span and parse that.
    """
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```[a-zA-Z]*\s*\n?", "", cleaned)
        cleaned = re.sub(r"\n?```\s*$", "", cleaned).strip()
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise AIError("AI returned no JSON object.")
    try:
        return json.loads(cleaned[start : end + 1])
    except json.JSONDecodeError as exc:
        raise AIError("AI returned malformed JSON.") from exc


def _validate_enrichment(parsed: dict) -> NarrativeEnrichment:
    summary = str(parsed.get("summary", "")).strip()
    if not summary:
        raise AIError("AI returned an empty summary.")
    actions = parsed.get("recommended_actions", [])
    fps = parsed.get("false_positive_indicators", [])
    report = str(parsed.get("incident_report", "")).strip()
    if not isinstance(actions, list) or not isinstance(fps, list):
        raise AIError("AI returned non-list narrative fields.")
    return NarrativeEnrichment(
        summary=summary,
        recommended_actions=[str(a) for a in actions] or [],
        false_positive_indicators=[str(f) for f in fps] or [],
        incident_report=report,
    )


class NVAPIProvider(BaseProvider):
    """Calls an NVIDIA-hosted NIM microservice via the OpenAI-compatible API.

    The engine's verdict remains authoritative; this provider only phrases the
    narrative, exactly like the Gemini provider. Falls back to deterministic
    output if the call fails, so a demo never breaks on model hiccups.
    """

    name = "nvidia"

    def __init__(self, api_key: str, model: str) -> None:
        self._api_key = api_key
        self._model = model
        self.model_name = model

    def is_configured(self) -> bool:
        return bool(self._api_key)

    def is_live(self) -> bool:
        return True

    def enrich(self, alert, result: AnalysisResult) -> NarrativeEnrichment:
        prompt = (
            build_enrichment_prompt(alert, result)
            + "\n\nRespond with STRICT JSON only (no markdown fences, no prose)."
        )
        text = self._chat(prompt, temperature=0.3, max_tokens=1024)
        return _validate_enrichment(_extract_json_object(text))

    def answer(self, alert, result: AnalysisResult, question: str) -> str:
        text = self._chat(
            build_question_prompt(alert, result, question),
            temperature=0.4,
            max_tokens=512,
        ).strip()
        if not text:
            raise AIError("NVIDIA returned an empty answer.")
        return text

    def incident_overview(self, facts: str) -> str:
        text = self._chat(
            build_incident_prompt(facts), temperature=0.3, max_tokens=512
        ).strip()
        if not text:
            raise AIError("NVIDIA returned an empty incident overview.")
        return text

    def _chat(self, prompt: str, temperature: float, max_tokens: int) -> str:
        """POST to NVIDIA NIM, retrying transient 429/5xx with backoff."""
        payload = {
            "model": self._model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
            "max_tokens": max_tokens,
            "top_p": 1.0,
        }
        req = urllib.request.Request(
            NVIDIA_API_URL,
            data=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._api_key}",
            },
        )
        last_error: Exception | None = None
        for attempt in range(4):
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    body = json.loads(resp.read().decode())
                choices = body.get("choices") or []
                content = _strip_thinking(choices[0]["message"]["content"])
                if not content:
                    raise AIError("NVIDIA returned an empty completion.")
                return content
            except urllib.error.HTTPError as exc:
                if exc.code in (429, 500, 502, 503, 504) and attempt < 3:
                    last_error = exc
                    time.sleep(1.5 * (attempt + 1))
                    continue
                raise AIError(f"NVIDIA HTTP {exc.code}: {exc.read().decode()[:200]}") from exc
            except (KeyError, IndexError) as exc:
                raise AIError("NVIDIA returned an unexpected payload shape.") from exc
            except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
                raise AIError(f"NVIDIA request failed: {exc}") from exc
        raise AIError(f"NVIDIA request failed: {last_error}") from last_error


class MockProvider(BaseProvider):
    """Fallback when no API key is configured. Labels itself as demo.

    Uses the deterministic engine's own narrative so the demo flows
    identically, but is clearly marked analysis_mode="fallback".
    """

    name = "fallback"

    def is_configured(self) -> bool:
        return True

    def is_live(self) -> bool:
        return False

    def enrich(self, alert, result: AnalysisResult) -> NarrativeEnrichment:
        return NarrativeEnrichment(
            summary=result.summary,
            recommended_actions=result.recommended_actions,
            false_positive_indicators=result.false_positive_indicators,
            incident_report=result.incident_report,
        )

    def answer(self, alert, result: AnalysisResult, question: str) -> str:
        return (
            "Fallback (demo) mode — live AI is not configured. Grounding your "
            "question in what the deterministic engine found: "
            f"{result.threat_type}, severity {result.severity} (confidence "
            f"{result.confidence}%). Recommended next step: "
            f"{result.recommended_actions[0] if result.recommended_actions else 'review the alert.'} "
            "Add a GEMINI_API_KEY or NVIDIA_API_KEY to get live answers to "
            "questions like yours."
        )

    def incident_overview(self, facts: str) -> str:
        return (
            "Fallback (demo) mode — live AI is not configured. Correlation is "
            "based on the deterministic engine's per-phase verdicts above: the "
            "alerts share a plausible stage sequence and should be treated as "
            "one investigation priority. Add a GEMINI_API_KEY or NVIDIA_API_KEY "
            "for a live AI-narrated incident overview."
        )


def get_provider() -> BaseProvider:
    """Pick the active AI provider by precedence.

    NVIDIA (build.nvidia.com NIM) first — the hackathon sponsor — then Gemini,
    then the honest demo Mock. Each live provider fails soft: AI errors fall
    back to deterministic output rather than breaking the demo.
    """
    nvidia_key = os.environ.get("NVIDIA_API_KEY", "").strip()
    if nvidia_key:
        model = os.environ.get("NVIDIA_MODEL", DEFAULT_NVIDIA_MODEL).strip()
        return NVAPIProvider(api_key=nvidia_key, model=model)
    gemini_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if gemini_key:
        model = os.environ.get("GEMINI_MODEL", "gemini-3.5-flash-lite").strip()
        return GeminiProvider(api_key=gemini_key, model=model)
    return MockProvider()