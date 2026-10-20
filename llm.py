"""
llm.py - LLM integration module for scam message analysis using Google Gemini.

Designed with a modular provider pattern so the backend LLM can easily be swapped
(e.g., Gemini, OpenAI, Claude, or a local model) without touching the scoring or UI layers.
"""

from __future__ import annotations
import json
import os
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv(override=True)


@dataclass
class RedFlagItem:
    flag: str
    why: str


@dataclass
class LLMAnalysisResult:
    """Holds structured findings from LLM inspection."""
    score: int = 0
    verdict: str = "Safe"
    red_flags: List[Dict[str, str]] = field(default_factory=list)
    advice: str = ""
    success: bool = True
    error_message: Optional[str] = None


class BaseLLMProvider(ABC):
    """Abstract base provider to allow swapping LLM backends."""

    @abstractmethod
    def analyze(self, message: str) -> LLMAnalysisResult:
        """Analyzes a message and returns a validated LLMAnalysisResult."""
        pass


class GeminiProvider(BaseLLMProvider):
    """
    Google Gemini implementation using the official `google-genai` SDK.
    Loads API key from GEMINI_API_KEY environment variable.
    """

    DEFAULT_MODEL = "gemini-2.5-flash"

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        load_dotenv(override=True)
        raw_key = api_key or os.getenv("GEMINI_API_KEY")
        self.api_key = raw_key.strip() if raw_key else None
        raw_model = model or os.getenv("GEMINI_MODEL")
        self.model_name = raw_model.strip() if raw_model else self.DEFAULT_MODEL

    def _build_prompt(self, message: str) -> str:
        return f"""You are an elite cybersecurity and fraud prevention analyst.
Evaluate the following message (SMS, WhatsApp, or email) to determine if it is a scam, phishing attempt, social engineering attack, or fraudulent communication.

Analyze:
1. Pressure tactics, artificial urgency, or emotional manipulation.
2. Requests for credentials, OTPs, PINs, bank details, or personal data.
3. Unrealistic financial promises, prize wins, or fake refunds.
4. Threatening consequences (legal action, arrest, account termination).
5. Demands for unusual payments (gift cards, wire transfer, cryptocurrency, UPI collect).
6. Sender impersonation (banks, delivery couriers, government agencies, tech support).
7. Suspicious links, domain spoofing, or secrecy requests.

Message to analyze:
\"\"\"
{message}
\"\"\"

You MUST respond strictly with a valid JSON object with the following schema:
{{
  "score": <integer from 0 to 100 representing scam risk where 0 is completely safe and 100 is definite scam>,
  "verdict": "<Safe | Suspicious | Likely Scam>",
  "red_flags": [
    {{
      "flag": "<concise name of the red flag>",
      "why": "<plain language explanation of why this indicates a scam>"
    }}
  ],
  "advice": "<clear, actionable advice for the recipient on what to do or avoid>"
}}

Guidelines for score & verdict:
- 0 to 29: "Safe" (legitimate personal, transactional, or informational communication)
- 30 to 65: "Suspicious" (unsolicited marketing, vague links, minor urgency, unverified sender)
- 66 to 100: "Likely Scam" (credential harvesting, impersonation, threats, financial fraud)

Return ONLY the raw JSON string. Do not include markdown code block backticks (```json or ```)."""

    def analyze(self, message: str) -> LLMAnalysisResult:
        if not self.api_key or self.api_key.strip() in ("", "your_gemini_api_key_here"):
            return LLMAnalysisResult(
                success=False,
                error_message="Gemini API key is not configured. Set GEMINI_API_KEY in your .env file.",
            )

        try:
            # Import google-genai official package
            from google import genai
            from google.genai import types

            client = genai.Client(api_key=self.api_key)

            prompt = self._build_prompt(message)

            response = client.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    temperature=0.1,
                ),
            )

            response_text = response.text or ""
            return self._parse_and_validate(response_text)

        except ImportError:
            return LLMAnalysisResult(
                success=False,
                error_message="The 'google-genai' package is not installed. Run: pip install google-genai",
            )
        except Exception as e:
            return LLMAnalysisResult(
                success=False,
                error_message=f"Gemini API request failed: {str(e)}",
            )

    def _parse_and_validate(self, raw_output: str) -> LLMAnalysisResult:
        """Parses LLM response JSON and validates structure defensively."""
        clean_text = raw_output.strip()

        # Strip markdown fences if present
        if clean_text.startswith("```"):
            clean_text = re.sub(r"^```(?:json)?\s*", "", clean_text)
            clean_text = re.sub(r"\s*```$", "", clean_text)
            clean_text = clean_text.strip()

        try:
            data = json.loads(clean_text)
        except json.JSONDecodeError as err:
            return LLMAnalysisResult(
                success=False,
                error_message=f"LLM returned invalid JSON: {err}. Raw output: {raw_output[:200]}",
            )

        # Validate score
        raw_score = data.get("score")
        if not isinstance(raw_score, (int, float)):
            return LLMAnalysisResult(
                success=False,
                error_message="Invalid LLM response: 'score' must be an integer.",
            )
        score = max(0, min(100, int(round(raw_score))))

        # Validate verdict
        verdict = str(data.get("verdict", "")).strip()
        if verdict not in ("Safe", "Suspicious", "Likely Scam"):
            # Normalize or infer based on score
            if score >= 66:
                verdict = "Likely Scam"
            elif score >= 30:
                verdict = "Suspicious"
            else:
                verdict = "Safe"

        # Validate red_flags
        raw_flags = data.get("red_flags", [])
        validated_flags: List[Dict[str, str]] = []
        if isinstance(raw_flags, list):
            for item in raw_flags:
                if isinstance(item, dict):
                    flag = str(item.get("flag", "")).strip()
                    why = str(item.get("why", "")).strip()
                    if flag or why:
                        validated_flags.append({"flag": flag or "Suspicious Element", "why": why})

        # Validate advice
        advice = str(data.get("advice", "")).strip()
        if not advice:
            advice = "Do not click unverified links, never share passwords or OTPs, and verify through official channels."

        return LLMAnalysisResult(
            score=score,
            verdict=verdict,
            red_flags=validated_flags,
            advice=advice,
            success=True,
            error_message=None,
        )


def analyze_with_llm(
    message: str,
    api_key: Optional[str] = None,
    provider: Optional[BaseLLMProvider] = None,
) -> LLMAnalysisResult:
    """
    Convenience function to analyze a message using the active provider.
    Defaults to GeminiProvider.
    """
    active_provider = provider or GeminiProvider(api_key=api_key)
    return active_provider.analyze(message)
