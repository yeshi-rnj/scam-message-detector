"""
scorer.py - Hybrid risk scoring engine for Scam Message Detector.

Combines rule-based regex detection (40%) and LLM deep analysis (60%).
Gracefully falls back to 100% regex scoring if the LLM call fails or is unconfigured.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from rules import RuleMatch, check_rules
from llm import BaseLLMProvider, LLMAnalysisResult, analyze_with_llm


@dataclass
class ScamAnalysisReport:
    """Comprehensive analysis report for UI rendering."""
    final_score: int
    verdict: str  # "Safe", "Suspicious", "Likely Scam"
    verdict_color: str  # "green", "orange", "red"
    regex_score: int
    llm_score: Optional[int]
    regex_matches: List[RuleMatch] = field(default_factory=list)
    llm_red_flags: List[Dict[str, str]] = field(default_factory=list)
    advice: str = ""
    llm_fallback_used: bool = False
    llm_error_message: Optional[str] = None


def get_verdict_and_color(score: int) -> Tuple[str, str]:
    """Maps a risk score (0-100) to a verdict string and visual indicator color."""
    if score >= 66:
        return "Likely Scam", "red"
    elif score >= 30:
        return "Suspicious", "orange"
    else:
        return "Safe", "green"


def get_default_fallback_advice(score: int, verdict: str) -> str:
    """Produces situational advice when LLM advice is unavailable."""
    if verdict == "Likely Scam":
        return (
            "🚨 CRITICAL: Do NOT click any links, open attachments, or reply. "
            "Never share OTPs, PINs, passwords, or bank account numbers. "
            "Block the sender immediately and report the message to official cybersecurity portals."
        )
    elif verdict == "Suspicious":
        return (
            "⚠️ CAUTION: Avoid clicking any unverified links or downloading attachments. "
            "Verify the sender's identity through official independent channels (such as typing the official URL into your browser). "
            "Do not disclose confidential personal or financial information."
        )
    else:
        return (
            "✅ SAFE: This message does not exhibit known high-risk scam patterns. "
            "However, always remain vigilant when receiving unexpected communications containing links or requests."
        )


def analyze_message(
    message: str,
    api_key: Optional[str] = None,
    llm_provider: Optional[BaseLLMProvider] = None,
) -> ScamAnalysisReport:
    """
    Main orchestration function:
    1. Runs regex pattern checks -> regex_score (0-100)
    2. Runs LLM analysis -> llm_score (0-100)
    3. Blends scores: final_score = 0.4 * regex_score + 0.6 * llm_score
       (Or 100% regex_score if LLM fails)
    4. Compiles actionable advice and red flags.
    """
    # 1. Regex rule-based analysis
    regex_score, regex_matches = check_rules(message)

    # 2. LLM deep analysis
    llm_result: LLMAnalysisResult = analyze_with_llm(
        message=message,
        api_key=api_key,
        provider=llm_provider,
    )

    # 3. Hybrid score calculation & fallback handling
    if llm_result.success:
        llm_score = llm_result.score
        calculated_final = round((0.4 * regex_score) + (0.6 * llm_score))
        final_score = max(0, min(100, int(calculated_final)))
        verdict, verdict_color = get_verdict_and_color(final_score)
        advice = llm_result.advice or get_default_fallback_advice(final_score, verdict)
        llm_fallback_used = False
        llm_error = None
    else:
        # Graceful fallback: regex score only
        final_score = regex_score
        verdict, verdict_color = get_verdict_and_color(final_score)
        advice = get_default_fallback_advice(final_score, verdict)
        llm_score = None
        llm_fallback_used = True
        llm_error = llm_result.error_message

    return ScamAnalysisReport(
        final_score=final_score,
        verdict=verdict,
        verdict_color=verdict_color,
        regex_score=regex_score,
        llm_score=llm_score,
        regex_matches=regex_matches,
        llm_red_flags=llm_result.red_flags if not llm_fallback_used else [],
        advice=advice,
        llm_fallback_used=llm_fallback_used,
        llm_error_message=llm_error,
    )
