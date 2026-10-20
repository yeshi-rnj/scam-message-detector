"""
tests/test_scorer.py - Tests for scoring formula, capping, and LLM fallback mechanics.
"""

from scorer import analyze_message, get_verdict_and_color
from llm import BaseLLMProvider, LLMAnalysisResult


class MockSuccessLLMProvider(BaseLLMProvider):
    """Mock LLM provider returning a controlled score and findings."""
    def __init__(self, score: int = 80, verdict: str = "Likely Scam"):
        self._score = score
        self._verdict = verdict

    def analyze(self, message: str) -> LLMAnalysisResult:
        return LLMAnalysisResult(
            score=self._score,
            verdict=self._verdict,
            red_flags=[{"flag": "Mock Flag", "why": "Testing explanation"}],
            advice="Mock advice: Stay alert.",
            success=True,
        )


class MockFailingLLMProvider(BaseLLMProvider):
    """Mock LLM provider simulating API failure or missing keys."""
    def analyze(self, message: str) -> LLMAnalysisResult:
        return LLMAnalysisResult(
            success=False,
            error_message="Simulated API failure or unconfigured key.",
        )


def test_verdict_thresholds():
    assert get_verdict_and_color(0) == ("Safe", "green")
    assert get_verdict_and_color(29) == ("Safe", "green")
    assert get_verdict_and_color(30) == ("Suspicious", "orange")
    assert get_verdict_and_color(65) == ("Suspicious", "orange")
    assert get_verdict_and_color(66) == ("Likely Scam", "red")
    assert get_verdict_and_color(100) == ("Likely Scam", "red")


def test_hybrid_score_calculation():
    """
    Tests 0.4 * regex + 0.6 * llm formula.
    Example:
    regex triggers urgency (20) and payment (30) = 50.
    LLM returns 90.
    Expected: 0.4 * 50 + 0.6 * 90 = 20 + 54 = 74 ("Likely Scam").
    """
    message = "Act now and send money via Bitcoin immediately!"
    mock_llm = MockSuccessLLMProvider(score=90)
    report = analyze_message(message, llm_provider=mock_llm)

    assert not report.llm_fallback_used
    assert report.regex_score == 50
    assert report.llm_score == 90
    assert report.final_score == 74
    assert report.verdict == "Likely Scam"
    assert report.verdict_color == "red"


def test_fallback_when_llm_fails():
    """
    When LLM fails, final_score should equal regex_score,
    and llm_fallback_used should be True.
    """
    message = "Act now and send money via Bitcoin immediately!"
    failing_llm = MockFailingLLMProvider()
    report = analyze_message(message, llm_provider=failing_llm)

    assert report.llm_fallback_used is True
    assert report.llm_score is None
    assert report.regex_score == 50
    assert report.final_score == 50
    assert report.verdict == "Suspicious"
    assert report.verdict_color == "orange"
    assert "Simulated API failure" in (report.llm_error_message or "")


def test_score_capping_at_100():
    """
    If multiple rules exceed 100 points, regex_score must cap at 100.
    """
    super_scam = (
        "URGENT: Act now within 24 hours! Your Chase Bank account is suspended. "
        "Visit http://secure-bank-login.com to verify your OTP and debit card PIN. "
        "A formal arrest warrant has been issued. Send money via Bitcoin immediately. "
        "Keep this strictly confidential. USPS package delivery unpaid fee."
    )
    mock_llm = MockSuccessLLMProvider(score=100)
    report = analyze_message(super_scam, llm_provider=mock_llm)

    assert report.regex_score == 100
    assert report.final_score == 100
    assert report.verdict == "Likely Scam"
