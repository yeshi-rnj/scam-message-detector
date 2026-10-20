"""
rules.py - Regex-based heuristic rules for scam message detection.

Covers 9 scam indicator categories:
1. Urgency & pressure tactics
2. Credential/OTP/PIN/CVV requests
3. Prize, lottery, refund, and inheritance claims
4. Threats of legal action, arrest, or account blocking
5. Demands for unusual payment methods (gift cards, crypto, UPI collect, wire)
6. Shortened and suspicious URLs (IP addresses, high-risk TLDs)
7. Impersonation of institutions (banks, couriers, government, tech support)
8. Secrecy requests ("do not tell anyone", "strictly confidential")
9. Lookalike domains and typo-squatting oddities
"""

from __future__ import annotations
import re
from dataclasses import dataclass
from typing import List, Tuple


@dataclass
class Rule:
    """Represents a scam detection rule."""
    name: str
    pattern: str
    weight: int
    explanation: str
    flags: int = re.IGNORECASE


@dataclass
class RuleMatch:
    """Represents a rule that was triggered by message content."""
    rule_name: str
    weight: int
    explanation: str
    matched_text: str


# Heuristic rule definitions
RULES: List[Rule] = [
    # 1. Urgency & Pressure
    Rule(
        name="Urgency & Pressure",
        pattern=r"\b(?:act\s+now|immediate(?:ly)?\s+action|within\s+(?:24|12|48)\s*h(?:ou)?rs?|account\s+suspended|expires?\s+today|final\s+(?:notice|warning)|respond\s+immediately|last\s+chance|urgent\s+action\s+required)\b",
        weight=20,
        explanation="Uses artificial urgency and high-pressure phrasing to rush you into acting before thinking.",
    ),

    # 2. Requests for OTP, PIN, Password, CVV, Card or Bank Details
    # Crafted to detect requests/prompts to provide credentials, while not false-flagging legitimate "Do not share your OTP" texts
    Rule(
        name="Credential & OTP Request",
        pattern=r"\b(?:share|enter|send|provide|update|verify|confirm|submit)\b[^\.\n]{0,50}\b(?:otp|one[- ]time\s+pass(?:word)?|pin|cvv|cvc|password|net\s*banking\s+pass(?:word)?|debit\s*card\s*number|credit\s*card\s*details|bank\s*account\s*number|passcode)\b",
        weight=35,
        explanation="Demands sensitive security credentials like OTP, PIN, CVV, or passwords. Legitimate institutions never request these.",
    ),

    # 3. Prize, Lottery, Refund, or Inheritance Claims
    Rule(
        name="Prize & Refund Claims",
        pattern=r"\b(?:won|winner|claim\s+your|lottery|lucky\s+draw|inheritance|unclaimed\s+(?:fund|money|tax\s+refund)|cash\s+prize|selected\s+to\s+receive|congratulations\s+you(?:'ve|\s+have)?\s+won|free\s+voucher)\b",
        weight=30,
        explanation="Claims you won an unearned prize, lottery, tax refund, or inheritance to entice you into engaging.",
    ),

    # 4. Threats (Legal Action, Arrest, Account Blocked)
    Rule(
        name="Threats & Intimidation",
        pattern=r"\b(?:arrest\s+warrant|legal\s+action|law\s+enforcement|court\s+summons|police\s+complaint|account\s+(?:will\s+be\s+)?(?:blocked|terminated|frozen|closed)|penalty\s+charges|fir\s+filed|seizure\s+notice)\b",
        weight=30,
        explanation="Uses fear and threats of arrest, legal prosecution, or account confiscation to intimidate you.",
    ),

    # 5. Payment Demands (Gift Cards, Crypto, Wire Transfer, UPI Collect)
    Rule(
        name="Suspicious Payment Method",
        pattern=r"\b(?:(?:buy|pay\s+with|purchase)\s+(?:itunes|google\s*play|amazon|steam|apple)\s+gift\s*cards?|crypto(?:currency)?|bitcoins?|usdt|eth|wire\s*transfer|western\s*union|upi\s+collect\s+request|send\s+money\s+to\s+upi|advance\s+processing\s+fee)\b",
        weight=30,
        explanation="Demands payment through non-reversible or anonymous channels like gift cards, cryptocurrency, or UPI collect.",
    ),

    # 6. Shortened or Suspicious Links (Shorteners, IP addresses, high-risk TLDs)
    Rule(
        name="Suspicious or Shortened Link",
        pattern=r"(?:https?://)?(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rb\.gy|ow\.ly|goo\.gl|tiny\.cc)/[a-zA-Z0-9_\-]+|(?:https?://)?(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/[^\s]*)?|(?:https?://)?[a-zA-Z0-9.\-]+\.(?:xyz|top|click|club|work|buzz|rest|gq|cf|tk|ml|loan|racing|download|review)(?:/[^\s]*)?",
        weight=25,
        explanation="Contains a URL shortener, raw IP address, or high-risk domain extension commonly used to mask malicious sites.",
    ),

    # 7. Impersonation of Banks, Couriers, Government, or Tech Support
    Rule(
        name="Institutional Impersonation",
        pattern=r"\b(?:fedex|dhl|usps|ups|india\s*post)\b[^\.\n]{0,60}\b(?:parcel|package|delivery|address\s+issue|customs\s+duty|unpaid\s+fee)\b|\b(?:rbi|irs|hmrc|tax\s+department|customs\s+office|fbi|interpol)\b|\b(?:microsoft|apple|windows)\s+(?:support|helpdesk|security\s+team|technician)\b[^\.\n]{0,50}\b(?:virus|hacked|breach|compromised)\b",
        weight=25,
        explanation="Impersonates legitimate delivery services, government authorities, or tech support to exploit institutional trust.",
    ),

    # 8. "Do Not Tell Anyone" / Secrecy Requests
    Rule(
        name="Secrecy & Isolation Request",
        pattern=r"\b(?:do\s+not\s+(?:tell|inform|share\s+with)\s+anyone|strictly\s+confidential|keep\s+this\s+(?:between\s+us|a\s+secret|confidential)|tell\s+no\s+one|do\s+not\s+(?:call|contact)\s+your\s+bank)\b",
        weight=25,
        explanation="Instructs you to maintain secrecy or isolate yourself from family or officials so nobody can alert you.",
    ),

    # 9. Lookalike Domains and Spelling Oddities
    Rule(
        name="Lookalike Domain or Brand Spoofing",
        pattern=r"\b(?:paypa1|micros0ft|g00gle|amaz0n|netfl1x|app1e|chase-security|secure-bank[a-z0-9\-]*\.com|support-[a-z0-9\-]+\.com|login-[a-z0-9\-]+\.com|kyc-update[a-z0-9\-]*\.com)\b",
        weight=25,
        explanation="Uses typo-squatting or synthetic hyphenated domain patterns designed to mimic recognizable brands.",
    ),
]


def check_rules(message: str) -> Tuple[int, List[RuleMatch]]:
    """
    Evaluates all rules against the input message text.

    Returns:
        regex_score: Sum of weights of triggered rules, capped at 100.
        matches: List of RuleMatch instances detailing what was matched and why.
    """
    if not message or not message.strip():
        return 0, []

    matches: List[RuleMatch] = []
    total_weight = 0

    for rule in RULES:
        match = re.search(rule.pattern, message, rule.flags)
        if match:
            # Capture the snippet that triggered the rule
            snippet = match.group(0).strip()
            matches.append(
                RuleMatch(
                    rule_name=rule.name,
                    weight=rule.weight,
                    explanation=rule.explanation,
                    matched_text=snippet,
                )
            )
            total_weight += rule.weight

    regex_score = min(total_weight, 100)
    return regex_score, matches
