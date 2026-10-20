"""
tests/test_rules.py - Pytest suite for regex heuristic rules in rules.py.

Includes:
- Verification of all 9 rule categories
- 5 comprehensive scam message samples
- 3 genuine message samples (testing false-positive resilience)
"""

import pytest
from rules import check_rules, RULES


# --- Category-specific unit tests ---

def test_urgency_pressure_rule():
    msg = "Act now within 24 hours or your account suspended permanently!"
    score, matches = check_rules(msg)
    matched_names = [m.rule_name for m in matches]
    assert "Urgency & Pressure" in matched_names
    assert score >= 20


def test_credential_otp_request_rule():
    msg = "Please share your OTP and enter net banking password to confirm identity."
    score, matches = check_rules(msg)
    matched_names = [m.rule_name for m in matches]
    assert "Credential & OTP Request" in matched_names
    assert score >= 35


def test_prize_refund_rule():
    msg = "Congratulations, you have won an unclaimed cash prize in our international lottery!"
    score, matches = check_rules(msg)
    matched_names = [m.rule_name for m in matches]
    assert "Prize & Refund Claims" in matched_names
    assert score >= 30


def test_threats_intimidation_rule():
    msg = "A formal arrest warrant has been issued and legal action will be initiated immediately."
    score, matches = check_rules(msg)
    matched_names = [m.rule_name for m in matches]
    assert "Threats & Intimidation" in matched_names
    assert score >= 30


def test_suspicious_payment_rule():
    msg = "To resolve the fine, purchase Apple gift cards or send money via Bitcoin immediately."
    score, matches = check_rules(msg)
    matched_names = [m.rule_name for m in matches]
    assert "Suspicious Payment Method" in matched_names
    assert score >= 30


def test_shortened_and_suspicious_links():
    short_url_msg = "Track your parcel status at http://bit.ly/3x8kL9"
    score1, matches1 = check_rules(short_url_msg)
    assert any(m.rule_name == "Suspicious or Shortened Link" for m in matches1)

    ip_url_msg = "Login to http://192.168.1.105:8080/secure to verify."
    score2, matches2 = check_rules(ip_url_msg)
    assert any(m.rule_name == "Suspicious or Shortened Link" for m in matches2)

    odd_tld_msg = "Claim your bonus at http://rewards-portal.xyz/claim"
    score3, matches3 = check_rules(odd_tld_msg)
    assert any(m.rule_name == "Suspicious or Shortened Link" for m in matches3)


def test_institutional_impersonation_rule():
    msg = "USPS Notice: Your package delivery has an unpaid fee and address issue."
    score, matches = check_rules(msg)
    matched_names = [m.rule_name for m in matches]
    assert "Institutional Impersonation" in matched_names


def test_secrecy_rule():
    msg = "Keep this strictly confidential and do not tell anyone until funds clear."
    score, matches = check_rules(msg)
    matched_names = [m.rule_name for m in matches]
    assert "Secrecy & Isolation Request" in matched_names


def test_lookalike_domain_rule():
    msg = "Verify your account at https://micros0ft.com or http://paypa1.com"
    score, matches = check_rules(msg)
    matched_names = [m.rule_name for m in matches]
    assert "Lookalike Domain or Brand Spoofing" in matched_names


# --- 5 SCAM SAMPLES ---

def test_scam_sample_1_bank_credential_harvesting():
    """Scam 1: Urgent bank account suspension asking to verify OTP/PIN on a fake domain."""
    sample = (
        "URGENT: Your Wells Fargo account has been suspended due to suspicious activity. "
        "Act now within 24 hours. Visit http://secure-bank-login.com to verify your OTP and debit card PIN."
    )
    score, matches = check_rules(sample)
    matched_names = [m.rule_name for m in matches]

    assert "Urgency & Pressure" in matched_names
    assert "Credential & OTP Request" in matched_names
    assert "Lookalike Domain or Brand Spoofing" in matched_names
    assert score >= 70  # High risk score


def test_scam_sample_2_courier_delivery_fee():
    """Scam 2: Courier parcel fee with shortened URL."""
    sample = (
        "FedEx delivery notification: Your package delivery is held due to unpaid fee. "
        "Act now to avoid return to sender: http://tinyurl.com/fedx-parcel-release"
    )
    score, matches = check_rules(sample)
    matched_names = [m.rule_name for m in matches]

    assert "Institutional Impersonation" in matched_names
    assert "Suspicious or Shortened Link" in matched_names
    assert "Urgency & Pressure" in matched_names
    assert score >= 65


def test_scam_sample_3_lottery_prize_gift_card():
    """Scam 3: Prize lottery claim demanding gift card fee and secrecy."""
    sample = (
        "Congratulations! You won a cash prize of $250,000 in the UK National Lottery. "
        "To claim your prize, buy Apple gift cards for the $150 processing fee. "
        "Keep this strictly confidential until payout."
    )
    score, matches = check_rules(sample)
    matched_names = [m.rule_name for m in matches]

    assert "Prize & Refund Claims" in matched_names
    assert "Suspicious Payment Method" in matched_names
    assert "Secrecy & Isolation Request" in matched_names
    assert score >= 80


def test_scam_sample_4_arrest_threat_crypto_demand():
    """Scam 4: Arrest warrant threat demanding cryptocurrency transfer."""
    sample = (
        "FINAL WARNING from IRS: A legal action and arrest warrant has been issued against you. "
        "To avoid police complaint and your account blocked, send money via Bitcoin immediately. "
        "Do not tell anyone."
    )
    score, matches = check_rules(sample)
    matched_names = [m.rule_name for m in matches]

    assert "Threats & Intimidation" in matched_names
    assert "Suspicious Payment Method" in matched_names
    assert "Secrecy & Isolation Request" in matched_names
    assert score >= 80


def test_scam_sample_5_tech_support_lookalike():
    """Scam 5: Microsoft tech support virus alert with lookalike domain and urgent response."""
    sample = (
        "Windows security team alert: Your computer has been compromised by a dangerous virus. "
        "Urgent action required. Visit http://micros0ft-security.xyz immediately to reach helpdesk. "
        "Do not call your bank."
    )
    score, matches = check_rules(sample)
    matched_names = [m.rule_name for m in matches]

    assert "Urgency & Pressure" in matched_names
    assert "Suspicious or Shortened Link" in matched_names
    assert "Lookalike Domain or Brand Spoofing" in matched_names
    assert score >= 65


# --- 3 GENUINE SAMPLES ---

def test_genuine_sample_1_legitimate_otp():
    """
    Genuine 1: Legitimate 2FA notification.
    Contains "OTP" and "do not share", but DOES NOT request credentials or threaten.
    Should not trigger the Credential Request rule.
    """
    sample = (
        "Your verification code is 591042. For security, do not share this code with anyone. "
        "We will never ask you for this code."
    )
    score, matches = check_rules(sample)
    matched_names = [m.rule_name for m in matches]

    assert "Credential & OTP Request" not in matched_names
    assert "Threats & Intimidation" not in matched_names
    assert score < 30  # Should be classified as Safe


def test_genuine_sample_2_work_meeting_invite():
    """
    Genuine 2: Normal professional communication.
    """
    sample = (
        "Hi David, hope you're having a productive week. Can we catch up tomorrow afternoon "
        "around 2:00 PM over Google Meet to review the sprint backlog? Let me know."
    )
    score, matches = check_rules(sample)
    assert score == 0
    assert len(matches) == 0


def test_genuine_sample_3_order_confirmation():
    """
    Genuine 3: Standard e-commerce shipping confirmation without phishing elements.
    """
    sample = (
        "Thank you for shopping with us! Your order #84920 has been received and is being prepared "
        "for dispatch. You will receive standard tracking details once it ships."
    )
    score, matches = check_rules(sample)
    assert score == 0
    assert len(matches) == 0
