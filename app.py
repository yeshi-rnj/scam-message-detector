"""
app.py - Scam Message Detector Streamlit Application.

Interactive web interface for analyzing suspicious SMS, WhatsApp, and email messages
using a hybrid detection system (Regex heuristics + Gemini LLM).
"""

import os
import streamlit as st
from dotenv import load_dotenv

from scorer import ScamAnalysisReport, analyze_message

# Load environment variables
load_dotenv(override=True)

# Page configuration
st.set_page_config(
    page_title="Scam Message Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for high-impact visual presentation
st.markdown(
    """
    <style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 700;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        font-size: 1.05rem;
        color: #64748b;
        margin-bottom: 1.5rem;
    }
    .score-card {
        padding: 1.5rem;
        border-radius: 12px;
        text-align: center;
        margin-bottom: 1.5rem;
        border: 2px solid;
    }
    .score-card-green {
        background-color: rgba(34, 197, 94, 0.08);
        border-color: #22c55e;
        color: #15803d;
    }
    .score-card-orange {
        background-color: rgba(245, 158, 11, 0.08);
        border-color: #f59e0b;
        color: #b45309;
    }
    .score-card-red {
        background-color: rgba(239, 68, 68, 0.08);
        border-color: #ef4444;
        color: #b91c1c;
    }
    .score-number {
        font-size: 3.5rem;
        font-weight: 800;
        line-height: 1;
    }
    .verdict-title {
        font-size: 1.7rem;
        font-weight: 700;
        margin-top: 0.5rem;
    }
    .flag-card {
        background: #f8fafc;
        border-left: 4px solid #64748b;
        padding: 0.8rem 1rem;
        margin-bottom: 0.8rem;
        border-radius: 0 8px 8px 0;
    }
    .flag-card-regex {
        border-left-color: #3b82f6;
    }
    .flag-card-llm {
        border-left-color: #8b5cf6;
    }
    .flag-title {
        font-weight: 600;
        font-size: 1rem;
        color: #1e293b;
    }
    .flag-why {
        font-size: 0.92rem;
        color: #475569;
        margin-top: 0.2rem;
    }
    .matched-snippet {
        font-family: monospace;
        background: #e2e8f0;
        padding: 2px 6px;
        border-radius: 4px;
        font-size: 0.85rem;
        color: #0f172a;
    }
    .advice-box {
        background: #eff6ff;
        border: 1px solid #bfdbfe;
        border-radius: 8px;
        padding: 1rem 1.2rem;
        margin-top: 1rem;
    }
    .privacy-box {
        font-size: 0.82rem;
        color: #64748b;
        background: #f1f5f9;
        padding: 0.6rem 0.8rem;
        border-radius: 6px;
        margin-top: 1.5rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Preset examples for fast testing
SAMPLE_MESSAGES = {
    "-- Select a sample or paste your own message below --": "",
    "🚨 Scam: Urgent Bank OTP / CVV Theft": (
        "URGENT: Your Chase Bank account has been suspended due to suspicious activity. "
        "Act now within 24 hours to avoid permanent closure. Click http://chase-security-update.xyz/login "
        "and verify your OTP and debit card PIN immediately."
    ),
    "🚨 Scam: Fake Delivery / Customs Fee": (
        "USPS Notice: Your package delivery has been put on hold due to unpaid customs duty of $2.50. "
        "Update your address and pay immediately at http://tinyurl.com/usps-fee-update to prevent return."
    ),
    "🚨 Scam: Lottery / Cash Prize": (
        "Congratulations! You have been selected as the lucky draw winner of $500,000 in the International "
        "Cash Prize. Claim your prize now. Buy an Apple gift card for $100 processing fee and send code. "
        "Keep this strictly confidential."
    ),
    "🚨 Scam: Legal Threat & Crypto Demand": (
        "FINAL NOTICE: A formal arrest warrant and legal action has been issued against you by the Tax Department. "
        "To avoid police complaint and account frozen, you must immediately send $1,500 via Bitcoin to wallet "
        "address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa. Tell no one."
    ),
    "✅ Genuine: Authentic 2FA Code (Informational)": (
        "Your Google verification code is 849204. Do not share this OTP with anyone. "
        "Google will never call or ask for this code."
    ),
    "✅ Genuine: Office Calendar Meeting": (
        "Hi Sarah, let's meet tomorrow at 10:30 AM in Conference Room B to review the quarterly roadmap. "
        "Let me know if this time works for you."
    ),
}

# Sidebar
with st.sidebar:
    st.image(
        "https://api.iconify.design/lucide:shield-alert.svg?color=%232563eb",
        width=50,
    )
    st.title("About Detector")
    st.markdown(
        """
        **Scam Message Detector** uses a hybrid engine:
        - **40% Regex Heuristics**: Immediate detection of known social engineering patterns, urgent phrases, credential harvesting, and suspicious links.
        - **60% AI Deep Analysis**: Google Gemini evaluates semantic deception, context, impersonation, and pressure tactics.
        """
    )

    api_key_env = os.getenv("GEMINI_API_KEY")
    has_api_key = bool(api_key_env and api_key_env.strip() not in ("", "your_gemini_api_key_here"))

    st.markdown("---")
    st.subheader("System Status")
    if has_api_key:
        st.success("🟢 Gemini API Key detected")
        active_model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
        st.caption(f"Active Model: `{active_model}`")
    else:
        st.warning("🟡 Gemini API Key not set")
        st.caption("Running in **Regex-Only Fallback** mode. Add `GEMINI_API_KEY` to your `.env` to enable full AI analysis.")

    # Optional manual API key override
    user_api_key = st.text_input(
        "Override Gemini API Key (optional):",
        type="password",
        help="Leave empty to use GEMINI_API_KEY from .env",
    )

    st.markdown("---")
    st.markdown(
        """
        **Score Guide:**
        - `0 - 29`: **Safe** (Low risk)
        - `30 - 65`: **Suspicious** (Exercise caution)
        - `66 - 100`: **Likely Scam** (High danger)
        """
    )


# Main layout
st.markdown('<div class="main-header">🛡️ Scam Message Detector</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="sub-header">Paste any suspicious SMS, WhatsApp message, or email to analyze fraud risk and identify red flags.</div>',
    unsafe_allow_html=True,
)

# Sample selector helper
selected_sample = st.selectbox(
    "💡 Or try a preset sample:",
    options=list(SAMPLE_MESSAGES.keys()),
    index=0,
)

# Populate text area if preset selected
default_text = SAMPLE_MESSAGES.get(selected_sample, "")

# User input text box
message_input = st.text_area(
    "Message Content:",
    value=default_text,
    height=150,
    placeholder="Paste suspicious text here (e.g., 'URGENT: Your account has been suspended. Click here to verify your OTP...')...",
)

# Analyze Button
col_btn, col_clear = st.columns([1, 5])
with col_btn:
    analyze_clicked = st.button("🔍 Analyze Message", type="primary", use_container_width=True)

if analyze_clicked:
    if not message_input.strip():
        st.warning("⚠️ Please paste or type a message before analyzing.")
    else:
        effective_key = user_api_key.strip() if user_api_key.strip() else None

        with st.spinner("Analyzing message through heuristic rules and AI engine..."):
            report: ScamAnalysisReport = analyze_message(
                message=message_input,
                api_key=effective_key,
            )

        # Fallback Alert if LLM failed
        if report.llm_fallback_used:
            st.info(
                f"ℹ️ **Pattern Matching Fallback:** AI deep analysis was skipped ({report.llm_error_message}). "
                "Displaying heuristic regex-only score.",
                icon="⚠️",
            )

        # Big colored risk score and verdict card
        color_class = f"score-card-{report.verdict_color}"
        verdict_icon = "🚨" if report.verdict == "Likely Scam" else ("⚠️" if report.verdict == "Suspicious" else "✅")

        st.markdown(
            f"""
            <div class="score-card {color_class}">
                <div style="font-size: 1rem; text-transform: uppercase; letter-spacing: 1px; font-weight: 600;">Scam Risk Score</div>
                <div class="score-number">{report.final_score}<span style="font-size: 1.8rem; font-weight: 400;">/100</span></div>
                <div class="verdict-title">{verdict_icon} Verdict: {report.verdict}</div>
                <div style="margin-top: 0.6rem; font-size: 0.95rem;">
                    Regex Heuristics: <strong>{report.regex_score}/100</strong> (40% weight) | 
                    AI Analysis: <strong>{report.llm_score if report.llm_score is not None else 'N/A'}/100</strong> (60% weight)
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Red Flags Sections
        st.subheader("🚩 Detected Red Flags")
        col_regex, col_llm = st.columns(2)

        # Column 1: Pattern matches (Regex)
        with col_regex:
            st.markdown("#### 🔍 Pattern Matches (Heuristic Engine)")
            if report.regex_matches:
                for match in report.regex_matches:
                    st.markdown(
                        f"""
                        <div class="flag-card flag-card-regex">
                            <div class="flag-title">⚡ {match.rule_name} <span style="font-size: 0.8rem; color: #dc2626;">(+{match.weight} pts)</span></div>
                            <div class="flag-why">{match.explanation}</div>
                            <div style="margin-top: 0.4rem; font-size: 0.85rem;">
                                Matched: <span class="matched-snippet">{match.matched_text}</span>
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
            else:
                st.success("No known scam regex patterns triggered.")

        # Column 2: AI Analysis (LLM)
        with col_llm:
            st.markdown("#### 🤖 AI Analysis (Gemini Model)")
            if report.llm_fallback_used:
                st.caption("AI analysis unavailable. Configure `GEMINI_API_KEY` to enable.")
            elif report.llm_red_flags:
                for flag in report.llm_red_flags:
                    st.markdown(
                        f"""
                        <div class="flag-card flag-card-llm">
                            <div class="flag-title">🧠 {flag.get('flag', 'Red Flag')}</div>
                            <div class="flag-why">{flag.get('why', '')}</div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
            else:
                st.success("AI found no deceptive phrasing or social engineering indicators.")

        # "What to do next" Advice
        st.subheader("🛡️ What To Do Next")
        st.markdown(
            f"""
            <div class="advice-box">
                <p style="margin: 0; font-size: 1rem; line-height: 1.5; color: #1e3a8a;">
                    {report.advice}
                </p>
                <ul style="margin-top: 0.8rem; margin-bottom: 0; color: #1e3a8a; font-size: 0.95rem;">
                    <li><strong>Never click links</strong> sent in unsolicited or urgent messages.</li>
                    <li><strong>Never disclose</strong> OTPs, banking PINs, CVVs, passwords, or personal identity numbers.</li>
                    <li><strong>Verify independently:</strong> Contact the sender organization through their official phone number or website.</li>
                    <li><strong>Block and Report:</strong> Mark as spam/phishing on your phone or email provider and report to cybercrime authorities.</li>
                </ul>
            </div>
            """,
            unsafe_allow_html=True,
        )

# Privacy Note at the bottom
st.markdown(
    """
    <div class="privacy-box">
        🔒 <strong>Privacy Note:</strong> When AI analysis is enabled, message content is transmitted to the Google Gemini API for scam evaluation.
        Do not paste messages containing sensitive personal passwords, private financial credentials, or confidential personal data.
    </div>
    """,
    unsafe_allow_html=True,
)
