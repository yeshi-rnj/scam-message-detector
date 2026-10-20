# 🛡️ Scam Message Detector

A hybrid AI & heuristic fraud detection web application built with Python and Streamlit. Paste any suspicious SMS, WhatsApp message, or email to receive an instant risk score (0–100), a clear verdict (**Safe**, **Suspicious**, or **Likely Scam**), and a detailed breakdown of red flags explained in plain language.

---

## 🚀 Features

- **Hybrid Detection Engine**:
  - **40% Regex Heuristics (`rules.py`)**: Instant pattern matching for 9 classic scam indicators (urgency, credential harvesting, fake prizes, legal threats, gift cards/crypto demands, suspicious shorteners/TLDs, institutional impersonation, secrecy requests, and lookalike domains).
  - **60% AI Deep Analysis (`llm.py`)**: Google Gemini (`google-genai` SDK) analyzes semantic deception, subtle pressure, and contextual social engineering.
- **Fail-Safe Architecture**: If the Gemini API key is missing or an API call fails, the app seamlessly falls back to 100% regex analysis and clearly notifies the user.
- **Swappable LLM Provider**: Clean abstract base class interface (`BaseLLMProvider`) allowing easy switching to alternative models (OpenAI, Anthropic, or local models).
- **Intuitive Streamlit UI (`app.py`)**:
  - High-impact color-coded risk meter and verdict.
  - Side-by-side red flags breakdown: **Pattern Matches** vs. **AI Analysis**.
  - Actionable **"What To Do Next"** guidance.
  - One-click preset samples for instant testing.
  - Transparent privacy disclosure.
- **Automated Testing (`tests/`)**: Pytest test suite covering all 9 rule categories, 5 realistic scam samples, 3 legitimate messages, and scoring formula edge cases.

---

## 📁 Project Structure

```
Scam_detect/
├── app.py              # Streamlit web application & user interface
├── rules.py            # Regex heuristic rules (9 categories, weights, explanations)
├── llm.py              # Modular LLM integration with Google Gemini & JSON validator
├── scorer.py           # Hybrid scoring engine (0.4 regex + 0.6 LLM) and fallback
├── requirements.txt    # Project dependencies
├── .env.example        # Environment variable template
├── .gitignore          # Ignores .env, virtual environments, and cache files
├── README.md           # Documentation & Windows setup guide
└── tests/
    ├── __init__.py
    ├── test_rules.py   # Pytest tests for regex rules, 5 scam & 3 genuine samples
    └── test_scorer.py  # Pytest tests for scoring weights, capping, and fallback
```

---

## ⚙️ Windows Setup Instructions

### 1. Prerequisites
- Python 3.10 or higher installed on Windows. Ensure Python is added to your system `PATH`.

### 2. Open PowerShell or Command Prompt
Open PowerShell and navigate to the project directory:
```powershell
cd c:\Users\ASUS\OneDrive\Desktop\Scam_detect
```

### 3. Create and Activate a Virtual Environment
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```
*(If PowerShell shows an execution policy error, run `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process` first).*

### 4. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 5. Configure Your Gemini API Key
1. Copy `.env.example` to `.env`:
   ```powershell
   copy .env.example .env
   ```
2. Open `.env` in any text editor and paste your Google Gemini API key:
   ```env
   GEMINI_API_KEY=AIzaSy...YourActualKeyHere
   GEMINI_MODEL=gemini-2.5-flash
   ```
   *(Get an API key for free at [Google AI Studio](https://aistudio.google.com/)).*

> **Note:** If no API key is provided, the application will automatically run in **Regex-Only Fallback Mode**.

---

## 🖥️ Running the Application

Start the Streamlit web server:
```powershell
streamlit run app.py
```
Streamlit will automatically open your default browser at:
`http://localhost:8501`

---

## 🧪 Running Automated Tests

Run the full pytest suite:
```powershell
pytest -v
```

All 16 test cases (individual rule tests, 5 scam samples, 3 genuine messages, scoring weights, score capping, and fallback behavior) should pass.

---

## 📊 Scoring Breakdown & Verdict Thresholds

| Risk Score | Verdict | Visual Indicator | Meaning |
| :--- | :--- | :--- | :--- |
| **0 – 29** | **Safe** | 🟢 Green | Low risk; no common fraud indicators detected. |
| **30 – 65** | **Suspicious** | 🟠 Orange | Medium risk; potential marketing lure or unverified links. Exercise caution. |
| **66 – 100** | **Likely Scam** | 🔴 Red | High risk; typical of credential harvesting, extortion, or impersonation fraud. |

Formula:
$$\text{Final Score} = \min(100, \text{round}(0.4 \times \text{regex\_score} + 0.6 \times \text{llm\_score}))$$
*(If LLM is unavailable: $\text{Final Score} = \text{regex\_score}$)*

---

## 🔒 Privacy Notice

When the Gemini API key is configured, message text is sent to Google Gemini for contextual analysis. Never paste messages containing actual passwords, private PINs, full payment card numbers, or sensitive personal identification information.
