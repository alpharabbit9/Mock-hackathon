"""
QueueStorm ticket classifier.

Pure-Python, rules-based. No external dependencies so it can be imported and
tested without FastAPI installed. main.py wraps this in the web service.

Public entry point: classify(message, locale=None) -> dict
"""

import re

# ---------------------------------------------------------------------------
# Keyword banks (all lowercased; Bengali is unaffected by .lower())
# ---------------------------------------------------------------------------

CREDENTIAL_TERMS = [
    "otp", "o.t.p", "one time password", "one-time password",
    "pin", "passcode", "password", "cvv", "card number", "card no",
    "verification code", "secret code",
    "ওটিপি", "পিন", "পাসওয়ার্ড", "গোপন কোড",
]

# Signals that someone ELSE is requesting the credential / a scam contact.
# This separates phishing from a legit "I forgot my pin" support ticket.
PHISHING_CONTEXT = [
    "asking", "asked", "ask me", "wants my", "want my", "demand", "demanded",
    "called", "calling", "someone", "stranger", "unknown number",
    "share", "give them", "give him", "give her", "send them", "tell them",
    "click", "link", "suspicious", "scam", "scammer", "fraud call",
    "prize", "lottery", "lucky draw", "reward", "claiming", "pretend",
    "pretending", "verify your", "account blocked", "blocked your",
    "is that bkash", "is this bkash", "fake", "phishing",
    "কল", "ফোন", "সন্দেহজনক", "প্রতারক", "লিংক",
]

# Strong standalone scam phrases (phishing even without a credential term).
PHISHING_STRONG = [
    "won a prize", "won prize", "lottery", "lucky draw", "click this link",
    "click the link", "click here", "suspicious call", "suspicious sms",
    "suspicious message", "scammer", "is that bkash", "is this bkash",
    "phishing", "fake call", "account blocked", "verify your account",
]

WRONG_TRANSFER = [
    "wrong number", "wrong nmbr", "wrong no", "wrong recipient", "wrong account",
    "wrong person", "wrong mobile", "wrong receiver", "sent to wrong",
    "sent to a wrong", "mistakenly sent", "sent by mistake", "sent it by mistake",
    "wrong nagad", "wrong bkash number", "vul number", "vul nmbr",
    "ভুল নম্বর", "ভুল নাম্বার", "ভুল নাম্বারে", "ভুল নম্বরে", "ভুলে পাঠিয়েছি",
    "ভুল করে পাঠিয়েছি",
]

PAYMENT_FAILED = [
    "payment failed", "transaction failed", "failed transaction", "failed but",
    "balance deducted", "balance was deducted", "money deducted", "amount deducted",
    "deducted but", "deducted but not", "did not go through", "didn't go through",
    "did not complete", "cash out failed", "cashout failed", "send money failed",
    "recharge failed", "bill payment failed", "money cut but",
    "ব্যর্থ", "টাকা কাটা", "টাকা কেটে", "কেটে নিয়েছে", "কাটা হয়েছে",
    "টাকা কেটে নিয়েছে",
]

REFUND = [
    "refund", "money back", "return my money", "give back my money",
    "want my money back", "changed my mind", "reverse the payment",
    "ফেরত", "রিফান্ড", "টাকা ফেরত",
]

# Refund signals that make it a contested dispute (-> dispute_resolution).
CONTESTED_REFUND = [
    "unauthorized", "did not authorize", "didn't authorize", "not authorized",
    "without my permission", "without permission", "fraudulent", "double charged",
    "charged twice", "charged me twice", "billed twice", "disputed", "dispute",
    "i did not make", "i didn't make", "never made this",
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _contains_any(text, keywords):
    return any(k in text for k in keywords)


def _extract_amount(text):
    """Best-effort numeric amount for the agent summary. Returns a string like
    '5000' or None."""
    # number directly followed by a currency word: "5000 taka", "5000tk"
    m = re.search(r"(\d[\d,]*)\s*(?:taka|tk\.?|bdt|৳|টাকা)", text)
    if not m:
        # currency word then number: "taka 5000", "৳ 5000"
        m = re.search(r"(?:taka|tk\.?|bdt|৳|টাকা)\s*(\d[\d,]*)", text)
    if not m:
        # fallback: any standalone 3+ digit number
        m = re.search(r"\b(\d{3,})\b", text)
    if not m:
        return None
    return m.group(1).replace(",", "")


def _is_phishing(text):
    has_cred = _contains_any(text, CREDENTIAL_TERMS)
    has_context = _contains_any(text, PHISHING_CONTEXT)
    if has_cred and has_context:
        return True
    if _contains_any(text, PHISHING_STRONG):
        return True
    return False


# ---------------------------------------------------------------------------
# Summaries (NEVER ask the customer for PIN / OTP / password / card number)
# ---------------------------------------------------------------------------


def _build_summary(case_type, text, contested):
    amount = _extract_amount(text)
    amt_bdt = f"{amount} BDT" if amount else None

    if case_type == "wrong_transfer":
        target = amt_bdt or "money"
        return f"Customer reports sending {target} to the wrong recipient and requests recovery."
    if case_type == "payment_failed":
        clause = f" of {amt_bdt}" if amt_bdt else ""
        return f"Customer reports a failed transaction{clause} with a possible balance deduction."
    if case_type == "refund_request":
        if contested:
            return "Customer is disputing a charge they say was unauthorized and requesting a refund."
        return "Customer is requesting a refund for a recent transaction."
    if case_type == "phishing_or_social_engineering":
        return ("Customer reports a suspicious contact requesting sensitive account "
                "credentials, indicating a possible phishing or social engineering attempt.")
    return "Customer reports a general issue that does not match transfer, payment, refund, or fraud categories."


# Defense-in-depth: guarantee the summary never instructs the customer to
# share credentials, regardless of how it was built.
_BANNED_REQUEST_PATTERNS = [
    r"(share|send|provide|give|enter|tell|type|confirm)\b[^.]*\b(otp|pin|password|passcode|cvv|card number)",
]


def _sanitize_summary(summary):
    for pat in _BANNED_REQUEST_PATTERNS:
        if re.search(pat, summary, re.IGNORECASE):
            return ("Customer reports a suspected phishing attempt involving sensitive "
                    "credentials; specifics withheld for safety.")
    return summary


# ---------------------------------------------------------------------------
# Main classifier
# ---------------------------------------------------------------------------

# severity / department lookups keyed by case_type
_BASE_SEVERITY = {
    "phishing_or_social_engineering": "critical",
    "wrong_transfer": "high",
    "payment_failed": "high",
    "refund_request": "low",
    "other": "low",
}

_BASE_CONFIDENCE = {
    "phishing_or_social_engineering": 0.9,
    "wrong_transfer": 0.86,
    "payment_failed": 0.86,
    "refund_request": 0.8,
    "other": 0.45,
}


def classify(message, locale=None):
    text = (message or "").lower()

    # Detect every category that fires, so we can measure ambiguity.
    phishing = _is_phishing(text)
    wrong = _contains_any(text, WRONG_TRANSFER)
    failed = _contains_any(text, PAYMENT_FAILED)
    refund = _contains_any(text, REFUND)
    contested = refund and _contains_any(text, CONTESTED_REFUND)

    # Precedence: fraud safety first, then money-at-risk, then refund, then other.
    if phishing:
        case_type = "phishing_or_social_engineering"
    elif wrong:
        case_type = "wrong_transfer"
    elif failed:
        case_type = "payment_failed"
    elif refund:
        case_type = "refund_request"
    else:
        case_type = "other"

    severity = _BASE_SEVERITY[case_type]
    # A contested refund is more than a low-priority "changed my mind".
    if case_type == "refund_request" and contested:
        severity = "medium"

    if case_type == "phishing_or_social_engineering":
        department = "fraud_risk"
    elif case_type == "wrong_transfer":
        department = "dispute_resolution"
    elif case_type == "payment_failed":
        department = "payments_ops"
    elif case_type == "refund_request":
        department = "dispute_resolution" if contested else "customer_support"
    else:
        department = "customer_support"

    summary = _sanitize_summary(_build_summary(case_type, text, contested))

    human_review_required = (
        severity == "critical" or case_type == "phishing_or_social_engineering"
    )

    # Confidence: start from the base, drop a little if multiple money/refund
    # categories also fired (ambiguous wording).
    fired = sum([wrong, failed, refund])
    confidence = _BASE_CONFIDENCE[case_type]
    if case_type != "other" and case_type != "phishing_or_social_engineering" and fired > 1:
        confidence = round(confidence - 0.1, 2)
    if case_type == "other" and not text.strip():
        confidence = 0.3

    return {
        "case_type": case_type,
        "severity": severity,
        "department": department,
        "agent_summary": summary,
        "human_review_required": human_review_required,
        "confidence": confidence,
    }
