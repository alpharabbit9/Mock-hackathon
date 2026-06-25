"""Quick offline check against the 5 public sample cases. Run: python test_local.py"""
from classifier import classify

CASES = [
    ("I sent 3000 to wrong number", "wrong_transfer", "high"),
    ("Payment failed but balance deducted", "payment_failed", "high"),
    ("Someone called asking my OTP, is that bKash?", "phishing_or_social_engineering", "critical"),
    ("Please refund my last transaction, I changed my mind", "refund_request", "low"),
    ("App crashed when I opened it", "other", "low"),
]

ok = True
for i, (msg, want_type, want_sev) in enumerate(CASES, 1):
    r = classify(msg)
    type_ok = r["case_type"] == want_type
    sev_ok = r["severity"] == want_sev
    ok = ok and type_ok and sev_ok
    mark = "PASS" if (type_ok and sev_ok) else "FAIL"
    print(f"[{mark}] case {i}: {msg!r}")
    print(f"        case_type={r['case_type']} (want {want_type})  severity={r['severity']} (want {want_sev})")
    print(f"        dept={r['department']}  review={r['human_review_required']}  conf={r['confidence']}")
    print(f"        summary={r['agent_summary']}")

print("\nALL PASS" if ok else "\nSOME FAILED")
