import re
from typing import List, Tuple

BANK_FORBIDDEN_PATTERNS = [
    r"\b(otp|one[- ]time|2fa|mfa)\b.*\b(code|passcode|token)\b",
    r"\b(password|passphrase)\b",
    r"\b(card\s+pin|banking\s+pin|\bpin\b)\b",
    r"\b(cvv|cvc)\b",
    r"\b(full\s+card\s+number|card\s+number)\b",
    r"\b(security\s+question|mother's\s+maiden)\b",
    r"\b(seed\s+phrase|private\s+key)\b",
    r"\b(i\s+(checked|accessed)\s+your\s+account)\b",
    r"\b(i\s+(transferred|sent)\s+the\s+money)\b",
    r"\b(i\s+(reversed|refunded)\s+the\s+transaction)\b",
    r"\b(i\s+(unlocked|reset)\s+your\s+account)\b",
]

def role_policy_check(role_id: str, assistant_draft: str) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    text = assistant_draft or ""

    if role_id == "bank_support":
        for pat in BANK_FORBIDDEN_PATTERNS:
            if re.search(pat, text, flags=re.IGNORECASE):
                reasons.append(f"forbidden_pattern:{pat}")

    return (len(reasons) == 0), reasons
