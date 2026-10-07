"""Find and redact personal / financial identifiers (Indian formats) in A2A messages.

Types
    pan       PAN card            ABCDE1234F
    aadhaar   Aadhaar number      1234 5678 9012 (spaced, or 12 digits after "aadhaar"/"uid")
    card      payment card        13-19 digits that pass the Luhn check
    email     e-mail address
    phone     Indian mobile       +91 98xxxxxxxx / 98xxxxxxxx
    bank      bank account/IFSC   structured fields bank_account / ifsc, or
                                  "account number: 1234567890" and IFSC codes in text

Each receiving agent has an allow-list (e.g. the payment approver may see bank details);
everything else is replaced with [REDACTED:<type>] before the message is forwarded.
"""

from __future__ import annotations

import re

PATTERNS = {
    "pan": re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
    "aadhaar": re.compile(r"(?<![\d-])(?<!\d )[2-9]\d{3} \d{4} \d{4}(?![ -]?\d)"
                          r"|(?i:(?:aadhaar|aadhar|uid)\D{0,15})\b[2-9]\d{11}\b"),
    "email": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    "phone": re.compile(r"(?<![\w+])(?:\+91[\s-]?)?[6-9]\d{9}(?!\w)"),
    "bank": re.compile(r"(?i:account\s*(?:number|no\.?)?\s*[:#]?\s*)\d{9,18}\b|\b[A-Z]{4}0[A-Z0-9]{6}\b"),
}
CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")
BANK_KEYS = {"bank_account", "ifsc", "account_number"}
ID_KEYS = {"messageId", "contextId", "taskId", "id", "approval_id", "payment_id", "mediaType", "role"}


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d = d * 2 - 9 if d > 4 else d * 2
        total, alt = total + d, not alt
    return total % 10 == 0


def find(text: str) -> list[tuple[str, str]]:
    hits, spans = [], []
    for kind, p in PATTERNS.items():
        for m in p.finditer(text):
            hits.append((kind, m.group(0)))
            spans.append((m.start(), m.end()))
    for m in CARD.finditer(text):
        if any(s < m.end() and m.start() < e for s, e in spans):
            continue  # already explained, e.g. a labelled bank account number
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            hits.append(("card", m.group(0).strip()))
    return hits


def redact_text(text: str, allowed: set[str]) -> tuple[str, list[str]]:
    found = []
    for kind, value in sorted(find(text), key=lambda h: -len(h[1])):
        if kind in allowed or value not in text:
            continue
        text = text.replace(value, f"[REDACTED:{kind}]")
        found.append(kind)
    return text, found


def redact(obj, allowed: set[str], key: str | None = None):
    """Recursively redact a JSON-like object. Returns (new_obj, list_of_redacted_types)."""
    if isinstance(obj, str):
        if key in ID_KEYS:
            return obj, []
        if key in BANK_KEYS:
            return (obj, []) if "bank" in allowed else ("[REDACTED:bank]", ["bank"])
        return redact_text(obj, allowed)
    if isinstance(obj, dict):
        out, found = {}, []
        for k, v in obj.items():
            out[k], f = redact(v, allowed, k)
            found += f
        return out, found
    if isinstance(obj, list):
        out, found = [], []
        for v in obj:
            nv, f = redact(v, allowed, key)
            out.append(nv); found += f
        return out, found
    return obj, []
