"""Detection rules.

Each rule is a pure function: (ParsedEmail, TrustRoster) -> list[Finding].
Add new rules by writing a function and appending to ALL_RULES.
"""
from __future__ import annotations

import re

from .findings import Finding
from .parser import ParsedEmail
from .schema import TrustRoster

# Financial-action keywords that warrant scrutiny on first-contact senders.
FINANCIAL_KEYWORDS = [
    "wire transfer", "wire", "ach", "banking details", "bank details",
    "change of bank", "invoice attached", "urgent payment", "gift card",
    "iban", "swift", "routing number", "account number",
    "remit", "remittance", "vendor payment", "update payment",
]


# --- helpers ---

def _levenshtein(a: str, b: str) -> int:
    """Iterative Levenshtein distance. Used for lookalike-domain detection."""
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        current = [i + 1]
        for j, cb in enumerate(b):
            ins = previous[j + 1] + 1
            dele = current[j] + 1
            sub = previous[j] + (ca != cb)
            current.append(min(ins, dele, sub))
        previous = current
    return previous[-1]


# --- rules ---

def rule_display_name_impersonation(
    email: ParsedEmail, roster: TrustRoster
) -> list[Finding]:
    """ROSTER-001: From display name matches a roster person, address does not."""
    findings: list[Finding] = []
    if not email.from_display_name:
        return findings

    matches = roster.find_by_display_name(email.from_display_name)
    addr_lower = email.from_address.lower().strip()
    for person in matches:
        allowed = [a.lower().strip() for a in person.addresses]
        if addr_lower in allowed:
            continue  # legitimate
        findings.append(Finding(
            rule_id="ROSTER-001",
            severity="critical",
            title="Display name impersonation",
            description=(
                f"Sender uses display name '{email.from_display_name}' which matches "
                f"roster entry '{person.id}' ({person.role}), but the email address "
                f"'{email.from_address}' is not in their allowed list."
            ),
            evidence={
                "from_display_name": email.from_display_name,
                "from_address": email.from_address,
                "matched_person_id": person.id,
                "allowed_addresses": person.addresses,
            },
            suggested_action="BLOCK. Verify out-of-band (phone) before any action.",
        ))
    return findings


def rule_lookalike_domain(
    email: ParsedEmail, roster: TrustRoster
) -> list[Finding]:
    """ROSTER-002: Sender domain is suspiciously close to a primary domain."""
    findings: list[Finding] = []
    primaries = [d.lower() for d in roster.organization.primary_domains]
    sender = email.from_domain
    if not sender or sender in primaries:
        return findings

    for trusted in primaries:
        dist = _levenshtein(sender, trusted)
        if 0 < dist <= 2:
            findings.append(Finding(
                rule_id="ROSTER-002",
                severity="high",
                title="Lookalike sender domain",
                description=(
                    f"Sender domain '{sender}' is suspiciously similar to trusted "
                    f"primary domain '{trusted}' (edit distance: {dist})."
                ),
                evidence={
                    "sender_domain": sender,
                    "trusted_domain": trusted,
                    "edit_distance": dist,
                },
                suggested_action="BLOCK or QUARANTINE. Likely typosquat.",
            ))
            break
    return findings


def rule_punycode_or_unicode_in_from(
    email: ParsedEmail, roster: TrustRoster
) -> list[Finding]:
    """ROSTER-003: IDN / non-ASCII / Punycode in the From address."""
    findings: list[Finding] = []
    addr = email.from_address
    if not addr:
        return findings

    try:
        addr.encode("ascii")
    except UnicodeEncodeError:
        findings.append(Finding(
            rule_id="ROSTER-003",
            severity="high",
            title="Non-ASCII characters in sender address",
            description=(
                f"Sender address '{addr}' contains non-ASCII characters — a common "
                f"homograph attack technique (e.g., Cyrillic 'а' vs Latin 'a')."
            ),
            evidence={"from_address": addr},
            suggested_action="QUARANTINE. Verify if an IDN sender is genuinely expected.",
        ))
        return findings

    if "xn--" in email.from_domain:
        findings.append(Finding(
            rule_id="ROSTER-003",
            severity="medium",
            title="Punycode in sender domain",
            description=(
                f"Sender domain '{email.from_domain}' uses Punycode (xn--). "
                f"Legitimate for IDN, but commonly used for homograph attacks."
            ),
            evidence={"from_domain": email.from_domain},
            suggested_action="QUARANTINE for manual review.",
        ))
    return findings


def rule_reply_to_divergence(
    email: ParsedEmail, roster: TrustRoster
) -> list[Finding]:
    """ROSTER-004: From is in roster, but Reply-To points elsewhere."""
    findings: list[Finding] = []
    if not email.reply_to_domain or not email.from_domain:
        return findings
    if email.reply_to_domain == email.from_domain:
        return findings

    person = roster.find_by_address(email.from_address)
    if person:
        findings.append(Finding(
            rule_id="ROSTER-004",
            severity="high",
            title="Reply-To divergence on roster sender",
            description=(
                f"From address '{email.from_address}' matches roster entry "
                f"'{person.id}' ({person.role}), but Reply-To points to a different "
                f"domain: '{email.reply_to_address}'. Classic BEC technique."
            ),
            evidence={
                "from_address": email.from_address,
                "reply_to_address": email.reply_to_address,
                "matched_person_id": person.id,
            },
            suggested_action="BLOCK. Do not reply. Verify out-of-band.",
        ))
    return findings


def rule_authentication_on_roster(
    email: ParsedEmail, roster: TrustRoster
) -> list[Finding]:
    """ROSTER-005/006: SPF/DKIM/DMARC failure on a roster sender."""
    findings: list[Finding] = []
    person = roster.find_by_address(email.from_address)
    if not person:
        return findings

    auth = (email.authentication_results or "").lower()

    if not auth:
        if roster.organization.dmarc_required:
            findings.append(Finding(
                rule_id="ROSTER-005",
                severity="medium",
                title="Missing authentication results on roster sender",
                description=(
                    f"From address '{email.from_address}' is in the roster but the "
                    f"message has no Authentication-Results header. Your MTA may "
                    f"not be checking SPF/DKIM/DMARC."
                ),
                evidence={"from_address": email.from_address},
                suggested_action="QUARANTINE. Audit your MTA configuration.",
            ))
        return findings

    failed = [
        proto.upper()
        for proto in ("spf", "dkim", "dmarc")
        if re.search(rf"\b{proto}\s*=\s*fail\b", auth)
    ]
    if failed:
        findings.append(Finding(
            rule_id="ROSTER-006",
            severity="critical",
            title="Authentication failure on roster sender",
            description=(
                f"From address '{email.from_address}' matches roster entry "
                f"'{person.id}' ({person.role}), but {', '.join(failed)} "
                f"authentication FAILED. Almost certainly spoofed."
            ),
            evidence={
                "from_address": email.from_address,
                "failed_protocols": failed,
                "authentication_results": email.authentication_results,
            },
            suggested_action="BLOCK. Strong spoofing indicator.",
        ))
    return findings


def rule_first_contact_financial(
    email: ParsedEmail, roster: TrustRoster
) -> list[Finding]:
    """ROSTER-007: Unknown sender + financial-action language in body/subject."""
    findings: list[Finding] = []
    if roster.find_by_address(email.from_address):
        return findings  # known sender, different rules apply

    haystack = (email.body_text or "").lower() + " " + (email.subject or "").lower()
    matched = [kw for kw in FINANCIAL_KEYWORDS if kw in haystack]
    if matched:
        findings.append(Finding(
            rule_id="ROSTER-007",
            severity="medium",
            title="First-contact sender with financial language",
            description=(
                f"Sender '{email.from_address}' is not in the trust roster and the "
                f"message contains financial-action keywords: {matched}."
            ),
            evidence={
                "from_address": email.from_address,
                "matched_keywords": matched,
            },
            suggested_action="WARN user. Verify the request out-of-band before acting.",
        ))
    return findings


ALL_RULES = [
    rule_display_name_impersonation,
    rule_lookalike_domain,
    rule_punycode_or_unicode_in_from,
    rule_reply_to_divergence,
    rule_authentication_on_roster,
    rule_first_contact_financial,
]
