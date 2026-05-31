"""Tests for detection rules."""
from __future__ import annotations

import pytest

from roster.engine import analyze
from roster.schema import Organization, Person, TrustRoster


@pytest.fixture
def roster() -> TrustRoster:
    return TrustRoster(
        organization=Organization(
            name="ACME Corp",
            primary_domains=["acme.com"],
            dmarc_required=True,
        ),
        people=[
            Person(
                id="alice-cfo",
                display_names=["Alice Johnson", "A. Johnson"],
                addresses=["alice@acme.com", "alice.johnson@acme.com"],
                role="CFO",
                authority={"financial": "high"},
            ),
        ],
    )


def _make_eml(
    from_header: str,
    reply_to: str | None = None,
    auth_results: str | None = None,
    subject: str = "Test",
    body: str = "Hello",
) -> bytes:
    headers = [f"From: {from_header}"]
    if reply_to:
        headers.append(f"Reply-To: {reply_to}")
    if auth_results:
        headers.append(f"Authentication-Results: {auth_results}")
    headers.append(f"Subject: {subject}")
    headers.append("To: <user@acme.com>")
    headers.append("Content-Type: text/plain; charset=utf-8")
    return ("\r\n".join(headers) + "\r\n\r\n" + body).encode("utf-8")


def test_display_name_impersonation_detected(roster: TrustRoster) -> None:
    eml = _make_eml('"Alice Johnson" <alice@evil.com>')
    findings = analyze(eml, roster)
    assert any(f.rule_id == "ROSTER-001" for f in findings)


def test_legitimate_email_has_no_critical_findings(roster: TrustRoster) -> None:
    eml = _make_eml(
        '"Alice Johnson" <alice@acme.com>',
        auth_results="mx.example.com; spf=pass; dkim=pass; dmarc=pass",
        body="Just a reminder about tomorrow's meeting.",
    )
    findings = analyze(eml, roster)
    high_or_critical = [f for f in findings if f.severity in ("critical", "high")]
    assert high_or_critical == []


def test_lookalike_domain_detected(roster: TrustRoster) -> None:
    # "acrne.com" vs "acme.com" — edit distance of 2 (r,n inserted; m removed)
    eml = _make_eml('"Someone" <someone@acrne.com>')
    findings = analyze(eml, roster)
    assert any(f.rule_id == "ROSTER-002" for f in findings)


def test_reply_to_divergence_detected(roster: TrustRoster) -> None:
    eml = _make_eml(
        '"Alice Johnson" <alice@acme.com>',
        reply_to="<attacker@gmail.com>",
        auth_results="spf=pass; dkim=pass; dmarc=pass",
    )
    findings = analyze(eml, roster)
    assert any(f.rule_id == "ROSTER-004" for f in findings)


def test_auth_failure_on_roster_sender(roster: TrustRoster) -> None:
    eml = _make_eml(
        '"Alice Johnson" <alice@acme.com>',
        auth_results="spf=fail; dkim=fail; dmarc=fail",
    )
    findings = analyze(eml, roster)
    assert any(f.rule_id == "ROSTER-006" for f in findings)


def test_first_contact_financial(roster: TrustRoster) -> None:
    eml = _make_eml(
        '"Unknown" <unknown@randomdomain.com>',
        subject="urgent payment needed",
        body="Please process this wire transfer today.",
    )
    findings = analyze(eml, roster)
    assert any(f.rule_id == "ROSTER-007" for f in findings)
