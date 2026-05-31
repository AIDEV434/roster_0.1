"""Engine — runs all rules over a parsed email and returns findings."""
from __future__ import annotations

from pathlib import Path

from .findings import Finding
from .parser import parse_eml
from .rules import ALL_RULES
from .schema import TrustRoster


def analyze(eml_bytes: bytes, roster: TrustRoster) -> list[Finding]:
    """Run every rule against an EML byte string and return all findings."""
    parsed = parse_eml(eml_bytes)
    findings: list[Finding] = []
    for rule in ALL_RULES:
        findings.extend(rule(parsed, roster))
    return findings


def analyze_file(eml_path: str | Path, roster: TrustRoster) -> list[Finding]:
    """Read an EML file from disk and analyze it."""
    with open(eml_path, "rb") as f:
        return analyze(f.read(), roster)
