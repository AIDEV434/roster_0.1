"""Findings — structured output from detection rules.

The MISP/STIX-friendly shape so SOC tooling can consume verdicts.
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high", "critical"]


class Finding(BaseModel):
    rule_id: str
    severity: Severity
    title: str
    description: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    suggested_action: str
