"""Trust roster schema — the YAML file the user maintains.

This is the heart of the project: a user-defined list of trusted people,
their roles, their domains, and what authority they hold.
"""
from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field

AuthorityLevel = Literal["none", "low", "medium", "high"]


class Person(BaseModel):
    """A trusted person — internal employee or external contact."""

    id: str
    display_names: list[str] = Field(default_factory=list)
    addresses: list[str]
    role: str = ""
    organization: str | None = None
    authority: dict[str, AuthorityLevel] = Field(default_factory=dict)
    pgp_fingerprint: str | None = None
    valid_until: date | None = None


class Organization(BaseModel):
    """The organization Roster is protecting."""

    name: str
    primary_domains: list[str]
    dmarc_required: bool = False


class TrustRoster(BaseModel):
    """The full trust roster — load this from YAML."""

    version: int = 1
    organization: Organization
    people: list[Person] = Field(default_factory=list)

    # --- lookup helpers ---

    def find_by_display_name(self, name: str) -> list[Person]:
        """Case-insensitive lookup by display name (handles aliases)."""
        if not name:
            return []
        target = name.lower().strip()
        return [
            p for p in self.people
            if any(dn.lower().strip() == target for dn in p.display_names)
        ]

    def find_by_address(self, address: str) -> Person | None:
        """Case-insensitive exact-match lookup by email address."""
        if not address:
            return None
        target = address.lower().strip()
        for p in self.people:
            if any(addr.lower().strip() == target for addr in p.addresses):
                return p
        return None

    # --- loading ---

    @classmethod
    def from_yaml(cls, path: str | Path) -> TrustRoster:
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(**data)
