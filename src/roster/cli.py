"""CLI entry point — `roster verify <eml> --roster <yaml>`."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engine import analyze_file
from .findings import Finding
from .schema import TrustRoster

SEVERITY_COLORS = {
    "critical": "\033[1;31m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "info": "\033[37m",
}
GREEN = "\033[32m"
RESET = "\033[0m"
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _format_human(findings: list[Finding]) -> str:
    if not findings:
        return f"{GREEN}OK   No findings. Email appears clean against the current roster.{RESET}"

    lines: list[str] = []
    by_severity: dict[str, list[Finding]] = {s: [] for s in SEVERITY_ORDER}
    for f in findings:
        by_severity[f.severity].append(f)

    for sev in SEVERITY_ORDER:
        for f in by_severity[sev]:
            color = SEVERITY_COLORS[sev]
            lines.append(f"{color}[{sev.upper()}] {f.rule_id}: {f.title}{RESET}")
            lines.append(f"  {f.description}")
            lines.append(f"  -> {f.suggested_action}")
            lines.append("")
    return "\n".join(lines).rstrip()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="roster",
        description=(
            "Analyze an email (.eml) against a trust roster for BEC and impersonation."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    verify = sub.add_parser("verify", help="Verify an EML file against a trust roster")
    verify.add_argument("eml", help="Path to the .eml file")
    verify.add_argument(
        "--roster", "-r", required=True, help="Path to trust-roster.yaml"
    )
    verify.add_argument(
        "--json", action="store_true", help="Output findings as JSON"
    )

    args = parser.parse_args()

    if args.command == "verify":
        eml_path = Path(args.eml)
        roster_path = Path(args.roster)
        if not eml_path.exists():
            print(f"Error: EML file not found: {eml_path}", file=sys.stderr)
            sys.exit(2)
        if not roster_path.exists():
            print(f"Error: roster file not found: {roster_path}", file=sys.stderr)
            sys.exit(2)

        roster = TrustRoster.from_yaml(roster_path)
        findings = analyze_file(eml_path, roster)

        if args.json:
            print(json.dumps(
                [f.model_dump() for f in findings], indent=2, default=str
            ))
        else:
            print(_format_human(findings))

        # Exit 0 if clean, 1 if any findings (CI-friendly).
        sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
