# Contributing to Roster

Thanks for considering a contribution. Roster grows by community-maintained detection rules and real-world test samples.

## Ways to help

### 1. New detection rules

Add a function to `src/roster/rules.py`:

```python
def rule_my_new_check(email: ParsedEmail, roster: TrustRoster) -> list[Finding]:
    """ROSTER-XYZ: One-line description of what this catches."""
    findings: list[Finding] = []
    # your logic
    return findings
```

Append it to `ALL_RULES` at the bottom of the file. Add tests in `tests/test_rules.py`. Rule IDs are monotonic — pick the next free `ROSTER-NNN`.

Good rules:
- Are pure functions (no I/O, no network calls)
- Return explainable evidence dictionaries
- Have at least one positive and one negative test

### 2. Sanitized phish samples

Drop sanitized real-world .eml files into `examples/corpus/`. Strip recipient PII first. These help us grow the public test corpus.

### 3. Documentation

Threat-model docs, deployment guides for specific MTAs (Postfix, Exim, Microsoft 365 connectors), Gmail/Outlook integration walkthroughs — all welcome.

## Dev setup

```bash
git clone https://github.com/yourname/roster
cd roster
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check src tests
```

## Pull request checklist

- [ ] Tests added/updated and `pytest` passes
- [ ] `ruff check` passes
- [ ] No external network calls in rules
- [ ] No telemetry / no upload of email content anywhere
- [ ] README updated if you added a rule ID

## Code of conduct

Be kind. Assume good faith. This is a defensive security project — keep it focused on protecting users.
