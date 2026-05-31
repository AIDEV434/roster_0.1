# Roster

> **Open-source, local-first defense against display-name spoofing, lookalike-domain phishing, and Business Email Compromise.**

![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)

There are two ways to use Roster:

1. **In your browser, no installation** — open locally on GitHub Pages
2. **As a Python CLI** — for SOC analysts and integration with SIEM / SOAR / MISP

Both share the same detection rules. Nothing is ever uploaded.

## In-browser (recommended for everyone)

The GUI has three tabs:
- **Check Email** — paste a raw email, click *Check Email*, see findings
- **Trust Roster** — define your organization, primary domains, and the people whose names get impersonated (CEO, CFO, contractors). Saved automatically in your browser's localStorage.
- **About** — the threat model and what the tool does and does not defend against

## How to get a raw email to paste in

- **Gmail:** open the email → 3-dot menu → *Show original* → copy the entire content
- **Outlook (web):** 3-dot menu → *View → View message source*
- **Apple Mail:** *View → Message → Raw Source*

## Detection rules

| Rule | What it catches | Severity |
|------|-----------------|----------|
| `ROSTER-001` | Display-name impersonation (right name, wrong address) | Critical |
| `ROSTER-002` | Lookalike sender domain (typosquats, edit distance ≤ 2) | High |
| `ROSTER-003` | Punycode / non-ASCII (homograph attacks) | High |
| `ROSTER-004` | Reply-To divergence on roster sender | High |
| `ROSTER-005` | Missing auth headers (when DMARC required) | Medium |
| `ROSTER-006` | SPF / DKIM / DMARC failure on roster sender | Critical |
| `ROSTER-007` | Unknown sender + financial-action language | Medium |

## Enabling the hosted version (GitHub Pages)

If you're hosting this repo, you can get a free public URL for the tool in 30 seconds:

1. On your repo page, click **Settings** (top tab)
2. In the left sidebar, click **Pages**
3. Under "Build and deployment":
   - **Source:** Deploy from a branch
   - **Branch:** `main` and `/` (root)
4. Click **Save**
5. Wait 1–2 minutes, then visit `https://YOUR-USERNAME.github.io/roster/`

That's the URL you can share with anyone. They paste an email, the tool runs in their browser, nothing gets uploaded.

## Python CLI (for analysts)

If you have Python 3.10+:

```bash
git clone https://github.com/YOUR-USERNAME/roster
cd roster
pip install -e ".[dev]"
roster verify examples/sample-phish.eml --roster examples/trust-roster.yaml
```

JSON output (for SIEM / SOAR / MISP):

```bash
roster verify message.eml --roster trust-roster.yaml --json
```

Run the tests:

```bash
pytest
```

## Threat model

**Defends against:**
- Display-name spoofing from arbitrary domains
- Lookalike / typosquatted sender domains
- IDN / Punycode homograph attacks
- Reply-To redirects on roster senders
- SPF / DKIM / DMARC bypass attempts
- First-contact senders using financial-fraud language

**Does NOT defend against:**
- Compromised legitimate vendor mailboxes (no behavioral profiling in v0.1)
- Malicious attachments or URLs (use ClamAV or a URL sandbox in parallel)
- Deepfake voice / video referenced inside email bodies
- Account compromise via session token theft

## Privacy

Everything runs locally. The browser version stores your roster in `localStorage`, which never leaves your device. The Python version reads YAML files on your disk. There is no telemetry, no analytics, no phone-home, no cloud component.

## Contributing

This is a community-driven project. The maintainer is a CTI/OSINT professional; Python contributors are very welcome — see `CONTRIBUTING.md`.

The biggest help right now: code review on the detection rules, and sanitized real-world phish samples to build a public test corpus.

## License

Apache 2.0.
