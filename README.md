# ROSTER — BEC Forensic Console

> Detect business email compromise, phishing infrastructure, and display-name spoofing in seconds. No installation. No account. Runs entirely in your browser.

**🔗 [roster.mom](https://roster.mom)**

![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)

---

## What is ROSTER?

ROSTER is an open-source forensic tool built for security analysts, IT teams, and anyone who receives suspicious emails. Paste a raw email, get a full breakdown — risk score, IP trail, domain intelligence, threat intel, and a geolocation map of where the email came from.

Everything runs in your browser. Nothing is uploaded. Your data never leaves your device.

---

## Features

- **Risk scoring** — 0–100 composite score with detailed findings and evidence
- **IP origin tracing** — follows every hop in the Received chain, plots them on a live map
- **DMARC / SPF / DKIM analysis** — checks authentication results and flags failures
- **Display name spoofing detection** — catches the right name from the wrong address
- **Lookalike domain detection** — typosquats, Punycode, homograph attacks
- **RDAP domain intelligence** — registration date, registrar, nameservers
- **VirusTotal + URLhaus + Talos** — multi-engine threat reputation
- **Trust Roster** — define your org, executives, and trusted senders once, reuse forever
- **Detection history** — every analysis saved locally, click any entry to replay it
- **Custom detection rules** — write your own rules with no code
- **PDF report export** — one-click forensic report

---

## AI Roster Setup

Instead of manually configuring your Trust Roster, paste any text about your organisation — an email signature, org chart, LinkedIn bio, or plain description — and AI fills everything in automatically.

Works with any LLM:

| Provider | Cost | Get Key |
|---|---|---|
| Gemini Flash | Free | [aistudio.google.com](https://aistudio.google.com) |
| Groq / Llama 3 | Free | [console.groq.com](https://console.groq.com) |
| OpenAI GPT-4o | Paid | [platform.openai.com](https://platform.openai.com) |
| Claude Haiku | Paid | [console.anthropic.com](https://console.anthropic.com) |
| Custom / Self-hosted | — | Ollama, LM Studio, any OpenAI-compatible endpoint |

---

## How to get a raw email

- **Gmail** — open email → three-dot menu → *Show original* → copy all
- **Outlook (web)** — three-dot menu → *View → View message source*
- **Apple Mail** — *View → Message → Raw Source*

---

## Detection Rules

| Rule | What it catches | Severity |
|---|---|---|
| `ROSTER-001` | Display-name impersonation | Critical |
| `ROSTER-002` | Lookalike / typosquatted sender domain | High |
| `ROSTER-003` | Punycode / homograph attack | High |
| `ROSTER-004` | Reply-To divergence on trusted sender | High |
| `ROSTER-005` | Missing authentication headers | Medium |
| `ROSTER-006` | SPF / DKIM / DMARC failure | Critical |
| `ROSTER-007` | Unknown sender with financial language | Medium |

Custom rules can be added directly in the app under Detection Rules.

---

## Security

- Content Security Policy headers on all responses
- Input validation and sanitisation on every field
- All localStorage access wrapped in try/catch with schema validation
- No telemetry, no analytics, no backend, no accounts
- API keys stored locally in your browser only

---

## Threat Model

**Defends against:**
- Display-name spoofing from arbitrary domains
- Lookalike and typosquatted sender domains
- IDN / Punycode homograph attacks
- Reply-To redirects on trusted senders
- SPF / DKIM / DMARC bypass attempts
- First-contact senders using financial language

**Does not defend against:**
- Compromised legitimate vendor mailboxes
- Malicious attachments or URLs
- Account compromise via session token theft

---

## Roadmap

- ML-based pattern detection trained on company-specific threat history
- Shared threat intelligence across clients
- Backend API for enterprise deployments
- ISO 27001 compliance package

---

## License

Apache 2.0 — free to use, fork, and deploy.
