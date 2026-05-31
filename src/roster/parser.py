"""Parse a raw .eml file into a structured object the rules can consume."""
from __future__ import annotations

from email import policy
from email.parser import BytesParser
from email.utils import parseaddr

from pydantic import BaseModel


class ParsedEmail(BaseModel):
    """A normalized view of an email message for rule evaluation."""

    from_display_name: str
    from_address: str
    from_domain: str
    reply_to_address: str | None = None
    reply_to_domain: str | None = None
    return_path: str | None = None
    subject: str = ""
    body_text: str = ""
    body_html: str | None = None
    authentication_results: str | None = None
    raw_headers: dict[str, str] = {}


def _extract_domain(address: str) -> str:
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[-1].lower().strip()


def _extract_body(msg) -> tuple[str, str | None]:
    """Return (text_body, html_body) from an email.message.Message."""
    body_text = ""
    body_html: str | None = None

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disposition = str(part.get("Content-Disposition", "")).lower()
            if "attachment" in disposition:
                continue
            if ctype == "text/plain" and not body_text:
                body_text = _safe_get_content(part)
            elif ctype == "text/html" and body_html is None:
                body_html = _safe_get_content(part)
    else:
        body_text = _safe_get_content(msg)

    return body_text, body_html


def _safe_get_content(part) -> str:
    """Try the modern API first, fall back to manual decode."""
    try:
        content = part.get_content()
        return content if isinstance(content, str) else str(content)
    except Exception:
        payload = part.get_payload(decode=True)
        if payload is None:
            return ""
        if isinstance(payload, bytes):
            charset = part.get_content_charset() or "utf-8"
            try:
                return payload.decode(charset, errors="replace")
            except (LookupError, UnicodeDecodeError):
                return payload.decode("utf-8", errors="replace")
        return str(payload)


def parse_eml(eml_bytes: bytes) -> ParsedEmail:
    """Parse a raw .eml byte string into a ParsedEmail."""
    msg = BytesParser(policy=policy.default).parsebytes(eml_bytes)

    from_raw = str(msg.get("From", ""))
    from_display, from_addr = parseaddr(from_raw)

    reply_to_raw = str(msg.get("Reply-To", ""))
    reply_to_addr: str | None = None
    reply_to_domain: str | None = None
    if reply_to_raw:
        _, reply_to_addr = parseaddr(reply_to_raw)
        if reply_to_addr:
            reply_to_domain = _extract_domain(reply_to_addr)

    return_path = str(msg.get("Return-Path", "")).strip("<>").strip() or None
    subject = str(msg.get("Subject", ""))
    auth_results = str(msg.get("Authentication-Results", "")) or None

    body_text, body_html = _extract_body(msg)

    return ParsedEmail(
        from_display_name=from_display,
        from_address=from_addr,
        from_domain=_extract_domain(from_addr),
        reply_to_address=reply_to_addr,
        reply_to_domain=reply_to_domain,
        return_path=return_path,
        subject=subject,
        body_text=body_text,
        body_html=body_html,
        authentication_results=auth_results,
        raw_headers={k: str(v) for k, v in msg.items()},
    )
