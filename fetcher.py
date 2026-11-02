"""Safe, lightweight retrieval of public HTML pages and PDF reports."""

from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
import ipaddress
import re
import socket
from urllib.parse import urlparse

from bs4 import BeautifulSoup
from pypdf import PdfReader
import requests


MAX_BYTES = 15 * 1024 * 1024
USER_AGENT = (
    "Mozilla/5.0 (compatible; CPS-Taxonomy-Research-Demo/1.0; "
    "+https://streamlit.io/)"
)


@dataclass
class FetchResult:
    url: str
    ok: bool
    text: str
    message: str
    content_type: str = ""


def _is_public_host(hostname: str) -> bool:
    """Reject loopback/private/link-local/reserved targets to reduce SSRF risk."""
    if not hostname:
        return False
    lowered = hostname.lower()
    if lowered in {"localhost", "localhost.localdomain"}:
        return False

    try:
        addresses = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False

    for item in addresses:
        ip_text = item[4][0]
        try:
            ip = ipaddress.ip_address(ip_text)
        except ValueError:
            return False
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return False
    return True


def validate_public_url(url: str) -> tuple[bool, str]:
    try:
        parsed = urlparse(url.strip())
    except Exception:
        return False, "Invalid URL."
    if parsed.scheme not in {"http", "https"}:
        return False, "Only http:// and https:// URLs are allowed."
    if not _is_public_host(parsed.hostname or ""):
        return False, "The URL does not resolve to a permitted public host."
    return True, ""


def _html_to_text(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript", "svg", "nav", "footer", "header", "form"]):
        tag.decompose()

    candidates = []
    for selector in ["article", "main"]:
        for node in soup.select(selector):
            txt = " ".join(node.stripped_strings)
            if len(txt) > 300:
                candidates.append(txt)

    if candidates:
        text = max(candidates, key=len)
    else:
        blocks = []
        for node in soup.find_all(["p", "li", "h1", "h2", "h3"]):
            txt = " ".join(node.stripped_strings)
            if len(txt) >= 35:
                blocks.append(txt)
        text = "\n".join(blocks)

    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _pdf_to_text(content: bytes) -> str:
    reader = PdfReader(BytesIO(content))
    pages = []
    for page in reader.pages[:80]:
        try:
            text = page.extract_text() or ""
        except Exception:
            text = ""
        if text.strip():
            pages.append(text.strip())
    return "\n".join(pages)


def fetch_public_document(url: str, timeout: int = 20) -> FetchResult:
    url = (url or "").strip()
    if not url:
        return FetchResult(url=url, ok=False, text="", message="Empty URL.")

    valid, reason = validate_public_url(url)
    if not valid:
        return FetchResult(url=url, ok=False, text="", message=reason)

    try:
        response = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/pdf,*/*"},
            allow_redirects=True,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        return FetchResult(url=url, ok=False, text="", message=f"Fetch failed: {exc}")

    valid_final, reason_final = validate_public_url(response.url)
    if not valid_final:
        return FetchResult(url=url, ok=False, text="", message=f"Unsafe redirect blocked: {reason_final}")

    if len(response.content) > MAX_BYTES:
        return FetchResult(
            url=url,
            ok=False,
            text="",
            message=f"Document exceeds the {MAX_BYTES // (1024 * 1024)} MB demo limit.",
        )

    content_type = (response.headers.get("content-type") or "").lower()
    try:
        if "pdf" in content_type or response.url.lower().split("?")[0].endswith(".pdf"):
            text = _pdf_to_text(response.content)
        else:
            response.encoding = response.encoding or response.apparent_encoding
            text = _html_to_text(response.text)
    except Exception as exc:
        return FetchResult(
            url=url,
            ok=False,
            text="",
            message=f"Text extraction failed: {exc}",
            content_type=content_type,
        )

    if len(text.strip()) < 80:
        return FetchResult(
            url=url,
            ok=False,
            text=text,
            message="The source was reached, but too little article text was extractable.",
            content_type=content_type,
        )

    return FetchResult(
        url=response.url,
        ok=True,
        text=text[:250_000],
        message=f"Extracted {len(text):,} characters.",
        content_type=content_type,
    )
