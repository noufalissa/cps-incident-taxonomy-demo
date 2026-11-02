"""Source retrieval, boilerplate-stripped text extraction, on-disk caching, and chunking.

Role in the two-layer design
----------------------------
Layer 1 (``classifier.py``) is the deterministic lexical baseline and reads only the
Verified Impact Summary. Layer 2 (``llm_classifier.py``) reads *fetched source pages*,
which is where this module is used.

Full page text is hostile input: navigation menus, cookie banners, newsletter prompts and
"related coverage" sidebars all look like prose to a clause splitter, and security
journalism routinely recaps unrelated incidents as background. This module's job is to
reduce a URL to main-content text, freeze that text on disk so a run is reproducible and
survives blocked cloud egress IPs, and hand Layer 2 stable, addressable chunks.

Nothing here classifies anything. Attribution and labelling belong to Layer 2.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import unicodedata
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Iterator, Sequence

import requests

try:  # pragma: no cover - exercised only when the optional dep is missing
    import trafilatura
except ImportError:  # pragma: no cover
    trafilatura = None  # type: ignore[assignment]

try:  # pragma: no cover
    from bs4 import BeautifulSoup
except ImportError:  # pragma: no cover
    BeautifulSoup = None  # type: ignore[assignment]

try:  # pragma: no cover
    from pypdf import PdfReader
except ImportError:  # pragma: no cover
    PdfReader = None  # type: ignore[assignment]

try:
    # Reuse the project's SSRF guard rather than reimplementing it. It rejects
    # loopback, private, link-local, reserved and multicast targets, which matters
    # because incident URLs can come from a user-uploaded spreadsheet.
    from fetcher import validate_public_url as _project_validate_public_url
except ImportError:  # pragma: no cover - standalone use outside the repo
    _project_validate_public_url = None  # type: ignore[assignment]


CACHE_ROOT = Path("data/cache/pages")

REQUEST_TIMEOUT = 30
MAX_BYTES = 15 * 1024 * 1024
"""Body size cap, matching ``fetcher.MAX_BYTES``."""
USER_AGENT = (
    "cps-incident-taxonomy-demo/1.0 (research prototype; "
    "contact repository owner)"
)

CHUNK_SIZE = 2000
CHUNK_OVERLAP = 200

MIN_USEFUL_TEXT = 200
"""Below this many characters, extraction is treated as having failed."""

URL_COLUMNS = ("URL1", "URL2", "URL3", "URL4")

_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9\u201c\u2018(])")


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class ExtractedPage:
    """Boilerplate-stripped text for one source URL, as cached on disk."""

    url: str
    fetched_at: str
    http_status: int
    extractor: str
    text: str
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error and len(self.text) >= MIN_USEFUL_TEXT

    @property
    def url_key(self) -> str:
        return url_key(self.url)


@dataclass
class Chunk:
    """One classification unit handed to Layer 2.

    ``chunk_id`` is stable across runs for a given URL and extraction, so LLM
    response caches and rejected-finding audit trails stay comparable between runs.
    """

    chunk_id: str
    url: str
    index: int
    text: str


@dataclass
class ExtractionReport:
    """Per-run counters, surfaced in the Streamlit UI."""

    cache_hits: int = 0
    fetched: int = 0
    failures: int = 0
    pages_ok: int = 0
    chunks: int = 0
    failed_urls: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Identity helpers
# ---------------------------------------------------------------------------


def url_key(url: str) -> str:
    """First 16 hex characters of the SHA-256 of the URL.

    Used for cache filenames and as the stable prefix of ``chunk_id``.
    """
    return hashlib.sha256(url.strip().encode("utf-8")).hexdigest()[:16]


def slugify(value: str, max_length: int = 60) -> str:
    """Filesystem-safe slug for an incident name."""
    normalized = unicodedata.normalize("NFKD", value or "")
    ascii_only = normalized.encode("ascii", "ignore").decode("ascii")
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", ascii_only).strip("-").lower()
    slug = slug[:max_length].strip("-")
    return slug or "unnamed-incident"


def cache_path(incident_name: str, url: str, cache_root: Path = CACHE_ROOT) -> Path:
    return cache_root / slugify(incident_name) / f"{url_key(url)}.json"


# ---------------------------------------------------------------------------
# Cache I/O
# ---------------------------------------------------------------------------


def load_cached(
    incident_name: str, url: str, cache_root: Path = CACHE_ROOT
) -> ExtractedPage | None:
    """Return the cached page, or ``None`` on a miss or unreadable cache entry."""
    path = cache_path(incident_name, url, cache_root)
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    try:
        return ExtractedPage(
            url=payload["url"],
            fetched_at=payload.get("fetched_at", ""),
            http_status=int(payload.get("http_status", 0)),
            extractor=payload.get("extractor", "unknown"),
            text=payload.get("text", ""),
            error=payload.get("error", ""),
        )
    except (KeyError, TypeError, ValueError):
        return None


def save_cached(
    incident_name: str,
    page: ExtractedPage,
    cache_root: Path = CACHE_ROOT,
) -> Path:
    """Write a page to the cache. Commit the cache directory to the repository."""
    path = cache_path(incident_name, page.url, cache_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(asdict(page), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return path


# ---------------------------------------------------------------------------
# Retrieval
# ---------------------------------------------------------------------------

FetcherFn = Callable[[str], tuple[int, bytes, str]]
"""Signature of a pluggable fetcher: ``url -> (http_status, body, content_type)``.

Pass the project's existing ``fetcher.py`` retrieval function here (wrapped to match
this signature) so retrieval policy lives in one place. ``default_fetcher`` is used
when nothing is supplied.
"""


class UnsafeURLError(RuntimeError):
    """Raised when a URL fails the public-host safety check."""


def validate_url(url: str) -> tuple[bool, str]:
    """Delegate to ``fetcher.validate_public_url`` when available.

    The fallback only enforces the scheme, so running this module outside the repo
    is possible but loses the SSRF protection. That is deliberate: the repo copy is
    the authoritative policy and should not be silently duplicated here.
    """
    if _project_validate_public_url is not None:
        return _project_validate_public_url(url)

    from urllib.parse import urlparse

    try:
        parsed = urlparse(url.strip())
    except ValueError:
        return False, "Invalid URL."
    if parsed.scheme not in {"http", "https"}:
        return False, "Only http:// and https:// URLs are allowed."
    return True, ""


def default_fetcher(url: str) -> tuple[int, bytes, str]:
    """Retrieve raw bytes, capped and redirect-revalidated.

    Raw bytes rather than text, because trafilatura needs the original HTML to strip
    boilerplate — pre-extracted text has already lost the structure it relies on.
    """
    response = requests.get(
        url,
        timeout=REQUEST_TIMEOUT,
        headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/pdf,*/*"},
        allow_redirects=True,
        stream=True,
    )
    with response:
        # A redirect can land somewhere the original check would have rejected.
        final_ok, final_reason = validate_url(response.url)
        if not final_ok:
            raise UnsafeURLError(f"Unsafe redirect blocked: {final_reason}")

        chunks: list[bytes] = []
        total = 0
        for block in response.iter_content(chunk_size=65536):
            if not block:
                continue
            total += len(block)
            if total > MAX_BYTES:
                raise UnsafeURLError(
                    f"Document exceeds the {MAX_BYTES // (1024 * 1024)} MB limit."
                )
            chunks.append(block)

        content_type = response.headers.get("Content-Type", "")
        return response.status_code, b"".join(chunks), content_type


def fetcher_from_project(url: str) -> tuple[int, bytes, str]:
    """Adapter around ``fetcher.fetch_public_document`` for the text-only path.

    ``fetch_public_document`` returns already-extracted text, so trafilatura cannot
    run on its output. Use this only as a fallback when ``default_fetcher`` is
    blocked; the resulting pages are recorded with the ``fetcher.py`` extractor name
    so weaker extraction is visible in the cache.
    """
    from fetcher import fetch_public_document

    result = fetch_public_document(url)
    if not result.ok:
        raise RuntimeError(result.message)
    # Wrapped as pre-extracted text; extract_html will pass it through unchanged.
    return 200, result.text.encode("utf-8"), "text/plain; charset=utf-8"


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------


def normalize_whitespace(text: str) -> str:
    text = (text or "").replace("\u00a0", " ")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def extract_html(body: bytes) -> tuple[str, str]:
    """Extract main content from HTML. Returns ``(text, extractor_name)``.

    trafilatura is preferred because it discards navigation, boilerplate and
    "related coverage" blocks. BeautifulSoup is a degraded fallback that keeps far
    more junk, so the extractor name is recorded to make that visible downstream.
    """
    html = body.decode("utf-8", errors="replace")

    if trafilatura is not None:
        extracted = trafilatura.extract(
            html,
            include_comments=False,
            include_tables=True,
            favor_precision=True,
            no_fallback=False,
        )
        if extracted and len(extracted) >= MIN_USEFUL_TEXT:
            return normalize_whitespace(extracted), "trafilatura"

    if BeautifulSoup is not None:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup(["script", "style", "nav", "header", "footer", "aside", "form"]):
            tag.decompose()
        return normalize_whitespace(soup.get_text("\n")), "beautifulsoup-fallback"

    return "", "none"


def extract_pdf(body: bytes) -> tuple[str, str]:
    """Extract text from a text-based PDF. Scanned-image PDFs yield nothing."""
    if PdfReader is None:
        return "", "none"
    import io

    try:
        reader = PdfReader(io.BytesIO(body))
        pages = [(page.extract_text() or "") for page in reader.pages]
    except Exception as exc:  # pypdf raises a wide range of parse errors
        raise RuntimeError(f"PDF parse failed: {exc}") from exc
    return normalize_whitespace("\n\n".join(pages)), "pypdf"


def _looks_like_pdf(url: str, content_type: str, body: bytes) -> bool:
    if "application/pdf" in content_type.lower():
        return True
    if url.lower().split("?")[0].endswith(".pdf"):
        return True
    return body[:5] == b"%PDF-"


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


def get_page(
    incident_name: str,
    url: str,
    *,
    refresh: bool = False,
    fetcher: FetcherFn | None = None,
    cache_root: Path = CACHE_ROOT,
    report: ExtractionReport | None = None,
) -> ExtractedPage:
    """Return extracted text for ``url``, from cache unless ``refresh`` is set.

    Never raises on retrieval or parse failure: the returned page carries ``error``
    and an empty ``text`` so one dead source cannot abort a run. Failures are cached
    too, so a blocked URL is not retried on every rerun; use ``refresh`` to retry.
    """
    url = (url or "").strip()
    if not url:
        return ExtractedPage(url="", fetched_at="", http_status=0, extractor="none",
                             text="", error="empty URL")

    if not refresh:
        cached = load_cached(incident_name, url, cache_root)
        if cached is not None:
            if report is not None:
                report.cache_hits += 1
                if cached.ok:
                    report.pages_ok += 1
                else:
                    report.failures += 1
                    report.failed_urls.append(url)
            return cached

    fetch = fetcher or default_fetcher
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    safe, reason = validate_url(url)
    if not safe:
        page = ExtractedPage(url=url, fetched_at=now, http_status=0, extractor="none",
                             text="", error=f"blocked: {reason}")
        save_cached(incident_name, page, cache_root)
        if report is not None:
            report.failures += 1
            report.failed_urls.append(url)
        return page

    try:
        status, body, content_type = fetch(url)
    except requests.RequestException as exc:
        page = ExtractedPage(url=url, fetched_at=now, http_status=0,
                             extractor="none", text="", error=f"fetch failed: {exc}")
    except Exception as exc:  # a user-supplied fetcher may raise anything
        page = ExtractedPage(url=url, fetched_at=now, http_status=0,
                             extractor="none", text="", error=f"fetch failed: {exc}")
    else:
        if status >= 400:
            page = ExtractedPage(url=url, fetched_at=now, http_status=status,
                                 extractor="none", text="",
                                 error=f"HTTP {status}")
        else:
            try:
                if _looks_like_pdf(url, content_type, body):
                    text, extractor = extract_pdf(body)
                elif content_type.lower().startswith("text/plain"):
                    # Already extracted upstream (see fetcher_from_project).
                    text = normalize_whitespace(body.decode("utf-8", errors="replace"))
                    extractor = "fetcher.py-preextracted"
                else:
                    text, extractor = extract_html(body)
            except Exception as exc:
                page = ExtractedPage(url=url, fetched_at=now, http_status=status,
                                     extractor="none", text="",
                                     error=f"extraction failed: {exc}")
            else:
                error = ""
                if len(text) < MIN_USEFUL_TEXT:
                    error = (
                        f"extracted only {len(text)} characters "
                        "(JavaScript-rendered page or scanned PDF?)"
                    )
                page = ExtractedPage(url=url, fetched_at=now, http_status=status,
                                     extractor=extractor, text=text, error=error)

    save_cached(incident_name, page, cache_root)

    if report is not None:
        report.fetched += 1
        if page.ok:
            report.pages_ok += 1
        else:
            report.failures += 1
            report.failed_urls.append(url)

    return page


def chunk_text(
    text: str,
    url: str,
    *,
    chunk_size: int = CHUNK_SIZE,
    overlap: int = CHUNK_OVERLAP,
) -> list[Chunk]:
    """Split text into overlapping, sentence-aligned chunks.

    Chunks are capped near ``chunk_size`` characters with roughly ``overlap``
    characters of trailing context carried into the next chunk, so a property
    described across a paragraph break is not lost at the seam. A single sentence
    longer than ``chunk_size`` is emitted as its own oversized chunk rather than
    being cut mid-clause.
    """
    text = normalize_whitespace(text)
    if not text:
        return []

    sentences = [s.strip() for s in _SENTENCE_SPLIT.split(text) if s.strip()]
    if not sentences:
        return []

    key = url_key(url)
    chunks: list[Chunk] = []
    current: list[str] = []
    current_len = 0

    def flush() -> list[str]:
        """Emit the current buffer and return the sentences to carry over."""
        nonlocal current_len
        if not current:
            return []
        body = " ".join(current)
        chunks.append(Chunk(chunk_id=f"{key}#{len(chunks)}", url=url,
                            index=len(chunks), text=body))
        carry: list[str] = []
        carry_len = 0
        for sentence in reversed(current):
            if carry_len >= overlap:
                break
            carry.insert(0, sentence)
            carry_len += len(sentence) + 1
        # Never carry the entire chunk, or chunking cannot make progress.
        if len(carry) == len(current):
            carry = carry[1:] if len(carry) > 1 else []
        current_len = sum(len(s) + 1 for s in carry)
        return carry

    for sentence in sentences:
        if current and current_len + len(sentence) + 1 > chunk_size:
            current = flush()
        current.append(sentence)
        current_len += len(sentence) + 1

    if current:
        chunks.append(Chunk(chunk_id=f"{key}#{len(chunks)}", url=url,
                            index=len(chunks), text=" ".join(current)))

    return chunks


def incident_chunks(
    incident: dict,
    *,
    refresh: bool = False,
    fetcher: FetcherFn | None = None,
    cache_root: Path = CACHE_ROOT,
    report: ExtractionReport | None = None,
    url_columns: Sequence[str] = URL_COLUMNS,
) -> Iterator[tuple[ExtractedPage, list[Chunk]]]:
    """Yield ``(page, chunks)`` for each non-empty source URL of one incident.

    ``incident`` is a row mapping using the dataset's column names. Pages that failed
    extraction are yielded with an empty chunk list so the UI can report them rather
    than silently dropping a source.
    """
    incident_name = str(incident.get("Incident Name", "")).strip()

    for column in url_columns:
        raw = incident.get(column)
        url = str(raw).strip() if raw is not None else ""
        if not url or url.lower() in {"nan", "none", "-"}:
            continue

        page = get_page(incident_name, url, refresh=refresh, fetcher=fetcher,
                        cache_root=cache_root, report=report)
        chunks = chunk_text(page.text, url) if page.ok else []
        if report is not None:
            report.chunks += len(chunks)
        yield page, chunks


def estimate_chunk_count(
    incidents: Iterable[dict],
    *,
    cache_root: Path = CACHE_ROOT,
    url_columns: Sequence[str] = URL_COLUMNS,
) -> int:
    """Count chunks obtainable from cache alone, without any network access.

    Used for the pre-run cost estimate: the app must show how many LLM calls a run
    would make before any uncached call is issued.
    """
    total = 0
    for incident in incidents:
        incident_name = str(incident.get("Incident Name", "")).strip()
        for column in url_columns:
            raw = incident.get(column)
            url = str(raw).strip() if raw is not None else ""
            if not url or url.lower() in {"nan", "none", "-"}:
                continue
            cached = load_cached(incident_name, url, cache_root)
            if cached is not None and cached.ok:
                total += len(chunk_text(cached.text, url))
    return total


# ---------------------------------------------------------------------------
# CLI: warm or refresh the cache without starting Streamlit
# ---------------------------------------------------------------------------


def _load_incidents(path: Path) -> list[dict]:
    import pandas as pd

    if path.suffix.lower() in {".xlsx", ".xls"}:
        frame = pd.read_excel(path)
    else:
        frame = pd.read_csv(path)
    return frame.to_dict("records")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Fetch and extract incident source pages into data/cache/pages/. "
            "Commit the cache so the app works when egress is blocked."
        )
    )
    parser.add_argument("--input", required=True, type=Path,
                        help="Incident dataset (CSV or XLSX) with URL1-URL4 columns.")
    parser.add_argument("--refresh", action="store_true",
                        help="Refetch every URL, ignoring cached copies.")
    parser.add_argument("--cache-root", type=Path, default=CACHE_ROOT)
    args = parser.parse_args(argv)

    if not args.input.is_file():
        print(f"Input not found: {args.input}", file=sys.stderr)
        return 2

    incidents = _load_incidents(args.input)
    report = ExtractionReport()

    for incident in incidents:
        name = str(incident.get("Incident Name", "")).strip() or "(unnamed)"
        print(f"\n{name}")
        for page, chunks in incident_chunks(
            incident, refresh=args.refresh, cache_root=args.cache_root, report=report
        ):
            status = "ok" if page.ok else f"FAILED — {page.error}"
            print(f"  [{page.extractor:>22}] {len(chunks):>3} chunks  {status}")
            print(f"  {page.url}")

    print(
        f"\ncache hits {report.cache_hits} | fetched {report.fetched} | "
        f"pages ok {report.pages_ok} | failures {report.failures} | "
        f"chunks {report.chunks}"
    )
    if report.failed_urls:
        print("\nFailed sources (rerun with --refresh to retry):")
        for url in report.failed_urls:
            print(f"  {url}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
