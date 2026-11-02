"""Layer 2: incident-scoped classification of fetched source pages using Claude.

Role in the two-layer design
----------------------------
Layer 1 (``classifier.py``) is the deterministic lexical baseline over the Verified
Impact Summary. It is auditable but cannot tell *which* incident a sentence describes,
so it cannot safely read full news pages: security journalism routinely recaps other
incidents as background, and a lexical matcher scores those recaps exactly as highly as
the target incident.

Layer 2 exists to solve that one problem. Each chunk of fetched page text is classified
with the target incident's identity supplied, and Claude must attribute every finding to
either the target incident or to background material. Two independent guards sit on the
output:

1. **Span verification** — every finding must quote a span that provably appears in the
   supplied chunk. Findings whose span cannot be located are discarded as unreliable.
2. **Attribution filter** — findings attributed to background material are removed from
   the result set but retained for inspection, as the contamination-control record.

Layer 2 output is *not* interchangeable with Layer 1 output. It carries no numeric
evidence score, it is not deterministic in the way a regex is, and per the project's
stated commitments it requires human review before any property it reports is counted
as CONFIRMED in published statistics.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Literal, Sequence
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from classifier import Evidence
from content_extraction import (
    Chunk,
    ExtractionReport,
    FetcherFn,
    incident_chunks,
)
from taxonomy import PROPERTY_TO_PARENT, STATUS_ORDER, TAXONOMY

try:  # pragma: no cover - the app must still run Layer 1 without this installed
    import anthropic
except ImportError:  # pragma: no cover
    anthropic = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Model configuration
# ---------------------------------------------------------------------------

MODEL_ID = "claude-sonnet-5"
"""Pinned model snapshot.

Model IDs in this format are snapshots, not floating aliases: the underlying model
stays constant for the lifetime of the ID. Cite this exact string in the methods
section. Do not replace it with an alias.
"""

STRUCTURED_OUTPUTS_BETA = os.environ.get(
    "ANTHROPIC_STRUCTURED_OUTPUTS_BETA", "structured-outputs-2025-11-13"
)
"""Beta header for schema-validated output.

Taken from https://docs.claude.com/en/docs/build-with-claude/structured-outputs —
verify against that page if requests start failing, and override via the environment
variable rather than editing this file.
"""

PROMPT_VERSION = "v1"
"""Bump on any edit to the system prompt. Part of the response cache key, so cached
results from an older prompt are never silently reused.
"""

MAX_TOKENS = 4096
TEMPERATURE = 0

MAX_ATTEMPTS = 3
BACKOFF_SECONDS = (1.0, 2.0, 4.0)

LLM_CACHE_ROOT = Path("data/cache/llm")

LLM_EVIDENCE_SCORE = 0.0
"""Layer 2 produces no numeric strength score.

Layer 1's ``evidence_score`` is a lexical-plus-similarity magnitude on a 0-100 scale.
Layer 2 has no comparable quantity, and inventing one would invite invalid
cross-layer comparison. All Layer 2 rows therefore carry 0.0, and ranking within
Layer 2 falls back to status precedence. Never sort or threshold the two layers'
scores together.
"""

Status = Literal["CONFIRMED", "CLAIMED", "POTENTIAL", "UNAFFECTED"]
Attribution = Literal["target_incident", "background_or_other_incident"]


# ---------------------------------------------------------------------------
# Response schema
# ---------------------------------------------------------------------------


class Finding(BaseModel):
    """One property assignment supported by one verbatim span."""

    property: str = Field(description="Exact property name from the supplied taxonomy.")
    status: Status
    span: str = Field(
        description="A sentence copied verbatim from the supplied text. Not paraphrased."
    )
    attribution: Attribution
    reasoning: str = Field(description="One sentence explaining the assignment.")


class ChunkFindings(BaseModel):
    """All findings for one chunk. Empty when the chunk supports nothing."""

    findings: list[Finding] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------


def _taxonomy_block() -> str:
    lines: list[str] = []
    for parent, properties in TAXONOMY.items():
        lines.append(f"\n{parent}")
        for prop, profile in properties.items():
            lines.append(f"  - {prop}: {profile['definition']}")
    return "\n".join(lines)


SYSTEM_PROMPT = f"""You classify evidence about cyber-physical-system security incidents \
against a fixed taxonomy. You are an annotator, not a summariser.

TAXONOMY — assign only these properties, using these definitions and no others:
{_taxonomy_block()}

STATUS — assign exactly one per finding:
  - CONFIRMED: the text states the impact occurred, as established fact.
  - CLAIMED: the impact is asserted by the attacker, or reported without independent \
confirmation, or hedged ("allegedly", "reportedly", "claimed", "unconfirmed", \
"sources say").
  - POTENTIAL: the text describes what could, may or might happen, or what a system was \
capable of, rather than what did happen.
  - UNAFFECTED: the text explicitly states something was NOT affected, remained \
operational, or was not disrupted.

ATTRIBUTION — assign exactly one per finding:
  - target_incident: the span describes the specific incident named in the user message.
  - background_or_other_incident: the span describes a different incident, historical \
background, general industry commentary, vendor marketing, or unrelated coverage.

Security journalism routinely recaps other incidents as context. A span may be perfectly \
clear evidence of an impact and still belong to a different incident. Judge attribution \
on the span and its surrounding text, not on how well it matches a property.

RULES — these are strict:
  1. NEVER infer an impact from an attack label alone. "Ransomware", "malware", "wiper", \
"APT intrusion" and similar labels do not by themselves establish Availability, \
Integrity, Safety or any other property. Require a stated effect.
  2. The span MUST be copied character-for-character from the supplied text. Do not \
paraphrase, do not tidy the wording, do not join fragments from different sentences. \
Spans are verified programmatically against the source and paraphrases are discarded.
  3. When the text is ambiguous, return no finding. A missing finding is corrected by a \
human reviewer; a speculative one corrupts the dataset.
  4. One property per finding. If one sentence evidences three properties, return three \
findings quoting the same span.
  5. Return an empty findings list when the chunk supports nothing. Most chunks of a news \
page support nothing; that is the expected outcome, not a failure.

Return only data conforming to the schema."""


def _user_prompt(incident: dict, chunk: Chunk) -> str:
    def value(key: str) -> str:
        raw = incident.get(key)
        text = "" if raw is None else str(raw).strip()
        return text if text and text.lower() != "nan" else "(not recorded)"

    return f"""TARGET INCIDENT — attribute findings to this incident only:
  Incident Name: {value('Incident Name')}
  Year: {value('Year')}
  Country/Region: {value('Country/Region')}
  Attack Type: {value('Attack Type')}
  Attacker / Group: {value('Attacker / Group')}

SOURCE URL: {chunk.url}

TEXT TO CLASSIFY (findings must quote from this text only):
\"\"\"
{chunk.text}
\"\"\""""


# ---------------------------------------------------------------------------
# Span verification
# ---------------------------------------------------------------------------

_QUOTE_MAP = {
    "\u201c": '"', "\u201d": '"', "\u201e": '"',
    "\u2018": "'", "\u2019": "'", "\u201a": "'",
    "\u2013": "-", "\u2014": "-", "\u2212": "-",
    "\u00a0": " ", "\u2026": "...",
}


def normalize_for_match(text: str) -> str:
    """Normalise text for span containment checks.

    Deliberately lossy: NFKC, unified quotes and dashes, collapsed whitespace, and
    casefolding. Exact string equality would reject valid spans over a curly
    apostrophe or a line break, producing false hallucination reports.
    """
    normalized = unicodedata.normalize("NFKC", text or "")
    for source, target in _QUOTE_MAP.items():
        normalized = normalized.replace(source, target)
    normalized = re.sub(r"\s+", " ", normalized)
    return normalized.strip().casefold()


def span_is_present(span: str, chunk_text: str) -> bool:
    needle = normalize_for_match(span)
    if len(needle) < 15:
        # Too short to be meaningful evidence, and trivially "present" by accident.
        return False
    return needle in normalize_for_match(chunk_text)


# ---------------------------------------------------------------------------
# Run accounting
# ---------------------------------------------------------------------------


@dataclass
class LLMRunReport:
    """Per-run counters. Every one of these is surfaced in the UI."""

    chunks_processed: int = 0
    chunks_cached: int = 0
    chunks_failed: int = 0
    findings_returned: int = 0
    rejected_unknown_property: int = 0
    rejected_span_unverified: int = 0
    dropped_attribution: int = 0
    accepted: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def span_rejection_rate(self) -> float:
        """Fraction of returned findings whose span could not be located.

        A rate above roughly 0.10 means the prompt or chunking is at fault, not the
        sources — investigate before trusting the run.
        """
        if not self.findings_returned:
            return 0.0
        return self.rejected_span_unverified / self.findings_returned


# ---------------------------------------------------------------------------
# Response cache
# ---------------------------------------------------------------------------


def _cache_key(chunk_text: str) -> str:
    payload = f"{MODEL_ID}\x00{PROMPT_VERSION}\x00{chunk_text}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _cache_read(key: str, cache_root: Path) -> list[dict] | None:
    path = cache_root / f"{key}.json"
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    findings = payload.get("findings")
    return findings if isinstance(findings, list) else None


def _cache_write(key: str, findings: list[dict], cache_root: Path) -> None:
    cache_root.mkdir(parents=True, exist_ok=True)
    (cache_root / f"{key}.json").write_text(
        json.dumps(
            {"model_id": MODEL_ID, "prompt_version": PROMPT_VERSION, "findings": findings},
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# API access
# ---------------------------------------------------------------------------


def resolve_api_key(explicit: str | None = None) -> str | None:
    """``st.secrets`` first, then the environment. Returns ``None`` if absent."""
    if explicit:
        return explicit
    try:
        import streamlit as st

        key = st.secrets.get("ANTHROPIC_API_KEY")  # type: ignore[union-attr]
        if key:
            return str(key)
    except Exception:
        pass
    return os.environ.get("ANTHROPIC_API_KEY") or None


def build_client(api_key: str | None = None) -> Any:
    if anthropic is None:
        raise RuntimeError(
            "The 'anthropic' package is not installed. Layer 2 is unavailable; "
            "run with Lexical only."
        )
    key = resolve_api_key(api_key)
    if not key:
        raise RuntimeError(
            "No ANTHROPIC_API_KEY found in st.secrets or the environment. "
            "Layer 2 is unavailable; run with Lexical only."
        )
    return anthropic.Anthropic(api_key=key)


def _is_retryable(exc: Exception) -> bool:
    if anthropic is None:
        return False
    if isinstance(exc, getattr(anthropic, "RateLimitError", ())):
        return True
    if isinstance(exc, getattr(anthropic, "APIConnectionError", ())):
        return True
    status = getattr(exc, "status_code", None)
    return isinstance(status, int) and status >= 500


def _call_model(client: Any, incident: dict, chunk: Chunk) -> list[dict]:
    """One schema-validated request. Raises on unrecoverable failure."""
    last: Exception | None = None

    for attempt in range(MAX_ATTEMPTS):
        try:
            response = client.beta.messages.parse(
                model=MODEL_ID,
                betas=[STRUCTURED_OUTPUTS_BETA],
                max_tokens=MAX_TOKENS,
                temperature=TEMPERATURE,
                system=[
                    {
                        "type": "text",
                        "text": SYSTEM_PROMPT,
                        # The taxonomy block is identical across every chunk call and
                        # is the bulk of the input tokens.
                        "cache_control": {"type": "ephemeral"},
                    }
                ],
                messages=[{"role": "user", "content": _user_prompt(incident, chunk)}],
                output_format=ChunkFindings,
            )
        except Exception as exc:  # noqa: BLE001 - classified by _is_retryable
            last = exc
            if attempt < MAX_ATTEMPTS - 1 and _is_retryable(exc):
                time.sleep(BACKOFF_SECONDS[attempt])
                continue
            raise

        parsed = getattr(response, "parsed_output", None)
        if parsed is None:
            raise RuntimeError("Response contained no parsed output.")
        return [finding.model_dump() for finding in parsed.findings]

    raise last if last else RuntimeError("Unreachable")


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def _to_evidence(finding: dict, chunk: Chunk, source: str) -> Evidence:
    prop = finding["property"]
    return Evidence(
        parent_category=PROPERTY_TO_PARENT[prop],
        property=prop,
        status=finding["status"],
        evidence_score=LLM_EVIDENCE_SCORE,
        lexical_score=0.0,
        semantic_similarity=0.0,
        sentence=finding["span"].strip(),
        source=source,
        url=chunk.url,
        matched_terms="",
        layer="llm_url",
        model_id=MODEL_ID,
        chunk_id=chunk.chunk_id,
        llm_reasoning=finding.get("reasoning", "").strip(),
    )


def classify_chunks(
    incident: dict,
    chunks: Sequence[Chunk],
    *,
    client: Any,
    cache_root: Path = LLM_CACHE_ROOT,
    report: LLMRunReport | None = None,
) -> tuple[list[Evidence], list[Evidence]]:
    """Classify chunks. Returns ``(accepted, dropped_by_attribution)``.

    Never raises for a single failed chunk: the failure is counted and the run
    continues, because one unreachable source must not discard an entire incident.
    """
    report = report if report is not None else LLMRunReport()
    accepted: list[Evidence] = []
    dropped: list[Evidence] = []

    for chunk in chunks:
        key = _cache_key(chunk.text)
        findings = _cache_read(key, cache_root)

        if findings is None:
            try:
                findings = _call_model(client, incident, chunk)
            except Exception as exc:  # noqa: BLE001
                report.chunks_failed += 1
                report.errors.append(f"{chunk.chunk_id}: {exc}")
                continue
            _cache_write(key, findings, cache_root)
        else:
            report.chunks_cached += 1

        report.chunks_processed += 1
        source = urlparse(chunk.url).netloc or "source"

        for finding in findings:
            report.findings_returned += 1

            prop = str(finding.get("property", "")).strip()
            if prop not in PROPERTY_TO_PARENT:
                report.rejected_unknown_property += 1
                continue

            if finding.get("status") not in STATUS_ORDER:
                report.rejected_unknown_property += 1
                continue

            if not span_is_present(str(finding.get("span", "")), chunk.text):
                report.rejected_span_unverified += 1
                continue

            row = _to_evidence(finding, chunk, source)

            if finding.get("attribution") != "target_incident":
                report.dropped_attribution += 1
                dropped.append(row)
                continue

            report.accepted += 1
            accepted.append(row)

    accepted.sort(
        key=lambda r: (-STATUS_ORDER[r.status], r.parent_category, r.property)
    )
    return accepted, dropped


def classify_incident_urls(
    incident: dict,
    *,
    client: Any,
    refresh_pages: bool = False,
    fetcher: FetcherFn | None = None,
    llm_cache_root: Path = LLM_CACHE_ROOT,
    llm_report: LLMRunReport | None = None,
    extraction_report: ExtractionReport | None = None,
) -> tuple[list[Evidence], list[Evidence]]:
    """Fetch, extract, chunk and classify every source URL of one incident."""
    accepted: list[Evidence] = []
    dropped: list[Evidence] = []

    for _page, chunks in incident_chunks(
        incident, refresh=refresh_pages, fetcher=fetcher, report=extraction_report
    ):
        if not chunks:
            continue
        page_accepted, page_dropped = classify_chunks(
            incident, chunks, client=client, cache_root=llm_cache_root,
            report=llm_report,
        )
        accepted.extend(page_accepted)
        dropped.extend(page_dropped)

    return accepted, dropped


def summarize(rows: Iterable[Evidence]) -> list[dict]:
    """Collapse per-span findings into one verdict per property.

    Same output shape and status precedence as ``classifier.classify_sources``, so
    ``agreement.py`` can compare the two layers column for column. ``Evidence Score``
    is present for shape compatibility only — see ``LLM_EVIDENCE_SCORE``.
    """
    rows = list(rows)
    summaries: list[dict] = []

    for prop, parent in PROPERTY_TO_PARENT.items():
        matching = [r for r in rows if r.property == prop]
        if not matching:
            continue

        statuses = {r.status for r in matching}
        for candidate in ("CONFIRMED", "CLAIMED", "POTENTIAL", "UNAFFECTED"):
            if candidate in statuses:
                final_status = candidate
                break
        else:  # pragma: no cover - statuses is never empty here
            final_status = "UNAFFECTED"

        best = next(r for r in matching if r.status == final_status)
        scope_note = ""
        if final_status == "CONFIRMED" and "UNAFFECTED" in statuses:
            scope_note = (
                "Mixed scope: confirmed impact and explicit unaffected evidence "
                "both exist."
            )

        summaries.append(
            {
                "Parent Category": parent,
                "Property": prop,
                "Final Status": final_status,
                "Evidence Score": LLM_EVIDENCE_SCORE,
                "Best Evidence": best.sentence,
                "Source": best.source,
                "URL": best.url,
                "Scope Note": scope_note,
                "Layer": "llm_url",
                "Model": MODEL_ID,
                "Supporting Findings": len(matching),
            }
        )

    summaries.sort(
        key=lambda row: (
            -STATUS_ORDER[row["Final Status"]],
            row["Parent Category"],
            row["Property"],
        )
    )
    return summaries
