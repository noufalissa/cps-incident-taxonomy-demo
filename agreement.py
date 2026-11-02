"""Cross-layer comparison, agreement statistics, and the human-review queue.

Role in the two-layer design
----------------------------
Layer 1 (``classifier.py``) applies stated lexical rules to the Verified Impact Summary.
Layer 2 (``llm_classifier.py``) reads fetched source pages with incident-scoped
attribution. Neither is ground truth. This module treats them as two independent
annotators and reports how far they agree, which is the measurable claim the pilot can
actually support: that the taxonomy is operationalisable consistently by independent
methods, and where it is not.

Disagreements are not errors to be resolved automatically. They are the review queue.

Statistical caution
-------------------
There are 18 properties per incident, so every statistic here rests on a very small
number of items. Cohen's kappa over 18 binary decisions has wide confidence intervals
and is undefined when either annotator produces no variation. ``AgreementStats.kappa_note``
records exactly which situation applies; read it before quoting a figure.
"""

from __future__ import annotations

import csv
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

from taxonomy import PROPERTY_TO_PARENT, STATUS_ORDER

try:  # pragma: no cover
    from sklearn.metrics import cohen_kappa_score
except ImportError:  # pragma: no cover
    cohen_kappa_score = None  # type: ignore[assignment]


NO_VERDICT = "—"
"""Displayed when a layer produced no evidence for a property.

Distinct from UNAFFECTED: UNAFFECTED means the source explicitly said something was
not affected; NO_VERDICT means the layer found nothing either way.
"""

MANDATORY_REVIEW_PROPERTIES = frozenset(
    {
        "Safety",
        "Timing Constraints",
        "Hybrid Dynamics",
        "Compliance",
        "Non-repudiation",
        "Explainability",
    }
)
"""Properties the project README flags as always requiring human review.

Any verdict on these enters the queue regardless of whether the layers agree, because
agreement between two imperfect annotators is not evidence of correctness.
"""


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------


@dataclass
class ComparisonRow:
    """One property, as judged by each layer."""

    parent_category: str
    property: str
    lexical_status: str
    llm_status: str
    agree: bool
    both_have_verdict: bool
    needs_review: bool
    review_reasons: str
    lexical_evidence: str = ""
    llm_evidence: str = ""
    llm_reasoning: str = ""
    url: str = ""

    @property
    def lexical_confirmed(self) -> bool:
        return self.lexical_status == "CONFIRMED"

    @property
    def llm_confirmed(self) -> bool:
        return self.llm_status == "CONFIRMED"


def _index(summaries: Iterable[dict]) -> dict[str, dict]:
    """Index summary rows by property name, keeping the first (highest-ranked)."""
    indexed: dict[str, dict] = {}
    for row in summaries:
        prop = str(row.get("Property", "")).strip()
        if prop and prop not in indexed:
            indexed[prop] = row
    return indexed


def compare(
    lexical_summaries: Iterable[dict],
    llm_summaries: Iterable[dict],
) -> list[ComparisonRow]:
    """Build one row per taxonomy property, in taxonomy order.

    Every one of the 18 properties is represented, including those neither layer
    reported. A property absent from both is a shared negative decision and belongs in
    the denominator of any confirmed-versus-not statistic.
    """
    lexical = _index(lexical_summaries)
    llm = _index(llm_summaries)

    rows: list[ComparisonRow] = []

    for prop, parent in PROPERTY_TO_PARENT.items():
        lex_row = lexical.get(prop)
        llm_row = llm.get(prop)

        lex_status = str(lex_row["Final Status"]) if lex_row else NO_VERDICT
        llm_status = str(llm_row["Final Status"]) if llm_row else NO_VERDICT

        both = lex_row is not None and llm_row is not None
        agree = lex_status == llm_status

        reasons: list[str] = []
        if both and not agree:
            reasons.append(f"status disagreement ({lex_status} vs {llm_status})")
        if llm_row is not None and lex_row is None:
            reasons.append("LLM-only verdict: no lexical support in the verified summary")
        if lex_row is not None and llm_row is None:
            reasons.append("lexical-only verdict: not corroborated in fetched sources")
        if llm_status == "CONFIRMED" and lex_status != "CONFIRMED":
            reasons.append("CONFIRMED reached only via fetched page text")
        for row in (lex_row, llm_row):
            note = str(row.get("Scope Note", "")).strip() if row else ""
            if note:
                reasons.append(note)
        if prop in MANDATORY_REVIEW_PROPERTIES and (lex_row or llm_row):
            reasons.append("property flagged for mandatory review in the README")

        rows.append(
            ComparisonRow(
                parent_category=parent,
                property=prop,
                lexical_status=lex_status,
                llm_status=llm_status,
                agree=agree,
                both_have_verdict=both,
                needs_review=bool(reasons),
                review_reasons="; ".join(dict.fromkeys(reasons)),
                lexical_evidence=str(lex_row.get("Best Evidence", "")) if lex_row else "",
                llm_evidence=str(llm_row.get("Best Evidence", "")) if llm_row else "",
                llm_reasoning=str(llm_row.get("Reasoning", "")) if llm_row else "",
                url=str(llm_row.get("URL", "")) if llm_row else (
                    str(lex_row.get("URL", "")) if lex_row else ""
                ),
            )
        )

    return rows


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------


@dataclass
class AgreementStats:
    """Agreement between the two layers, with the caveats attached."""

    properties_total: int = 0
    properties_with_any_verdict: int = 0
    properties_with_both_verdicts: int = 0
    agreements_among_any: int = 0
    agreement_rate_any: float | None = None
    agreements_among_both: int = 0
    agreement_rate_both: float | None = None

    both_confirmed: int = 0
    lexical_only_confirmed: int = 0
    llm_only_confirmed: int = 0
    neither_confirmed: int = 0

    kappa: float | None = None
    kappa_note: str = ""

    review_queue_size: int = 0

    def as_display_rows(self) -> list[tuple[str, str]]:
        """Label/value pairs for a Streamlit table."""

        def pct(value: float | None) -> str:
            return "n/a" if value is None else f"{value:.1%}"

        return [
            ("Properties in taxonomy", str(self.properties_total)),
            ("Reported by at least one layer", str(self.properties_with_any_verdict)),
            ("Reported by both layers", str(self.properties_with_both_verdicts)),
            ("Agreement (at least one layer)", pct(self.agreement_rate_any)),
            ("Agreement (both layers)", pct(self.agreement_rate_both)),
            ("CONFIRMED by both", str(self.both_confirmed)),
            ("CONFIRMED by lexical only", str(self.lexical_only_confirmed)),
            ("CONFIRMED by LLM only", str(self.llm_only_confirmed)),
            ("Cohen's kappa (CONFIRMED vs not)",
             "n/a" if self.kappa is None else f"{self.kappa:.3f}"),
            ("Kappa caveat", self.kappa_note),
            ("Items in review queue", str(self.review_queue_size)),
        ]


def _kappa(
    lexical_flags: Sequence[int], llm_flags: Sequence[int]
) -> tuple[float | None, str]:
    """Cohen's kappa on the CONFIRMED/not-CONFIRMED binary, with a diagnostic note.

    Returns ``(None, reason)`` rather than a misleading number when the statistic is
    not meaningful. Kappa is undefined when either annotator gives every item the same
    label: the chance-agreement term then equals observed agreement, so the formula
    reduces to 0/0. scikit-learn returns 0.0 in that case, which reads as "no better
    than chance" when the truth is "not computable".
    """
    n = len(lexical_flags)
    if n == 0:
        return None, "No properties to compare."
    if cohen_kappa_score is None:
        return None, "scikit-learn not available."

    if len(set(lexical_flags)) == 1 and len(set(llm_flags)) == 1:
        return None, (
            "Undefined: both layers assigned the same label to every property. "
            "Report raw agreement instead."
        )
    if len(set(lexical_flags)) == 1 or len(set(llm_flags)) == 1:
        return None, (
            "Undefined: one layer assigned the same label to every property, so "
            "chance agreement cannot be estimated. Report raw agreement instead."
        )

    value = float(cohen_kappa_score(list(lexical_flags), list(llm_flags)))
    note = (
        f"Computed over {n} properties. With n this small the confidence interval is "
        "wide; treat the value as indicative, not a precision estimate."
    )
    return value, note


def summarize_agreement(rows: Sequence[ComparisonRow]) -> AgreementStats:
    """Compute agreement statistics over a comparison table."""
    stats = AgreementStats(properties_total=len(rows))

    any_verdict = [
        r for r in rows
        if r.lexical_status != NO_VERDICT or r.llm_status != NO_VERDICT
    ]
    both_verdict = [r for r in rows if r.both_have_verdict]

    stats.properties_with_any_verdict = len(any_verdict)
    stats.properties_with_both_verdicts = len(both_verdict)

    stats.agreements_among_any = sum(1 for r in any_verdict if r.agree)
    if any_verdict:
        stats.agreement_rate_any = stats.agreements_among_any / len(any_verdict)

    stats.agreements_among_both = sum(1 for r in both_verdict if r.agree)
    if both_verdict:
        stats.agreement_rate_both = stats.agreements_among_both / len(both_verdict)

    # Kappa uses all 18 properties: "no verdict" is a genuine not-CONFIRMED decision,
    # and restricting to the union would inflate agreement by dropping shared negatives.
    lexical_flags = [1 if r.lexical_confirmed else 0 for r in rows]
    llm_flags = [1 if r.llm_confirmed else 0 for r in rows]

    for lex, llm in zip(lexical_flags, llm_flags):
        if lex and llm:
            stats.both_confirmed += 1
        elif lex:
            stats.lexical_only_confirmed += 1
        elif llm:
            stats.llm_only_confirmed += 1
        else:
            stats.neither_confirmed += 1

    stats.kappa, stats.kappa_note = _kappa(lexical_flags, llm_flags)
    stats.review_queue_size = sum(1 for r in rows if r.needs_review)
    return stats


# ---------------------------------------------------------------------------
# Review queue and export
# ---------------------------------------------------------------------------


def review_queue(rows: Sequence[ComparisonRow]) -> list[ComparisonRow]:
    """Rows requiring human attention, most consequential first.

    Ordering puts anything CONFIRMED by either layer at the top, because those are the
    rows that would enter the paper's statistics if accepted uncritically.
    """
    queue = [r for r in rows if r.needs_review]
    queue.sort(
        key=lambda r: (
            -max(
                STATUS_ORDER.get(r.lexical_status, 0),
                STATUS_ORDER.get(r.llm_status, 0),
            ),
            not r.both_have_verdict,
            r.parent_category,
            r.property,
        )
    )
    return queue


def to_records(rows: Iterable[ComparisonRow]) -> list[dict]:
    """Plain dicts for a DataFrame or CSV writer."""
    return [asdict(row) for row in rows]


def write_csv(rows: Iterable[ComparisonRow], path: str | Path) -> Path:
    records = to_records(rows)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(records[0].keys()) if records else [
        f.name for f in ComparisonRow.__dataclass_fields__.values()  # type: ignore[attr-defined]
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)
    return path
