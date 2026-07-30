"""Evidence-aware, transparent multi-label classifier for the exact CPS taxonomy."""

from __future__ import annotations

from dataclasses import dataclass, asdict
import re
from typing import Iterable

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from taxonomy import PROPERTY_TO_PARENT, STATUS_ORDER, TAXONOMY


CLAIM_PATTERNS = [
    r"\bclaimed\b", r"\balleged\b", r"\bsuspected\b", r"\breportedly\b",
    r"\baccording to the attacker\b", r"\bnot independently confirmed\b",
    r"\bunconfirmed\b",
]
POTENTIAL_PATTERNS = [
    r"\bcould\b", r"\bmay\b", r"\bmight\b", r"\bpotential(?:ly)?\b",
    r"\bcapable of\b", r"\bcan be used to\b", r"\bpossible\b",
]
NEGATION_PATTERNS = [
    r"\bnot affected\b", r"\bunaffected\b", r"\bno impact\b",
    r"\bno evidence\b", r"\bnot compromised\b", r"\bno disruption\b",
    r"\bremained operational\b", r"\bcontinued normally\b",
    r"\bwithout interruption\b", r"\bdid not destabilize\b",
    r"\bwas not disrupted\b", r"\bwere not disrupted\b",
    r"\bnot interrupted\b", r"\bno sensitive .* compromised\b",
]

CLAUSE_BOUNDARY = re.compile(
    r"\s*(?:;|\bbut\b|\bhowever\b|\balthough\b|\bwhile\b|\bwhereas\b)\s*",
    flags=re.IGNORECASE,
)


@dataclass
class SourceText:
    source: str
    url: str
    text: str


@dataclass
class Evidence:
    parent_category: str
    property: str
    status: str
    evidence_score: float
    lexical_score: float
    semantic_similarity: float
    sentence: str
    source: str
    url: str
    matched_terms: str


def normalize_text(text: str) -> str:
    text = (text or "").replace("\u00a0", " ")
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def split_into_clauses(text: str) -> list[str]:
    """Sentence splitting followed by contrast-clause splitting."""
    text = normalize_text(text)
    if not text:
        return []

    sentences = re.split(r"(?<=[.!?])\s+(?=[A-Z0-9])", text)
    clauses: list[str] = []
    for sentence in sentences:
        for clause in CLAUSE_BOUNDARY.split(sentence):
            clause = clause.strip(" -–—:;,")
            if 25 <= len(clause) <= 1200:
                clauses.append(clause)
    return clauses


def detect_status(clause: str) -> str:
    lowered = clause.lower()
    if any(re.search(pattern, lowered) for pattern in NEGATION_PATTERNS):
        return "UNAFFECTED"
    if any(re.search(pattern, lowered) for pattern in CLAIM_PATTERNS):
        return "CLAIMED"
    if any(re.search(pattern, lowered) for pattern in POTENTIAL_PATTERNS):
        return "POTENTIAL"
    return "CONFIRMED"


def _profile_text(parent: str, prop: str, profile: dict) -> str:
    return " ".join(
        [
            parent,
            prop,
            profile["definition"],
            *profile.get("phrases", []),
            *profile.get("keywords", []),
        ]
    )


def _all_profiles() -> list[tuple[str, str, dict]]:
    return [
        (parent, prop, profile)
        for parent, properties in TAXONOMY.items()
        for prop, profile in properties.items()
    ]


def _matched_terms(clause_lower: str, profile: dict) -> tuple[list[str], float]:
    matches: list[str] = []
    lexical = 0.0

    for phrase in profile.get("phrases", []):
        phrase_lower = phrase.lower()
        if phrase_lower in clause_lower:
            matches.append(phrase)
            lexical += 4.0

    for keyword in profile.get("keywords", []):
        keyword_lower = keyword.lower()
        pattern = r"\b" + re.escape(keyword_lower) + r"\b"
        if re.search(pattern, clause_lower):
            matches.append(keyword)
            lexical += 1.8

    # Cap repeated lexical evidence so very long pages do not dominate.
    return sorted(set(matches)), min(lexical, 10.0)


def classify_sources(sources: Iterable[SourceText]) -> tuple[list[Evidence], list[dict]]:
    profiles = _all_profiles()
    profile_texts = [_profile_text(parent, prop, profile) for parent, prop, profile in profiles]

    clause_records: list[tuple[str, str, str]] = []
    for src in sources:
        for clause in split_into_clauses(src.text):
            clause_records.append((clause, src.source, src.url))

    if not clause_records:
        return [], []

    clause_texts = [record[0] for record in clause_records]
    vectorizer = TfidfVectorizer(
        lowercase=True,
        ngram_range=(1, 2),
        stop_words="english",
        min_df=1,
        sublinear_tf=True,
    )
    matrix = vectorizer.fit_transform(profile_texts + clause_texts)
    profile_matrix = matrix[: len(profile_texts)]
    clause_matrix = matrix[len(profile_texts) :]
    similarities = cosine_similarity(clause_matrix, profile_matrix)

    evidence_rows: list[Evidence] = []

    for clause_index, (clause, source, url) in enumerate(clause_records):
        clause_lower = clause.lower()
        status = detect_status(clause)

        for profile_index, (parent, prop, profile) in enumerate(profiles):
            matches, lexical_score = _matched_terms(clause_lower, profile)
            similarity = float(similarities[clause_index, profile_index])

            # Semantic similarity supports retrieval, but does not independently
            # assign a label unless it is unusually strong.
            if lexical_score <= 0 and similarity < 0.24:
                continue

            semantic_points = min(3.0, similarity * 8.0)
            raw_score = lexical_score + semantic_points

            # Conservative threshold. A weak generic keyword alone is not enough.
            if raw_score < 2.6:
                continue

            status_adjustment = {
                "CONFIRMED": 0.8,
                "CLAIMED": -0.3,
                "POTENTIAL": -0.8,
                "UNAFFECTED": 0.2,
            }[status]
            final_score = max(0.0, min(10.0, raw_score + status_adjustment))

            evidence_rows.append(
                Evidence(
                    parent_category=parent,
                    property=prop,
                    status=status,
                    evidence_score=round(final_score * 10.0, 1),
                    lexical_score=round(lexical_score, 2),
                    semantic_similarity=round(similarity, 3),
                    sentence=clause,
                    source=source,
                    url=url,
                    matched_terms=", ".join(matches),
                )
            )

    # Keep the strongest duplicate evidence per property/status/sentence.
    dedup: dict[tuple, Evidence] = {}
    for row in evidence_rows:
        key = (row.property, row.status, row.sentence, row.source)
        if key not in dedup or row.evidence_score > dedup[key].evidence_score:
            dedup[key] = row
    evidence_rows = sorted(
        dedup.values(),
        key=lambda r: (-STATUS_ORDER[r.status], -r.evidence_score, r.parent_category, r.property),
    )

    summaries: list[dict] = []
    for prop, parent in PROPERTY_TO_PARENT.items():
        rows = [r for r in evidence_rows if r.property == prop]
        if not rows:
            continue

        statuses = {r.status for r in rows}
        if "CONFIRMED" in statuses:
            final_status = "CONFIRMED"
        elif "CLAIMED" in statuses:
            final_status = "CLAIMED"
        elif "POTENTIAL" in statuses:
            final_status = "POTENTIAL"
        else:
            final_status = "UNAFFECTED"

        strongest = max(
            [r for r in rows if r.status == final_status] or rows,
            key=lambda r: r.evidence_score,
        )
        scope_note = ""
        if final_status == "CONFIRMED" and "UNAFFECTED" in statuses:
            scope_note = "Mixed scope: confirmed impact and explicit unaffected evidence both exist."

        summaries.append(
            {
                "Parent Category": parent,
                "Property": prop,
                "Final Status": final_status,
                "Evidence Score": strongest.evidence_score,
                "Best Evidence": strongest.sentence,
                "Source": strongest.source,
                "URL": strongest.url,
                "Scope Note": scope_note,
            }
        )

    summaries.sort(
        key=lambda row: (
            -STATUS_ORDER[row["Final Status"]],
            -float(row["Evidence Score"]),
            row["Parent Category"],
            row["Property"],
        )
    )
    return evidence_rows, summaries


def evidence_to_dicts(rows: list[Evidence]) -> list[dict]:
    return [asdict(row) for row in rows]
