from __future__ import annotations

from io import BytesIO
from pathlib import Path

import pandas as pd
import streamlit as st

import agreement
import llm_classifier
from classifier import SourceText, classify_sources, evidence_to_dicts
from content_extraction import (
    URL_COLUMNS,
    ExtractionReport,
    default_fetcher,
    estimate_chunk_count,
)
from fetcher import fetch_public_document
from taxonomy import TAXONOMY


st.set_page_config(
    page_title="CPS Incident Taxonomy Classifier",
    page_icon="🛡️",
    layout="wide",
)

BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR / "data" / "incidents.csv"

STANDARD_COLUMNS = [
    "Year",
    "Incident Name",
    "Country/Region",
    "Attack Type",
    "Attacker / Group",
    "Verified Impact Summary",
    "Source",
    "Verification Status",
    "URL1",
    "URL2",
    "URL3",
    "URL4",
]

MODE_LEXICAL = "Lexical only (Layer 1)"
MODE_LLM = "LLM only (Layer 2)"
MODE_BOTH = "Both + agreement"


@st.cache_data
def load_bundled_data() -> pd.DataFrame:
    return pd.read_csv(DATA_PATH).fillna("")


def _looks_like_header(row: pd.Series) -> bool:
    joined = " ".join(str(value).lower() for value in row.tolist())
    return "incident" in joined and ("year" in joined or "country" in joined)


def read_uploaded_table(uploaded_file) -> pd.DataFrame:
    suffix = Path(uploaded_file.name).suffix.lower()

    if suffix == ".csv":
        return pd.read_csv(uploaded_file).fillna("")

    if suffix not in {".xlsx", ".xls"}:
        raise ValueError("Please upload CSV, XLSX, or XLS.")

    raw_bytes = uploaded_file.getvalue()
    xls = pd.ExcelFile(BytesIO(raw_bytes))
    candidates = []
    for sheet_name in xls.sheet_names:
        raw = pd.read_excel(BytesIO(raw_bytes), sheet_name=sheet_name, header=None)
        nonempty = int(raw.notna().sum().sum())
        candidates.append((nonempty, sheet_name, raw))
    _, chosen_sheet, raw = max(candidates, key=lambda item: item[0])

    raw = raw.dropna(how="all").dropna(axis=1, how="all")
    if raw.empty:
        raise ValueError("The uploaded workbook contains no readable incident rows.")

    if _looks_like_header(raw.iloc[0]):
        headers = [str(value).strip() for value in raw.iloc[0].tolist()]
        df = raw.iloc[1:].copy()
        df.columns = headers
    else:
        df = raw.copy()
        names = STANDARD_COLUMNS[: df.shape[1]]
        if len(names) < df.shape[1]:
            names.extend([f"Extra_{i}" for i in range(1, df.shape[1] - len(names) + 1)])
        df.columns = names

    df = df.dropna(how="all").fillna("")
    df.attrs["chosen_sheet"] = chosen_sheet
    return df


@st.cache_data(ttl=3600, show_spinner=False)
def cached_fetch(url: str):
    """Legacy text-only retrieval, retained for the extracted-text previews."""
    return fetch_public_document(url)


@st.cache_data(ttl=3600, show_spinner=False)
def cached_raw_fetch(url: str) -> tuple[int, bytes, str]:
    """Session-level cache in front of the on-disk page cache.

    Returns raw bytes so trafilatura can strip boilerplate; pre-extracted text has
    already lost the structure it needs.
    """
    return default_fetcher(url)


def get_urls(row: pd.Series) -> list[str]:
    urls = []
    for col in row.index:
        if str(col).upper().startswith("URL"):
            value = str(row[col]).strip()
            if value.startswith(("http://", "https://")):
                urls.append(value)
    return list(dict.fromkeys(urls))


def incident_dict(row: pd.Series, allowed_urls: list[str]) -> dict:
    """Row as a plain dict, with URL columns restricted to ``allowed_urls``."""
    record = {key: row.get(key, "") for key in row.index}
    for column in URL_COLUMNS:
        record[column] = ""
    for index, url in enumerate(allowed_urls[: len(URL_COLUMNS)]):
        record[URL_COLUMNS[index]] = url
    return record


def taxonomy_panel():
    st.subheader("Exact Taxonomy")
    cols = st.columns(3)
    for col, (parent, properties) in zip(cols, TAXONOMY.items()):
        with col:
            st.markdown(f"#### {parent}")
            for prop in properties:
                st.markdown(f"- {prop}")


st.title("🛡️ CPS Security Incident — Evidence-Aware Taxonomy Classifier")
st.caption(
    "Two-layer pilot: a deterministic lexical classifier over the verified impact "
    "summary, and an optional incident-scoped LLM annotator over fetched sources."
)

with st.expander("View the taxonomy used by the classifier", expanded=False):
    taxonomy_panel()

st.info(
    "This is a research prototype. Neither layer treats ransomware, malware, or "
    "unauthorized access as proof of a property by itself — a property needs an "
    "impact-oriented evidence clause."
)

# ---------------------------------------------------------------------------
# Sidebar: data
# ---------------------------------------------------------------------------

with st.sidebar:
    st.header("1. Select data")
    data_mode = st.radio(
        "Dataset",
        ["Bundled five incidents", "Upload CSV/XLSX", "Manual incident"],
    )

df = None
manual_row = None

if data_mode == "Bundled five incidents":
    df = load_bundled_data()
elif data_mode == "Upload CSV/XLSX":
    uploaded = st.sidebar.file_uploader("Upload incident file", type=["csv", "xlsx", "xls"])
    if uploaded:
        try:
            df = read_uploaded_table(uploaded)
            chosen = df.attrs.get("chosen_sheet")
            if chosen:
                st.sidebar.success(f"Loaded worksheet: {chosen}")
        except Exception as exc:
            st.sidebar.error(str(exc))
else:
    st.sidebar.subheader("Manual input")
    name = st.sidebar.text_input("Incident name", "New CPS incident")
    description = st.sidebar.text_area(
        "Incident description",
        "Paste the verified impact description here.",
        height=180,
    )
    year = st.sidebar.text_input("Year", "")
    country = st.sidebar.text_input("Country/Region", "")
    attack_type = st.sidebar.text_input("Attack Type", "")
    attacker = st.sidebar.text_input("Attacker / Group", "")
    urls_text = st.sidebar.text_area("Source URLs — one per line", "", height=120)
    manual_row = {
        "Incident Name": name,
        "Year": year,
        "Country/Region": country,
        "Attack Type": attack_type,
        "Attacker / Group": attacker,
        "Verified Impact Summary": description,
        "URL1": "",
        "URL2": "",
        "URL3": "",
        "URL4": "",
    }
    for i, url in enumerate(
        [u.strip() for u in urls_text.splitlines() if u.strip()][:4], start=1
    ):
        manual_row[f"URL{i}"] = url

if data_mode != "Manual incident" and df is not None:
    if "Incident Name" not in df.columns:
        st.error(
            "The table needs an 'Incident Name' column. "
            "For headerless files, place the year in column A and incident name in column B."
        )
        st.stop()

    incident_names = df["Incident Name"].astype(str).tolist()
    selected_name = st.sidebar.selectbox("Incident", incident_names)
    selected_row = df[df["Incident Name"].astype(str) == selected_name].iloc[0]
elif data_mode == "Manual incident":
    selected_row = pd.Series(manual_row)
else:
    st.warning("Upload a file to continue.")
    st.stop()

# ---------------------------------------------------------------------------
# Sidebar: classification mode
# ---------------------------------------------------------------------------

st.sidebar.header("2. Classification mode")
mode = st.sidebar.radio(
    "Layers to run",
    [MODE_LEXICAL, MODE_LLM, MODE_BOTH],
    index=0,
    help=(
        "Layer 1 reads only the verified impact summary and is deterministic. "
        "Layer 2 reads fetched source pages with Claude and requires an API key."
    ),
)
needs_llm = mode in {MODE_LLM, MODE_BOTH}

api_key = llm_classifier.resolve_api_key()
llm_available = api_key is not None and llm_classifier.anthropic is not None

if needs_llm and not llm_available:
    if llm_classifier.anthropic is None:
        st.sidebar.error(
            "The 'anthropic' package is not installed, so Layer 2 is unavailable. "
            "Add `anthropic` to requirements.txt, or use Lexical only."
        )
    else:
        st.sidebar.error(
            "No ANTHROPIC_API_KEY found in st.secrets or the environment, so Layer 2 "
            "is unavailable. Add it under Streamlit Secrets, or use Lexical only."
        )

st.sidebar.header("3. Source retrieval")
st.sidebar.caption(
    "These settings affect Layer 2 only. Layer 1 deliberately reads just the verified "
    "impact summary, because a lexical matcher cannot tell the target incident from a "
    "background recap in a news article."
)
max_sources = st.sidebar.slider("Maximum URLs to use", 1, 4, 3)
refresh_pages = st.sidebar.checkbox(
    "Refetch sources (ignore the on-disk cache)", value=False
)
show_full_text = st.sidebar.checkbox("Show extracted source-text previews", value=False)

urls = get_urls(selected_row)
limited_incident = incident_dict(selected_row, urls[:max_sources])

if needs_llm and llm_available:
    cached_chunks = estimate_chunk_count([limited_incident])
    st.sidebar.metric("Chunks available from cache", cached_chunks)
    if refresh_pages:
        st.sidebar.warning(
            "Refetch is on: every page will be retrieved again and every chunk "
            "re-sent to the model."
        )
    approve_api_calls = st.sidebar.checkbox(
        "Allow API calls for uncached chunks",
        value=False,
        help=(
            "Cached chunks cost nothing. Tick this to permit new billable requests "
            "for chunks that are not yet cached."
        ),
    )
else:
    approve_api_calls = False

# ---------------------------------------------------------------------------
# Incident detail
# ---------------------------------------------------------------------------

st.subheader("Selected incident")
display_fields = [
    "Year",
    "Incident Name",
    "Country/Region",
    "Attack Type",
    "Attacker / Group",
    "Verified Impact Summary",
    "Verification Status",
]
incident_display = {
    field: str(selected_row.get(field, ""))
    for field in display_fields
    if str(selected_row.get(field, "")).strip()
}
st.json(incident_display, expanded=False)

description = str(selected_row.get("Verified Impact Summary", "")).strip()

run = st.button(
    "🔎 Retrieve evidence and classify", type="primary", use_container_width=True
)

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if run:
    run_lexical = mode in {MODE_LEXICAL, MODE_BOTH}
    run_llm = needs_llm and llm_available

    lexical_evidence: list = []
    lexical_summaries: list[dict] = []
    llm_accepted: list = []
    llm_dropped: list = []
    llm_summaries: list[dict] = []
    llm_report = llm_classifier.LLMRunReport()
    extraction_report = ExtractionReport()

    # ---- Layer 1: verified impact summary only -----------------------------
    if run_lexical:
        if not description:
            st.warning("This incident has no verified impact summary, so Layer 1 has no input.")
        else:
            lexical_evidence, lexical_summaries = classify_sources(
                [SourceText(source="Verified Impact Summary", url="", text=description)]
            )

    # ---- Layer 2: fetched source pages -------------------------------------
    if run_llm:
        if not urls:
            st.warning("This incident has no source URLs, so Layer 2 has no input.")
        elif not approve_api_calls and estimate_chunk_count([limited_incident]) == 0:
            st.warning(
                "No chunks are cached yet and API calls are not approved. Tick "
                "'Allow API calls for uncached chunks' in the sidebar to run Layer 2."
            )
        else:
            try:
                client = llm_classifier.build_client(api_key)
            except RuntimeError as exc:
                st.error(str(exc))
                client = None

            if client is not None:
                with st.spinner(
                    f"Layer 2: extracting sources and classifying with "
                    f"{llm_classifier.MODEL_ID}..."
                ):
                    if not approve_api_calls:
                        # Cache-only run: an uncached chunk must not reach the API.
                        class _CacheOnlyClient:
                            class beta:
                                class messages:
                                    @staticmethod
                                    def parse(**_kwargs):
                                        raise RuntimeError(
                                            "uncached chunk skipped (API calls not approved)"
                                        )

                        client_for_run = _CacheOnlyClient()
                    else:
                        client_for_run = client

                    llm_accepted, llm_dropped = llm_classifier.classify_incident_urls(
                        limited_incident,
                        client=client_for_run,
                        refresh_pages=refresh_pages,
                        fetcher=cached_raw_fetch,
                        llm_report=llm_report,
                        extraction_report=extraction_report,
                    )
                llm_summaries = llm_classifier.summarize(llm_accepted)

    if not lexical_summaries and not llm_summaries:
        st.error(
            "No property passed either layer. Check the retrieval log for blocked or "
            "empty sources."
        )

    # ---- Presentation ------------------------------------------------------
    tabs = ["Classification summary", "Evidence"]
    if mode == MODE_BOTH:
        tabs.append("Agreement & review queue")
    if run_llm:
        tabs.append("Contamination record")
    tabs.append("Retrieval log")
    tab_objects = st.tabs(tabs)
    tab_map = dict(zip(tabs, tab_objects))

    # Summary tab
    with tab_map["Classification summary"]:
        for label, summaries in (
            ("Layer 1 — lexical, verified impact summary", lexical_summaries),
            (f"Layer 2 — {llm_classifier.MODEL_ID}, fetched sources", llm_summaries),
        ):
            if not summaries and not (
                (label.startswith("Layer 1") and run_lexical)
                or (label.startswith("Layer 2") and run_llm)
            ):
                continue

            st.markdown(f"#### {label}")
            frame = pd.DataFrame(summaries)
            if frame.empty:
                st.warning("No property passed this layer's threshold.")
                continue

            statuses = frame["Final Status"]
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Confirmed", int((statuses == "CONFIRMED").sum()))
            c2.metric("Claimed", int((statuses == "CLAIMED").sum()))
            c3.metric("Potential", int((statuses == "POTENTIAL").sum()))
            c4.metric("Explicitly unaffected", int((statuses == "UNAFFECTED").sum()))

            confirmed = frame[statuses == "CONFIRMED"]
            if not confirmed.empty:
                labels = [
                    f"{row['Parent Category']} → {row['Property']}"
                    for _, row in confirmed.iterrows()
                ]
                st.success("Confirmed: " + " | ".join(labels))
            else:
                st.warning("No confirmed taxonomy property was detected by this layer.")

            column_config = {"URL": st.column_config.LinkColumn("URL")}
            if label.startswith("Layer 1"):
                column_config["Evidence Score"] = st.column_config.ProgressColumn(
                    "Evidence Score", min_value=0, max_value=100, format="%.1f"
                )
            st.dataframe(
                frame, use_container_width=True, hide_index=True,
                column_config=column_config,
            )

            slug = "layer1_lexical" if label.startswith("Layer 1") else "layer2_llm"
            st.download_button(
                f"Download {slug} summary CSV",
                data=frame.to_csv(index=False).encode("utf-8-sig"),
                file_name=f"classification_summary_{slug}.csv",
                mime="text/csv",
                key=f"dl_{slug}",
            )

        if llm_summaries:
            st.caption(
                "Layer 2 rows carry no numeric evidence score. Layer 1 scores are a "
                "lexical-plus-similarity magnitude and are not comparable across layers."
            )

    # Evidence tab
    with tab_map["Evidence"]:
        combined = evidence_to_dicts(lexical_evidence) + evidence_to_dicts(llm_accepted)
        if not combined:
            st.info("No evidence rows were retained.")
        else:
            evidence_df = pd.DataFrame(combined)
            col_a, col_b = st.columns(2)
            with col_a:
                status_filter = st.multiselect(
                    "Status",
                    ["CONFIRMED", "CLAIMED", "POTENTIAL", "UNAFFECTED"],
                    default=["CONFIRMED", "CLAIMED", "POTENTIAL", "UNAFFECTED"],
                )
            with col_b:
                layer_filter = st.multiselect(
                    "Layer",
                    sorted(evidence_df["layer"].unique().tolist()),
                    default=sorted(evidence_df["layer"].unique().tolist()),
                    help=(
                        "lexical_summary = verified impact summary. "
                        "llm_url = fetched page text, requires human review."
                    ),
                )
            filtered = evidence_df[
                evidence_df["status"].isin(status_filter)
                & evidence_df["layer"].isin(layer_filter)
            ].copy()
            st.dataframe(
                filtered,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "url": st.column_config.LinkColumn("URL"),
                    "evidence_score": st.column_config.ProgressColumn(
                        "Score", min_value=0, max_value=100, format="%.1f"
                    ),
                },
            )
            st.download_button(
                "Download all evidence CSV",
                data=evidence_df.to_csv(index=False).encode("utf-8-sig"),
                file_name="classification_evidence.csv",
                mime="text/csv",
                key="dl_evidence",
            )

    # Agreement tab
    if mode == MODE_BOTH:
        with tab_map["Agreement & review queue"]:
            comparison = agreement.compare(lexical_summaries, llm_summaries)
            stats = agreement.summarize_agreement(comparison)

            st.markdown("#### Agreement between the two layers")
            st.dataframe(
                pd.DataFrame(stats.as_display_rows(), columns=["Measure", "Value"]),
                use_container_width=True,
                hide_index=True,
            )
            if stats.kappa is None:
                st.warning(f"Cohen's kappa not reported. {stats.kappa_note}")

            st.markdown("#### Property-by-property comparison")
            st.dataframe(
                pd.DataFrame(agreement.to_records(comparison)),
                use_container_width=True,
                hide_index=True,
            )

            queue = agreement.review_queue(comparison)
            st.markdown(f"#### Human review queue — {len(queue)} item(s)")
            if not queue:
                st.info("Nothing flagged for review.")
            else:
                st.warning(
                    "Resolve these before counting any property as CONFIRMED in "
                    "published statistics."
                )
                queue_df = pd.DataFrame(agreement.to_records(queue))
                st.dataframe(queue_df, use_container_width=True, hide_index=True)
                st.download_button(
                    "Download review queue CSV",
                    data=queue_df.to_csv(index=False).encode("utf-8-sig"),
                    file_name="human_review_queue.csv",
                    mime="text/csv",
                    key="dl_queue",
                )

    # Contamination record
    if run_llm:
        with tab_map["Contamination record"]:
            st.markdown("#### Findings excluded as background or another incident")
            st.caption(
                "Each row is evidence that provably appears in a fetched source but "
                "was attributed to a different incident or to general background. A "
                "lexical classifier reading full pages would have counted these."
            )
            if not llm_dropped:
                st.info("No findings were excluded by the attribution filter.")
            else:
                dropped_df = pd.DataFrame(evidence_to_dicts(llm_dropped))
                st.dataframe(
                    dropped_df,
                    use_container_width=True,
                    hide_index=True,
                    column_config={"url": st.column_config.LinkColumn("URL")},
                )
                st.download_button(
                    "Download contamination record CSV",
                    data=dropped_df.to_csv(index=False).encode("utf-8-sig"),
                    file_name="attribution_excluded.csv",
                    mime="text/csv",
                    key="dl_dropped",
                )

    # Retrieval log
    with tab_map["Retrieval log"]:
        if run_llm:
            st.markdown("#### Layer 2 run statistics")
            m1, m2, m3 = st.columns(3)
            m1.metric("Chunks processed", llm_report.chunks_processed)
            m2.metric("From response cache", llm_report.chunks_cached)
            m3.metric("Chunks failed", llm_report.chunks_failed)
            m4, m5, m6 = st.columns(3)
            m4.metric("Findings returned", llm_report.findings_returned)
            m5.metric(
                "Rejected: span unverified",
                llm_report.rejected_span_unverified,
                help="Findings whose quoted span could not be located in the source.",
            )
            m6.metric("Dropped: attribution", llm_report.dropped_attribution)

            rate = llm_report.span_rejection_rate
            if llm_report.findings_returned:
                if rate > 0.10:
                    st.error(
                        f"Span rejection rate {rate:.1%} — above 10%. Investigate the "
                        "prompt or chunking before trusting this run."
                    )
                else:
                    st.success(f"Span rejection rate {rate:.1%}.")

            if llm_report.rejected_unknown_property:
                st.warning(
                    f"{llm_report.rejected_unknown_property} finding(s) rejected for an "
                    "unrecognised property or status."
                )
            if llm_report.errors:
                with st.expander(f"{len(llm_report.errors)} chunk error(s)"):
                    for message in llm_report.errors:
                        st.text(message)

            st.markdown("#### Source extraction")
            e1, e2, e3 = st.columns(3)
            e1.metric("Pages from cache", extraction_report.cache_hits)
            e2.metric("Pages fetched", extraction_report.fetched)
            e3.metric("Pages failed", extraction_report.failures)
            if extraction_report.failed_urls:
                st.warning("Failed sources:")
                for url in extraction_report.failed_urls:
                    st.text(url)
        else:
            st.info(
                "Layer 2 was not run, so no sources were retrieved. Layer 1 reads only "
                "the verified impact summary."
            )

        if show_full_text and urls:
            st.markdown("#### Extracted source text previews")
            for url in urls[:max_sources]:
                result = cached_fetch(url)
                with st.expander(f"{url} — {result.message}"):
                    st.text(result.text[:12000])

    st.caption(
        "Interpretation rule: only CONFIRMED labels enter the paper's incident-frequency "
        "statistics, and any CONFIRMED originating from Layer 2 requires human review "
        "first. CLAIMED, POTENTIAL, and UNAFFECTED evidence remains visible for audit."
    )
