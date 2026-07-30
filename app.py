from __future__ import annotations

from io import BytesIO
from pathlib import Path
import re

import pandas as pd
import streamlit as st

from classifier import SourceText, classify_sources, evidence_to_dicts
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
    return fetch_public_document(url)


def get_urls(row: pd.Series) -> list[str]:
    urls = []
    for col in row.index:
        if str(col).upper().startswith("URL"):
            value = str(row[col]).strip()
            if value.startswith(("http://", "https://")):
                urls.append(value)
    return list(dict.fromkeys(urls))


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
    "Pilot system: retrieve source text, split it into evidence clauses, "
    "detect negation/claims/potential language, and perform transparent multi-label classification."
)

with st.expander("View the taxonomy used by the classifier", expanded=False):
    taxonomy_panel()

st.info(
    "This is a research prototype. It never treats ransomware, malware, or unauthorized access "
    "as proof of a property by themselves. A property needs an impact-oriented evidence clause."
)

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
    urls_text = st.sidebar.text_area(
        "Source URLs — one per line",
        "",
        height=120,
    )
    manual_row = {
        "Incident Name": name,
        "Verified Impact Summary": description,
        "URL1": "",
        "URL2": "",
        "URL3": "",
        "URL4": "",
    }
    for i, url in enumerate([u.strip() for u in urls_text.splitlines() if u.strip()][:4], start=1):
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

st.sidebar.header("2. Retrieval settings")
fetch_links = st.sidebar.checkbox("Fetch and analyze source URLs", value=True)
max_sources = st.sidebar.slider("Maximum URLs to fetch", 1, 4, 3)
show_full_text = st.sidebar.checkbox("Show extracted source-text previews", value=False)

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
urls = get_urls(selected_row)

run = st.button("🔎 Retrieve evidence and classify", type="primary", use_container_width=True)

if run:
    sources = []
    if description:
        sources.append(
            SourceText(
                source="Dataset description",
                url="",
                text=description,
            )
        )

    fetch_log = []
    if fetch_links and urls:
        progress = st.progress(0, text="Fetching source documents...")
        for index, url in enumerate(urls[:max_sources], start=1):
            result = cached_fetch(url)
            fetch_log.append(
                {
                    "URL": url,
                    "Status": "OK" if result.ok else "FAILED",
                    "Message": result.message,
                    "Extracted Characters": len(result.text),
                }
            )
            if result.ok:
                sources.append(
                    SourceText(
                        source=f"Fetched source {index}",
                        url=result.url,
                        text=result.text,
                    )
                )
            progress.progress(index / min(max_sources, len(urls)), text=f"Processed source {index}")
        progress.empty()

    if not sources:
        st.error("No description or fetchable source text is available.")
        st.stop()

    evidence, summaries = classify_sources(sources)
    evidence_df = pd.DataFrame(evidence_to_dicts(evidence))
    summary_df = pd.DataFrame(summaries)

    tab1, tab2, tab3 = st.tabs(
        ["Classification summary", "Evidence clauses", "Retrieval log"]
    )

    with tab1:
        if summary_df.empty:
            st.warning("No property passed the conservative evidence threshold.")
        else:
            confirmed = summary_df[summary_df["Final Status"] == "CONFIRMED"]
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Confirmed properties", len(confirmed))
            c2.metric("Claimed properties", int((summary_df["Final Status"] == "CLAIMED").sum()))
            c3.metric("Potential properties", int((summary_df["Final Status"] == "POTENTIAL").sum()))
            c4.metric("Explicitly unaffected", int((summary_df["Final Status"] == "UNAFFECTED").sum()))

            if not confirmed.empty:
                labels = [
                    f"{row['Parent Category']} → {row['Property']}"
                    for _, row in confirmed.iterrows()
                ]
                st.success("Confirmed classification: " + " | ".join(labels))
            else:
                st.warning("No confirmed taxonomy property was detected.")

            st.dataframe(
                summary_df,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "URL": st.column_config.LinkColumn("URL"),
                    "Evidence Score": st.column_config.ProgressColumn(
                        "Evidence Score",
                        min_value=0,
                        max_value=100,
                        format="%.1f",
                    ),
                },
            )

            st.download_button(
                "Download classification summary CSV",
                data=summary_df.to_csv(index=False).encode("utf-8-sig"),
                file_name="classification_summary.csv",
                mime="text/csv",
            )

    with tab2:
        if evidence_df.empty:
            st.info("No evidence clauses were retained.")
        else:
            status_filter = st.multiselect(
                "Evidence status",
                ["CONFIRMED", "CLAIMED", "POTENTIAL", "UNAFFECTED"],
                default=["CONFIRMED", "CLAIMED", "POTENTIAL", "UNAFFECTED"],
            )
            filtered = evidence_df[evidence_df["status"].isin(status_filter)].copy()
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
            )

    with tab3:
        if fetch_log:
            st.dataframe(pd.DataFrame(fetch_log), use_container_width=True, hide_index=True)
        else:
            st.info("URL retrieval was disabled or the incident has no source URLs.")

        if show_full_text:
            for source in sources:
                with st.expander(f"{source.source} — {source.url or 'local description'}"):
                    st.text(source.text[:12000])

    st.caption(
        "Interpretation rule: only CONFIRMED labels should enter the paper's incident-frequency statistics. "
        "CLAIMED, POTENTIAL, and UNAFFECTED evidence remain visible for audit and human review."
    )
