# Two-layer classification

Append this to `README.md`, after the existing "What the prototype does" section.

---

## Two-layer classification

The prototype runs two independent annotators over each incident. They are not
interchangeable, and their outputs must not be pooled.

### Layer 1 — lexical, deterministic (`classifier.py`)

Reads **only the Verified Impact Summary**. Matches keywords and phrases from
`taxonomy.py`, with TF-IDF cosine similarity as a weak tiebreaker, then assigns
`CONFIRMED` / `CLAIMED` / `POTENTIAL` / `UNAFFECTED` from negation and hedging patterns.

Every verdict traces to a specific matched term, recorded in `matched_terms`. The same
input always produces the same output, and it will keep producing it years from now with
no external service involved. This is the auditable baseline.

Layer 1 deliberately does **not** read fetched page text. It scores each clause in
isolation and has no representation of *which* incident a clause describes, so applied to
a news article it counts background recaps of unrelated incidents as evidence for the
target incident. Earlier versions of this app pooled the summary and fetched pages into a
single input; that behaviour has been removed.

### Layer 2 — incident-scoped LLM annotator (`llm_classifier.py`)

Reads **fetched source pages**. Pages are retrieved, stripped of boilerplate with
`trafilatura`, cached to disk, and split into overlapping 2000-character chunks aligned to
sentence boundaries. Each chunk is classified with the target incident's name, year,
country, attack type and attacker supplied, and every finding must be attributed either
to the target incident or to background material.

- **Model:** `claude-sonnet-5`, pinned. Model IDs in this format are snapshots rather
  than floating aliases, so the underlying model stays constant for the lifetime of the
  ID. Cite this exact string in the methods section.
- **Temperature:** 0. **Output:** schema-validated structured output.
- **Two output guards.** Every finding must quote a span that provably appears in the
  supplied chunk after whitespace and punctuation normalisation; unlocatable spans are
  discarded as unreliable. Findings attributed to background material are then removed
  from the result set and written to a separate contamination record.
- **No numeric score.** Layer 2 carries no evidence score. Layer 1's score is a
  lexical-plus-similarity magnitude on a 0–100 scale with no Layer 2 equivalent, so the
  two must never be sorted or thresholded together.

### Agreement reporting (`agreement.py`)

With both layers enabled, the app reports per-property agreement, Cohen's kappa on the
`CONFIRMED` / not-`CONFIRMED` binary, and a human review queue.

Two figures are reported because they answer different questions: agreement across
properties **either** layer reported, and agreement across properties **both** reported.
The gap between them is usually large. State which one you are quoting.

Kappa is computed over all 18 properties, treating "no verdict" as a genuine
not-`CONFIRMED` decision — restricting to reported properties would drop shared negatives
and inflate the figure. When either layer assigns the same label to every property, kappa
is mathematically undefined and the app reports "not applicable" rather than a misleading
`0.000`. With 18 items the confidence interval is wide in any case; treat the value as
indicative.

## Caching

Two on-disk caches, both **committed to the repository on purpose**:

| Path | Contents | Key |
|---|---|---|
| `data/cache/pages/<incident>/<url-hash>.json` | extracted page text, HTTP status, extractor used | SHA-256 of the URL |
| `data/cache/llm/<hash>.json` | raw model findings per chunk | SHA-256 of model ID + prompt version + chunk text |

This is not an optimisation. It is why:

- the app works on hosts whose egress IPs news sites block;
- published results are reproducible against frozen source text, even after pages change
  or disappear;
- reruns cost nothing.

Failed retrievals are cached too, so a paywalled URL is not retried on every run. Use the
sidebar "Refetch sources" control, or `python content_extraction.py --input
data/incidents.csv --refresh`, to retry.

`PROMPT_VERSION` in `llm_classifier.py` is part of the LLM cache key. Bump it whenever
you edit the system prompt, so results from an older prompt are never silently reused.

## Supplying an API key

Layer 2 needs an Anthropic API key. Layer 1 does not, and the app defaults to Layer 1
only, so it never makes a billable call unless you select an LLM mode and tick "Allow API
calls for uncached chunks".

**Locally:** create `.streamlit/secrets.toml` (already in `.gitignore`):

```toml
ANTHROPIC_API_KEY = "sk-ant-..."
```

Or export `ANTHROPIC_API_KEY` in your shell.

**On Streamlit Community Cloud:** paste the same TOML into the app's Secrets panel. Never
commit a key. If no key is present, the app runs Layer 1 and says so.

## Research interpretation

Count only `CONFIRMED` properties in the final statistics, and additionally:

> **Any `CONFIRMED` property originating from Layer 2 requires human review before it is
> counted.** Layer 2 is not deterministic, its verdicts cannot be traced to a fixed rule,
> and its model endpoint may not exist in a few years' time. It is an independent
> annotator and a measurement instrument, not the source of the results.

Keep `CLAIMED`, `POTENTIAL` and `UNAFFECTED` records as audit evidence, as before. The
contamination record — findings that genuinely appear in a source but describe a different
incident — is evidence that attribution control is working, and is worth reporting.

The `layer` column in every evidence export records which annotator produced each row
(`lexical_summary` or `llm_url`), alongside `model_id` and `chunk_id`.

## Limitations (additions)

- Some websites block automated retrieval or require JavaScript; the committed page cache
  mitigates this but does not eliminate it.
- PDF extraction works only for text-based PDFs, not scanned images.
- Layer 1 keywords and rules are an interpretable pilot, not a validated production
  classifier.
- Layer 2 depends on an external service. Its results are reproducible only through the
  committed response cache; regenerating them requires the same pinned model to still be
  served.
- Agreement between the two layers is not evidence of correctness. Both can be wrong in
  the same direction, which is why Safety, Timing Constraints, Hybrid Dynamics,
  Compliance, Non-repudiation and Explainability always enter the review queue regardless
  of agreement.
- Human review remains mandatory.
