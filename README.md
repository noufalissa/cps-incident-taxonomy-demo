# CPS Incident Taxonomy Classifier — Five-Incident Pilot
A transparent Streamlit prototype for classifying CPS security incidents according to the exact taxonomy:
- **Functional Correctness:** Safety, Liveness, Reachability, Timing Constraints, Hybrid Dynamics
- **Information Protection:** Confidentiality, Integrity, Availability, Authenticity, Authorization, Accountability, Non-repudiation
- **Operational Assurance:** Privacy, Reliability, Resilience, Recoverability, Compliance, Explainability

## What the prototype does
1. Loads the bundled five energy-sector incidents, a user-uploaded CSV/XLSX file, or a manually entered incident.
2. Uses the verified impact description as baseline evidence.
3. Optionally fetches public HTML pages and PDF reports.
4. Splits text into sentences and contrast clauses.
5. Retrieves evidence with keywords, phrases, and TF-IDF similarity.
6. detects:
   - `CONFIRMED`
   - `CLAIMED`
   - `POTENTIAL`
   - `UNAFFECTED`
7. Produces an auditable, multi-label classification with evidence sentences and source URLs.
The prototype is intentionally conservative. It does **not** infer an impact merely from an attack label such as ransomware or malware.

## Input format
The bundled data use these columns:
```text
Year
Incident Name
Country/Region
Attack Type
Attacker / Group
Verified Impact Summary
Source
Verification Status
URL1
URL2
URL3
URL4
```
The uploader also accepts a headerless workbook with the same column order.

## Research interpretation
For the final paper statistics, count only `CONFIRMED` properties. Keep `CLAIMED`, `POTENTIAL`, and `UNAFFECTED` records as audit evidence and human-review material.

## Limitations
- Some websites block automated retrieval or require JavaScript.
- PDF extraction works only for text-based PDFs, not scanned-image PDFs.
- Keywords and rules are an interpretable pilot, not a validated production classifier.
- Human review remains mandatory, especially for Safety, Timing Constraints, Hybrid Dynamics, Compliance, Non-repudiation, and Explainability.
