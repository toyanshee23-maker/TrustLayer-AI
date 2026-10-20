# TrustLayer AI

TrustLayer AI is a local-first privacy, evidence-checking, risk-routing, human-review, and audit prototype for the **Challenge 5: Managing Data and AI Safely**. It is designed to improve an existing AI workflow, not to replace it with a chatbot.

> **Prototype limitations:** Common PII patterns and lexical evidence retrieval are imperfect. A matching passage is not proof that a claim is true. This prototype has no production model integration, authentication, legal-compliance certification, or tamper-proof storage. Validate independently before any production use.

## What works

- Eight Streamlit views: Overview, Privacy shield, Output verification, Risk engine, Human review, Model quality lab, Audit trail, and Governance settings.
- Local detection for email addresses, common phone numbers, SSN-shaped values, contextual names, and configurable literal sensitive keywords; redaction and masking previews.
- In-memory UTF-8 TXT, MD, CSV, and JSON uploads with extension, byte, character, and encoding checks.
- Claim-by-claim lexical evidence lookup with source locations, missing/invalid citation findings, numeric/polarity conflict flags, and conservative "Needs review" states.
- Explainable LOW / MEDIUM / HIGH / UNCERTAIN / BLOCKED routing with editable score thresholds, high-impact terms, configurable SSN blocking, and fail-closed handling for failed required checks.
- A functioning persisted review queue. Review answers and evidence are stored **only after the submitter explicitly opts in**; every decision requires a reason. Review decisions do not assert factual correctness.
- Local SQLite request metadata with keyed fingerprints rather than raw request text, hash-linked audit events, integrity verification, filters, JSON/CSV exports, and explicit local deletion.
- Synthetic labeled evaluation fixture and actual baseline-versus-TrustLayer timings, counts, precision, recall, F1, false positives, false negatives, review rate, median/p95 latency, and throughput.
- Governance inventory, configurable review-content retention, evaluation history, and incident records.

## Architecture

```text
app.py                         Streamlit navigation and interactive views
trustlayer/privacy.py          Local PII patterns, upload validation, redaction
trustlayer/verification.py     Claim-to-passage lookup, citations, bounded safe cache
trustlayer/policy.py           Configurable risk scoring and fail-closed routing
trustlayer/storage.py          SQLite persistence, reviews, incidents, hash-linked audit
trustlayer/evaluation.py       Labeled metrics and measured comparison
data/sample_cases.csv          Synthetic labeled evaluation data (12 cases)
tests/                         Unit, persistence, benchmark, and Streamlit smoke tests
```

SQLite is local at `trustlayer.db` by default. Set `TRUSTLAYER_DB_PATH` to choose another location. The request audit does not store the raw request, answer, or source text; the fingerprint is keyed with an installation-local salt. Review records can contain private text and are persisted only with explicit consent. Expired review content is purged on startup and when a retention setting is saved; full local deletion is available in Governance settings. The local database and its hash chain are not a substitute for protected production storage.

## Setup on Windows PowerShell

From the project folder:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
pytest -q
streamlit run app.py
```

Open the local URL printed by Streamlit (normally `http://localhost:8501`). No paid API key or external model is needed or used.

## Workflow

1. Use **Privacy shield** to scan pasted text or a supported document. Inspect detections and the redacted/masked preview before copying information elsewhere.
2. In **Output verification**, provide the request/context, proposed answer, and source passages. TrustLayer checks local PII patterns, citations, lexical support, numeric/polarity mismatches, and incomplete outputs.
3. Inspect the risk score, matched rules, evidence, source locations, and recommended route. An SSN-shaped finding is blocked by the default policy. Missing or inconclusive evidence routes conservatively to review.
4. When a human review is needed, explicitly opt in to local persistence. In **Human review**, an authorized local-demo user can approve, reject, or request revision with a required reason.
5. Review metadata and decisions in **Audit trail**; run the integrity check and export filtered JSON or CSV.
6. Run the **Model quality lab** against the bundled synthetic fixture or upload a labeled CSV. Governance settings contain retention controls, inventory, evaluation history, and incidents.

No source/document text is interpreted as instructions. Uploaded files are decoded in memory, never executed, and not saved as temporary files. No external provider integration is configured; therefore there is no external-call consent flow because no external call can occur.

## Evaluation methodology

The bundled 12-row synthetic fixture documents expected binary labels for privacy-pattern presence and unsupported claims. Positive means "the labeled issue is present." Precision, recall, F1, TP/TN/FP/FN, and class supports are calculated from those labels. If either class is absent, the UI reports the metric as not evaluated.

- **Baseline:** email-only regex and a simple 20% answer/source token-overlap support heuristic.
- **TrustLayer:** common local PII patterns, claim-to-passage lexical evidence checking, citation and basic contradiction checks, and configurable risk-based review routing.
- Both pipelines process the same cases. Per-case wall-clock time is measured using `time.perf_counter_ns()`; median, nearest-rank p95, total elapsed time, and cases/second are calculated from those measurements.
- Results depend on hardware, Python/runtime warm-up, and dataset composition. The sample is small and synthetic; it does not demonstrate production-model performance, broad fairness, general factuality, or production safety.
- Scores are configurable workflow rules, not statistically calibrated probabilities. Similarity/lexical overlap is never represented as certainty.

Upload CSV columns:

```text
case_id,scenario,text,answer,sources,expected_pii,expected_unsupported
```

Labels accept `true`/`false`, `yes`/`no`, or `1`/`0`. Each row is capped at 100,000 characters per text field, uploads at 2 MiB, and evaluation batches at 10,000 rows. Keep uploaded evaluation datasets synthetic or otherwise approved; they're not automatically copied into the audit log.

## Privacy, security, and known gaps

- PII detection is regex-based and intentionally local. Names are only detected in a limited set of contextual forms; free-form names, non-English identifiers, and many sensitive categories can be missed. False positives are possible.
- Evidence checking uses local lexical retrieval and simple polarity/number checks, not embeddings, a separate verifier, or an AI model. Paraphrases can be missed; matching text does not establish truth. Unclear evidence is routed to review.
- The prototype has no user authentication or server-side reviewer roles. Do not expose it to untrusted users or use it as a multi-tenant service.
- SQLite persistence is local and may be ephemeral on hosted platforms. Hash-linked logs detect many accidental edits but are not tamper-proof against a privileged database editor.
- Review rationale is pattern-redacted before storage, but incident narratives and opted-in review answers/evidence can still contain sensitive content. Restrict access to the local database and apply retention/deletion controls.
- No Presidio, embedding model, external AI, or drift detector is active. No drift metric is claimed. Fairness metrics are not reported because the fixture has no documented group labels.
- The baseline is a deliberately simple, disclosed comparator; synthetic benchmark results must not be generalized.

## Deployment preparation

The repository contains `requirements.txt`, `.python-version`, and `.streamlit/config.toml` for a Streamlit-compatible deployment. To deploy on Streamlit Community Cloud, push this repository to a Git host, create a new app pointing at `app.py`, select Python 3.12, and deploy. This prototype does not require secrets. A hosted instance needs a deliberate persistent-storage and authentication design before it is used with real user data. **No deployment has been performed or verified.**

## Tests

Run `pytest -q`. The suite covers detection/redaction and input validation, evidence and citations, routing thresholds and fail-closed behavior, review transitions, persistent SQLite records, audit tampering, exports, labeled metrics, benchmark execution, cache privacy/invalidation, and a Streamlit entry-point smoke test.
