"""TrustLayer AI: a local-first privacy, verification, and governance workbench."""

from __future__ import annotations

from collections import Counter
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import statistics
import time
from typing import Any

import pandas as pd
import streamlit as st

from trustlayer.evaluation import load_sample_cases, parse_uploaded_csv, run_benchmark
from trustlayer.policy import RiskPolicy, route_request
from trustlayer.privacy import MAX_TEXT_CHARS, detect_pii, read_text_upload, redact_text
from trustlayer.storage import Store, export_events_csv, export_events_json
from trustlayer.verification import VerificationCache, check_answer, is_incomplete_output

PROJECT_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("TRUSTLAYER_DB_PATH") or PROJECT_DIR / "trustlayer.db")
DEFAULT_POLICY = RiskPolicy()


@st.cache_resource
def get_store() -> Store:
    store = Store(DB_PATH)
    retention_days = int(store.get_setting("retention_days", 90))
    deleted = store.purge_expired_review_content(retention_days)
    if deleted:
        store.append_event("review_content_purged", {
            "deleted_count": deleted, "retention_days": retention_days,
        })
    return store


@st.cache_resource
def get_verification_cache() -> VerificationCache:
    return VerificationCache(max_entries=128)


def get_policy(store: Store) -> RiskPolicy:
    saved = store.get_setting("risk_policy")
    if saved is None:
        return RiskPolicy()
    policy = RiskPolicy(**saved)
    policy.validate()
    return policy


def get_custom_keywords(store: Store) -> list[str]:
    return store.get_setting("custom_sensitive_keywords", [])


def get_fingerprint(store: Store, value: str) -> str:
    salt = store.get_setting("fingerprint_salt")
    if salt is None:
        salt = secrets.token_hex(32)
        store.set_setting("fingerprint_salt", salt)
    return hmac.new(bytes.fromhex(salt), value.encode("utf-8"), hashlib.sha256).hexdigest()


def _audit_checks(findings: list[dict[str, Any]], verification: dict[str, Any]) -> dict[str, Any]:
    counts = Counter(item["kind"] for item in findings)
    return {
        "privacy": {"finding_count": len(findings), "types": dict(counts)},
        "verification": {
            "overall": verification["overall"],
            "supported_count": verification["supported_count"],
            "unsupported_count": verification["unsupported_count"],
            "needs_review_count": verification["needs_review_count"],
            "source_count": verification["source_count"],
            "citation_status": verification["citation_status"],
            "errors": verification["errors"],
            "evidence_references": sorted({
                claim["source_id"] for claim in verification["claims"] if claim.get("source_id")
            }),
        },
    }


def _status_message(level: str) -> None:
    if level == "BLOCKED":
        st.error("Blocked by policy. Do not forward this content.")
    elif level == "HIGH":
        st.error("High risk. Human review is required before downstream use.")
    elif level == "UNCERTAIN":
        st.warning("Evidence is insufficient for automated clearance. Route to human review.")
    elif level == "MEDIUM":
        st.warning("Additional review is recommended under the configured policy.")
    else:
        st.success("Low risk under the current configured checks. This is not a factuality guarantee.")


def _render_route(route: dict[str, Any]) -> None:
    _status_message(route["level"])
    st.markdown(f"**Risk level:** `{route['level']}` · **Rule score:** {route['score']}/100")
    st.markdown("**Why this route**")
    for reason in route["reasons"]:
        st.markdown(f"- {reason}")
    for action in route["actions"]:
        st.info(action)


def _process_request(
    request_text: str,
    answer: str,
    sources: str,
    policy: RiskPolicy,
    custom_keywords: list[str],
    allow_review_persistence: bool,
) -> dict[str, Any]:
    started = time.perf_counter_ns()
    segments = [("request", request_text), ("answer", answer), ("sources", sources)]
    findings: list[dict[str, Any]] = []
    for segment, text in segments:
        if text:
            for finding in detect_pii(text, custom_keywords):
                item = finding.to_dict()
                item["segment"] = segment
                findings.append(item)

    text_bundle = "\n".join(value for _, value in segments)
    try:
        verification = check_answer(
            answer, sources, policy.version, get_verification_cache(),
            custom_sensitive_keywords=custom_keywords,
        )
        checks_ok = True
        check_error = None
    except (TypeError, ValueError) as error:
        # Invalid inputs fail closed and remain visible to the user.
        verification = {
            "claims": [], "errors": [f"Required evidence check could not run ({type(error).__name__})."],
            "unsupported_count": 0, "needs_review_count": 1, "supported_count": 0,
            "overall": "needs_review", "source_count": 0,
        }
        checks_ok = False
        check_error = type(error).__name__

    if is_incomplete_output(answer):
        if not any("incomplete" in item.lower() for item in verification["errors"]):
            verification["errors"].append("Answer appears empty or incomplete.")
        verification["needs_review_count"] = max(verification["needs_review_count"], 1)
        verification["overall"] = "needs_review"

    route = route_request(text_bundle, findings, verification, policy, required_checks_ok=checks_ok)
    checks = _audit_checks(findings, verification)
    if check_error:
        checks["failure"] = check_error
    latency_ms = (time.perf_counter_ns() - started) / 1_000_000
    fingerprint = get_fingerprint(
        get_store(),
        "\0".join([request_text, answer, sources]),
    )
    store = get_store()
    request_id = store.record_request(
        fingerprint, policy.version, route, checks, latency_ms,
        error_status=check_error or "ok",
    )
    review_id = None
    if route["requires_review"] and allow_review_persistence:
        evidence = [
            {key: claim.get(key) for key in ("claim", "status", "evidence", "source_id", "reason")}
            for claim in verification["claims"]
        ]
        safe_reasons = [
            redact_text(reason, detect_pii(reason, custom_keywords))
            for reason in route["reasons"]
        ]
        review_id = store.enqueue_review(
            request_id, route["level"], safe_reasons, answer, evidence, findings, checks,
            actions=route["actions"],
        )
    return {
        "request_id": request_id, "review_id": review_id, "findings": findings,
        "verification": verification, "route": route, "latency_ms": latency_ms,
        "request_text": request_text, "answer": answer, "sources": sources,
    }


def render_overview() -> None:
    store = get_store()
    requests = store.get_requests()
    reviews = store.get_reviews()
    events = store.get_events()
    pending = sum(item["status"] == "pending" for item in reviews)
    risk_count = sum(item["risk_level"] in {"HIGH", "UNCERTAIN", "BLOCKED"} for item in requests)
    median_latency = statistics.median([row["latency_ms"] for row in requests]) if requests else None

    st.title("TrustLayer AI")
    st.caption("A local-first privacy, reliability, and governance layer for existing AI workflows.")
    st.warning("Local demo only · No external AI provider is configured or called. Detection and verification are imperfect.")
    with st.container(horizontal=True):
        st.metric("Processed requests", len(requests), border=True)
        st.metric("Pending human reviews", pending, border=True)
        st.metric("Elevated / blocked", risk_count, border=True)
        st.metric("Median processing time", f"{median_latency:.2f} ms" if median_latency is not None else "Not evaluated", border=True)

    left, right = st.columns(2)
    with left, st.container(border=True):
        st.subheader("Risk routing")
        if requests:
            counts = Counter(row["risk_level"] for row in requests)
            chart = pd.DataFrame(
                [{"Risk level": name, "Requests": counts.get(name, 0)} for name in ("LOW", "MEDIUM", "HIGH", "UNCERTAIN", "BLOCKED")]
            )
            st.bar_chart(chart, x="Risk level", y="Requests")
        else:
            st.info("Process a request to populate risk metrics. No demo results are preloaded.")
    with right, st.container(border=True):
        st.subheader("Review queue")
        if reviews:
            review_counts = Counter(item["status"] for item in reviews)
            st.dataframe(pd.DataFrame(
                [{"Status": status.replace("_", " ").title(), "Items": review_counts.get(status, 0)}
                 for status in ("pending", "approved", "rejected", "revision_requested")]
            ), hide_index=True)
        else:
            st.info("No review items have been saved.")

    st.subheader("Recent request records")
    if requests:
        st.dataframe(pd.DataFrame([
            {
                "Request": item["request_id"][:8], "Timestamp": item["timestamp"],
                "Risk": item["risk_level"], "Latency (ms)": round(item["latency_ms"], 2),
                "Policy": item["policy_version"], "Status": item["error_status"],
            }
            for item in requests[:10]
        ]), hide_index=True)
    else:
        st.caption("Request records contain fingerprints and check metadata, not raw request text.")
    st.caption(f"{len(events)} audit events are currently stored. See Audit trail to export and verify the chain.")


def render_privacy() -> None:
    store = get_store()
    custom_keywords = get_custom_keywords(store)
    st.title("Privacy shield")
    st.caption("Scan and sanitize locally before information is copied into another workflow.")
    st.warning("Pattern detection is heuristic and incomplete. No text leaves this app; no external provider is configured.")
    uploaded = st.file_uploader(
        "Optional text document", type=["txt", "md", "csv", "json"], key="privacy_upload",
        help="UTF-8 TXT, Markdown, CSV, or JSON; up to 2 MiB. The upload is processed in memory and not saved.",
    )
    text = st.text_area("Text to scan", height=220, max_chars=MAX_TEXT_CHARS, key="privacy_text")
    mode = st.radio("Sanitization style", ["Redact with type labels", "Mask detected spans"], horizontal=True)
    scan = st.button("Scan and sanitize", type="primary", icon=":material/shield:", key="privacy_scan")
    if scan:
        try:
            if uploaded is not None:
                text = read_text_upload(uploaded.name, uploaded.getvalue())
            if not text.strip():
                st.error("Enter text or choose a supported document before scanning.")
            else:
                findings = detect_pii(text, custom_keywords)
                sanitized = redact_text(text, findings, "mask" if mode.startswith("Mask") else "redact")
                st.session_state["privacy_result"] = {
                    "original": text, "sanitized": sanitized,
                    "findings": [item.to_dict() for item in findings],
                }
        except (ValueError, TypeError) as error:
            st.error(str(error))

    result = st.session_state.get("privacy_result")
    if result:
        st.subheader("Scan results")
        if result["findings"]:
            st.dataframe(pd.DataFrame([
                {"Type": item["kind"], "Detected span": item["value"], "Start": item["start"], "End": item["end"]}
                for item in result["findings"]
            ]), hide_index=True)
            st.caption("Detected spans are displayed only in this local browser session. Detection is not exhaustive.")
        else:
            st.success("No configured pattern matched. This does not prove that the text contains no sensitive data.")
        with st.container(border=True):
            st.subheader("Sanitized preview")
            st.text_area("Sanitized text", value=result["sanitized"], height=180, key="privacy_sanitized")
        with st.expander("Compare original and sanitized text locally"):
            left, right = st.columns(2)
            left.text_area("Original (local session only)", value=result["original"], height=220, key="privacy_original")
            right.text_area("Sanitized version", value=result["sanitized"], height=220, key="privacy_compare")
    else:
        st.info("No scan has been run in this session yet.")


def render_verification() -> None:
    store = get_store()
    policy = get_policy(store)
    custom_keywords = get_custom_keywords(store)
    st.title("Output verification")
    st.caption("Compare a proposed answer with supplied sources, then explain the routing decision.")
    st.warning("Sources and answers are treated as untrusted data; document instructions are never executed. Evidence matching is lexical, not a factuality guarantee. No external model call is made.")
    with st.form("verification_form"):
        request_text = st.text_area("Original request or context (optional)", height=100)
        answer = st.text_area("Proposed AI answer", height=150)
        sources = st.text_area(
            "Supporting source text (separate documents with a blank line)", height=200,
            help="Source locations are labeled S1, S2, and so on by document paragraph.",
        )
        consent = st.checkbox(
            "I consent to store this answer and its evidence locally if the policy routes it for review.",
            value=False,
        )
        submitted = st.form_submit_button("Verify and route", type="primary", icon=":material/fact_check:")
    if submitted:
        if not answer.strip():
            st.error("A proposed answer is required.")
        elif len(answer) > 50_000 or len(sources) > 100_000 or len(request_text) > MAX_TEXT_CHARS:
            st.error("Input exceeds a processing limit. Shorten the request, answer, or source text.")
        else:
            result = _process_request(
                request_text, answer, sources, policy, custom_keywords, consent,
            )
            st.session_state["last_pipeline"] = result
            st.success(
                f"Processed request `{result['request_id']}` in {result['latency_ms']:.2f} ms. "
                "Only a keyed fingerprint and check metadata were added to the audit trail."
            )
            if result["route"]["requires_review"]:
                if result["review_id"]:
                    st.info(f"Review content was saved with consent. Review ID: `{result['review_id']}`")
                else:
                    st.warning("Review is required, but private review content was not saved because consent was not given.")

    result = st.session_state.get("last_pipeline")
    if result:
        st.divider()
        st.subheader("Explainable routing")
        _render_route(result["route"])
        left, right = st.columns(2)
        with left:
            st.markdown("**Privacy scan**")
            if result["findings"]:
                st.dataframe(pd.DataFrame([
                    {"Segment": item["segment"], "Type": item["kind"], "Detected span": item["value"]}
                    for item in result["findings"]
                ]), hide_index=True)
            else:
                st.success("No configured pattern matched; this is not a guarantee of privacy.")
        with right:
            st.markdown("**Reliability result**")
            st.markdown(f"Overall: **{result['verification']['overall'].replace('_', ' ').title()}**")
            st.caption(
                f"{result['verification']['supported_count']} supported-pattern match(es), "
                f"{result['verification']['unsupported_count']} unsupported/contradicted, "
                f"{result['verification']['needs_review_count']} needing review."
            )
        if result["verification"]["errors"]:
            for error in result["verification"]["errors"]:
                st.warning(error)
        st.caption(f"Inline citation status: {result['verification']['citation_status']}.")
        if result["verification"]["claims"]:
            st.subheader("Claim-by-claim evidence")
            for index, claim in enumerate(result["verification"]["claims"], start=1):
                with st.container(border=True):
                    st.markdown(f"**Claim {index}:** {claim['claim']}")
                    st.markdown(f"**Status:** `{claim['status'].replace('_', ' ').upper()}` · {claim['reason']}")
                    if claim.get("source_id"):
                        st.caption(f"Source location: {claim['source_id']}")
                    if claim.get("evidence"):
                        st.text(f"Evidence: {claim['evidence']}")
                    else:
                        st.caption("No evidence passage was identified.")
        with st.expander("Sanitized text preview"):
            for segment, label in (
                ("request_text", "Request"), ("answer", "Answer"), ("sources", "Sources"),
            ):
                content = result[segment]
                safe = redact_text(content, detect_pii(content, custom_keywords)) if content else content
                st.text_area(label, value=safe, height=120, key=f"safe_{result['request_id']}_{segment}")


def render_risk_engine() -> None:
    store = get_store()
    current = get_policy(store)
    st.title("Risk engine")
    st.caption("Configure thresholds and explainable routing rules; thresholds are policy choices, not universal scores.")
    st.warning("Privacy and evidence checks are required in this demo. If a required check fails, processing is blocked.")
    with st.form("risk_policy_form"):
        low = st.slider("Medium-risk score threshold", min_value=0, max_value=99, value=current.low_threshold)
        high = st.slider("High-risk score threshold", min_value=1, max_value=100, value=current.high_threshold)
        block_ssn = st.checkbox("Block on detected SSN pattern", value=current.block_on_ssn)
        review_high = st.checkbox("Require human review for high risk", value=current.review_high)
        terms_text = st.text_area(
            "High-impact terms (comma separated)", value=", ".join(current.high_impact_terms), height=90,
        )
        custom_text = st.text_area(
            "Additional sensitive keywords (comma separated; literal words, not regular expressions)",
            value=", ".join(get_custom_keywords(store)), height=80,
        )
        saved = st.form_submit_button("Save policy", type="primary")
    if saved:
        try:
            next_policy = RiskPolicy(
                version=str(int(current.version) + 1) if current.version.isdigit() else f"{current.version}-next",
                low_threshold=low, high_threshold=high, block_on_ssn=block_ssn,
                review_high=review_high,
                high_impact_terms=[term.strip() for term in terms_text.split(",") if term.strip()],
            )
            next_policy.validate()
            keywords = [term.strip() for term in custom_text.split(",") if term.strip()]
            if len(keywords) > 100 or any(len(term) > 80 for term in keywords):
                raise ValueError("Use at most 100 custom keywords, each no longer than 80 characters.")
            store.set_setting("risk_policy", next_policy.to_dict())
            store.set_setting("custom_sensitive_keywords", keywords)
            store.append_event("policy_updated", {
                "policy_version": next_policy.version, "low_threshold": low,
                "high_threshold": high, "block_on_ssn": block_ssn,
                "review_high": review_high, "high_impact_term_count": len(next_policy.high_impact_terms),
                "custom_keyword_count": len(keywords),
            })
            get_verification_cache().clear()
            st.success(f"Saved policy version {next_policy.version}. Verification cache cleared.")
            current = next_policy
        except ValueError as error:
            st.error(str(error))
    with st.container(border=True):
        st.subheader("Active decision logic")
        st.markdown(
            f"- Low: score below {current.low_threshold}.\n"
            f"- Medium: score at or above {current.low_threshold}; human review is required for unsupported claims.\n"
            f"- High: score at or above {current.high_threshold}; review follows the configured rule.\n"
            "- Uncertain: missing or inconclusive evidence routes conservatively to review.\n"
            f"- Blocked: a required check fails, or an SSN matches while the configured block rule is on.\n"
            "- Points: email/phone +12, contextual name +8, SSN +60, each unsupported claim +30 (capped), "
            "inconclusive evidence +25, configured high-impact terms +35. These are configurable-policy "
            "heuristics, not validated risk probabilities."
        )
        st.caption(f"Current policy version: {current.version}")


def render_review() -> None:
    store = get_store()
    custom_keywords = get_custom_keywords(store)
    st.title("Human review")
    st.warning("Local demo reviewer only; no authentication or role-based access is configured. Approval is a workflow decision, not proof of correctness.")
    status = st.selectbox("Filter by status", ["all", "pending", "approved", "rejected", "revision_requested"])
    reviews = store.get_reviews(status)
    if not reviews:
        st.info("No saved review items match this filter. Review content is stored only when the submitter opted in.")
        return
    for item in reviews:
        with st.container(border=True):
            st.markdown(f"**{item['risk_level']}** · `{item['status'].replace('_', ' ').title()}`")
            st.caption(f"Review `{item['review_id']}` · Request `{item['request_id']}` · {item['created_at']}")
            st.markdown("**Routing reasons**")
            for reason in item["reasons"]:
                st.markdown(f"- {reason}")
            st.markdown("**Suggested next action**")
            for action in item["actions"]:
                st.markdown(f"- {action}")
            st.markdown("**Proposed answer**")
            st.text(item["answer"])
            if item["evidence"]:
                st.markdown("**Evidence and checks**")
                st.dataframe(pd.DataFrame(item["evidence"]), hide_index=True)
            if item["findings"]:
                st.caption("Privacy findings were detected. Original spans are kept in this local review record only.")
                st.dataframe(pd.DataFrame([
                    {"Segment": hit.get("segment"), "Type": hit["kind"],
                     "Sanitized span": redact_text(
                         hit["value"], detect_pii(hit["value"], custom_keywords),
                     )}
                    for hit in item["findings"]
                ]), hide_index=True)
            with st.expander("Check results and evidence references"):
                st.json(item["checks"])
            if item["decision_reason"]:
                st.markdown(f"**Decision reason:** {item['decision_reason']}")
            if item["status"] == "pending":
                with st.form(f"review_{item['review_id']}"):
                    decision_reason = st.text_area(
                        "Required decision reason", key=f"reason_{item['review_id']}", max_chars=2000,
                    )
                    decision = st.selectbox(
                        "Decision", ["approved", "rejected", "revision_requested"],
                        key=f"decision_{item['review_id']}",
                    )
                    submit = st.form_submit_button("Record decision")
                if submit:
                    if not decision_reason.strip():
                        st.error("Enter a reason before recording this decision.")
                    else:
                        try:
                            store.decide_review(item["review_id"], decision, decision_reason)
                            st.success("Decision saved to the review record and audit trail.")
                            st.rerun()
                        except (KeyError, ValueError) as error:
                            st.error(str(error))


def _display_metric(metric: dict[str, Any], label: str) -> None:
    st.markdown(f"**{label}**")
    st.caption(metric["method"])
    if metric["positive_support"] == 0:
        st.info("Not evaluated: dataset has no positive examples for this class.")
    elif metric["negative_support"] == 0:
        st.info("Not evaluated: dataset has no negative examples for this class.")
    else:
        st.dataframe(pd.DataFrame([{
            "n": metric["n"], "TP": metric["tp"], "TN": metric["tn"], "FP": metric["fp"], "FN": metric["fn"],
            "Precision": metric["precision"], "Recall": metric["recall"], "F1": metric["f1"],
        }]), hide_index=True)


def render_quality_lab() -> None:
    store = get_store()
    st.title("Model quality lab")
    st.caption("Evaluate actual labeled rows. The bundled fixture contains synthetic, documented examples.")
    st.warning("This local deterministic pipeline is not a production AI model benchmark. No labels or metrics are fabricated; upload labels or use the included synthetic fixture.")
    upload = st.file_uploader("Optional labeled evaluation CSV", type=["csv"], key="quality_csv")
    st.download_button(
        "Download synthetic sample dataset",
        data=(PROJECT_DIR / "data" / "sample_cases.csv").read_bytes(),
        file_name="trustlayer_sample_cases.csv", mime="text/csv",
    )
    st.caption("Required CSV columns: case_id, scenario, text, answer, sources, expected_pii, expected_unsupported. Labels accept true/false or 1/0.")
    if st.button("Run baseline vs TrustLayer benchmark", type="primary", icon=":material/science:"):
        try:
            cases = parse_uploaded_csv(upload.name, upload.getvalue()) if upload is not None else load_sample_cases()
            report = run_benchmark(cases, get_policy(store))
            store.save_test_run(report)
            st.session_state["benchmark_report"] = report
            st.success(f"Measured {report['dataset_size']} labeled cases in this process.")
        except (ValueError, UnicodeError, OSError) as error:
            st.error(str(error))
    report = st.session_state.get("benchmark_report")
    if not report:
        previous = store.get_test_runs()
        if previous:
            st.subheader("Previous evaluation runs")
            st.dataframe(pd.DataFrame([
                {"Run": item["run_id"][:8], "Timestamp": item["created_at"],
                 "Cases": item["summary"]["dataset_size"]}
                for item in previous[:10]
            ]), hide_index=True)
        else:
            st.info("Run a benchmark to display measured metrics. No results are preloaded.")
        return

    st.subheader("Measured comparison")
    st.markdown(f"**Dataset:** {report['dataset_size']} labeled cases. **Conditions:** {report['conditions']['timing']}")
    st.markdown(f"**Baseline:** {report['conditions']['baseline']}")
    st.markdown(f"**TrustLayer:** {report['conditions']['trustlayer']}")
    for label, result in (("Baseline", report["baseline"]), ("TrustLayer", report["trustlayer"])):
        st.markdown(f"### {label}")
        with st.container(horizontal=True):
            st.metric("Total latency", f"{result['latency']['total_ms']:.3f} ms", border=True)
            st.metric("Median / p95", f"{result['latency']['median_ms']:.3f} / {result['latency']['p95_ms']:.3f} ms", border=True)
            st.metric("Throughput", f"{result['latency']['cases_per_second']:.1f} cases/s", border=True)
            st.metric(
                "Review routing",
                f"{result.get('review_cases', 0)} ({result.get('review_rate', 0.0):.1%})",
                border=True,
            )
        _display_metric(result["privacy"], "Privacy detection")
        _display_metric(result["unsupported"], "Unsupported-claim detection")
    st.markdown("### Case-level outcomes")
    st.dataframe(pd.DataFrame(report["case_results"]), hide_index=True)
    st.warning(report["conditions"]["caveat"])
    st.caption("Latency includes the measured case processing only, not app startup or database writes. Timings vary by machine and cache state.")


def render_audit() -> None:
    store = get_store()
    st.title("Audit trail")
    st.caption("Metadata-only records with a SHA-256 hash-linked integrity check. This is tamper-evident, not tamper-proof.")
    events = store.get_events(limit=10_000)
    event_types = sorted({item["event_type"] for item in events})
    selected_type = st.selectbox("Event type", ["all", *event_types])
    search = st.text_input("Filter by event or request ID", max_chars=80)
    filtered = [
        event for event in events
        if (selected_type == "all" or event["event_type"] == selected_type)
        and (not search.strip() or search.casefold() in event["event_id"].casefold()
             or search.casefold() in json.dumps(event["payload"], ensure_ascii=False).casefold())
    ]
    st.caption(f"Showing {len(filtered)} of {len(events)} stored events.")
    check_col, json_col, csv_col = st.columns(3)
    if check_col.button("Verify audit integrity", icon=":material/verified_user:"):
        st.session_state["audit_integrity"] = store.verify_chain()
    integrity = st.session_state.get("audit_integrity")
    if integrity:
        if integrity["valid"]:
            st.success(f"Verified {integrity['checked']} audit event(s). {integrity['reason']}")
        else:
            st.error(
                f"Integrity check failed at sequence {integrity['failure_sequence']} "
                f"after {integrity['checked']} event(s): {integrity['reason']}"
            )
    json_col.download_button(
        "Export filtered JSON", data=export_events_json(filtered), file_name="trustlayer_audit.json",
        mime="application/json",
    )
    csv_col.download_button(
        "Export filtered CSV", data=export_events_csv(filtered), file_name="trustlayer_audit.csv",
        mime="text/csv",
    )
    if filtered:
        st.dataframe(pd.DataFrame([
            {"Sequence": item["sequence"], "Timestamp": item["timestamp"], "Type": item["event_type"],
             "Event ID": item["event_id"], "Previous hash": item["previous_hash"][:16] + "…",
             "Hash": item["event_hash"][:16] + "…"}
            for item in filtered
        ]), hide_index=True)
        with st.expander("View safe event metadata"):
            selected = st.selectbox("Select event", [item["event_id"] for item in filtered])
            st.json(next(item for item in filtered if item["event_id"] == selected))
    else:
        st.info("No events match the current filter.")
    st.info("Audit events contain a keyed input fingerprint and metadata, not raw answer text or source passages.")


def render_governance() -> None:
    store = get_store()
    st.title("Governance settings")
    st.caption("Local retention, integration inventory, evaluation history, and incident tracking.")
    policy = get_policy(store)
    retention_days = int(store.get_setting("retention_days", 90))
    with st.container(border=True):
        st.subheader("Data inventory")
        st.dataframe(pd.DataFrame([
            {"Source": "User-entered text / uploaded UTF-8 text", "Purpose": "Local privacy scan and evidence verification", "Sensitivity": "Potentially sensitive", "Retention": "Session only unless explicit review consent"},
            {"Source": "SQLite request and audit metadata", "Purpose": "Routing traceability and integrity checks", "Sensitivity": "Pseudonymous fingerprint and metadata", "Retention": "Until local deletion"},
            {"Source": "Opt-in human review records", "Purpose": "Reviewer decision workflow", "Sensitivity": "May contain personal or private output", "Retention": f"{retention_days} days for review content"},
            {"Source": "Synthetic labeled CSV fixture", "Purpose": "Reproducible evaluation", "Sensitivity": "Synthetic; no real personal data", "Retention": "Bundled with project"},
        ]), hide_index=True)
    st.subheader("Configured integrations")
    st.dataframe(pd.DataFrame([
        {"Provider": "Local deterministic privacy + evidence checks", "Status": "Available", "Version": "TrustLayer 0.1.0"},
        {"Provider": "Microsoft Presidio", "Status": "Not configured", "Version": "Optional; fallback patterns are active"},
        {"Provider": "Sentence Transformers", "Status": "Not configured", "Version": "Lexical retrieval is active; no model download"},
        {"Provider": "External AI APIs", "Status": "Disabled / no credentials", "Version": "No external calls are implemented"},
    ]), hide_index=True)
    requests = store.get_requests()
    reviews = store.get_reviews()
    incidents = store.get_incidents()
    pending_reviews = sum(item["status"] == "pending" for item in reviews)
    elevated_requests = sum(item["risk_level"] in {"HIGH", "UNCERTAIN", "BLOCKED"} for item in requests)
    open_incidents = sum(item["status"] != "resolved" for item in incidents)
    with st.container(horizontal=True):
        st.metric("Review backlog", pending_reviews, border=True)
        st.metric("Elevated / blocked requests", elevated_requests, border=True)
        st.metric("Open incidents", open_incidents, border=True)
    st.caption(f"Active policy version: {policy.version}. Test runs: {len(store.get_test_runs())}.")
    st.caption("Drift is not evaluated: no separate, documented baseline and current production datasets are configured.")

    st.subheader("Review-content retention")
    with st.form("retention_form"):
        days = st.number_input("Retain opt-in review content for days", min_value=1, max_value=3650, value=retention_days)
        purge = st.form_submit_button("Save retention and purge expired review content")
    if purge:
        store.set_setting("retention_days", int(days))
        deleted = store.purge_expired_review_content(int(days))
        st.success(f"Saved {int(days)}-day retention. Removed {deleted} expired review record(s).")
        if deleted:
            store.append_event("review_content_purged", {"deleted_count": deleted, "retention_days": int(days)})

    st.subheader("Incident records")
    with st.form("incident_create"):
        severity = st.selectbox("Incident severity", ["low", "medium", "high", "critical"])
        description = st.text_area("Incident description (avoid unnecessary personal data)")
        owner = st.text_input("Owner")
        add_incident = st.form_submit_button("Create incident")
    if add_incident:
        try:
            incident_id = store.create_incident(severity, description, owner)
            st.success(f"Created incident `{incident_id}`.")
        except ValueError as error:
            st.error(str(error))
    for incident in store.get_incidents():
        with st.container(border=True):
            st.markdown(f"**{incident['severity'].upper()}** · {incident['status']} · `{incident['incident_id']}`")
            st.write(incident["description"])
            with st.form(f"incident_{incident['incident_id']}"):
                incident_status = st.selectbox(
                    "Status", ["open", "investigating", "resolved"],
                    index=["open", "investigating", "resolved"].index(incident["status"]),
                )
                incident_owner = st.text_input("Owner", value=incident["owner"])
                notes = st.text_area("Resolution notes", value=incident["resolution_notes"])
                update = st.form_submit_button("Update incident")
            if update:
                try:
                    store.update_incident(incident["incident_id"], incident_status, notes, incident_owner)
                    st.success("Incident updated.")
                    st.rerun()
                except (KeyError, ValueError) as error:
                    st.error(str(error))

    st.divider()
    st.subheader("Delete local data")
    st.warning("This irreversibly deletes this demo's local requests, review content, audit chain, incidents, settings, and test history.")
    confirm = st.checkbox("I understand and want to delete all local TrustLayer records.")
    if st.button("Delete all local records", disabled=not confirm, type="secondary"):
        store.delete_all_local_records()
        get_verification_cache().clear()
        st.session_state.clear()
        st.success("Local data was deleted. The audit chain was deleted as part of this reset.")
        st.rerun()


def main() -> None:
    st.set_page_config(
        page_title="TrustLayer AI",
        page_icon=":material/shield_with_heart:",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    st.sidebar.title("TrustLayer AI")
    st.sidebar.caption("Privacy · Reliability · Governance")
    st.sidebar.info("Local demo. No external AI provider is configured.")
    pages = [
        st.Page(render_overview, title="Overview", icon=":material/dashboard:", default=True),
        st.Page(render_privacy, title="Privacy shield", icon=":material/shield:"),
        st.Page(render_verification, title="Output verification", icon=":material/fact_check:"),
        st.Page(render_risk_engine, title="Risk engine", icon=":material/tune:"),
        st.Page(render_review, title="Human review", icon=":material/rate_review:"),
        st.Page(render_quality_lab, title="Model quality lab", icon=":material/science:"),
        st.Page(render_audit, title="Audit trail", icon=":material/receipt_long:"),
        st.Page(render_governance, title="Governance settings", icon=":material/admin_panel_settings:"),
    ]
    page = st.navigation(pages, position="sidebar")
    page.run()


if __name__ == "__main__":
    main()
