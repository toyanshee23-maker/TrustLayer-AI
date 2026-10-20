"""Reproducible labeled-sample metrics and measured baseline comparison."""

from __future__ import annotations

import csv
from functools import lru_cache
import io
from pathlib import Path
import re
import statistics
import time
from typing import Any, Iterable

from .policy import RiskPolicy, route_request
from .privacy import MAX_UPLOAD_BYTES, detect_pii, read_text_upload
from .verification import check_answer, clear_token_cache

SAMPLE_PATH = Path(__file__).resolve().parent.parent / "data" / "sample_cases.csv"
REQUIRED_COLUMNS = {
    "case_id", "scenario", "text", "answer", "sources", "expected_pii", "expected_unsupported",
}


@lru_cache(maxsize=1)
def _read_sample_bytes() -> bytes:
    return SAMPLE_PATH.read_bytes()


def load_sample_cases() -> list[dict[str, Any]]:
    reader = csv.DictReader(_read_sample_bytes().decode("utf-8").splitlines())
    validate_columns(reader.fieldnames or [])
    cases = []
    for row in reader:
        cases.append({
            **row,
            "expected_pii": parse_label(row.get("expected_pii", "")),
            "expected_unsupported": parse_label(row.get("expected_unsupported", "")),
        })
    validate_cases(cases)
    return cases


def parse_label(value: str) -> bool:
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes"}:
        return True
    if normalized in {"0", "false", "no"}:
        return False
    raise ValueError(f"Invalid binary label: {value!r}.")


def validate_columns(columns: Iterable[str]) -> None:
    missing = REQUIRED_COLUMNS - set(columns)
    if missing:
        raise ValueError("CSV is missing required columns: " + ", ".join(sorted(missing)))


def validate_cases(cases: list[dict[str, Any]]) -> None:
    if not cases:
        raise ValueError("The evaluation dataset contains no rows.")
    if len(cases) > 10_000:
        raise ValueError("At most 10,000 evaluation rows are supported.")
    for index, case in enumerate(cases, start=1):
        for key in ("case_id", "scenario", "text", "answer", "sources"):
            if not isinstance(case.get(key), str) or len(case[key]) > 100_000:
                raise ValueError(f"Row {index} has a missing, malformed, or oversized '{key}' value.")
        for key in ("expected_pii", "expected_unsupported"):
            if not isinstance(case.get(key), bool):
                raise ValueError(f"Row {index} has an invalid '{key}' label.")


def parse_uploaded_csv(name: str, data: bytes) -> list[dict[str, Any]]:
    if not name.lower().endswith(".csv"):
        raise ValueError("Evaluation uploads must be CSV files.")
    content = read_text_upload(name, data, MAX_UPLOAD_BYTES)
    try:
        reader = csv.DictReader(io.StringIO(content, newline=""), strict=True)
        validate_columns(reader.fieldnames or [])
        if len(reader.fieldnames or []) != len(set(reader.fieldnames or [])):
            raise ValueError("CSV contains duplicate column names.")
        cases: list[dict[str, Any]] = []
        for row in reader:
            if None in row:
                raise ValueError("CSV row contains more values than the header.")
            normalized = {key: row.get(key, "") for key in REQUIRED_COLUMNS}
            normalized["expected_pii"] = parse_label(normalized["expected_pii"])
            normalized["expected_unsupported"] = parse_label(normalized["expected_unsupported"])
            cases.append(normalized)
        validate_cases(cases)
        return cases
    except csv.Error as error:
        raise ValueError(f"Malformed CSV: {error}") from error


def classification_metrics(expected: list[bool], predicted: list[bool]) -> dict[str, Any]:
    if len(expected) != len(predicted) or not expected:
        raise ValueError("Expected and predicted labels must have the same non-zero length.")
    tp = sum(actual and prediction for actual, prediction in zip(expected, predicted))
    tn = sum(not actual and not prediction for actual, prediction in zip(expected, predicted))
    fp = sum(not actual and prediction for actual, prediction in zip(expected, predicted))
    fn = sum(actual and not prediction for actual, prediction in zip(expected, predicted))
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (2 * precision * recall / (precision + recall)) if precision is not None and recall is not None and precision + recall else None
    return {
        "positive_class": True, "method": "Per-case binary classification; positive means the labeled issue is present.",
        "n": len(expected), "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "precision": precision, "recall": recall, "f1": f1,
        "positive_support": sum(expected), "negative_support": len(expected) - sum(expected),
    }


def _baseline_case(case: dict[str, Any]) -> tuple[bool, bool]:
    """Minimal baseline: email regex plus token-overlap support heuristic."""
    email_only = re.search(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b", case["text"]) is not None
    answer_terms = {word.lower() for word in re.findall(r"[a-zA-Z0-9]+", case["answer"]) if len(word) > 2}
    source_terms = {word.lower() for word in re.findall(r"[a-zA-Z0-9]+", case["sources"]) if len(word) > 2}
    overlap = len(answer_terms & source_terms) / max(len(answer_terms), 1)
    unsupported = not answer_terms or not source_terms or overlap < 0.2
    return email_only, unsupported


def _measure(function: Any, cases: list[dict[str, Any]]) -> tuple[list[Any], list[float]]:
    results, latencies = [], []
    for case in cases:
        started = time.perf_counter_ns()
        results.append(function(case))
        latencies.append((time.perf_counter_ns() - started) / 1_000_000)
    return results, latencies


def _latency_summary(latencies: list[float]) -> dict[str, float]:
    ordered = sorted(latencies)
    p95_index = max(0, min(len(ordered) - 1, int(0.95 * len(ordered) + 0.999999) - 1))
    return {
        "median_ms": statistics.median(ordered),
        "p95_ms": ordered[p95_index],
        "total_ms": sum(ordered),
        "cases_per_second": len(ordered) / (sum(ordered) / 1000) if sum(ordered) else 0.0,
    }


def run_benchmark(cases: list[dict[str, Any]], policy: RiskPolicy | None = None) -> dict[str, Any]:
    validate_cases(cases)
    clear_token_cache()
    active_policy = policy or RiskPolicy()

    baseline_results, baseline_times = _measure(_baseline_case, cases)

    def enhanced_case(case: dict[str, Any]) -> dict[str, Any]:
        findings = detect_pii(case["text"])
        verification = check_answer(case["answer"], case["sources"], active_policy.version)
        route = route_request(case["text"], [finding.to_dict() for finding in findings], verification, active_policy)
        return {"findings": findings, "verification": verification, "route": route}

    enhanced_results, enhanced_times = _measure(enhanced_case, cases)
    expected_pii = [case["expected_pii"] for case in cases]
    expected_unsupported = [case["expected_unsupported"] for case in cases]
    baseline_pii = [result[0] for result in baseline_results]
    baseline_unsupported = [result[1] for result in baseline_results]
    enhanced_pii = [bool(result["findings"]) for result in enhanced_results]
    enhanced_unsupported = [
        result["verification"]["unsupported_count"] > 0 for result in enhanced_results
    ]
    enhanced_review = [
        result["route"]["requires_review"] or result["route"]["blocked"] for result in enhanced_results
    ]
    return {
        "dataset_size": len(cases),
        "conditions": {
            "baseline": "Email-only regex and a simple 20% answer/source token-overlap heuristic.",
            "trustlayer": "Local PII patterns, claim-to-passage lexical evidence checks, contradiction checks, and configurable routing.",
            "timing": "Measured with time.perf_counter_ns() per case in this process; no external model calls.",
            "caveat": "Synthetic fixture labels are illustrative, not a production validation set. Semantic overlap is not factual proof.",
        },
        "baseline": {
            "privacy": classification_metrics(expected_pii, baseline_pii),
            "unsupported": classification_metrics(expected_unsupported, baseline_unsupported),
            "latency": _latency_summary(baseline_times),
            "review_cases": 0,
        },
        "trustlayer": {
            "privacy": classification_metrics(expected_pii, enhanced_pii),
            "unsupported": classification_metrics(expected_unsupported, enhanced_unsupported),
            "latency": _latency_summary(enhanced_times),
            "review_cases": sum(enhanced_review),
            "review_rate": sum(enhanced_review) / len(cases),
            "risk_counts": {
                level: sum(result["route"]["level"] == level for result in enhanced_results)
                for level in ("LOW", "MEDIUM", "HIGH", "UNCERTAIN", "BLOCKED")
            },
        },
        "case_results": [
            {
                "case_id": case["case_id"], "scenario": case["scenario"],
                "expected_pii": case["expected_pii"], "baseline_pii": baseline_pii[index],
                "trustlayer_pii": enhanced_pii[index],
                "expected_unsupported": case["expected_unsupported"],
                "baseline_unsupported": baseline_unsupported[index],
                "trustlayer_unsupported": enhanced_unsupported[index],
                "risk": enhanced_results[index]["route"]["level"],
            }
            for index, case in enumerate(cases)
        ],
    }
