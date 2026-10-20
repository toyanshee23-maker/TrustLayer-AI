import pytest

from trustlayer.evaluation import (
    classification_metrics,
    load_sample_cases,
    parse_uploaded_csv,
    run_benchmark,
)
from trustlayer.policy import RiskPolicy


def test_classification_metrics_against_known_labels():
    result = classification_metrics(
        [True, True, False, False], [True, False, True, False],
    )
    assert (result["tp"], result["tn"], result["fp"], result["fn"]) == (1, 1, 1, 1)
    assert result["precision"] == 0.5
    assert result["recall"] == 0.5
    assert result["f1"] == 0.5
    assert result["positive_class"] is True


def test_sample_data_and_benchmark_are_reproducible_and_measured():
    cases = load_sample_cases()
    report = run_benchmark(cases, RiskPolicy())
    assert report["dataset_size"] == 12
    assert report["baseline"]["latency"]["total_ms"] > 0
    assert report["trustlayer"]["latency"]["total_ms"] > 0
    assert report["trustlayer"]["privacy"]["positive_support"] == 4
    assert len(report["case_results"]) == 12
    assert "synthetic" in report["conditions"]["caveat"].lower()


def test_uploaded_csv_validation_and_missing_columns():
    with pytest.raises(ValueError, match="CSV"):
        parse_uploaded_csv("data.json", b"{}")
    with pytest.raises(ValueError, match="missing required columns"):
        parse_uploaded_csv("data.csv", b"case_id,expected_pii\nA,false\n")
    with pytest.raises(ValueError, match="Malformed CSV"):
        parse_uploaded_csv("data.csv", b'case_id,scenario,text,answer,sources,expected_pii,expected_unsupported\n"unterminated')
    with pytest.raises(ValueError, match="duplicate column"):
        parse_uploaded_csv(
            "data.csv",
            b"case_id,case_id,scenario,text,answer,sources,expected_pii,expected_unsupported\n1,2,x,x,x,x,false,false\n",
        )


def test_metrics_are_not_computed_for_empty_or_mismatched_data():
    with pytest.raises(ValueError):
        classification_metrics([], [])
    with pytest.raises(ValueError):
        classification_metrics([True], [True, False])
