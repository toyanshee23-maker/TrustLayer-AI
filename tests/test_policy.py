from trustlayer.policy import RiskPolicy, route_request


def good_verification():
    return {
        "unsupported_count": 0, "needs_review_count": 0, "errors": [],
        "source_count": 1,
    }


def test_low_medium_and_high_threshold_routing():
    policy = RiskPolicy(low_threshold=30, high_threshold=65, high_impact_terms=[])
    low = route_request("ordinary content", [], good_verification(), policy)
    medium = route_request(
        "ordinary content", [], {**good_verification(), "unsupported_count": 1}, policy,
    )
    high = route_request(
        "ordinary content", [], {**good_verification(), "unsupported_count": 3}, policy,
    )
    assert low["level"] == "LOW"
    assert medium["level"] == "MEDIUM" and medium["requires_review"]
    assert high["level"] == "HIGH" and high["requires_review"]


def test_uncertainty_and_critical_privacy_rule_route_conservatively():
    policy = RiskPolicy()
    uncertain = route_request(
        "ordinary", [], {"unsupported_count": 0, "needs_review_count": 1, "errors": [], "source_count": 1}, policy,
    )
    blocked = route_request(
        "ordinary", [{"kind": "ssn"}], good_verification(), policy,
    )
    assert uncertain["level"] == "UNCERTAIN" and uncertain["requires_review"]
    assert blocked["level"] == "BLOCKED" and blocked["blocked"]


def test_required_safety_check_failure_fails_closed():
    result = route_request("ordinary", [], good_verification(), RiskPolicy(), required_checks_ok=False)
    assert result["level"] == "BLOCKED"
    assert result["blocked"]


def test_invalid_thresholds_are_rejected():
    policy = RiskPolicy(low_threshold=70, high_threshold=50)
    try:
        policy.validate()
    except ValueError as error:
        assert "thresholds" in str(error)
    else:
        raise AssertionError("Invalid thresholds were accepted.")
