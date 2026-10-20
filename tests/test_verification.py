from trustlayer.verification import (
    VerificationCache,
    _tokens,
    check_answer,
)


def test_supported_claim_is_attributed_to_source():
    result = check_answer("The policy covers remote workers. [S1]", "The policy covers remote workers.")
    assert result["claims"][0]["status"] == "supported"
    assert result["claims"][0]["source_id"] == "S1"
    assert result["citation_status"] == "present"


def test_unsupported_and_numeric_contradiction_are_not_marked_supported():
    unsupported = check_answer("Mars is made of chocolate. [S1]", "Mars is a rocky planet.")
    contradiction = check_answer("Water boils at 50 C at sea level. [S1]", "At sea level, water boils at 100 C.")
    assert unsupported["claims"][0]["status"] == "unsupported"
    assert contradiction["claims"][0]["status"] == "contradicted"
    assert contradiction["unsupported_count"] == 1


def test_missing_invalid_citations_and_empty_or_incomplete_output_are_flagged():
    missing = check_answer("The policy covers remote workers.", "The policy covers remote workers.")
    invalid = check_answer("The policy covers remote workers. [S9]", "The policy covers remote workers.")
    empty = check_answer("", "The policy covers remote workers.")
    incomplete = check_answer("The policy covers remote workers...", "The policy covers remote workers.")
    assert missing["citation_status"] == "missing"
    assert any("No inline citations" in item for item in missing["errors"])
    assert invalid["citation_status"] == "invalid"
    assert any("Invalid source reference" in item for item in invalid["errors"])
    assert empty["overall"] == "needs_review"
    assert any("empty or incomplete" in item for item in incomplete["errors"])


def test_no_source_is_uncertain_and_never_invented_as_verified():
    result = check_answer("A statement without evidence. [S1]", "")
    assert result["overall"] == "unsupported"
    assert result["source_count"] == 0


def test_custom_sensitive_keywords_skip_raw_text_caches():
    _tokens.cache_clear()
    cache = VerificationCache()
    result = check_answer(
        "AcmeSecret approved the change. [S1]",
        "AcmeSecret approved the change.",
        cache=cache,
        custom_sensitive_keywords=["AcmeSecret"],
    )
    assert result["citation_status"] == "present"
    assert cache._values == {}
    assert _tokens.cache_info().currsize == 0


def test_cache_keys_include_content_and_policy_version():
    cache = VerificationCache()
    answer = "The policy covers remote workers. [S1]"
    source = "The policy covers remote workers."
    check_answer(answer, source, "policy-1", cache)
    assert len(cache._values) == 1
    check_answer(answer, source + " It is updated yearly.", "policy-1", cache)
    check_answer(answer, source, "policy-2", cache)
    assert len(cache._values) == 3
