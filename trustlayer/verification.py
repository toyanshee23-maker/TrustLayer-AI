"""Conservative, lexical evidence checks that avoid unsupported confidence claims."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
from functools import lru_cache
import re
import threading
from typing import Any

from .privacy import detect_pii

_WORD_RE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9'-]*")
_STOPWORDS = {
    "a", "an", "and", "are", "as", "at", "be", "been", "by", "for", "from",
    "has", "have", "in", "is", "it", "of", "on", "or", "that", "the", "their",
    "this", "to", "was", "were", "with", "will",
}
_CITATION_RE = re.compile(r"\[S(\d+)\]", re.I)
_NEGATIONS = {"no", "not", "never", "without", "false", "cannot", "can't"}


@dataclass(frozen=True)
class ClaimCheck:
    claim: str
    status: str
    evidence: str | None
    source_id: str | None
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@lru_cache(maxsize=512)
def _tokens(sentence: str) -> frozenset[str]:
    """Cache only normalized non-sensitive tokens; callers avoid PII-bearing inputs."""
    return frozenset(
        word.lower().rstrip("s")
        for word in _WORD_RE.findall(sentence)
        if word.lower() not in _STOPWORDS and len(word) > 2
    )


class VerificationCache:
    """Bounded, process-local cache used only when both answer and sources are PII-free."""

    def __init__(self, max_entries: int = 128):
        self.max_entries = max_entries
        self._values: dict[tuple[str, str, str], dict[str, Any]] = {}
        self._lock = threading.Lock()

    def get(
        self, answer: str, sources: str, policy_version: str,
        custom_sensitive_keywords: tuple[str, ...] = (),
    ) -> dict[str, Any] | None:
        if detect_pii(answer, custom_sensitive_keywords) or detect_pii(sources, custom_sensitive_keywords):
            return None
        import hashlib

        key = tuple(
            hashlib.sha256(value.encode("utf-8")).hexdigest()
            for value in (answer, sources, policy_version)
        )
        with self._lock:
            value = self._values.get(key)  # type: ignore[arg-type]
            if value is not None:
                self._values.pop(key)  # type: ignore[arg-type]
                self._values[key] = value  # type: ignore[index]
            return value

    def put(
        self, answer: str, sources: str, policy_version: str, value: dict[str, Any],
        custom_sensitive_keywords: tuple[str, ...] = (),
    ) -> None:
        if detect_pii(answer, custom_sensitive_keywords) or detect_pii(sources, custom_sensitive_keywords):
            return
        import hashlib

        key = tuple(
            hashlib.sha256(item.encode("utf-8")).hexdigest()
            for item in (answer, sources, policy_version)
        )
        with self._lock:
            self._values.pop(key, None)  # type: ignore[arg-type]
            self._values[key] = value  # type: ignore[index]
            while len(self._values) > self.max_entries:
                self._values.pop(next(iter(self._values)))

    def clear(self) -> None:
        with self._lock:
            self._values.clear()


def _sentences(text: str) -> list[str]:
    return [item.strip() for item in re.split(r"(?<=[.!?])\s+|\n+", text) if item.strip()]


def _source_passages(sources: str) -> list[tuple[str, str]]:
    passages: list[tuple[str, str]] = []
    for index, paragraph in enumerate((part.strip() for part in sources.split("\n\n")), start=1):
        for sentence in _sentences(paragraph):
            passages.append((f"S{index}", sentence))
    return passages


def _safe_tokens(sentence: str, custom_sensitive_keywords: tuple[str, ...]) -> frozenset[str]:
    if detect_pii(sentence, custom_sensitive_keywords):
        return frozenset(
            word.lower().rstrip("s")
            for word in _WORD_RE.findall(sentence)
            if word.lower() not in _STOPWORDS and len(word) > 2
        )
    return _tokens(sentence)


def check_answer(
    answer: str,
    sources: str,
    policy_version: str = "1",
    cache: VerificationCache | None = None,
    custom_sensitive_keywords: tuple[str, ...] | list[str] = (),
) -> dict[str, Any]:
    """Attribute claims to source sentences; borderline matches stay needs-review."""
    if not isinstance(answer, str) or not isinstance(sources, str):
        raise TypeError("Answer and source text must be strings.")
    if len(answer) > 50_000 or len(sources) > 100_000:
        raise ValueError("Answer or source exceeds the processing limit.")
    if cache:
        cached = cache.get(answer, sources, policy_version, tuple(custom_sensitive_keywords))
        if cached is not None:
            return cached

    passages = _source_passages(sources)
    claims: list[ClaimCheck] = []
    errors: list[str] = []
    citation_numbers = [int(value) for value in _CITATION_RE.findall(answer)]
    valid_ids = {int(source_id[1:]) for source_id, _ in passages}
    invalid_citations = sorted({number for number in citation_numbers if number not in valid_ids})
    if invalid_citations:
        errors.append("Invalid source reference(s): " + ", ".join(f"[S{item}]" for item in invalid_citations))
    citation_status = "invalid" if invalid_citations else (
        "missing" if passages and not citation_numbers else "present"
    )
    if citation_status == "missing":
        errors.append("No inline citations were supplied; retrieved source locations are shown for review.")

    answer_body = _CITATION_RE.sub("", answer).strip()
    if is_incomplete_output(answer_body):
        errors.append("Answer appears empty or incomplete.")
    if not answer_body:
        result = {
            "claims": [], "errors": ["Answer is empty or contains only citations."],
            "unsupported_count": 0, "needs_review_count": 0, "supported_count": 0,
            "overall": "needs_review", "source_count": len({item[0] for item in passages}),
            "citation_status": citation_status,
        }
        if cache:
            cache.put(answer, sources, policy_version, result, tuple(custom_sensitive_keywords))
        return result
    if not passages:
        errors.append("No source passages were supplied.")

    for claim in _sentences(answer_body):
        claim_tokens = _safe_tokens(claim, tuple(custom_sensitive_keywords))
        if not claim_tokens:
            claims.append(ClaimCheck(claim, "needs_review", None, None, "No verifiable content words."))
            continue
        best: tuple[float, str, str, bool] | None = None
        for source_id, passage in passages:
            source_tokens = _safe_tokens(passage, tuple(custom_sensitive_keywords))
            overlap = len(claim_tokens & source_tokens) / max(len(claim_tokens), 1)
            coverage = overlap
            claim_numbers = set(re.findall(r"\b\d+(?:\.\d+)?\b", claim))
            source_numbers = set(re.findall(r"\b\d+(?:\.\d+)?\b", passage))
            polarity_conflict = bool(_NEGATIONS & claim_tokens) != bool(_NEGATIONS & source_tokens)
            numeric_conflict = bool(claim_numbers and source_numbers and claim_numbers != source_numbers)
            # Strong coverage is required; resemblance is not proof of factual correctness.
            score = coverage - (0.12 if polarity_conflict else 0.0)
            if best is None or score > best[0]:
                best = (score, source_id, passage, polarity_conflict or numeric_conflict)

        if best and best[0] >= 0.55:
            status = "contradicted" if best[3] else "supported"
            reason = "Potential polarity conflict; manual verification is required." if best[3] else "Strong lexical evidence match; this is not a factuality guarantee."
            claims.append(ClaimCheck(claim, status, best[2], best[1], reason))
        elif best and best[0] >= 0.35:
            claims.append(ClaimCheck(claim, "needs_review", best[2], best[1], "Partial lexical overlap; evidence is inconclusive."))
        else:
            claims.append(ClaimCheck(
                claim, "unsupported", best[2] if best else None, best[1] if best else None,
                "No sufficiently relevant supporting passage was identified.",
            ))

    statuses = [item.status for item in claims]
    overall = (
        "unsupported" if "unsupported" in statuses or "contradicted" in statuses
        else "needs_review" if "needs_review" in statuses or errors
        else "supported"
    )
    result = {
        "claims": [item.to_dict() for item in claims],
        "errors": errors,
        "unsupported_count": sum(status in {"unsupported", "contradicted"} for status in statuses),
        "needs_review_count": statuses.count("needs_review"),
        "supported_count": statuses.count("supported"),
        "overall": overall,
        "source_count": len({item[0] for item in passages}),
        "citation_status": citation_status,
    }
    if cache:
        cache.put(answer, sources, policy_version, result, tuple(custom_sensitive_keywords))
    return result


def is_incomplete_output(answer: str) -> bool:
    cleaned = answer.strip()
    return not cleaned or cleaned.endswith(("...", "…", ":", "—", "-"))


def clear_token_cache() -> None:
    _tokens.cache_clear()
