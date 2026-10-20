"""Local, pattern-based detection and redaction for common sensitive data."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import re
from typing import Literal

MAX_TEXT_CHARS = 100_000
MAX_UPLOAD_BYTES = 2 * 1024 * 1024
SUPPORTED_EXTENSIONS = {".txt", ".md", ".csv", ".json"}


@dataclass(frozen=True)
class Finding:
    kind: str
    start: int
    end: int
    value: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("email", re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+(?![\w.-])", re.I)),
    ("ssn", re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")),
    ("phone", re.compile(r"(?<!\w)(?:\+?\d[\d().\s-]{6,}\d)(?!\w)")),
    (
        "name",
        re.compile(
            r"(?i:\b(?:my\s+name\s+is|name\s*:|contact\s*:|patient\s*:))\s*"
            r"(?P<name>[A-Z][a-z]{1,30}(?:\s+[A-Z][a-z]{1,30}){0,2})(?!\w)"
        ),
    ),
)


def _valid_phone(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    return 7 <= len(digits) <= 15 and len(set(digits)) > 1


def detect_pii(text: str, custom_keywords: tuple[str, ...] | list[str] = ()) -> list[Finding]:
    """Find common PII spans locally; results are heuristic, not exhaustive."""
    if not isinstance(text, str):
        raise TypeError("Text must be a string.")
    if len(text) > MAX_TEXT_CHARS:
        raise ValueError(f"Text exceeds the {MAX_TEXT_CHARS:,}-character processing limit.")

    candidates: list[Finding] = []
    for kind, pattern in _PATTERNS:
        for match in pattern.finditer(text):
            if kind == "phone" and not _valid_phone(match.group()):
                continue
            if kind == "phone" and re.fullmatch(r"\d{4}[-/]\d{1,2}[-/]\d{1,2}", match.group().strip()):
                continue
            if kind == "name":
                start, end = match.span("name")
                value = match.group("name")
            else:
                start, end = match.span()
                value = match.group()
            candidates.append(Finding(kind, start, end, value))

    for keyword in custom_keywords:
        term = keyword.strip()
        if not term or len(term) > 80:
            continue
        pattern = re.compile(rf"(?<!\w){re.escape(term)}(?!\w)", re.I)
        for match in pattern.finditer(text):
            candidates.append(Finding("custom", *match.span(), match.group()))

    # Prefer specific patterns (such as SSNs) if broad phone matching overlaps.
    priority = {"ssn": 0, "email": 1, "phone": 2, "name": 3, "custom": 4}
    chosen: list[Finding] = []
    for finding in sorted(candidates, key=lambda item: (item.start, priority[item.kind], -(item.end - item.start))):
        if any(finding.start < item.end and item.start < finding.end for item in chosen):
            continue
        chosen.append(finding)
    return sorted(chosen, key=lambda item: item.start)


def redact_text(text: str, findings: list[Finding] | None = None, mode: Literal["redact", "mask"] = "redact") -> str:
    if mode not in {"redact", "mask"}:
        raise ValueError("Redaction mode must be 'redact' or 'mask'.")
    hits = detect_pii(text) if findings is None else findings
    output = text
    for finding in sorted(hits, key=lambda item: item.start, reverse=True):
        replacement = f"[REDACTED:{finding.kind.upper()}]"
        if mode == "mask":
            replacement = "*" * max(3, min(12, len(finding.value)))
        output = output[:finding.start] + replacement + output[finding.end:]
    return output


def read_text_upload(name: str, data: bytes, max_bytes: int = MAX_UPLOAD_BYTES) -> str:
    """Validate and decode an in-memory text upload; never writes it to disk."""
    extension = Path(name).suffix.lower()
    if extension not in SUPPORTED_EXTENSIONS:
        raise ValueError(f"Unsupported file type '{extension or '(no extension)'}'. Use TXT, MD, CSV, or JSON.")
    if len(data) > max_bytes:
        raise ValueError(f"File exceeds the {max_bytes // (1024 * 1024)} MiB upload limit.")
    if b"\x00" in data:
        raise ValueError("Binary content is not supported.")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise ValueError("File must be UTF-8 encoded text.") from error
    if len(text) > MAX_TEXT_CHARS:
        raise ValueError(f"Decoded file exceeds the {MAX_TEXT_CHARS:,}-character processing limit.")
    return text
