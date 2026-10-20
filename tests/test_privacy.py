import pytest

from trustlayer.privacy import detect_pii, read_text_upload, redact_text


def test_detects_common_pii_and_contextual_name():
    text = "Email alex@example.com; call +1 (415) 555-0132. SSN 123-45-6789. My name is Alex Johnson."
    findings = detect_pii(text)
    assert {item.kind for item in findings} == {"email", "phone", "ssn", "name"}
    assert [text[item.start:item.end] for item in findings] == [item.value for item in findings]


def test_redaction_and_masking():
    text = "Write to alex@example.com"
    findings = detect_pii(text)
    assert redact_text(text, findings) == "Write to [REDACTED:EMAIL]"
    assert "*" in redact_text(text, findings, "mask")


def test_custom_keywords_are_literal_and_case_insensitive():
    text = "The Project Cedar launch."
    hits = detect_pii(text, ["Cedar"])
    assert [(hit.kind, hit.value) for hit in hits] == [("custom", "Cedar")]
    assert not detect_pii("cedarwood", ["Cedar"])


def test_false_positive_guards_for_dates_and_repeated_digits():
    assert detect_pii("The meeting is on 2025-05-14.") == []
    assert detect_pii("The reference code is 2222222.") == []
    assert detect_pii("Reach extension 123456.") == []


def test_text_upload_accepts_supported_utf8_in_memory():
    assert read_text_upload("memo.TXT", b"\xef\xbb\xbfhello") == "hello"
    assert read_text_upload("file.csv", "name,value\nA,2".encode()) == "name,value\nA,2"


@pytest.mark.parametrize(
    ("name", "data", "message"),
    [
        ("x.exe", b"hello", "Unsupported file type"),
        ("x.txt", b"\xff", "UTF-8"),
        ("x.txt", b"a\x00b", "Binary"),
        ("x.txt", b"12345", "upload limit"),
    ],
)
def test_text_upload_rejects_unsupported_or_malformed_inputs(name, data, message):
    with pytest.raises(ValueError, match=message):
        read_text_upload(name, data, max_bytes=4 if message == "upload limit" else 100)


def test_pii_text_limit():
    with pytest.raises(ValueError, match="character processing limit"):
        detect_pii("x" * 100_001)
