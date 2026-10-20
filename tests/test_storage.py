import json

import pytest

from trustlayer.storage import Store, export_events_csv, export_events_json


def test_request_and_review_persist_across_store_restart(tmp_path):
    path = tmp_path / "persistent.db"
    store = Store(path)
    route = {"level": "HIGH", "score": 75, "requires_review": True, "reasons": []}
    checks = {"privacy": {"finding_count": 0}, "verification": {"overall": "supported"}}
    request_id = store.record_request("a" * 64, "1", route, checks, 2.5)
    review_id = store.enqueue_review(request_id, "HIGH", ["Needs review"], "Answer [S1]", [], [], checks)

    reopened = Store(path)
    assert reopened.get_requests()[0]["request_id"] == request_id
    assert reopened.get_reviews()[0]["review_id"] == review_id


def test_review_requires_reason_and_only_allows_pending_transition(tmp_path):
    store = Store(tmp_path / "review.db")
    request_id = store.record_request("b" * 64, "1", {"level": "HIGH"}, {}, 1.0)
    review_id = store.enqueue_review(request_id, "HIGH", [], "answer", [], [], {})
    with pytest.raises(ValueError, match="reason"):
        store.decide_review(review_id, "approved", " ")
    store.decide_review(review_id, "approved", "Checked source and answer")
    assert store.get_reviews()[0]["status"] == "approved"
    with pytest.raises(ValueError, match="Only pending"):
        store.decide_review(review_id, "rejected", "Second decision")


def test_review_reason_is_redacted_in_storage_and_audit(tmp_path):
    store = Store(tmp_path / "redact.db")
    request_id = store.record_request("c" * 64, "1", {"level": "HIGH"}, {}, 1.0)
    review_id = store.enqueue_review(request_id, "HIGH", [], "answer", [], [], {})
    store.decide_review(review_id, "rejected", "Email alex@example.com is visible.")
    review = store.get_reviews()[0]
    event = store.get_events()[0]
    assert "alex@example.com" not in review["decision_reason"]
    assert "alex@example.com" not in json.dumps(event["payload"])


def test_hash_linked_audit_verification_detects_tampering(tmp_path):
    store = Store(tmp_path / "integrity.db")
    store.append_event("one", {"safe": "metadata"})
    store.append_event("two", {"safe": "other"})
    assert store.verify_chain()["valid"]
    with store.connect() as db:
        db.execute("UPDATE audit_events SET payload = ? WHERE sequence = 1", ('{"changed":true}',))
    result = store.verify_chain()
    assert not result["valid"]
    assert result["failure_sequence"] == 1


def test_exports_include_headers_and_safe_event_data(tmp_path):
    store = Store(tmp_path / "export.db")
    store.append_event("request_processed", {"request_id": "abc"})
    events = store.get_events()
    assert '"event_type": "request_processed"' in export_events_json(events)
    assert "sequence,event_id,timestamp,event_type,payload" in export_events_csv(events)


def test_incident_crud_and_full_local_deletion(tmp_path):
    store = Store(tmp_path / "delete.db")
    incident = store.create_incident("high", "Synthetic demo incident", "Reviewer")
    store.update_incident(incident, "resolved", "Closed after review", "Reviewer")
    assert store.get_incidents()[0]["status"] == "resolved"
    store.append_event("test", {"value": 1})
    store.delete_all_local_records()
    assert store.get_incidents() == []
    assert store.get_events() == []
    store.append_event("after_reset", {"value": 2})
    assert store.verify_chain()["valid"]
