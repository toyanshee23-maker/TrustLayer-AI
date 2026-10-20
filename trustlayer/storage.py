"""Local SQLite persistence and a hash-linked, metadata-only audit trail."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .privacy import detect_pii, redact_text

GENESIS_HASH = "0" * 64


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _event_hash(sequence: int, event_id: str, timestamp: str, event_type: str, payload: str, previous_hash: str) -> str:
    encoded = _canonical({
        "sequence": sequence, "event_id": event_id, "timestamp": timestamp,
        "event_type": event_type, "payload": payload, "previous_hash": previous_hash,
    })
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript(
                """
                PRAGMA foreign_keys = ON;
                CREATE TABLE IF NOT EXISTS requests (
                    request_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    route_json TEXT NOT NULL,
                    checks_json TEXT NOT NULL,
                    latency_ms REAL NOT NULL,
                    error_status TEXT NOT NULL DEFAULT 'ok'
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS review_items (
                    review_id TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    reasons_json TEXT NOT NULL,
                    answer TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    findings_json TEXT NOT NULL,
                    checks_json TEXT NOT NULL,
                    actions_json TEXT NOT NULL DEFAULT '[]',
                    status TEXT NOT NULL CHECK(status IN ('pending','approved','rejected','revision_requested')),
                    decision_reason TEXT NOT NULL DEFAULT '',
                    decided_at TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('open','investigating','resolved')),
                    owner TEXT NOT NULL DEFAULT '',
                    resolution_notes TEXT NOT NULL DEFAULT ''
                );
                """
            )
            review_columns = {
                row["name"] for row in db.execute("PRAGMA table_info(review_items)").fetchall()
            }
            if "actions_json" not in review_columns:
                db.execute("ALTER TABLE review_items ADD COLUMN actions_json TEXT NOT NULL DEFAULT '[]'")

    def connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        return db

    def append_event(self, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        timestamp = utc_now()
        event_id = str(uuid.uuid4())
        payload_text = _canonical(payload)
        with self.connect() as db:
            row = db.execute(
                "SELECT sequence, event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            previous_hash = row["event_hash"] if row else GENESIS_HASH
            sequence = (row["sequence"] + 1) if row else 1
            digest = _event_hash(sequence, event_id, timestamp, event_type, payload_text, previous_hash)
            db.execute(
                """INSERT INTO audit_events
                   (sequence,event_id,timestamp,event_type,payload,previous_hash,event_hash)
                   VALUES (?,?,?,?,?,?,?)""",
                (sequence, event_id, timestamp, event_type, payload_text, previous_hash, digest),
            )
        return {"event_id": event_id, "timestamp": timestamp, "sequence": sequence, "event_hash": digest}

    def record_request(
        self, fingerprint: str, policy_version: str, route: dict[str, Any],
        checks: dict[str, Any], latency_ms: float, error_status: str = "ok",
    ) -> str:
        request_id = str(uuid.uuid4())
        timestamp = utc_now()
        with self.connect() as db:
            db.execute(
                """INSERT INTO requests
                   (request_id,timestamp,fingerprint,policy_version,risk_level,route_json,checks_json,latency_ms,error_status)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (request_id, timestamp, fingerprint, policy_version, route["level"],
                 _canonical(route), _canonical(checks), max(0.0, latency_ms), error_status),
            )
        self.append_event("request_processed", {
            "request_id": request_id, "fingerprint": fingerprint, "policy_version": policy_version,
            "risk_level": route["level"], "route": route, "checks": checks,
            "latency_ms": round(max(0.0, latency_ms), 3), "error_status": error_status,
        })
        return request_id

    def enqueue_review(
        self, request_id: str, risk_level: str, reasons: list[str], answer: str,
        evidence: list[dict[str, Any]], findings: list[dict[str, Any]], checks: dict[str, Any],
        actions: list[str] | None = None,
    ) -> str:
        review_id = str(uuid.uuid4())
        timestamp = utc_now()
        with self.connect() as db:
            db.execute(
                """INSERT INTO review_items
                   (review_id,request_id,created_at,risk_level,reasons_json,answer,evidence_json,
                    findings_json,checks_json,actions_json,status)
                   VALUES (?,?,?,?,?,?,?,?,?,?,'pending')""",
                (review_id, request_id, timestamp, risk_level, _canonical(reasons), answer,
                 _canonical(evidence), _canonical(findings), _canonical(checks), _canonical(actions or [])),
            )
        self.append_event("review_enqueued", {"review_id": review_id, "request_id": request_id, "risk_level": risk_level})
        return review_id

    def decide_review(self, review_id: str, decision: str, reason: str) -> None:
        if decision not in {"approved", "rejected", "revision_requested"}:
            raise ValueError("Decision must be approved, rejected, or revision_requested.")
        if not reason.strip():
            raise ValueError("A reason is required for every review decision.")
        safe_reason = redact_text(reason.strip()[:2000], detect_pii(reason.strip()[:2000]))
        timestamp = utc_now()
        with self.connect() as db:
            row = db.execute("SELECT status FROM review_items WHERE review_id = ?", (review_id,)).fetchone()
            if row is None:
                raise KeyError("Review item was not found.")
            if row["status"] != "pending":
                raise ValueError("Only pending review items can receive a decision.")
            db.execute(
                """UPDATE review_items SET status=?,decision_reason=?,decided_at=? WHERE review_id=?""",
                (decision, safe_reason, timestamp, review_id),
            )
        self.append_event("review_decided", {
            "review_id": review_id, "decision": decision, "reason": safe_reason, "decided_at": timestamp,
        })

    def get_reviews(self, status: str = "all") -> list[dict[str, Any]]:
        query = "SELECT * FROM review_items"
        params: tuple[Any, ...] = ()
        if status != "all":
            if status not in {"pending", "approved", "rejected", "revision_requested"}:
                raise ValueError("Unsupported review status.")
            query += " WHERE status = ?"
            params = (status,)
        query += " ORDER BY created_at DESC"
        with self.connect() as db:
            rows = db.execute(query, params).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            for field in ("reasons_json", "evidence_json", "findings_json", "checks_json", "actions_json"):
                item[field.removesuffix("_json")] = json.loads(item.pop(field))
            result.append(item)
        return result

    def get_requests(self, limit: int = 1000) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT * FROM requests ORDER BY timestamp DESC LIMIT ?", (max(1, min(limit, 10000)),)
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["route"] = json.loads(item.pop("route_json"))
            item["checks"] = json.loads(item.pop("checks_json"))
            result.append(item)
        return result

    def get_events(self, limit: int = 1000) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT * FROM audit_events ORDER BY sequence DESC LIMIT ?", (max(1, min(limit, 10000)),)
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(item["payload"])
            result.append(item)
        return result

    def verify_chain(self) -> dict[str, Any]:
        with self.connect() as db:
            rows = db.execute("SELECT * FROM audit_events ORDER BY sequence").fetchall()
        previous_hash = GENESIS_HASH
        for expected_sequence, row in enumerate(rows, start=1):
            if row["sequence"] != expected_sequence:
                return {"valid": False, "checked": expected_sequence - 1, "failure_sequence": expected_sequence, "reason": "Event sequence has a gap or was reordered."}
            if row["previous_hash"] != previous_hash:
                return {"valid": False, "checked": expected_sequence - 1, "failure_sequence": expected_sequence, "reason": "Previous-hash link does not match."}
            calculated = _event_hash(
                row["sequence"], row["event_id"], row["timestamp"], row["event_type"],
                row["payload"], row["previous_hash"],
            )
            if calculated != row["event_hash"]:
                return {"valid": False, "checked": expected_sequence - 1, "failure_sequence": expected_sequence, "reason": "Event content hash does not match."}
            previous_hash = row["event_hash"]
        return {"valid": True, "checked": len(rows), "failure_sequence": None, "reason": "All stored events match the hash-linked chain."}

    def get_setting(self, key: str, default: Any = None) -> Any:
        with self.connect() as db:
            row = db.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return json.loads(row["value"]) if row else default

    def set_setting(self, key: str, value: Any) -> None:
        with self.connect() as db:
            db.execute(
                "INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, _canonical(value)),
            )

    def purge_expired_review_content(self, retention_days: int) -> int:
        if not 1 <= retention_days <= 3650:
            raise ValueError("Retention must be between 1 and 3,650 days.")
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
        with self.connect() as db:
            cursor = db.execute("DELETE FROM review_items WHERE created_at < ?", (cutoff,))
            return cursor.rowcount

    def create_incident(self, severity: str, description: str, owner: str = "") -> str:
        if severity not in {"low", "medium", "high", "critical"} or not description.strip():
            raise ValueError("Choose a severity and provide an incident description.")
        incident_id = str(uuid.uuid4())
        timestamp = utc_now()
        with self.connect() as db:
            db.execute(
                "INSERT INTO incidents(incident_id,created_at,severity,description,status,owner) VALUES(?,?,?,?,?,?)",
                (incident_id, timestamp, severity, description.strip()[:5000], "open", owner.strip()[:120]),
            )
        self.append_event("incident_created", {"incident_id": incident_id, "severity": severity, "status": "open"})
        return incident_id

    def get_incidents(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            return [dict(row) for row in db.execute("SELECT * FROM incidents ORDER BY created_at DESC").fetchall()]

    def save_test_run(self, report: dict[str, Any]) -> str:
        run_id = str(uuid.uuid4())
        summary = {
            "dataset_size": report["dataset_size"],
            "conditions": report["conditions"],
            "baseline": report["baseline"],
            "trustlayer": report["trustlayer"],
        }
        with self.connect() as db:
            db.execute(
                "INSERT INTO settings(key,value) VALUES(?,?)",
                (f"test_run:{run_id}", _canonical({"run_id": run_id, "created_at": utc_now(), "summary": summary})),
            )
        self.append_event("evaluation_completed", {
            "run_id": run_id, "dataset_size": report["dataset_size"],
            "baseline_latency_ms": report["baseline"]["latency"]["total_ms"],
            "trustlayer_latency_ms": report["trustlayer"]["latency"]["total_ms"],
        })
        return run_id

    def get_test_runs(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT value FROM settings WHERE key LIKE 'test_run:%' ORDER BY key DESC"
            ).fetchall()
        return [json.loads(row["value"]) for row in rows]

    def update_incident(self, incident_id: str, status: str, resolution_notes: str, owner: str) -> None:
        if status not in {"open", "investigating", "resolved"}:
            raise ValueError("Invalid incident status.")
        with self.connect() as db:
            result = db.execute(
                "UPDATE incidents SET status=?,resolution_notes=?,owner=? WHERE incident_id=?",
                (status, resolution_notes.strip()[:5000], owner.strip()[:120], incident_id),
            )
            if result.rowcount != 1:
                raise KeyError("Incident was not found.")
        self.append_event("incident_updated", {
            "incident_id": incident_id, "status": status, "owner": owner.strip()[:120],
        })

    def delete_all_local_records(self) -> None:
        """Explicit demo reset: remove private review content and related audit records."""
        with self.connect() as db:
            db.execute("DELETE FROM review_items")
            db.execute("DELETE FROM incidents")
            db.execute("DELETE FROM requests")
            db.execute("DELETE FROM audit_events")
            db.execute("DELETE FROM sqlite_sequence WHERE name = 'audit_events'")
            db.execute("DELETE FROM settings")


def export_events_json(events: list[dict[str, Any]]) -> str:
    return json.dumps(events, ensure_ascii=False, indent=2)


def export_events_csv(events: list[dict[str, Any]]) -> str:
    output = io.StringIO(newline="")
    columns = ["sequence", "event_id", "timestamp", "event_type", "payload", "previous_hash", "event_hash"]
    writer = csv.DictWriter(output, fieldnames=columns)
    writer.writeheader()
    for event in events:
        row = dict(event)
        row["payload"] = _canonical(row.get("payload", {}))
        writer.writerow({key: row.get(key, "") for key in columns})
    return output.getvalue()
