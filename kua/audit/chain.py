"""Hash chaining algorithms and verification for audit event streams."""

import hashlib
import json
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from kua.audit.events import AuditEvent, AuditEventType


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON serialization.

    Uses sorted keys, compact separators, UTF-8 encoding, and string fallback
    for unknown types.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def compute_hash(event: AuditEvent) -> str:
    """Compute the SHA-256 hex digest of an AuditEvent excluding its hash field."""
    payload = event.model_dump(exclude={"hash"}, mode="json")
    return hashlib.sha256(canonical_json(payload)).hexdigest()


class HashChain:
    """Stateful hash chain builder for a stream of audit events."""

    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        self.seq = 1
        self.last_hash = "GENESIS"

    def next(
        self,
        type: AuditEventType,
        actor: str,
        payload: dict[str, Any],
        ts: datetime | None = None,
    ) -> AuditEvent:
        """Create the next hash-chained AuditEvent and update internal state."""
        event_ts = ts if ts is not None else datetime.now(UTC)
        draft = AuditEvent(
            run_id=self.run_id,
            seq=self.seq,
            ts=event_ts,
            type=type,
            actor=actor,
            payload=payload,
            prev_hash=self.last_hash,
            hash="",
        )
        event_hash = compute_hash(draft)
        event = AuditEvent(
            run_id=self.run_id,
            seq=self.seq,
            ts=event_ts,
            type=type,
            actor=actor,
            payload=payload,
            prev_hash=self.last_hash,
            hash=event_hash,
        )
        self.last_hash = event_hash
        self.seq += 1
        return event


def verify_chain(events: Iterable[AuditEvent]) -> tuple[bool, int | None]:
    """Verify that an iterable of audit events forms an unbroken, untampered chain.

    Validates that:
    1. seq increments sequentially by 1 starting at 1.
    2. prev_hash equals preceding event's hash (first event has prev_hash == 'GENESIS').
    3. event.hash == compute_hash(event).

    Returns:
        (True, None) if the entire chain is valid, or (False, index_of_first_bad_event).
    """
    last_hash = "GENESIS"
    expected_seq = 1

    for idx, event in enumerate(events):
        if event.seq != expected_seq:
            return False, idx
        if event.prev_hash != last_hash:
            return False, idx
        if not event.hash or event.hash != compute_hash(event):
            return False, idx
        last_hash = event.hash
        expected_seq += 1

    return True, None
