"""Unit tests for audit hash chaining and verification."""

import json
from datetime import UTC, datetime

from kua.audit.chain import HashChain, canonical_json, compute_hash, verify_chain
from kua.audit.events import AuditEvent, AuditEventType


def test_canonical_json_determinism() -> None:
    """Test that canonical_json sorts keys, eliminates spaces, and handles nested data."""
    obj1 = {"b": 2, "a": 1, "nested": {"z": 26, "y": 25}}
    obj2 = {"a": 1, "nested": {"y": 25, "z": 26}, "b": 2}
    assert canonical_json(obj1) == canonical_json(obj2)
    assert canonical_json(obj1) == b'{"a":1,"b":2,"nested":{"y":25,"z":26}}'


def test_compute_hash_ignores_hash_field() -> None:
    """compute_hash should compute the hash over event fields excluding the hash itself."""
    ts = datetime(2026, 10, 3, 12, 0, 0, tzinfo=UTC)
    event1 = AuditEvent(
        run_id="run-1",
        seq=1,
        ts=ts,
        type=AuditEventType.RUN_STARTED,
        actor="kua/0.1.0",
        payload={"cluster": "test"},
        prev_hash="GENESIS",
        hash="",
    )
    h1 = compute_hash(event1)
    assert len(h1) == 64

    event2 = AuditEvent(
        run_id="run-1",
        seq=1,
        ts=ts,
        type=AuditEventType.RUN_STARTED,
        actor="kua/0.1.0",
        payload={"cluster": "test"},
        prev_hash="GENESIS",
        hash=h1,
    )
    assert compute_hash(event2) == h1


def test_hash_chain_creation_and_verification() -> None:
    """A generated sequence of events passes chain verification."""
    chain = HashChain(run_id="run-abc")
    events = [
        chain.next(AuditEventType.RUN_STARTED, "kua/0.1.0", {"msg": "start"}),
        chain.next(AuditEventType.CONFIG_LOADED, "kua/0.1.0", {"version": "1.30"}),
        chain.next(AuditEventType.COLLECTOR_STARTED, "kua/0.1.0", {"collector": "eks"}),
        chain.next(AuditEventType.COLLECTOR_FINISHED, "kua/0.1.0", {"status": "ok"}),
        chain.next(AuditEventType.RUN_FINISHED, "kua/0.1.0", {"exit_code": 0}),
    ]

    assert len(events) == 5
    assert events[0].seq == 1
    assert events[0].prev_hash == "GENESIS"
    for i in range(1, 5):
        assert events[i].seq == i + 1
        assert events[i].prev_hash == events[i - 1].hash

    valid, bad_idx = verify_chain(events)
    assert valid is True
    assert bad_idx is None


def test_verify_chain_empty() -> None:
    """Empty chain is trivially valid."""
    valid, bad_idx = verify_chain([])
    assert valid is True
    assert bad_idx is None


def test_verify_chain_mutated_payload_detected() -> None:
    """Mutating any payload field in event k causes verify_chain to return (False, k)."""
    chain = HashChain(run_id="run-tamper")
    events = [
        chain.next(AuditEventType.RUN_STARTED, "kua/0.1.0", {"step": 0}),
        chain.next(AuditEventType.IDENTITY, "kua/0.1.0", {"step": 1}),
        chain.next(AuditEventType.FINDING, "kua/0.1.0", {"step": 2}),
        chain.next(AuditEventType.GATE, "kua/0.1.0", {"step": 3}),
        chain.next(AuditEventType.RUN_FINISHED, "kua/0.1.0", {"step": 4}),
    ]

    # Mutate event at index 3
    tampered_event = AuditEvent(
        run_id=events[3].run_id,
        seq=events[3].seq,
        ts=events[3].ts,
        type=events[3].type,
        actor=events[3].actor,
        payload={"step": 999},  # modified
        prev_hash=events[3].prev_hash,
        hash=events[3].hash,
    )
    tampered_events = list(events)
    tampered_events[3] = tampered_event

    valid, bad_idx = verify_chain(tampered_events)
    assert valid is False
    assert bad_idx == 3


def test_verify_chain_tampered_prev_hash() -> None:
    """Tampering with prev_hash at index k returns (False, k)."""
    chain = HashChain(run_id="run-prev")
    events = [
        chain.next(AuditEventType.RUN_STARTED, "kua/0.1.0", {"step": 0}),
        chain.next(AuditEventType.CONFIG_LOADED, "kua/0.1.0", {"step": 1}),
        chain.next(AuditEventType.RUN_FINISHED, "kua/0.1.0", {"step": 2}),
    ]

    tampered_event = AuditEvent(
        run_id=events[1].run_id,
        seq=events[1].seq,
        ts=events[1].ts,
        type=events[1].type,
        actor=events[1].actor,
        payload=events[1].payload,
        prev_hash="tampered_hash",
        hash=events[1].hash,
    )
    tampered_events = list(events)
    tampered_events[1] = tampered_event

    valid, bad_idx = verify_chain(tampered_events)
    assert valid is False
    assert bad_idx == 1


def test_verify_chain_tampered_hash() -> None:
    """Tampering with hash at index k returns (False, k)."""
    chain = HashChain(run_id="run-hash")
    events = [
        chain.next(AuditEventType.RUN_STARTED, "kua/0.1.0", {}),
        chain.next(AuditEventType.RUN_FINISHED, "kua/0.1.0", {}),
    ]

    tampered_event = AuditEvent(
        run_id=events[1].run_id,
        seq=events[1].seq,
        ts=events[1].ts,
        type=events[1].type,
        actor=events[1].actor,
        payload=events[1].payload,
        prev_hash=events[1].prev_hash,
        hash="badhash123",
    )
    tampered_events = [events[0], tampered_event]

    valid, bad_idx = verify_chain(tampered_events)
    assert valid is False
    assert bad_idx == 1


def test_verify_chain_tampered_seq() -> None:
    """Skipping a sequence number at index k returns (False, k)."""
    chain = HashChain(run_id="run-seq")
    events = [
        chain.next(AuditEventType.RUN_STARTED, "kua/0.1.0", {}),
        chain.next(AuditEventType.CONFIG_LOADED, "kua/0.1.0", {}),
        chain.next(AuditEventType.RUN_FINISHED, "kua/0.1.0", {}),
    ]

    # Change seq of event 1 to 5
    tampered_event = AuditEvent(
        run_id=events[1].run_id,
        seq=5,
        ts=events[1].ts,
        type=events[1].type,
        actor=events[1].actor,
        payload=events[1].payload,
        prev_hash=events[1].prev_hash,
        hash=events[1].hash,
    )
    tampered_events = [events[0], tampered_event, events[2]]

    valid, bad_idx = verify_chain(tampered_events)
    assert valid is False
    assert bad_idx == 1


def test_verify_chain_first_event_not_genesis() -> None:
    """First event must have prev_hash == GENESIS and seq == 1."""
    event = AuditEvent(
        run_id="run-1",
        seq=1,
        ts=datetime.now(UTC),
        type=AuditEventType.RUN_STARTED,
        actor="kua",
        payload={},
        prev_hash="NOT_GENESIS",
        hash="",
    )
    event_with_hash = AuditEvent(
        run_id=event.run_id,
        seq=event.seq,
        ts=event.ts,
        type=event.type,
        actor=event.actor,
        payload=event.payload,
        prev_hash=event.prev_hash,
        hash=compute_hash(event),
    )
    valid, bad_idx = verify_chain([event_with_hash])
    assert valid is False
    assert bad_idx == 0


def test_event_json_serialization_roundtrip() -> None:
    """Serializing to JSON and validating back preserves hash and integrity."""
    chain = HashChain(run_id="run-roundtrip")
    original = chain.next(
        AuditEventType.FINDING,
        "kua/0.1.0",
        {"id": "DRAIN-PDB", "severity": "BLOCKER"},
    )

    json_str = json.dumps(original.model_dump(mode="json"))
    reloaded = AuditEvent.model_validate(json.loads(json_str))

    assert reloaded == original
    assert reloaded.hash == compute_hash(reloaded)
    valid, bad = verify_chain([reloaded])
    assert valid is True
    assert bad is None
