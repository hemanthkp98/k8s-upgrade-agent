"""High-level audit logger orchestrating redaction, chaining, and sinking."""

import secrets
from datetime import UTC, datetime
from typing import Any

from kua.audit.chain import HashChain
from kua.audit.events import AuditEvent, AuditEventType
from kua.audit.redact import redact
from kua.audit.sinks import AuditSink, MultiSink
from kua.core.errors import AuditError


def new_run_id() -> str:
    """Generate a run identifier of format kua-<yyyymmddTHHMMSSZ>-<6 hex chars>."""
    now = datetime.now(UTC)
    ts_str = now.strftime("%Y%m%dT%H%M%SZ")
    random_hex = secrets.token_hex(3)
    return f"kua-{ts_str}-{random_hex}"


class AuditLogger:
    """Manages an audit event stream with redacting, hash chaining, buffering, and sinking."""

    def __init__(
        self,
        run_id: str,
        actor: str,
        sinks: list[AuditSink] | AuditSink,
        buffer_size: int = 25,
    ) -> None:
        self.run_id = run_id
        self.actor = actor
        self.buffer_size = buffer_size
        self.chain = HashChain(run_id=run_id)
        self.buffer: list[AuditEvent] = []
        self._closed = False

        if isinstance(sinks, list):
            self.sinks: list[AuditSink] = list(sinks)
            self.sink: AuditSink = MultiSink(self.sinks)
        else:
            self.sinks = [sinks]
            self.sink = sinks

    def emit(
        self,
        type: AuditEventType,
        payload: dict[str, Any],
        ts: datetime | None = None,
    ) -> AuditEvent:
        """Redact payload, chain event, buffer, and auto-flush if buffer_size is reached."""
        if self._closed:
            raise AuditError("Cannot emit events on a closed AuditLogger")

        redacted_payload = redact(payload)
        if not isinstance(redacted_payload, dict):
            redacted_payload = {"value": redacted_payload}

        event = self.chain.next(
            type=type,
            actor=self.actor,
            payload=redacted_payload,
            ts=ts,
        )
        self.buffer.append(event)
        if len(self.buffer) >= self.buffer_size:
            self.flush()
        return event

    def flush(self) -> None:
        """Flush currently buffered events to the configured sink(s)."""
        if self.buffer:
            events_to_write = list(self.buffer)
            self.buffer.clear()
            self.sink.write(events_to_write)

    def close(self) -> None:
        """Flush remaining buffered events and close all underlying sinks."""
        if self._closed:
            return
        try:
            self.flush()
        finally:
            self._closed = True
            self.sink.close()

    def __enter__(self) -> "AuditLogger":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        self.close()
