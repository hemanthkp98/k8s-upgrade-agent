"""Audit event definitions and event type enumerations."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator


class AuditEventType(StrEnum):
    """Supported types of audit events throughout the lifecycle."""

    RUN_STARTED = "RUN_STARTED"
    RUN_FINISHED = "RUN_FINISHED"
    CONFIG_LOADED = "CONFIG_LOADED"
    IDENTITY = "IDENTITY"
    COLLECTOR_STARTED = "COLLECTOR_STARTED"
    COLLECTOR_FINISHED = "COLLECTOR_FINISHED"
    COLLECTOR_ERROR = "COLLECTOR_ERROR"
    FINDING = "FINDING"
    LLM_REQUEST = "LLM_REQUEST"
    LLM_RESPONSE = "LLM_RESPONSE"
    REPORT_WRITTEN = "REPORT_WRITTEN"
    GATE = "GATE"
    ACTION_PLANNED = "ACTION_PLANNED"
    ACTION_STARTED = "ACTION_STARTED"
    ACTION_FINISHED = "ACTION_FINISHED"
    ACTION_FAILED = "ACTION_FAILED"


class AuditEvent(BaseModel):
    """Immutable, hash-chained audit event.

    Attributes:
        run_id: Unique identifier for the run/execution session.
        seq: Monotonically increasing sequence number starting at 1.
        ts: UTC timestamp formatted as ISO8601 with trailing 'Z'.
        type: The category of event.
        actor: Principal or identity producing the event.
        payload: Redacted, structured event payload data.
        prev_hash: SHA-256 hash of the preceding event, or 'GENESIS'.
        hash: SHA-256 hash computed over canonical JSON of this event.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    run_id: str
    seq: int
    ts: datetime
    type: AuditEventType
    actor: str
    payload: dict[str, Any]
    prev_hash: str
    hash: str = Field(default="")

    @field_validator("ts", mode="before")
    @classmethod
    def _ensure_utc(cls, v: Any) -> Any:
        if isinstance(v, datetime):
            if v.tzinfo is None:
                return v.replace(tzinfo=UTC)
            return v.astimezone(UTC)
        return v

    @field_serializer("ts")
    def _serialize_ts(self, ts: datetime, _info: Any) -> str:
        utc_dt = ts if ts.tzinfo is not None else ts.replace(tzinfo=UTC)
        return utc_dt.astimezone(UTC).isoformat().replace("+00:00", "Z")
