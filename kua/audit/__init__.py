"""Audit logging subsystem with hash chaining, payload redaction, and sinks."""

from kua.audit.chain import HashChain, canonical_json, compute_hash, verify_chain
from kua.audit.events import AuditEvent, AuditEventType
from kua.audit.logger import AuditLogger, new_run_id
from kua.audit.redact import redact
from kua.audit.sinks import AuditSink, CloudWatchSink, LocalJsonlSink, MultiSink

__all__ = [
    "AuditEvent",
    "AuditEventType",
    "AuditLogger",
    "AuditSink",
    "CloudWatchSink",
    "HashChain",
    "LocalJsonlSink",
    "MultiSink",
    "canonical_json",
    "compute_hash",
    "new_run_id",
    "redact",
    "verify_chain",
]
