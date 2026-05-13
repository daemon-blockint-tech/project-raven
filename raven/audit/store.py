"""Audit log store.

Phase 1: in-memory ring buffer.
Phase 3 (Data plane): swap for SQLAlchemy-backed `audit_log` table with the
same `record()` and `tail()` interface.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from typing import Any, Deque, Dict, List, Optional


@dataclass
class AuditEntry:
    timestamp: float
    actor: str                  # username or "anonymous"
    method: str
    path: str
    status_code: int
    client_ip: str
    request_id: str
    duration_ms: float
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AuditStore:
    """Bounded in-memory append-only log."""

    def __init__(self, max_entries: int = 10_000) -> None:
        self._entries: Deque[AuditEntry] = deque(maxlen=max_entries)
        self._lock = threading.Lock()

    def record(self, entry: AuditEntry) -> None:
        with self._lock:
            self._entries.append(entry)

    def tail(self, n: int = 100, actor: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            entries = list(self._entries)
        if actor:
            entries = [e for e in entries if e.actor == actor]
        return [e.to_dict() for e in entries[-n:]]

    def count(self) -> int:
        return len(self._entries)


_singleton: Optional[AuditStore] = None


def audit_store() -> AuditStore:
    global _singleton
    if _singleton is None:
        _singleton = AuditStore()
    return _singleton


def reset_audit_store() -> None:
    global _singleton
    _singleton = None
