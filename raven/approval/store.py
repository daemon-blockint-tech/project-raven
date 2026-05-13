"""Approval state stores — pending-decision queue + permanent allowlist.

Phase 1 implementation is in-memory and thread-safe. A Redis-backed variant
slots in trivially when Phase 3 (Data plane) lands — interface stays identical.
"""

from __future__ import annotations

import re
import threading
import time
from typing import Dict, List, Optional

from raven.approval.models import PendingApproval


# ---------------------------------------------------------------------------
# PendingApprovalStore — queue of waiting decisions
# ---------------------------------------------------------------------------


class PendingApprovalStore:
    """Thread-safe in-memory queue of pending approval requests."""

    def __init__(self) -> None:
        self._items: Dict[str, PendingApproval] = {}
        self._lock = threading.RLock()

    def add(self, item: PendingApproval) -> PendingApproval:
        with self._lock:
            self._items[item.request_id] = item
            return item

    def get(self, request_id: str) -> Optional[PendingApproval]:
        return self._items.get(request_id)

    def pop(self, request_id: str) -> Optional[PendingApproval]:
        with self._lock:
            return self._items.pop(request_id, None)

    def list(self, actor: Optional[str] = None) -> List[PendingApproval]:
        now = time.time()
        with self._lock:
            items = [
                item
                for item in self._items.values()
                if item.deadline_at > now and (actor is None or item.actor == actor)
            ]
        return sorted(items, key=lambda x: x.created_at)

    def purge_expired(self) -> int:
        """Drop expired entries; returns count removed."""
        now = time.time()
        with self._lock:
            expired = [k for k, v in self._items.items() if v.deadline_at <= now]
            for k in expired:
                del self._items[k]
        return len(expired)


# ---------------------------------------------------------------------------
# AllowlistStore — patterns the operator has chosen "always allow"
# ---------------------------------------------------------------------------


class AllowlistStore:
    """Thread-safe permanent allowlist of regex patterns."""

    def __init__(self) -> None:
        self._patterns: List[str] = []
        self._compiled: List[re.Pattern[str]] = []
        self._lock = threading.RLock()

    def add(self, pattern: str) -> None:
        with self._lock:
            if pattern in self._patterns:
                return
            self._patterns.append(pattern)
            self._compiled.append(re.compile(pattern, re.IGNORECASE))

    def remove(self, pattern: str) -> bool:
        with self._lock:
            if pattern not in self._patterns:
                return False
            idx = self._patterns.index(pattern)
            del self._patterns[idx]
            del self._compiled[idx]
            return True

    def list(self) -> List[str]:
        return list(self._patterns)

    def matches(self, command: str) -> Optional[str]:
        for pat, rx in zip(self._patterns, self._compiled):
            if rx.search(command):
                return pat
        return None

    def clear(self) -> None:
        with self._lock:
            self._patterns.clear()
            self._compiled.clear()


# ---------------------------------------------------------------------------
# Module-level singletons
# ---------------------------------------------------------------------------

_pending: Optional[PendingApprovalStore] = None
_allowlist: Optional[AllowlistStore] = None


def pending_store() -> PendingApprovalStore:
    global _pending
    if _pending is None:
        _pending = PendingApprovalStore()
    return _pending


def allowlist_store() -> AllowlistStore:
    global _allowlist
    if _allowlist is None:
        _allowlist = AllowlistStore()
    return _allowlist


def reset_stores() -> None:
    """Reset both stores (tests only)."""
    global _pending, _allowlist
    _pending = None
    _allowlist = None
