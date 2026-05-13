"""Mine the audit log → conversational SFT pairs.

Every authenticated mutating request becomes one training example, framed as:

  system: "You are Raven — autonomous defense system."
  user:   "<method> <path>"
  assistant: "<status_code> result for <actor>"

PII scrubbing is applied via :func:`pii_scrub`. Audit entries flagged with
``metadata.no_training: true`` are excluded.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from raven.training.datasets.base import JsonlWriter, write_messages
from raven.training.models import Dataset, DatasetSource


_SYSTEM = (
    "You are Raven, Project Raven's autonomous defense system. You are "
    "reviewing past operator interactions to learn the right way to handle "
    "common security-operations requests."
)


def build_audit_dataset(
    out_path: str | Path,
    name: str = "audit-yesterday",
    limit: int = 1000,
    actor: Optional[str] = None,
    entries: Optional[Iterable[Dict[str, Any]]] = None,
) -> Dataset:
    """Materialise an audit-log dataset to ``out_path``.

    ``entries`` is exposed for testability — when None we read from the live
    in-process :func:`raven.audit.store.audit_store`. Records with status
    codes >= 400 are skipped (we don't want to learn failure patterns as
    successful behaviour)."""

    if entries is None:
        from raven.audit.store import audit_store
        entries = audit_store().tail(n=limit, actor=actor)

    out_path = Path(out_path)
    count = 0
    with JsonlWriter(out_path) as writer:
        for entry in entries:
            metadata = entry.get("metadata") or {}
            if metadata.get("no_training"):
                continue
            status = int(entry.get("status_code", 0))
            if status >= 400:
                continue
            method = entry.get("method", "GET")
            path = entry.get("path", "/")
            actor_name = entry.get("actor", "operator")
            req_id = entry.get("request_id", "")
            messages: List[Dict[str, str]] = [
                {"role": "system", "content": _SYSTEM},
                {"role": "user", "content": f"{method} {path}"},
                {
                    "role": "assistant",
                    "content": (
                        f"Resolved {method} {path} for {actor_name} with "
                        f"status {status} (request_id={req_id})."
                    ),
                },
            ]
            write_messages(writer, messages, scrub=True)
            count = writer.count

    return Dataset(
        source=DatasetSource.AUDIT_LOG,
        name=name,
        path=str(out_path),
        example_count=count,
        metadata={"limit": limit, "actor": actor or "", "built_at": time.time()},
    )
