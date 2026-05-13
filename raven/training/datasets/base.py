"""Shared dataset utilities — JSONL writer + PII scrubber."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List


# ---------------------------------------------------------------------------
# PII scrubber — conservative pattern-based redaction.
# ---------------------------------------------------------------------------

_PII_PATTERNS: List[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[email]"),
    (re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "[card]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[ssn]"),
    (re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"), "[ip]"),
    (re.compile(r"[A-Fa-f0-9]{40,64}"), "[hash]"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "[api_key]"),
    (re.compile(r"Bearer\s+[A-Za-z0-9._-]+"), "Bearer [token]"),
]


def pii_scrub(text: str) -> str:
    """Conservative PII redaction. Always run on operator-touching corpora."""
    for rx, repl in _PII_PATTERNS:
        text = rx.sub(repl, text)
    return text


# ---------------------------------------------------------------------------
# JSONL writer
# ---------------------------------------------------------------------------


class JsonlWriter:
    """Append-only JSONL writer with a running example count."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._count = 0
        # Truncate to start fresh
        self._fh = self.path.open("w", encoding="utf-8")

    def write(self, record: Dict[str, Any]) -> None:
        line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
        self._fh.write(line + "\n")
        self._count += 1

    def close(self) -> None:
        self._fh.close()

    @property
    def count(self) -> int:
        return self._count

    def __enter__(self) -> "JsonlWriter":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


def write_messages(
    writer: JsonlWriter, messages: List[Dict[str, str]], scrub: bool = True
) -> None:
    """Write one conversational training example."""
    if scrub:
        messages = [{**m, "content": pii_scrub(m.get("content", ""))} for m in messages]
    writer.write({"messages": messages})
