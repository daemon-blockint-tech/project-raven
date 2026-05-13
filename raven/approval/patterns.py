"""Dangerous-command pattern library + UNRECOVERABLE_BLOCKLIST.

Patterns ported from Hermes Agent's ``tools/approval.py`` plus Raven-specific
additions (kill-chain destructive stages, AI provider mutations).

Two tiers:
  * ``UNRECOVERABLE_BLOCKLIST`` — hardline floor. Even ``mode=off`` (``--yolo``)
    cannot bypass. There is no override flag.
  * ``DANGEROUS_PATTERNS``      — triggers approval per the active
    ``ApprovalMode``.
"""

from __future__ import annotations

import re
from typing import List

from raven.approval.models import DangerousPattern


# ---------------------------------------------------------------------------
# UNRECOVERABLE_BLOCKLIST — no-override floor
# ---------------------------------------------------------------------------

UNRECOVERABLE_BLOCKLIST: List[DangerousPattern] = [
    DangerousPattern(
        pattern=r"rm\s+(-[rRf]+\s+|--recursive\s+|--force\s+)+/\s*($|[^a-zA-Z0-9_./])",
        description="Recursive delete of filesystem root",
        severity="critical",
    ),
    DangerousPattern(
        pattern=r"rm\s+.*--no-preserve-root",
        description="Explicit no-preserve-root delete",
        severity="critical",
    ),
    DangerousPattern(
        pattern=r":\(\)\s*\{\s*:\s*\|\s*:&\s*\}\s*;\s*:",
        description="Bash fork bomb",
        severity="critical",
    ),
    DangerousPattern(
        pattern=r"\bmkfs\.[a-z0-9]+\s+/dev/(sd[a-z]\d*|nvme\d+n\d+|vd[a-z]\d*|xvd[a-z]\d*)\b",
        description="Format a mounted block device",
        severity="critical",
    ),
    DangerousPattern(
        pattern=r"\bdd\s+.*\bif=/dev/(zero|random|urandom)\b.*\bof=/dev/(sd[a-z]|nvme\d|vd[a-z]|xvd[a-z])",
        description="Zero/randomise a physical disk",
        severity="critical",
    ),
    DangerousPattern(
        pattern=r"\bcurl\s+.*\|\s*(sudo\s+)?(sh|bash|zsh)\b\s*$",
        description="Pipe untrusted URL to shell at top level",
        severity="critical",
    ),
    DangerousPattern(
        pattern=r"\bwget\s+.*\|\s*(sudo\s+)?(sh|bash|zsh)\b\s*$",
        description="Pipe untrusted URL to shell at top level",
        severity="critical",
    ),
    DangerousPattern(
        pattern=r"chmod\s+-[rR].*\s+/\s*($|\s)",
        description="Recursive chmod on filesystem root",
        severity="critical",
    ),
    DangerousPattern(
        pattern=r"chown\s+-[rR].*\s+/\s*($|\s)",
        description="Recursive chown on filesystem root",
        severity="critical",
    ),
    DangerousPattern(
        pattern=r"\bshred\s+.*\s+/dev/(sd[a-z]|nvme\d|vd[a-z])",
        description="Cryptographically erase a physical disk",
        severity="critical",
    ),
]


# ---------------------------------------------------------------------------
# DANGEROUS_PATTERNS — trigger approval but overridable in YOLO/--off
# ---------------------------------------------------------------------------

DANGEROUS_PATTERNS: List[DangerousPattern] = [
    # ---- filesystem ----
    DangerousPattern(r"\brm\s+(-[rRf]+\s+|--recursive\s+|--force\s+)", "Recursive or forced delete", "high"),
    DangerousPattern(r"\brm\s+.*\s+/[a-zA-Z]", "Delete inside system root", "high"),
    DangerousPattern(r"chmod\s+(777|666|a\+w|o\+w)\b", "World/other-writable permission", "medium"),
    DangerousPattern(r"chmod\s+(-[rR]|--recursive)\s+.*\b(777|666|a\+w|o\+w)\b", "Recursive world-writable", "high"),
    DangerousPattern(r"chown\s+(-[rR]|--recursive)\s+root\b", "Recursive chown to root", "high"),
    DangerousPattern(r"\bmkfs(\.[a-z0-9]+)?\s+", "Format filesystem", "high"),
    DangerousPattern(r"\bdd\s+.*\bof=", "dd output to device/file", "high"),
    DangerousPattern(r">\s*/dev/sd[a-z]", "Write to block device", "critical"),
    DangerousPattern(r"\btee\s+.*\s+/etc/", "Overwrite /etc via tee", "high"),
    DangerousPattern(r"\btee\s+.*\s+~/\.ssh/", "Overwrite SSH config via tee", "critical"),
    DangerousPattern(r">>?\s*/etc/", "Redirect into /etc", "high"),
    DangerousPattern(r">>?\s*~/\.ssh/", "Redirect into SSH config", "critical"),
    DangerousPattern(r"\bsed\s+(-i|--in-place)\s+.*\s+/etc/", "In-place edit of /etc", "high"),
    DangerousPattern(r"\bcp\s+.*\s+/etc/", "Copy into /etc", "medium"),
    DangerousPattern(r"\bmv\s+.*\s+/etc/", "Move into /etc", "medium"),

    # ---- processes / system services ----
    DangerousPattern(r"\bsystemctl\s+(stop|restart|disable|mask)\b", "Stop/restart/disable a service", "high"),
    DangerousPattern(r"\bkill\s+-9\s+-1\b", "Kill all processes", "critical"),
    DangerousPattern(r"\bpkill\s+-9\b", "Force kill processes", "high"),
    DangerousPattern(r"\bkillall\s+-9\b", "Force kill processes", "high"),
    DangerousPattern(r"\b(pkill|killall)\s+(hermes|raven|gateway)", "Self-termination of Raven/gateway", "high"),
    DangerousPattern(r"\bshutdown\b", "System shutdown", "high"),
    DangerousPattern(r"\breboot\b", "System reboot", "high"),

    # ---- shell execution of dynamic content ----
    DangerousPattern(r"\b(bash|sh|zsh|ksh)\s+(-[a-z]*c|--command)\b", "Inline shell command via -c", "medium"),
    DangerousPattern(r"\bpython\s+-c\b", "Inline Python via -c", "medium"),
    DangerousPattern(r"\b(perl|ruby|node)\s+-e\b", "Inline script via -e", "medium"),
    DangerousPattern(r"\bcurl\s+.*\|\s*(sh|bash|zsh)\b", "curl piped to shell", "high"),
    DangerousPattern(r"\bwget\s+.*\|\s*(sh|bash|zsh)\b", "wget piped to shell", "high"),
    DangerousPattern(r"\b(bash|sh)\s*<\(\s*(curl|wget)\s+", "Process substitution from curl/wget", "high"),

    # ---- find / xargs ----
    DangerousPattern(r"\bxargs\s+.*\brm\b", "xargs rm", "high"),
    DangerousPattern(r"\bfind\b.*-exec\s+rm\b", "find -exec rm", "high"),
    DangerousPattern(r"\bfind\b.*-delete\b", "find -delete", "high"),

    # ---- SQL ----
    DangerousPattern(r"\bDROP\s+(TABLE|DATABASE|SCHEMA)\b", "SQL DROP", "high"),
    DangerousPattern(r"\bDELETE\s+FROM\s+\w+\s*(;|$)", "SQL DELETE without WHERE", "high"),
    DangerousPattern(r"\bTRUNCATE\s+TABLE\b", "SQL TRUNCATE", "high"),

    # ---- raven-specific destructive operations ----
    DangerousPattern(r"\bgateway\s+run\b.*(&|disown|nohup|setsid)", "Detached gateway start outside service manager", "medium"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BLOCKLIST_COMPILED: List[tuple[re.Pattern[str], DangerousPattern]] = [
    (re.compile(p.pattern, re.IGNORECASE), p) for p in UNRECOVERABLE_BLOCKLIST
]
_DANGEROUS_COMPILED: List[tuple[re.Pattern[str], DangerousPattern]] = [
    (re.compile(p.pattern, re.IGNORECASE), p) for p in DANGEROUS_PATTERNS
]


def match_blocklist(command: str) -> DangerousPattern | None:
    """Return the blocklist entry that fires on this command, or None."""
    for rx, dp in _BLOCKLIST_COMPILED:
        if rx.search(command):
            return dp
    return None


def match_dangerous(command: str) -> DangerousPattern | None:
    """Return the first dangerous pattern that fires, or None."""
    for rx, dp in _DANGEROUS_COMPILED:
        if rx.search(command):
            return dp
    return None
