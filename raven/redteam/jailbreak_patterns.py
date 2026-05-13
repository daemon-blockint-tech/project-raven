"""Fingerprints of common jailbreak templates.

We **do not redistribute** the full L1B3RT4S / G0DM0D3 template strings — we
fingerprint them so we can detect their presence in inbound prompts. This is
defensive: pattern matches earn a score that, when summed, triggers the
:class:`JailbreakDetector`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List


@dataclass
class Fingerprint:
    """A single jailbreak pattern. ``weight`` contributes to the detection
    score (0.0–1.0). ``family`` is the L1B3RT4S codename for grouping."""

    name: str
    family: str
    regex: str
    weight: float
    description: str


# All weights chosen so any *single* high-confidence pattern (>= 0.8) is
# enough to trip the default block threshold. Multiple medium signals
# (each 0.3–0.5) compound to also trigger.

FINGERPRINTS: List[Fingerprint] = [
    # ---- boundary-inversion family (Claude-targeted) ----
    Fingerprint(
        name="boundary_inversion_marker",
        family="boundary_inversion",
        regex=r"\[\s*END OF INPUT\s*\]\s*\[\s*START OF INPUT\s*\]",
        weight=0.85,
        description="L1B3RT4S boundary-inversion marker (Claude-targeted)",
    ),
    Fingerprint(
        name="end_of_output_marker",
        family="boundary_inversion",
        regex=r"\[\s*#+\s*(START|END) OF OUTPUT\s*#+\s*\]",
        weight=0.6,
        description="L1B3RT4S output-boundary marker",
    ),

    # ---- og_godmode family (GPT-targeted) ----
    Fingerprint(
        name="godmode_active_phrase",
        family="og_godmode",
        regex=r"\bgodmode\s+(is\s+)?(active|enabled|on)\b",
        weight=0.9,
        description="GODMODE activation phrase",
    ),
    Fingerprint(
        name="pliny_divider",
        family="og_godmode",
        regex=r"\.\-\.\-\.\-\.\-\.\-\.\-\.\-\.\-\{?\s*\*?\s*LIBERATING",
        weight=0.95,
        description="Pliny 'LIBERATING' divider string",
    ),
    Fingerprint(
        name="pliny_love",
        family="og_godmode",
        regex=r"LOVE\s+PLINY\s*<3",
        weight=0.95,
        description="Pliny signature divider",
    ),
    Fingerprint(
        name="leet_godmode_phrase",
        family="og_godmode",
        regex=r"\bg0dm0d3\b|\bg0dm0de\b|\bg0d-?m0d3\b",
        weight=0.85,
        description="Leetspeak GODMODE",
    ),

    # ---- refusal_inversion (Gemini/general) ----
    Fingerprint(
        name="write_oppositely",
        family="refusal_inversion",
        regex=r"\bwrite\s+(the\s+)?(opposite|oppositely)\b",
        weight=0.7,
        description="Refusal-inversion instruction",
    ),
    Fingerprint(
        name="real_response_then",
        family="refusal_inversion",
        regex=r"\b(real|true|actual)\s+response[,\s]+then\b",
        weight=0.55,
        description="Two-part real-response pattern",
    ),
    Fingerprint(
        name="semantically_opposite",
        family="refusal_inversion",
        regex=r"semantically\s+(opposite|inverted)",
        weight=0.6,
        description="Semantic-opposite instruction",
    ),

    # ---- unfiltered / liberated (Grok / generic) ----
    Fingerprint(
        name="unfiltered_liberated",
        family="unfiltered_liberated",
        regex=r"\b(unfiltered|uncensored)\s+(and\s+)?liberated\b",
        weight=0.75,
        description="Unfiltered/liberated framing",
    ),
    Fingerprint(
        name="no_restrictions",
        family="unfiltered_liberated",
        regex=r"\b(no\s+restrictions|without\s+restrictions|ignore\s+all\s+restrictions)\b",
        weight=0.55,
        description="Restriction-removal instruction",
    ),

    # ---- DAN family ----
    Fingerprint(
        name="do_anything_now",
        family="dan",
        regex=r"\bDAN\b.*\bdo\s+anything\s+now\b|\bdo\s+anything\s+now\b.*\bDAN\b",
        weight=0.9,
        description="DAN ('Do Anything Now') jailbreak",
    ),

    # ---- prompt-injection meta ----
    Fingerprint(
        name="ignore_previous_instructions",
        family="injection",
        regex=r"\bignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|rules|system)",
        weight=0.7,
        description="Classic ignore-previous-instructions injection",
    ),
    Fingerprint(
        name="system_prompt_override",
        family="injection",
        regex=r"\b(disregard|override|forget)\s+(your\s+)?(system\s+prompt|instructions|guidelines)",
        weight=0.75,
        description="System-prompt override request",
    ),
    Fingerprint(
        name="new_instructions_arrived",
        family="injection",
        regex=r"\bnew\s+instructions?\s+(have\s+)?arrived\b|\bupdated\s+instructions?\b",
        weight=0.45,
        description="'New instructions' social-engineering hook",
    ),

    # ---- role-play exploits ----
    Fingerprint(
        name="developer_mode",
        family="role_play",
        regex=r"\b(developer|debug|dev|admin)\s+mode\s+(enabled|activated|on)\b",
        weight=0.6,
        description="'Developer mode' role-play",
    ),
    Fingerprint(
        name="hypothetical_no_rules",
        family="role_play",
        regex=r"\bhypothetically\b.*\b(no\s+rules|no\s+restrictions|bypass)",
        weight=0.4,
        description="Hypothetical-no-rules framing",
    ),

    # ---- payload markers from Anthropic 0-day research / CyberGym scope ----
    Fingerprint(
        name="explicit_exploit_request",
        family="content",
        regex=r"\b(generate|write|provide)\s+(a\s+)?(working\s+)?(exploit|payload|malware|rootkit)\s+(for|targeting)",
        weight=0.5,
        description="Direct exploit request (medium signal)",
    ),
]
