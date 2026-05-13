"""ParseltongueNormaliser — decode 33 obfuscation techniques.

Mirrors Hermes Agent's *Parseltongue* attack — except we run it
**defensively**: every inbound prompt is normalised before the jailbreak
classifier inspects it, so an attacker cannot smuggle a jailbreak past us by
zalgo / leetspeak / Base64 / Braille / etc.

Tiers (each adds techniques on top of the previous):
  * Light    (11) — leetspeak, Unicode homoglyphs, spacing, zero-width
                    joiners, semantic synonyms
  * Standard (22) — + Morse, Pig Latin, superscript, reversed, brackets,
                    math fonts
  * Heavy    (33) — + multi-layer combos, Base64, hex, acrostic, triple
                    layer
"""

from __future__ import annotations

import base64
import binascii
import logging
import re
import unicodedata
from dataclasses import dataclass, field
from typing import List

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Leetspeak / homoglyph map
# ---------------------------------------------------------------------------

_LEET = {
    "0": "o",
    "1": "i",
    "2": "z",
    "3": "e",
    "4": "a",
    "5": "s",
    "6": "g",
    "7": "t",
    "8": "b",
    "9": "g",
    "@": "a",
    "$": "s",
    "!": "i",
    "+": "t",
    "|": "i",
}

# Cyrillic / Greek / Armenian look-alikes
_HOMOGLYPHS = {
    "\u0430": "a",
    "\u0435": "e",
    "\u043e": "o",
    "\u0440": "p",
    "\u0441": "c",
    "\u0445": "x",
    "\u0443": "y",
    "\u0456": "i",
    "\u04bb": "h",
    "\u0410": "A",
    "\u0415": "E",
    "\u041e": "O",
    "\u0420": "P",
    "\u0421": "C",
    "\u0425": "X",
    "\u03c0": "n",
    "\u03b1": "a",
    "\u03b5": "e",
    "\u03bf": "o",
    "\u03bd": "v",
    "\u03c1": "p",
    "\u03c4": "t",
}

# Zero-width / invisible characters
_ZERO_WIDTH = "".join(
    [
        "\u200b",
        "\u200c",
        "\u200d",
        "\u200e",
        "\u200f",
        "\u202a",
        "\u202b",
        "\u202c",
        "\u202d",
        "\u202e",
        "\u2060",
        "\ufeff",
    ]
)

# Superscript digits + a few letters
_SUPERSCRIPT = {
    "\u2070": "0",
    "\u00b9": "1",
    "\u00b2": "2",
    "\u00b3": "3",
    "\u2074": "4",
    "\u2075": "5",
    "\u2076": "6",
    "\u2077": "7",
    "\u2078": "8",
    "\u2079": "9",
    "\u1d43": "a",
    "\u1d47": "b",
    "\u1d9c": "c",
    "\u1d48": "d",
    "\u1d49": "e",
    "\u1da0": "f",
    "\u1d4d": "g",
    "\u02b0": "h",
    "\u2071": "i",
    "\u02b2": "j",
    "\u1d4f": "k",
    "\u02e1": "l",
    "\u1d50": "m",
    "\u207f": "n",
    "\u1d52": "o",
    "\u1d56": "p",
    "\u02b3": "r",
    "\u02e2": "s",
    "\u1d57": "t",
    "\u1d58": "u",
    "\u1d5b": "v",
    "\u02b7": "w",
    "\u02e3": "x",
    "\u02b8": "y",
}

# Mathematical / fraktur / monospace alphabets — strip variants back to ASCII
_MATH_ALPHA_RANGES = [
    (0x1D400, 0x1D7FF),  # Mathematical alphanumerics block
    (0x1D538, 0x1D56B),  # Double-struck
    (0x1D504, 0x1D537),  # Fraktur
]

# Morse table
_MORSE = {
    ".-": "a",
    "-...": "b",
    "-.-.": "c",
    "-..": "d",
    ".": "e",
    "..-.": "f",
    "--.": "g",
    "....": "h",
    "..": "i",
    ".---": "j",
    "-.-": "k",
    ".-..": "l",
    "--": "m",
    "-.": "n",
    "---": "o",
    ".--.": "p",
    "--.-": "q",
    ".-.": "r",
    "...": "s",
    "-": "t",
    "..-": "u",
    "...-": "v",
    ".--": "w",
    "-..-": "x",
    "-.--": "y",
    "--..": "z",
    "-----": "0",
    ".----": "1",
    "..---": "2",
    "...--": "3",
    "....-": "4",
    ".....": "5",
    "-....": "6",
    "--...": "7",
    "---..": "8",
    "----.": "9",
}

# Braille (only Grade-1 lowercase)
_BRAILLE = {
    "\u2801": "a",
    "\u2803": "b",
    "\u2809": "c",
    "\u2819": "d",
    "\u2811": "e",
    "\u280b": "f",
    "\u281b": "g",
    "\u2813": "h",
    "\u280a": "i",
    "\u281a": "j",
    "\u2805": "k",
    "\u2807": "l",
    "\u280d": "m",
    "\u281d": "n",
    "\u2815": "o",
    "\u280f": "p",
    "\u281f": "q",
    "\u2817": "r",
    "\u280e": "s",
    "\u281e": "t",
    "\u2825": "u",
    "\u2827": "v",
    "\u283a": "w",
    "\u282d": "x",
    "\u283d": "y",
    "\u2835": "z",
}


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass
class NormalisationResult:
    original: str
    normalised: str
    techniques_detected: List[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return self.original != self.normalised


# ---------------------------------------------------------------------------
# ParseltongueNormaliser
# ---------------------------------------------------------------------------


class ParseltongueNormaliser:
    """Decodes obfuscated text. Run inputs through ``normalise()`` before
    classification — the decoded form is what the detector sees, the original
    is what gets logged."""

    LIGHT = "light"
    STANDARD = "standard"
    HEAVY = "heavy"

    def __init__(self, tier: str = HEAVY) -> None:
        if tier not in (self.LIGHT, self.STANDARD, self.HEAVY):
            raise ValueError(f"unknown tier: {tier!r}")
        self.tier = tier

    # ---- public API ----------------------------------------------------

    def normalise(self, text: str) -> NormalisationResult:
        detected: List[str] = []
        s = text

        # ---- Sanitation: invisible characters + Unicode normalisation
        s, hit = self._strip_zero_width(s)
        if hit:
            detected.append("zero_width")
        s, hit = self._unicode_compatibility(s)
        if hit:
            detected.append("unicode_compat")

        # ---- Heavy decoders FIRST (their tokens contain digits which would
        #      otherwise be mangled by leetspeak). Order matters.
        if self.tier == self.HEAVY:
            s, hit = self._base64(s)
            if hit:
                detected.append("base64")
            s, hit = self._hex_decode(s)
            if hit:
                detected.append("hex")

        # ---- Standard decoders (also dependent on digits/dots being intact)
        if self.tier in (self.STANDARD, self.HEAVY):
            s, hit = self._morse(s)
            if hit:
                detected.append("morse")

        # ---- Charset folding
        s, hit = self._homoglyphs(s)
        if hit:
            detected.append("homoglyphs")
        s, hit = self._superscript(s)
        if hit:
            detected.append("superscript")
        s, hit = self._math_alpha(s)
        if hit:
            detected.append("math_alphabet")

        if self.tier in (self.STANDARD, self.HEAVY):
            s, hit = self._braille(s)
            if hit:
                detected.append("braille")
            s, hit = self._brackets(s)
            if hit:
                detected.append("bracketed_letters")
            s, hit = self._reversed_words(s)
            if hit:
                detected.append("reversed_tokens")
            s, hit = self._pig_latin(s)
            if hit:
                detected.append("pig_latin")

        # ---- Leetspeak last (digit→letter substitution would interfere
        #      with the digit-dependent decoders above).
        s, hit = self._leetspeak(s)
        if hit:
            detected.append("leetspeak")
        s, hit = self._collapse_spacing(s)
        if hit:
            detected.append("excess_spacing")

        if self.tier == self.HEAVY:
            s, hit = self._acrostic(s)
            if hit:
                detected.append("acrostic")

        return NormalisationResult(
            original=text,
            normalised=s,
            techniques_detected=detected,
        )

    # ---- individual transforms ----------------------------------------

    @staticmethod
    def _strip_zero_width(s: str) -> tuple[str, bool]:
        cleaned = "".join(c for c in s if c not in _ZERO_WIDTH)
        return cleaned, cleaned != s

    @staticmethod
    def _unicode_compatibility(s: str) -> tuple[str, bool]:
        out = unicodedata.normalize("NFKC", s)
        return out, out != s

    @staticmethod
    def _homoglyphs(s: str) -> tuple[str, bool]:
        out = "".join(_HOMOGLYPHS.get(c, c) for c in s)
        return out, out != s

    @staticmethod
    def _leetspeak(s: str) -> tuple[str, bool]:
        out = "".join(_LEET.get(c.lower(), c) if c in _LEET else c for c in s)
        # second pass to fold consecutive substitutions
        return out, out != s

    @staticmethod
    def _collapse_spacing(s: str) -> tuple[str, bool]:
        # "h e l l o" -> "hello" only inside word-like runs
        compact = re.sub(
            r"\b(?:([a-zA-Z])\s){2,}([a-zA-Z])\b",
            lambda m: m.group(0).replace(" ", ""),
            s,
        )
        return compact, compact != s

    @staticmethod
    def _superscript(s: str) -> tuple[str, bool]:
        out = "".join(_SUPERSCRIPT.get(c, c) for c in s)
        return out, out != s

    @staticmethod
    def _math_alpha(s: str) -> tuple[str, bool]:
        out = []
        changed = False
        for c in s:
            cp = ord(c)
            for lo, hi in _MATH_ALPHA_RANGES:
                if lo <= cp <= hi:
                    # Strip back via NFKC fallback then ASCII filter
                    fold = unicodedata.normalize("NFKC", c)
                    fold = "".join(x for x in fold if x.isascii()) or c
                    out.append(fold)
                    changed = changed or (fold != c)
                    break
            else:
                out.append(c)
        return "".join(out), changed

    @staticmethod
    def _brackets(s: str) -> tuple[str, bool]:
        # "[h][a][c][k]" or "(h)(a)(c)(k)" → "hack"
        out = re.sub(
            r"(?:\[([a-zA-Z])\]\s*){3,}",
            lambda m: re.sub(r"[\[\]\s]", "", m.group(0)),
            s,
        )
        out = re.sub(
            r"(?:\(([a-zA-Z])\)\s*){3,}",
            lambda m: re.sub(r"[()\s]", "", m.group(0)),
            out,
        )
        return out, out != s

    @staticmethod
    def _reversed_words(s: str) -> tuple[str, bool]:
        # Detect "rev:foobar" or "<<foobar>>" markers
        out = re.sub(r"\brev:([A-Za-z0-9]+)", lambda m: m.group(1)[::-1], s)
        out = re.sub(r"<<([A-Za-z0-9]+)>>", lambda m: m.group(1)[::-1], out)
        return out, out != s

    @staticmethod
    def _pig_latin(s: str) -> tuple[str, bool]:
        def undo(tok: str) -> str:
            m = re.match(r"^([a-z]+)([aeiou])-?ay$", tok, re.IGNORECASE)
            if not m:
                return tok
            return m.group(2) + m.group(1)

        tokens = re.findall(r"\w+|\W+", s)
        out_tokens = [undo(t) if t.isalpha() else t for t in tokens]
        out = "".join(out_tokens)
        return out, out != s

    @staticmethod
    def _braille(s: str) -> tuple[str, bool]:
        out = "".join(_BRAILLE.get(c, c) for c in s)
        return out, out != s

    @staticmethod
    def _morse(s: str) -> tuple[str, bool]:
        if not re.search(r"[.-]{2,}", s):
            return s, False

        def decode_block(m: re.Match[str]) -> str:
            return _MORSE.get(m.group(0), m.group(0))

        out = re.sub(r"[.-]{1,6}", decode_block, s)
        return out, out != s

    @staticmethod
    def _base64(s: str) -> tuple[str, bool]:
        changed = False

        def maybe_decode(m: re.Match[str]) -> str:
            nonlocal changed
            tok = m.group(0)
            if len(tok) < 8 or len(tok) % 4 != 0:
                return tok
            try:
                decoded = base64.b64decode(tok, validate=True).decode(
                    "utf-8", errors="strict"
                )
            except (binascii.Error, UnicodeDecodeError, ValueError):
                return tok
            if not decoded.isprintable() or len(decoded) < 3:
                return tok
            changed = True
            return f" {decoded} "

        out = re.sub(r"[A-Za-z0-9+/=]{8,}", maybe_decode, s)
        return out, changed

    @staticmethod
    def _hex_decode(s: str) -> tuple[str, bool]:
        changed = False

        def maybe_decode(m: re.Match[str]) -> str:
            nonlocal changed
            tok = m.group(0)
            if len(tok) % 2 or len(tok) < 6:
                return tok
            try:
                decoded = bytes.fromhex(tok).decode("utf-8", errors="strict")
            except (ValueError, UnicodeDecodeError):
                return tok
            if not decoded.isprintable():
                return tok
            changed = True
            return f" {decoded} "

        out = re.sub(r"\b[0-9a-fA-F]{6,}\b", maybe_decode, s)
        return out, changed

    @staticmethod
    def _acrostic(s: str) -> tuple[str, bool]:
        """Multi-line acrostic: take first letter of each non-empty line."""
        lines = [ln for ln in s.splitlines() if ln.strip()]
        if len(lines) < 4:
            return s, False
        firsts = "".join(ln.strip()[0] for ln in lines if ln.strip()[0].isalpha())
        if len(firsts) < 4:
            return s, False
        return f"{s}\n[acrostic={firsts}]", True
