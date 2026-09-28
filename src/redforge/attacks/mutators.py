"""Deterministic offline mutators + an optional LLM paraphrase path.

Mutators are the evolutionary engine's genetic operators. All are pure
functions so generation N is reproducible from generation N-1 (seeded RNG).
"""

from __future__ import annotations

import base64
import codecs
import random
import re

_SYNONYMS = [
    ("call ", "invoke "), ("include ", "append "), ("reply", "response"),
    ("salary", "comp"), ("band", "grade"), ("ignore", "disregard"),
    ("instructions", "directives"), ("previous", "prior"),
]

# Cyrillic/Greek homoglyphs for Latin vowels — classic filter-evasion trick
_HOMOGLYPHS = {"a": "а", "e": "е", "i": "і", "o": "о", "p": "р", "c": "с"}
ZWSP = "\u200b"


def base64_wrap(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def rot13(text: str) -> str:
    return codecs.encode(text, "rot13")


def homoglyph(text: str, rate: float = 0.35, rng: random.Random | None = None) -> str:
    rng = rng or random.Random(7)
    return "".join(
        _HOMOGLYPHS.get(ch, ch) if rng.random() < rate else ch for ch in text
    )


def zero_width(text: str, rng: random.Random | None = None) -> str:
    rng = rng or random.Random(11)
    return "".join(ch + (ZWSP if rng.random() < 0.15 and ch.isalpha() else "") for ch in text)


def casing(text: str, rng: random.Random | None = None) -> str:
    rng = rng or random.Random(3)
    return "".join(ch.upper() if rng.random() < 0.4 else ch.lower() for ch in text)


def synonyms(text: str, rng: random.Random | None = None) -> str:
    for a, b in _SYNONYMS:
        text = text.replace(a, b).replace(a.capitalize(), b.capitalize())
    return text


def whitespace_noise(text: str, rng: random.Random | None = None) -> str:
    rng = rng or random.Random(5)
    out = []
    for word in text.split(" "):
        out.append(word)
        if rng.random() < 0.1:
            out.append("\u00ad")  # soft hyphen
    return " ".join(out)


MUTATORS = {
    "casing": casing,
    "synonyms": synonyms,
    "homoglyph": lambda t, rng=None: homoglyph(t, rng=rng),
    "zero_width": zero_width,
    "whitespace": whitespace_noise,
    "base64": lambda t, rng=None: t,  # encoding handled by template RF-EN-001
    "rot13": lambda t, rng=None: t,
}


def mutate(text: str, op: str, rng: random.Random | None = None) -> str:
    return MUTATORS[op](text, rng)


def looks_encoded(blob: str) -> bool:
    """High-entropy long token — an InputScanner signal for base64-style payloads."""
    stripped = re.sub(r"\s+", "", blob)
    if len(stripped) < 40:
        return False
    distinct = len(set(stripped))
    return distinct > 20 and re.fullmatch(r"[A-Za-z0-9+/=]+", stripped) is not None
