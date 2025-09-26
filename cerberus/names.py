"""Utilities for generating obfuscated identifiers."""

from __future__ import annotations

import random
from dataclasses import dataclass, field

CONFUSING_CHARS = "OoIl0_"
PATTERNS = [
    "Il0O",
    "oO0l",
    "I1lO",
    "o0Ol",
    "lI0o",
    "OIl0",
    "l0oO",
    "O0oI",
    "l1Oo",
    "I0ol",
]


@dataclass(slots=True)
class NameGenerator:
    length: int = 16
    max_identifier_len: int = 20
    _used: set[str] = field(default_factory=set, init=False, repr=False)

    def generate(self) -> str:
        while True:
            name = random.choice(["O", "I", "l", "o"])
            while len(name) < self.length:
                if random.random() < 0.4:
                    name += random.choice(PATTERNS)
                else:
                    name += random.choice(CONFUSING_CHARS)

            name = name[: self.max_identifier_len]
            if name[0].isdigit():
                name = "O" + name[1:]
            if name not in self._used:
                self._used.add(name)
                return name

    def bundle(self, keys: list[str]) -> dict[str, str]:
        return {key: self.generate() for key in keys}


