"""Utilities for generating obfuscated identifiers."""

from __future__ import annotations

import keyword
import secrets
import string
from dataclasses import dataclass, field

_IDENTIFIER_CHARS = string.ascii_letters


@dataclass(slots=True)
class NameGenerator:
    length: int = 20
    max_identifier_len: int = 24
    _used: set[str] = field(default_factory=set, init=False, repr=False)

    def generate(self) -> str:
        if self.length < 1 or self.max_identifier_len < 1:
            raise ValueError("identifier lengths must be positive")

        length = min(self.length, self.max_identifier_len)
        while True:
            name = secrets.choice(string.ascii_letters)
            name += "".join(
                secrets.choice(_IDENTIFIER_CHARS) for _ in range(length - 1)
            )
            if keyword.iskeyword(name):
                name = f"_{name}"
            if name not in self._used:
                self._used.add(name)
                return name

    def bundle(self, keys: list[str]) -> dict[str, str]:
        return {key: self.generate() for key in keys}
