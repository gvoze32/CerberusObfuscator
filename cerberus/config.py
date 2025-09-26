"""Configuration management for the Cerberus obfuscator."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional


@dataclass(slots=True)
class CerberusConfig:
    """Immutable configuration for the Cerberus obfuscator."""

    input_path: Path
    output_path: Path
    github_token: Optional[str] = None
    compile_binary: bool = False
    time_bomb: Optional[datetime] = None
    usage_limit: int = 0
    binary_timeout: int = 300

    def __post_init__(self) -> None:
        if self.usage_limit < 0:
            msg = "usage_limit must be non-negative"
            raise ValueError(msg)

        if self.time_bomb and self.time_bomb <= datetime.now():
            msg = "time_bomb must be a future datetime"
            raise ValueError(msg)

        if self.binary_timeout <= 0:
            msg = "binary_timeout must be positive"
            raise ValueError(msg)

    @property
    def requires_gist(self) -> bool:
        return self.github_token is not None

    def ensure_paths(self) -> None:
        """Ensure input exists and parent of output is ready."""

        if not self.input_path.exists():
            msg = f"Input file does not exist: {self.input_path}"
            raise FileNotFoundError(msg)

        if not self.input_path.is_file():
            msg = f"Input path is not a file: {self.input_path}"
            raise IsADirectoryError(msg)

        output_parent = self.output_path.parent
        output_parent.mkdir(parents=True, exist_ok=True)


