"""Configuration management for the Cerberus obfuscator."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .exceptions import ConfigurationError

_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


@dataclass(slots=True)
class CerberusConfig:
    """Validated configuration for one obfuscation build."""

    input_path: Path
    output_path: Path
    runtime_secret_env: str | None = None
    compile_binary: bool = False
    time_bomb: datetime | None = None
    usage_limit: int = 0
    binary_timeout: int = 300
    anti_debug: bool = False

    def __post_init__(self) -> None:
        if self.usage_limit < 0:
            raise ConfigurationError("usage_limit must be non-negative")

        if (
            self.time_bomb
            and self.time_bomb_timestamp <= datetime.now(timezone.utc).timestamp()
        ):
            raise ConfigurationError("time_bomb must be a future datetime")

        if self.binary_timeout <= 0:
            raise ConfigurationError("binary_timeout must be positive")

        if self.runtime_secret_env is not None and not _ENV_NAME.fullmatch(
            self.runtime_secret_env
        ):
            raise ConfigurationError(
                "runtime_secret_env must be a valid environment variable name"
            )

    @property
    def time_bomb_timestamp(self) -> float:
        """Return the expiry instant as a UTC Unix timestamp."""

        if self.time_bomb is None:
            raise ConfigurationError("time_bomb is not configured")

        value = self.time_bomb
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).timestamp()

    def ensure_paths(self) -> None:
        """Ensure the input exists and the output cannot overwrite it."""

        input_path = self.input_path.expanduser()
        output_path = self.output_path.expanduser()

        if not input_path.exists():
            raise FileNotFoundError(f"Input file does not exist: {input_path}")
        if not input_path.is_file():
            raise IsADirectoryError(f"Input path is not a file: {input_path}")

        try:
            if input_path.resolve() == output_path.resolve():
                raise ConfigurationError("input and output paths must be different")
            output_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ConfigurationError(
                f"unable to prepare output path: {output_path}"
            ) from exc
