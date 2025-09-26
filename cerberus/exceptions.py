"""Custom exception hierarchy for the Cerberus obfuscator."""

from __future__ import annotations


class CerberusError(RuntimeError):
    """Base error for the Cerberus obfuscator."""


class ConfigurationError(CerberusError):
    """Raised when configuration values are invalid."""


class ObfuscationFailure(CerberusError):
    """Raised when the obfuscation pipeline encounters a fatal error."""


class BinaryCompilationFailure(CerberusError):
    """Raised when Nuitka binary compilation fails."""


