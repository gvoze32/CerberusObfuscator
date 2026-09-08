"""Cryptographic primitives used by the Cerberus obfuscator."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

KDF_N = 2**15
KDF_R = 8
KDF_P = 1
PAYLOAD_AAD = b"cerberus-payload-v4"
NONCE_SIZE = 12
TAG_SIZE = 16


class KeyDerivationError(RuntimeError):
    """Raised when a symmetric key cannot be derived."""


class PayloadDecryptionError(RuntimeError):
    """Raised when an authenticated payload cannot be decrypted."""


@dataclass(slots=True)
class EntropyMaterial:
    """Build-time entropy plus an optional secret supplied at runtime."""

    entropy: bytes
    runtime_secret: bytes | None = None

    def material(self) -> bytes:
        if not self.entropy:
            raise ValueError("entropy must not be empty")

        secret = self.runtime_secret or b""
        return self.entropy + b"\x00" + secret


def derive_key(material: EntropyMaterial, salt: bytes, length: int = 32) -> bytes:
    """Derive a payload key using a per-build random salt."""

    if len(salt) < 16:
        raise KeyDerivationError("salt must contain at least 128 bits")
    if length <= 0:
        raise KeyDerivationError("key length must be positive")

    try:
        return cast(
            bytes,
            scrypt(material.material(), salt, length, N=KDF_N, r=KDF_R, p=KDF_P),  # type: ignore[arg-type]
        )
    except Exception as exc:  # pragma: no cover - defensive
        raise KeyDerivationError("failed to derive key") from exc


@dataclass(slots=True)
class PayloadCipher:
    """AES-GCM payload cipher with explicit framing and authentication."""

    key: bytes
    associated_data: bytes = PAYLOAD_AAD

    def encrypt(self, payload: bytes) -> bytes:
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=get_random_bytes(NONCE_SIZE))
        cipher.update(self.associated_data)
        ciphertext, tag = cipher.encrypt_and_digest(payload)
        return bytes(cipher.nonce) + bytes(tag) + bytes(ciphertext)

    def decrypt(self, payload: bytes) -> bytes:
        if len(payload) < NONCE_SIZE + TAG_SIZE:
            raise PayloadDecryptionError("payload is truncated")

        nonce = payload[:NONCE_SIZE]
        tag = payload[NONCE_SIZE : NONCE_SIZE + TAG_SIZE]
        ciphertext = payload[NONCE_SIZE + TAG_SIZE :]

        try:
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
            cipher.update(self.associated_data)
            return cipher.decrypt_and_verify(ciphertext, tag)
        except Exception as exc:  # pragma: no cover - defensive
            raise PayloadDecryptionError("payload authentication failed") from exc


def build_cipher(
    material: EntropyMaterial,
    salt: bytes,
    associated_data: bytes | None = None,
) -> PayloadCipher:
    """Construct an authenticated payload cipher for one build."""

    return PayloadCipher(
        key=derive_key(material, salt),
        associated_data=associated_data or PAYLOAD_AAD,
    )
