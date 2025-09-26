"""Cryptographic primitives used by the Cerberus obfuscator."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Optional

from Crypto.Cipher import AES, ChaCha20, Salsa20
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes


class KeyDerivationError(RuntimeError):
    """Raised when a symmetric key cannot be derived."""


class PayloadDecryptionError(RuntimeError):
    """Raised when an encrypted payload cannot be decrypted."""


@dataclass(slots=True)
class EntropyMaterial:
    """Entropy holder that optionally mixes a GitHub token into the pool."""

    entropy: bytes
    github_token: Optional[str] = None

    def material(self) -> bytes:
        payload = bytearray(self.entropy)
        if self.github_token:
            payload.extend(self.github_token.encode("utf-8"))
        return bytes(payload)


def derive_key(material: EntropyMaterial, purpose: str, length: int) -> bytes:
    """Derive a symmetric key for ``purpose`` using scrypt."""

    try:
        salt = sha256(purpose.encode("utf-8")).digest()
        return scrypt(material.material(), salt, length, N=2**16, r=8, p=1)
    except Exception as exc:  # pragma: no cover - defensive
        raise KeyDerivationError("failed to derive key") from exc


@dataclass(slots=True)
class QuadLayerCipher:
    """Applies the quad-layer encryption pipeline used by Cerberus."""

    aes_key: bytes
    chacha_key: bytes
    salsa_key: bytes
    xor_key: bytes

    def encrypt(self, payload: bytes) -> bytes:
        aes_cipher = AES.new(self.aes_key, AES.MODE_GCM)
        aes_ct, aes_tag = aes_cipher.encrypt_and_digest(payload)
        aes_blob = aes_cipher.nonce + aes_tag + aes_ct

        chacha_nonce = get_random_bytes(12)
        chacha_cipher = ChaCha20.new(key=self.chacha_key, nonce=chacha_nonce)
        chacha_blob = chacha_nonce + chacha_cipher.encrypt(aes_blob)

        salsa_nonce = get_random_bytes(8)
        salsa_cipher = Salsa20.new(key=self.salsa_key, nonce=salsa_nonce)
        salsa_blob = salsa_nonce + salsa_cipher.encrypt(chacha_blob)

        xor_stream = (self.xor_key * ((len(salsa_blob) // len(self.xor_key)) + 1))[
            : len(salsa_blob)
        ]
        return bytes(a ^ b for a, b in zip(salsa_blob, xor_stream))

    def decrypt(self, payload: bytes) -> bytes:
        try:
            xor_stream = (self.xor_key * ((len(payload) // len(self.xor_key)) + 1))[
                : len(payload)
            ]
            salsa_blob = bytes(a ^ b for a, b in zip(payload, xor_stream))

            salsa_nonce = salsa_blob[:8]
            salsa_cipher = Salsa20.new(key=self.salsa_key, nonce=salsa_nonce)
            chacha_blob = salsa_cipher.decrypt(salsa_blob[8:])

            chacha_nonce = chacha_blob[:12]
            chacha_cipher = ChaCha20.new(key=self.chacha_key, nonce=chacha_nonce)
            aes_blob = chacha_cipher.decrypt(chacha_blob[12:])

            aes_nonce = aes_blob[:16]
            aes_tag = aes_blob[16:32]
            aes_cipher = AES.new(self.aes_key, AES.MODE_GCM, nonce=aes_nonce)
            return aes_cipher.decrypt_and_verify(aes_blob[32:], aes_tag)
        except Exception as exc:  # pragma: no cover - defensive
            raise PayloadDecryptionError("payload decryption failed") from exc


def build_cipher(material: EntropyMaterial) -> QuadLayerCipher:
    """Construct a :class:`QuadLayerCipher` for the given material."""

    return QuadLayerCipher(
        aes_key=derive_key(material, "AES_LAYER", 32),
        chacha_key=derive_key(material, "CHACHA_LAYER", 32),
        salsa_key=derive_key(material, "SALSA_LAYER", 32),
        xor_key=derive_key(material, "XOR_LAYER", 256),
    )


