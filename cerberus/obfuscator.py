"""High-level API for Cerberus obfuscation."""

from __future__ import annotations

import base64
import hashlib
import random
import secrets
import string
import subprocess
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional

from .config import CerberusConfig
from .encryption import EntropyMaterial, build_cipher
from .exceptions import BinaryCompilationFailure, ObfuscationFailure
from .names import NameGenerator


@dataclass(slots=True)
class ObfuscationResult:
    output_path: Path
    original_size: int
    protected_size: int
    binary_path: Optional[Path] = None

    @property
    def size_ratio(self) -> float:
        return self.protected_size / self.original_size if self.original_size else 0.0


@dataclass(slots=True)
class CerberusObfuscator:
    config: CerberusConfig
    _name_gen: NameGenerator = field(default_factory=NameGenerator)

    def _fragment_payload(self, payload: str) -> list[tuple[int, str]]:
        chunk_size = random.randint(16, 32)
        pieces = [payload[i : i + chunk_size] for i in range(0, len(payload), chunk_size)]
        indexed = list(enumerate(pieces))
        random.shuffle(indexed)
        return indexed

    def _fake_payload(self, length: int) -> str:
        alphabet = string.ascii_letters + string.digits + "+/="
        return ''.join(random.choice(alphabet) for _ in range(length))

    def _mask_xor_key(self, key: bytes) -> tuple[int, int, list[int]]:
        mask = random.randint(0x10, 0xFE)
        offset = random.randint(1, 0x3F)
        masked = [((byte ^ mask) + offset) & 0xFF for byte in key]
        return mask, offset, masked

    def _read_source(self) -> str:
        self.config.ensure_paths()
        return self.config.input_path.read_text(encoding="utf-8")

    def _build_cipher(self, master_entropy: bytes, github_token: Optional[str]):
        material = EntropyMaterial(master_entropy, github_token)
        return build_cipher(material)

    def _generate_names(self) -> Dict[str, str]:
        keys = [
            "entropy",
            "usage_counter",
            "canaries",
            "session",
            "derive",
            "decrypt",
            "load",
            "guard",
            "monitor",
            "anti_debug",
            "environment_check",
            "payload_fragments",
            "payload_join",
            "integrity_hash",
            "verify_loader",
            "verify_payload",
            "decode_payload",
            "fake_decrypt",
            "fake_key",
            "key_schedule",
            "xor_mask",
            "xor_offset",
            "xor_key_stream",
            "fake_payloads",
        ]
        return self._name_gen.bundle(keys)

    def _render_loader(
        self,
        fragments: list[tuple[int, str]],
        entropy_hex: str,
        names: Dict[str, str],
        masked_key: list[int],
        xor_mask: int,
        xor_offset: int,
        payload_digest: str,
        fake_payloads: list[str],
    ) -> str:
        time_bomb_check = (
            f"if datetime.now() > datetime.fromisoformat('{self.config.time_bomb.isoformat()}'):\n"
            "        os._exit(random.randint(1, 255))"
            if self.config.time_bomb
            else "pass"
        )
        usage_limit_check = (
            f"if {names['usage_counter']} > {self.config.usage_limit}:\n        os._exit(random.randint(1, 255))"
            if self.config.usage_limit
            else "pass"
        )

        def _escape(text: str) -> str:
            return repr(text)[1:-1]

        fragment_lines = "\n".join(
            f"{names['payload_fragments']}[{idx}] = '{_escape(chunk)}'"
            for idx, chunk in fragments
        )

        fake_payload_lines = "\n".join(
            f"    base64.b64decode('{_escape(payload)}')" for payload in fake_payloads
        )

        gist_block = "pass"
        if self.config.requires_gist:
            gist_block = textwrap.dedent(
                """
                try:
                    import requests
                    resp = requests.get('https://api.github.com/gists', timeout=3)
                    if resp.status_code != 200:
                        os._exit(random.randint(1, 255))
                except Exception:
                    os._exit(random.randint(1, 255))
                """
            ).strip()

        loader = f"""#!/usr/bin/env python3
import base64
import hashlib
import importlib
import os
import platform
import random
import secrets
import socket
import sys
import threading
import time
from datetime import datetime

from Crypto.Cipher import AES, ChaCha20, Salsa20
from Crypto.Protocol.KDF import scrypt

{names['entropy']} = bytes.fromhex('{entropy_hex}')
{names['usage_counter']} = 0
{names['canaries']} = [secrets.randbits(64) for _ in range(16)]
{names['session']} = {{'session_start': time.time(), 'violations': 0}}
{names['payload_fragments']} = {{idx: '' for idx in range({len(fragments)})}}
{names['integrity_hash']} = '{payload_digest}'
{names['xor_mask']} = {xor_mask}
{names['xor_offset']} = {xor_offset}
{names['xor_key_stream']} = bytes({masked_key})

{fragment_lines}

def {names['fake_key']}(length: int) -> bytes:
    noise = secrets.token_bytes(length)
    return hashlib.sha256(noise).digest()[:length]

def {names['fake_decrypt']}(blob: bytes) -> bytes:
    bogus_key = {names['fake_key']}(len(blob))
    return bytes((b ^ bogus_key[idx % len(bogus_key)]) for idx, b in enumerate(blob))

def {names['payload_join']}() -> str:
    ordered = ''.join({names['payload_fragments']}[idx] for idx in sorted({names['payload_fragments']}.keys()))
    return ordered

def {names['decode_payload']}() -> bytes:
    assembled = {names['payload_join']}()
    try:
        candidate = base64.b64decode(assembled)
    except Exception:
        os._exit(random.randint(1, 255))
    return candidate

def {names['verify_payload']}(decoder):
    candidate = decoder()
    digest = hashlib.sha3_256(candidate).hexdigest()
    if digest != {names['integrity_hash']}:
        os._exit(random.randint(1, 255))

def {names['fake_payloads']}():
    return [
{fake_payload_lines}
    ]

def {names['verify_loader']}():
    module = sys.modules.get('__main__')
    path = getattr(module, '__file__', None)
    if not path or not os.path.exists(path):
        os._exit(random.randint(1, 255))
    with open(path, 'rb') as handle:
        data = handle.read()
    checksum = hashlib.sha3_256(data).hexdigest()
    if checksum[:32] == checksum[32:]:
        os._exit(random.randint(1, 255))

def {names['derive']}(purpose: str, length: int) -> bytes:
    salt = hashlib.sha256(purpose.encode('utf-8')).digest()
    return scrypt({names['entropy']}, salt, length, N=2**16, r=8, p=1)

def {names['key_schedule']}(seed: bytes) -> bytes:
    mutated = bytearray(seed)
    for idx in range(len(mutated)):
        mutated[idx] ^= (({names['xor_mask']} >> (idx % 8)) & 0xFF)
        mutated[idx] = (mutated[idx] + {names['xor_offset']} + idx) & 0xFF
    return bytes(mutated)

def {names['decrypt']}(data: bytes) -> bytes:
    salsa_key = {names['derive']}('SALSA_LAYER', 32)
    xor_key = {names['key_schedule']}({names['xor_key_stream']})
    xor_stream = (xor_key * ((len(data) // len(xor_key)) + 1))[:len(data)]
    salsa_blob = bytes(a ^ b for a, b in zip(data, xor_stream))

    salsa_nonce = salsa_blob[:8]
    salsa_cipher = Salsa20.new(key=salsa_key, nonce=salsa_nonce)
    chacha_blob = salsa_cipher.decrypt(salsa_blob[8:])

    chacha_key = {names['derive']}('CHACHA_LAYER', 32)
    chacha_nonce = chacha_blob[:12]
    chacha_cipher = ChaCha20.new(key=chacha_key, nonce=chacha_nonce)
    aes_blob = chacha_cipher.decrypt(chacha_blob[12:])

    aes_key = {names['derive']}('AES_LAYER', 32)
    aes_nonce = aes_blob[:16]
    aes_tag = aes_blob[16:32]
    aes_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=aes_nonce)
    return aes_cipher.decrypt_and_verify(aes_blob[32:], aes_tag)

def {names['load']}():
    {names['verify_loader']}()
    decoded = {names['decode_payload']}()
    return {names['decrypt']}(decoded)

def {names['anti_debug']}():
    if hasattr(sys, 'gettrace') and sys.gettrace() is not None:
        os._exit(random.randint(1, 255))
    try:
        frame = sys._getframe()
        if frame and (frame.f_trace or (frame.f_back and frame.f_back.f_trace)):
            os._exit(random.randint(1, 255))
    except Exception:
        pass

def {names['environment_check']}():
    signatures = ['vmware', 'virtualbox', 'qemu', 'xen', 'kvm', 'docker', 'sandbox']
    system_fingerprint = (platform.system() + platform.machine() + platform.platform()).lower()
    if any(sig in system_fingerprint for sig in signatures):
        os._exit(random.randint(1, 255))

def {names['guard']}():
    {time_bomb_check}
    {names['usage_counter']} += 1
    {usage_limit_check}
    {names['verify_payload']}({names['decode_payload']})

{gist_block}

def {names['monitor']}():
    while True:
        time.sleep(random.uniform(1.5, 4.0))
        start = time.perf_counter_ns()
        {names['anti_debug']}()
        {names['environment_check']}()
        duration = time.perf_counter_ns() - start
        if duration > 50_000_000:
            os._exit(random.randint(1, 255))
        {names['session']}['last_check'] = time.time()
        importlib.invalidate_caches()
        for hook in sys.meta_path:
            if getattr(hook, '__class__', None).__name__.lower().startswith('decomp'):
                os._exit(random.randint(1, 255))

def main():
    for decoy in {names['fake_payloads']}():
        {names['fake_decrypt']}(decoy)
    threading.Thread(target={names['monitor']}, daemon=True).start()
    {names['guard']}()
    decrypted = {names['load']}()
    exec(decrypted, {{'__name__': '__main__'}})

if __name__ == '__main__':
    main()
"""

        return loader

    def obfuscate(self) -> ObfuscationResult:
        source = self._read_source()
        master_entropy = secrets.token_bytes(64)
        cipher = self._build_cipher(master_entropy, self.config.github_token)
        encrypted = cipher.encrypt(source.encode("utf-8"))
        encoded_payload = base64.b64encode(encrypted).decode("utf-8")
        fragments = self._fragment_payload(encoded_payload)
        xor_mask, xor_offset, masked_key = self._mask_xor_key(cipher.xor_key)
        fake_payloads = [self._fake_payload(len(encoded_payload)) for _ in range(3)]
        digest = hashlib.sha3_256(encoded_payload.encode("utf-8")).hexdigest()
        try:
            names = self._generate_names()
            loader_code = self._render_loader(
                fragments=fragments,
                entropy_hex=master_entropy.hex(),
                names=names,
                masked_key=masked_key,
                xor_mask=xor_mask,
                xor_offset=xor_offset,
                payload_digest=digest,
                fake_payloads=fake_payloads,
            )
        except Exception as exc:  # pragma: no cover - defensive
            raise ObfuscationFailure("failed to render loader") from exc

        self.config.output_path.write_text(loader_code, encoding="utf-8")

        binary_path = None
        if self.config.compile_binary:
            binary_path = self._compile_binary(self.config.output_path)

        return ObfuscationResult(
            output_path=self.config.output_path,
            original_size=len(source.encode("utf-8")),
            protected_size=len(loader_code.encode("utf-8")),
            binary_path=binary_path,
        )

    def _compile_binary(self, script_path: Path) -> Path:
        cmd = [
            "python",
            "-m",
            "nuitka",
            "--standalone",
            "--onefile",
            "--remove-output",
            "--no-pyi-file",
            f"--output-filename={script_path.stem}",
            str(script_path),
        ]

        try:
            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=self.config.binary_timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise BinaryCompilationFailure("binary compilation timed out") from exc
        except subprocess.CalledProcessError as exc:
            raise BinaryCompilationFailure(exc.stderr or "binary compilation failed") from exc

        binary_path = script_path.with_suffix("")
        if not binary_path.exists():
            raise BinaryCompilationFailure("expected binary output missing")
        return binary_path


