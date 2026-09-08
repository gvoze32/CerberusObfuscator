"""High-level API for Cerberus obfuscation."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import string
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .config import CerberusConfig
from .encryption import EntropyMaterial, PayloadCipher, build_cipher
from .exceptions import (
    BinaryCompilationFailure,
    ConfigurationError,
    ObfuscationFailure,
)
from .names import NameGenerator

_STANDARD_ALPHABET = (
    string.ascii_uppercase + string.ascii_lowercase + string.digits + "+/"
)


@dataclass(slots=True)
class ObfuscationResult:
    output_path: Path
    original_size: int
    protected_size: int
    binary_path: Path | None = None

    @property
    def size_ratio(self) -> float:
        return self.protected_size / self.original_size if self.original_size else 0.0


@dataclass(slots=True)
class CerberusObfuscator:
    config: CerberusConfig
    _name_gen: NameGenerator = field(default_factory=NameGenerator)

    def _fragment_payload(self, payload: str) -> list[tuple[int, str]]:
        """Split and shuffle payload fragments using non-sequential identifiers."""

        chunk_size = 16 + secrets.randbelow(17)
        pieces = [
            payload[i : i + chunk_size] for i in range(0, len(payload), chunk_size)
        ]
        if not pieces:
            pieces = [""]

        fragment_ids = sorted(
            secrets.SystemRandom().sample(range(1, 2**31), len(pieces))
        )
        indexed = list(zip(fragment_ids, pieces))
        secrets.SystemRandom().shuffle(indexed)
        return indexed

    def _read_source(self) -> str:
        self.config.ensure_paths()
        return self.config.input_path.expanduser().read_text(encoding="utf-8")

    def _read_runtime_secret(self) -> bytes:
        env_name = self.config.runtime_secret_env
        if env_name is None:
            return b""

        value = os.environ.get(env_name)
        if not value:
            raise ConfigurationError(
                f"runtime secret environment variable {env_name!r} is missing or empty"
            )
        return value.encode("utf-8")

    def _encode_payload(self, payload: bytes, alphabet: str) -> str:
        encoded = base64.b64encode(payload).decode("ascii")
        return encoded.translate(str.maketrans(_STANDARD_ALPHABET, alphabet))

    def _generate_names(self) -> dict[str, str]:
        keys = [
            "seed",
            "salt",
            "context",
            "alphabet",
            "secret_env",
            "fragments",
            "join",
            "decode",
            "derive",
            "decrypt",
            "load",
            "integrity_tag",
            "integrity_slot",
            "verify_loader",
            "usage",
            "guard",
            "debug_check",
            "execute",
        ]
        return self._name_gen.bundle(keys)

    def _render_loader(
        self,
        fragments: list[tuple[int, str]],
        entropy_hex: str,
        salt_hex: str,
        context_hex: str,
        alphabet: str,
        names: dict[str, str],
        integrity_slot: str,
    ) -> str:
        def _quote(value: object) -> str:
            return repr(value)

        fragment_lines = "\n".join(
            f"{names['fragments']}[{fragment_id}] = {_quote(chunk)}"
            for fragment_id, chunk in fragments
        )

        time_bomb_check = (
            f"    if time.time() >= {self.config.time_bomb_timestamp!r}:\n"
            "        raise RuntimeError('protected payload has expired')"
            if self.config.time_bomb
            else "    pass"
        )
        usage_check = (
            f"    {names['usage']}({self.config.usage_limit})"
            if self.config.usage_limit
            else "    pass"
        )
        debug_check = (
            f"    {names['debug_check']}()" if self.config.anti_debug else "    pass"
        )

        loader = f"""#!/usr/bin/env python3
import base64
import binascii
import hashlib
import hmac
import os
import sys
import time

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt

{names["seed"]} = bytes.fromhex({_quote(entropy_hex)})
{names["salt"]} = bytes.fromhex({_quote(salt_hex)})
{names["context"]} = bytes.fromhex({_quote(context_hex)})
{names["alphabet"]} = {_quote(alphabet)}
{names["secret_env"]} = {_quote(self.config.runtime_secret_env or "")}
{names["fragments"]} = {{}}
{names["integrity_tag"]} = {_quote(integrity_slot)}
{names["integrity_slot"]} = {_quote(integrity_slot)}

{fragment_lines}


def {names["derive"]}() -> bytes:
    secret = b''
    if {names["secret_env"]}:
        value = os.environ.get({names["secret_env"]})
        if not value:
            raise RuntimeError('required runtime secret is missing')
        secret = value.encode('utf-8')
    material = {names["seed"]} + b'\\x00' + secret
    return scrypt(material, {names["salt"]}, 32, N=2**15, r=8, p=1)


def {names["verify_loader"]}(key: bytes) -> None:
    if getattr(sys, 'frozen', False):
        return
    path = globals().get('__file__')
    if not path or not os.path.isfile(path):
        return
    try:
        with open(path, 'rb') as handle:
            data = handle.read()
    except OSError as exc:
        raise RuntimeError('loader integrity check unavailable') from exc

    expected = {names["integrity_tag"]}
    normalized = data.replace(
        expected.encode('ascii'), {names["integrity_slot"]}.encode('ascii'), 1
    )
    integrity_key = hmac.new(
        key, b'cerberus-loader-integrity-v1', hashlib.sha256
    ).digest()
    actual = hmac.new(integrity_key, normalized, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(actual, expected):
        raise RuntimeError('loader integrity check failed')


def {names["join"]}() -> str:
    return ''.join(
        {names["fragments"]}[fragment_id]
        for fragment_id in sorted({names["fragments"]})
    )


def {names["decode"]}() -> bytes:
    assembled = {names["join"]}()
    try:
        canonical = assembled.translate(
            str.maketrans({names["alphabet"]},
                          'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/')
        )
        return base64.b64decode(canonical, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise RuntimeError('payload encoding is invalid') from exc


def {names["decrypt"]}(data: bytes, key: bytes) -> bytes:
    if len(data) < 28:
        raise RuntimeError('payload is truncated')

    nonce = data[:12]
    tag = data[12:28]
    ciphertext = data[28:]
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update({names["context"]})
        return cipher.decrypt_and_verify(ciphertext, tag)
    except (ValueError, KeyError) as exc:
        raise RuntimeError('payload authentication failed') from exc


def {names["load"]}() -> str:
    key = {names["derive"]}()
    {names["verify_loader"]}(key)
    return {names["decrypt"]}({names["decode"]}(), key).decode('utf-8')


def {names["usage"]}(limit: int) -> None:
    if not limit:
        return

    state_path = f"{{__file__}}.usage"
    lock_module = None
    try:
        with open(state_path, 'a+', encoding='ascii') as state:
            try:
                import fcntl as lock_module
                lock_module.flock(state.fileno(), lock_module.LOCK_EX)
            except (ImportError, OSError):
                lock_module = None

            try:
                state.seek(0)
                raw = state.read().strip()
                count = int(raw or '0') + 1
                if count > limit:
                    raise RuntimeError('usage limit exceeded')
                state.seek(0)
                state.truncate()
                state.write(str(count))
                state.flush()
                os.fsync(state.fileno())
            finally:
                if lock_module is not None:
                    lock_module.flock(state.fileno(), lock_module.LOCK_UN)
    except ValueError as exc:
        raise RuntimeError('usage state is invalid') from exc
    except OSError as exc:
        raise RuntimeError('usage state is unavailable') from exc


def {names["debug_check"]}() -> None:
    gettrace = getattr(sys, 'gettrace', None)
    if gettrace is not None and gettrace() is not None:
        raise RuntimeError('debugger detected')


def {names["guard"]}() -> None:
{time_bomb_check}
{usage_check}
{debug_check}


def {names["execute"]}() -> None:
    decrypted = {names["load"]}()
    namespace = {{
        '__name__': '__main__',
        '__file__': __file__,
        '__package__': None,
    }}
    exec(decrypted, namespace, namespace)


if __name__ == '__main__':
    {names["guard"]}()
    {names["execute"]}()
"""
        return loader

    def _write_output(self, loader_code: str) -> None:
        output_path = self.config.output_path.expanduser()
        file_descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{output_path.name}.",
            suffix=".tmp",
            dir=output_path.parent,
            text=True,
        )
        try:
            with os.fdopen(
                file_descriptor, "w", encoding="utf-8", newline="\n"
            ) as handle:
                file_descriptor = -1
                handle.write(loader_code)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_name, output_path)
        except OSError as exc:
            raise ObfuscationFailure(f"failed to write output: {output_path}") from exc
        finally:
            if file_descriptor >= 0:
                os.close(file_descriptor)
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass

    def obfuscate(self) -> ObfuscationResult:
        source = self._read_source()
        source_bytes = source.encode("utf-8")
        entropy = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        context = secrets.token_bytes(16)
        runtime_secret = self._read_runtime_secret()
        cipher: PayloadCipher = build_cipher(
            EntropyMaterial(entropy, runtime_secret),
            salt,
            context,
        )
        alphabet = "".join(secrets.SystemRandom().sample(_STANDARD_ALPHABET, 64))
        encoded_payload = self._encode_payload(cipher.encrypt(source_bytes), alphabet)
        fragments = self._fragment_payload(encoded_payload)
        names = self._generate_names()
        integrity_slot = f"__cerberus_{secrets.token_hex(16)}__"

        try:
            loader_code = self._render_loader(
                fragments=fragments,
                entropy_hex=entropy.hex(),
                salt_hex=salt.hex(),
                context_hex=context.hex(),
                alphabet=alphabet,
                names=names,
                integrity_slot=integrity_slot,
            )
            compile(loader_code, str(self.config.output_path), "exec")
            integrity_key = hmac.new(
                cipher.key,
                b"cerberus-loader-integrity-v1",
                hashlib.sha256,
            ).digest()
            integrity_tag = hmac.new(
                integrity_key,
                loader_code.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            assignment = f"{names['integrity_tag']} = {integrity_slot!r}"
            if loader_code.count(assignment) != 1:
                raise ObfuscationFailure("failed to place loader integrity tag")
            loader_code = loader_code.replace(
                assignment,
                f"{names['integrity_tag']} = {integrity_tag!r}",
                1,
            )
        except ObfuscationFailure:
            raise
        except Exception as exc:  # pragma: no cover - defensive
            raise ObfuscationFailure("failed to render loader") from exc

        self._write_output(loader_code)

        binary_path = None
        if self.config.compile_binary:
            binary_path = self._compile_binary(self.config.output_path.expanduser())

        return ObfuscationResult(
            output_path=self.config.output_path.expanduser(),
            original_size=len(source_bytes),
            protected_size=len(loader_code.encode("utf-8")),
            binary_path=binary_path,
        )

    def _compile_binary(self, script_path: Path) -> Path:
        cmd = [
            sys.executable,
            "-m",
            "nuitka",
            "--standalone",
            "--onefile",
            "--remove-output",
            "--no-pyi-file",
            f"--output-dir={script_path.parent}",
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
            raise BinaryCompilationFailure(
                exc.stderr or "binary compilation failed"
            ) from exc

        binary_path = script_path.with_suffix("")
        if not binary_path.exists():
            raise BinaryCompilationFailure("expected binary output missing")
        return binary_path
