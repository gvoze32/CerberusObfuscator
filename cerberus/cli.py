"""Command line entry-point for Cerberus."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from .config import CerberusConfig
from .exceptions import BinaryCompilationFailure, CerberusError
from .obfuscator import CerberusObfuscator


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cerberus",
        description="Cerberus Ultra-Secure Python Obfuscator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("-i", "--input", required=True, help="Input Python file to protect")
    parser.add_argument("-o", "--output", required=True, help="Output path for obfuscated file")
    parser.add_argument("--token", help="GitHub token for one-time Gist execution")
    parser.add_argument("--binary", action="store_true", help="Compile to binary via Nuitka")
    parser.add_argument("--time-bomb", help="Expiration date (YYYY-MM-DD)")
    parser.add_argument("--usage-limit", type=int, default=0, help="Maximum execution count (0 = unlimited)")
    parser.add_argument(
        "--binary-timeout",
        type=int,
        default=300,
        help="Seconds before Nuitka compilation times out (default: 300)",
    )
    return parser


def parse_time_bomb(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise CerberusError("invalid time bomb format, expected YYYY-MM-DD") from exc
    if parsed <= datetime.now():
        raise CerberusError("time bomb must be in the future")
    return parsed


def build_config(args: argparse.Namespace) -> CerberusConfig:
    time_bomb = parse_time_bomb(args.time_bomb)
    return CerberusConfig(
        input_path=Path(args.input).expanduser(),
        output_path=Path(args.output).expanduser(),
        github_token=args.token,
        compile_binary=args.binary,
        time_bomb=time_bomb,
        usage_limit=args.usage_limit,
        binary_timeout=args.binary_timeout,
    )


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        config = build_config(args)
        obfuscator = CerberusObfuscator(config)
        result = obfuscator.obfuscate()
    except BinaryCompilationFailure as exc:
        parser.error(str(exc))
        return 2
    except CerberusError as exc:
        parser.error(str(exc))
        return 1

    print("🛡️  Cerberus obfuscation complete!")
    print(f"📝  Output written to: {result.output_path}")
    print(f"📊  Original size: {result.original_size:,} bytes")
    print(f"📦  Protected size: {result.protected_size:,} bytes")
    print(f"📈  Expansion: {result.size_ratio:.1f}x")
    if result.binary_path:
        print(f"🔨  Binary: {result.binary_path}")

    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    raise SystemExit(main())


