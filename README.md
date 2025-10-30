# Cerberus Obfuscator

Modernised Python obfuscator that wraps source code in a hardened loader
featuring multi-layer symmetric encryption, optional binary compilation and
runtime self-defence mechanisms.

## Key Features

- Quad-layer payload encryption (AES-GCM → ChaCha20 → Salsa20 → XOR stream)
- Entropy-rich key derivation with optional GitHub token mixing
- Runtime anti-debugging and sandbox heuristics
- Optional GitHub Gist validation to restrict one-time execution
- Configurable usage limit and time-bomb guardrails
- Optional Nuitka compilation with timeout controls

## Installation

```bash
pip install pycryptodome requests psutil nuitka
```

For development and linting extras use `pip install -e .[dev]` after cloning.

## Quick Start

```bash
cerberus -i example.py -o protected.py
```

Add optional guards:

```bash
cerberus -i example.py -o protected.py --time-bomb 2025-12-31 --usage-limit 10
cerberus -i example.py -o protected.py --token $GITHUB_TOKEN
cerberus -i example.py -o protected.py --binary
```

## Architecture Overview

1. **Configuration** (`cerberus.config`) validates paths and guard rails.
2. **Entropy material** mixes random bytes and optional GitHub token.
3. **Quad layer cipher** handles encryption/decryption with scrypt derived keys.
4. **Loader template** embeds runtime checks (anti-debug + sandbox + usage limits).
5. **CLI** provides thin wrapper around the obfuscation API.

## Development

- Formatting and linting: `pip install -e .[dev]` then run `ruff check .` and `mypy .`
- Tests (to add): run `pytest`
- Package build: `python -m build`

## License

This project is licensed under the ISC License. See the LICENSE file for details.
