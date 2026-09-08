# Cerberus Obfuscator

Cerberus packages a Python source file in a randomized loader. The loader uses
AES-256-GCM, a per-build scrypt salt, randomized encoding and fragments, and a
keyed loader-integrity check when the source path is available.

## Security model

A self-contained Python file must contain enough material to decrypt itself.
That mode raises the cost of casual static extraction; it cannot protect source
from the person who is allowed to run the file. A determined analyst can trace
`exec`, inspect plaintext in memory, or patch the loader.

For distributed files, keep the decryption secret outside the artifact:

```bash
export CERBERUS_SECRET="a-long-random-value"
cerberus -i example.py -o protected.py --secret-env CERBERUS_SECRET
CERBERUS_SECRET="$CERBERUS_SECRET" python3 protected.py
```

The secret is read from the environment during the build and at runtime; it is
never written to `protected.py`. Do not pass secrets as command-line arguments
because shells and process monitors can record them.

The optional `--anti-debug` switch only rejects Python tracing. It is a
best-effort signal, not a reliable anti-debug or anti-decompile boundary.
`--time-bomb` uses the local UTC clock, and `--usage-limit` uses a writable
`<protected-file>.usage` counter; both are policy controls that a local user can
modify or bypass.

Nuitka compilation can increase reverse-engineering cost. The source-file
integrity check is unavailable inside onefile binaries, and compilation does
not turn Python code into a secret or replace access control.

## Installation

```bash
python3 -m pip install -e .
```

Install the optional compiler support with:

```bash
python3 -m pip install -e .[binary]
```

## Quick start

Self-contained protection:

```bash
cerberus -i example.py -o protected.py
python3 protected.py
```

External secret, recommended when distributing the output:

```bash
export CERBERUS_SECRET="a-long-random-value"
cerberus -i example.py -o protected.py --secret-env CERBERUS_SECRET
CERBERUS_SECRET="$CERBERUS_SECRET" python3 protected.py
```

Additional policy controls:

```bash
cerberus -i example.py -o protected.py \
  --time-bomb 2027-12-31 \
  --usage-limit 10 \
  --anti-debug
```

The legacy `cerberus.py` command remains a thin wrapper around the package
CLI. GitHub-token/Gist integration was removed: embedding or reusing a personal
access token is not a sound licensing or key-management design.

## Development

```bash
python3 -m pip install -e .[dev]
ruff check .
mypy .
pytest
```

## License

This project is licensed under the ISC License. See `LICENSE` for details.
