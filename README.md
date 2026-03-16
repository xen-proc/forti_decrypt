# forti_decrypt

Decrypts FortiDLP (formerly Ava Security) evidence files using an RSA private key.

Evidence files use a custom `age.reveal.avasecurity.com/v1` format. See [FORTIDLP_ENCRYPTION.md](FORTIDLP_ENCRYPTION.md) for format details.

**Requires Python 3.8+**

## Install (day-to-day use)

Install once with [pipx](https://pipx.pypa.io) and get a `forti-decrypt` command available everywhere — no venv activation, no `python` prefix:

```bash
# Install pipx if you don't have it (macOS)
brew install pipx

# Install forti-decrypt from this directory
pipx install .
```

After that, just use `forti-decrypt` from any directory:

```bash
forti-decrypt ~/Downloads/evidence.age --key ~/.config/forti/key.pem
```

**To upgrade** after pulling new changes:

```bash
pipx reinstall forti-decrypt
```

**To uninstall:**

```bash
pipx uninstall forti-decrypt
```

## Development setup

When working on the tool itself, use a local venv instead:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .          # editable install — changes to forti_decrypt.py take effect immediately
pip install pytest        # for running tests
```

## Usage

```bash
forti-decrypt <evidence_file> [evidence_file ...] [--key <key.pem>] [options]
```

**Arguments:**

| Argument | Default | Description |
|---|---|---|
| `evidence_files` | *(required)* | One or more `.evidence` files to decrypt |
| `--key` | `FORTI_KEY` env var or `.env/decrypted_key.pem` | RSA private key PEM file |
| `--output` | `<stem>.zip` | Output path — single file only |
| `--output-dir DIR` | | Directory for output ZIPs — batch-friendly |
| `--stdout` | | Write decrypted bytes to stdout instead of a file |
| `--verify-only` | | Confirm decryption succeeds without writing output |
| `--list` | | Print ZIP contents without writing any output |
| `--extract` | | Extract ZIP contents to a directory instead of saving a `.zip` |
| `--key-password` | *(prompted)* | PEM passphrase — see note below |
| `--key-password-file` | | File containing the PEM passphrase (one line) |
| `--quiet` / `-q` | | Suppress per-file success output |
| `--verbose` / `-v` | | Print fingerprint, stanza count, ZIP contents, and debug info |

**Examples:**

```bash
# Single file — output defaults to evidence.zip
forti-decrypt evidence.age --key private.pem

# Batch decrypt into a specific directory
forti-decrypt *.evidence --key private.pem --output-dir ~/decrypted/

# Extract ZIP contents directly (no intermediate .zip file)
forti-decrypt evidence.age --key private.pem --extract

# Extract batch of files into an output directory
forti-decrypt *.evidence --key private.pem --extract --output-dir ~/decrypted/

# Inspect what's inside without writing anything
forti-decrypt evidence.age --key private.pem --list

# Pipe directly into another tool
forti-decrypt evidence.age --key private.pem --stdout | funzip | grep keyword

# Verify key works without writing anything
forti-decrypt evidence.age --key private.pem --verify-only

# Encrypted PEM key — prompts securely for passphrase
forti-decrypt evidence.age --key encrypted_key.pem
```

## Environment variables

Set these to avoid passing flags on every invocation:

| Variable | Description |
|---|---|
| `FORTI_KEY` | Path to the RSA private key PEM file |
| `FORTI_KEY_PASSWORD` | Passphrase for an encrypted PEM key |

```bash
export FORTI_KEY=~/.config/forti/private.pem
export FORTI_KEY_PASSWORD=yourpassphrase

# Now no --key or passphrase prompt needed
forti-decrypt evidence.age
forti-decrypt *.evidence --output-dir ~/decrypted/
```

## Encrypted PEM keys

The tool auto-detects whether the PEM key is passphrase-protected. Passphrase resolution order:

1. `--key-password PASSWORD` — visible in `ps aux` and shell history, avoid in shared environments
2. `--key-password-file FILE` — recommended for scripting and piping; avoids shell quoting issues with special characters (`!`, `#`, etc.)
3. `FORTI_KEY_PASSWORD` env var — useful for CI/CD or containerised environments
4. Interactive `getpass` prompt — default for interactive use

```bash
# Create once, lock it down
echo 'your!p#ssword' > .env/passphrase.txt
chmod 600 .env/passphrase.txt

# Use in a pipeline
forti-decrypt evidence.age --key .env/key --key-password-file .env/passphrase.txt --stdout | funzip > out.txt
```

## Library

```python
from forti_decrypt import decrypt_evidence, decrypt_evidence_bytes

# From file paths — returns a DecryptResult. Optionally writes to disk
result = decrypt_evidence("file.evidence", "key.pem")
result = decrypt_evidence("file.evidence", "key.pem", output_path="out.zip")

# Decrypt from in-memory bytes (e.g. fetched from S3 or an API)
result = decrypt_evidence_bytes(data, key_pem)

# DecryptResult fields
result.data                 # bytes — the decrypted ZIP archive
result.matched_fingerprint  # str  — base64 SHA-256 fingerprint of the matched key
result.stanza_count         # int  — number of RSA stanzas in the file header
```

## Output

Decrypted evidence is a ZIP archive. Depending on the flags used:

- **Default**: saves `<stem>.zip` in the current directory
- **`--output-dir`**: saves `<stem>.zip` inside the specified directory
- **`--extract`**: unpacks the ZIP into `<stem>/` (or `<output-dir>/<stem>/`)
- **`--stdout`**: streams raw ZIP bytes to stdout for piping

Batch runs collect all errors and report at the end rather than stopping on the first failure.
