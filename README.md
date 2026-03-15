# forti_decrypt

Decrypts FortiDLP (formerly Ava Security) evidence files using an RSA private key.

Evidence files use a custom `age.reveal.avasecurity.com/v1` format. See [FORTIDLP_ENCRYPTION.md](FORTIDLP_ENCRYPTION.md) for format details.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install cryptography
```

## Usage

```bash
python forti_decrypt.py <evidence_files> [--key <key.pem>] [options]
```

**Arguments:**

| Argument | Default | Description |
|---|---|---|
| `evidence_files` | *(required)* | One or more `.evidence` files to decrypt |
| `--key` | `.env/decrypted_key.pem` | RSA private key PEM file |
| `--output` | `<stem>.zip` | Output path (single file only) |
| `--stdout` | | Write decrypted bytes to stdout instead of a file |
| `--verify-only` | | Verify decryption without writing any output |
| `--key-password` | *(prompted)* | PEM passphrase (avoid — exposes password in shell history) |
| `--key-password-file` | | File containing the PEM passphrase (one line) |
| `--quiet` / `-q` | | Suppress per-file success output |
| `--verbose` / `-v` | | Print fingerprint and stanza count per file |

`--output`, `--stdout`, and `--verify-only` are mutually exclusive.

**Examples:**

```bash
# Single file — output defaults to evidence.zip
python forti_decrypt.py evidence.age --key private.pem

# Batch decrypt
python forti_decrypt.py *.evidence --key private.pem

# Encrypted PEM key — will prompt for passphrase
python forti_decrypt.py evidence.age --key encrypted_key.pem

# Non-interactive (e.g. in a script) — prefer a password file or env var
python forti_decrypt.py evidence.age --key encrypted_key.pem --key-password-file pass.txt
FORTI_KEY_PASSWORD=secret python forti_decrypt.py evidence.age --key encrypted_key.pem

# Pipe decrypted ZIP to stdout
python forti_decrypt.py evidence.age --key private.pem --stdout | unzip -p - evidence/file.txt

# Verify without writing output
python forti_decrypt.py *.evidence --key private.pem --verify-only
```

## Encrypted PEM keys

The tool auto-detects whether the PEM key is passphrase-protected. If it is, the passphrase is resolved in this order:

1. `--key-password` CLI argument *(avoid — exposes password in shell history)*
2. `--key-password-file <file>` — reads the passphrase from a file
3. `FORTI_KEY_PASSWORD` environment variable
4. Interactive prompt (no echo)

## Library

```python
from forti_decrypt import decrypt_evidence, decrypt_evidence_bytes

# From file paths — returns a DecryptResult
result = decrypt_evidence("file.evidence", "key.pem")
result = decrypt_evidence("file.evidence", "key.pem", output_path="out.zip")

# From raw bytes (e.g. fetched from S3 or an API)
result = decrypt_evidence_bytes(evidence_bytes, key_pem_bytes)

# DecryptResult fields
result.data                 # bytes — the decrypted ZIP archive
result.matched_fingerprint  # str  — base64 SHA-256 fingerprint of the matched key
result.stanza_count         # int  — number of RSA stanzas in the file header
```

Encrypted PEM keys can be handled by passing `key_password=b"passphrase"` to either function.

## Output

Each decrypted file is a ZIP archive containing the original evidence files.
