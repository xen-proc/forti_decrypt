# FortiDLP Evidence File Encryption

FortiDLP encrypts captured evidence using a custom variant of the [age encryption format](https://github.com/C2SP/C2SP/blob/main/age.md). The format identifier is `age.reveal.avasecurity.com/v1` (vs standard age's `age-encryption.org/v1`).

## How FortiDLP Encrypts Evidence

### 1. Collect Evidence into a ZIP

FortiDLP gathers captured files into a ZIP archive containing an `evidence/` directory tree. This ZIP archive is the plaintext that gets encrypted.

### 2. Generate a Random 16-Byte File Key

A per-file symmetric key (16 bytes) is randomly generated. This key is never stored directly — it is wrapped (encrypted) for each authorized recipient and embedded in the file header.

### 3. Wrap the File Key for Each Recipient (RSA Stanzas)

For every RSA public key authorized to decrypt the file, the 16-byte file key is encrypted using **RSA-OAEP** with **SHA-256** for both the hash function and MGF1 padding.

Each recipient is identified by a **fingerprint**: the base64-encoded SHA-256 hash of the RSA public key in PKCS#1 DER encoding.

Each wrapped key becomes a "stanza" in the file header — a `-> rsa <fingerprint>` line followed by the base64-encoded RSA ciphertext (512 bytes for a 4096-bit RSA key). In practice, FortiDLP often writes two identical stanzas for the same key.

### 4. Compute a Header MAC

To protect header integrity, a MAC key is derived from the file key:

```
mac_key = HKDF-SHA256(ikm=file_key, salt="", info="header") → 32 bytes
```

An HMAC-SHA256 is computed over all header bytes up to and including the `---` separator (but excluding the space, MAC value, and trailing newline). The resulting 32-byte MAC is base64-encoded and placed on the separator line.

### 5. Derive a Payload Encryption Key

A random 16-byte nonce (salt) is generated and prepended to the binary payload. The payload encryption key is derived via:

```
payload_key = HKDF-SHA256(ikm=file_key, salt=nonce_16_bytes, info="payload") → 32 bytes
```

### 6. Encrypt the Payload with AES-256-GCM

The ZIP archive is encrypted using **AES-256-GCM**:

- **Key:** 32-byte payload key from step 5
- **Nonce:** 12 bytes — 11 zero bytes followed by `0x01` (the age STREAM convention for a single final chunk)
- **AAD:** none
- **Output:** ciphertext with the 16-byte GCM authentication tag appended

> **Key difference from standard age:** Standard age uses ChaCha20-Poly1305 for the payload STREAM cipher. FortiDLP substitutes AES-256-GCM, likely to leverage AES-NI hardware acceleration on endpoint agents.

## Encrypted File Layout

```
age.reveal.avasecurity.com/v1              ← version line (ASCII)
-> rsa <base64-fingerprint>                ← stanza header: recipient type + fingerprint
<base64 lines of RSA-OAEP ciphertext>      ← wrapped file key (512 bytes for 4096-bit RSA)
-> rsa <base64-fingerprint>                ← additional stanza (may repeat for same or different keys)
<base64 lines of RSA-OAEP ciphertext>
--- <base64 HMAC-SHA256>                   ← header MAC (32 bytes, base64-encoded)
<16-byte HKDF salt><AES-GCM ciphertext>    ← binary payload (not text-encoded)
```

Everything above the `---` line (inclusive) is ASCII text. The binary payload begins immediately after the newline following the MAC line.

### Field Details

| Field | Size | Encoding | Description |
|-------|------|----------|-------------|
| Version line | variable | ASCII | `age.reveal.avasecurity.com/v1` |
| Stanza header | variable | ASCII | `-> rsa <base64-SHA256-fingerprint>` |
| Stanza body | 512 bytes (4096-bit RSA) | base64, no padding | RSA-OAEP-SHA256 encrypted file key |
| MAC line | 32 bytes | `--- ` + base64, no padding | HMAC-SHA256 of header |
| Payload salt | 16 bytes | raw binary | HKDF salt for payload key derivation |
| Payload ciphertext | variable | raw binary | AES-256-GCM ciphertext + 16-byte auth tag |

## Differences from Standard Age

| Aspect | Standard Age (`age-encryption.org/v1`) | FortiDLP (`age.reveal.avasecurity.com/v1`) |
|--------|----------------------------------------|-------------------------------------------|
| Recipient type | `X25519` (Curve25519 ECDH) | `rsa` (RSA-OAEP-SHA256) |
| Key wrapping | X25519 + HKDF + ChaCha20-Poly1305 | RSA-OAEP with SHA-256 hash and MGF1 |
| Payload cipher | ChaCha20-Poly1305 (STREAM) | AES-256-GCM |
| HKDF derivation | Same | Same |
| Header MAC | Same (HMAC-SHA256) | Same |
| STREAM nonce | Same (11 zero bytes + counter) | Same |

## How `forti_decrypt.py` Handles It

The decryption code in [`forti_decrypt.py`](forti_decrypt.py) reverses the encryption pipeline through four internal functions:

### `_parse_header(data)` — Parse the File Structure

Splits the raw file bytes at the `\n---` separator. The ASCII portion above is parsed into stanzas (each with a `type`, `args` fingerprint, and decoded `body`). The base64 stanza bodies use standard base64 encoding with no trailing `=` padding — the parser re-adds padding before decoding. The `header_for_mac` slice captures the exact byte range needed for MAC verification (everything through `---`, excluding the space and MAC value). The binary payload starts at the byte after the MAC line's newline.

### `_recover_file_key(stanza_body, private_key)` — Unwrap the File Key

Takes the 512-byte RSA ciphertext from a stanza body and decrypts it using RSA-OAEP with SHA-256 for both the hash and MGF1. The result must be exactly 16 bytes. The code iterates over all stanzas and uses the first one that decrypts successfully, allowing multi-recipient files to work with any authorized key.

### `_verify_mac(file_key, header_bytes)` — Verify Header Integrity

Derives a MAC key from the file key using HKDF-SHA256 with an empty salt and `"header"` as the info string. Computes HMAC-SHA256 over the header bytes and returns the result for comparison against the MAC embedded in the file. A mismatch indicates the header was tampered with or the wrong file key was recovered.

### `_decrypt_payload(file_key, payload)` — Decrypt the Evidence

Splits the binary payload into the 16-byte HKDF salt (first 16 bytes) and the AES-GCM ciphertext (remainder). Derives a 32-byte AES key via HKDF-SHA256 using the salt and `"payload"` as the info string. Decrypts using AES-256-GCM with the age STREAM nonce convention: `\x00 * 11 + \x01` (11 zero bytes followed by `0x01`, indicating a single final chunk). The GCM auth tag is included at the end of the ciphertext and verified automatically by the library. The decrypted output is the original ZIP archive.

## RSA Key Requirements

- **Key size:** 4096-bit RSA (produces 512-byte ciphertext per stanza)
- **Format:** PEM-encoded private key (PKCS#8 or traditional)
- **Fingerprint calculation:** `SHA-256(PKCS#1 DER-encoded public key)`, base64-encoded
- **Padding scheme:** OAEP with SHA-256 hash + SHA-256 MGF1
