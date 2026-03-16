#!/usr/bin/env python3
"""Generate test fixtures for forti_decrypt tests.

Produces:
  tests/fixtures/test_key.pem    — 4096-bit RSA private key (TEST ONLY, not encrypted)
  tests/fixtures/test.evidence   — synthetic evidence file encrypted for that key

The plaintext ZIP contains a single dummy file. These fixtures are safe to commit
publicly; the key protects no real data.

Run from the repo root:
  python tests/create_fixtures.py
"""

import base64
import hashlib
import io
import os
import sys
import zipfile
from pathlib import Path

# Allow running from repo root or tests/
sys.path.insert(0, str(Path(__file__).parent.parent))

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

VERSION_LINE = "age.reveal.avasecurity.com/v1"
FIXTURES = Path(__file__).parent / "fixtures"


def _b64_nopad(data: bytes) -> str:
    return base64.b64encode(data).rstrip(b"=").decode("ascii")


def _key_fingerprint(public_key) -> str:
    """SHA-256 of PKCS#1 DER public key, base64-encoded (no padding)."""
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.PKCS1,
    )
    return _b64_nopad(hashlib.sha256(der).digest())


def encrypt_fortidlp(plaintext: bytes, public_key) -> bytes:
    """Encrypt bytes using the FortiDLP age variant.

    This is the inverse of forti_decrypt.decrypt_evidence_bytes() and is only
    intended for generating test fixtures.
    """
    # 1. Random 16-byte file key
    file_key = os.urandom(16)

    # 2. RSA-OAEP-SHA256 wrap the file key
    wrapped_key = public_key.encrypt(
        file_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    fingerprint = _key_fingerprint(public_key)

    # 3. Build stanza body: base64, no padding, 64-char lines
    wrapped_b64 = _b64_nopad(wrapped_key)
    body_lines = "\n".join(wrapped_b64[i : i + 64] for i in range(0, len(wrapped_b64), 64))

    # 4. header_for_mac = everything up to and including "---"
    #    This matches what _parse_header() computes: data[:mac_line_start + 3]
    header_for_mac = f"{VERSION_LINE}\n-> rsa {fingerprint}\n{body_lines}\n---".encode("ascii")

    # 5. HMAC-SHA256 over header_for_mac with HKDF-derived key
    mac_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=b"", info=b"header"
    ).derive(file_key)
    h = HMAC(mac_key, hashes.SHA256())
    h.update(header_for_mac)
    mac_bytes = h.finalize()

    full_header = header_for_mac + f" {_b64_nopad(mac_bytes)}\n".encode("ascii")

    # 6. AES-256-GCM payload: 16-byte HKDF salt + STREAM chunks
    nonce_salt = os.urandom(16)
    payload_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=nonce_salt, info=b"payload"
    ).derive(file_key)
    aesgcm = AESGCM(payload_key)
    chunk_size = 64 * 1024
    chunks = [plaintext[i : i + chunk_size] for i in range(0, len(plaintext), chunk_size)]
    if not chunks:
        chunks = [b""]
    ciphertext_parts = []
    for counter, chunk in enumerate(chunks):
        is_last = counter == len(chunks) - 1
        nonce = counter.to_bytes(11, "big") + (b"\x01" if is_last else b"\x00")
        ciphertext_parts.append(aesgcm.encrypt(nonce, chunk, None))
    ciphertext = b"".join(ciphertext_parts)

    return full_header + nonce_salt + ciphertext


def make_test_zip() -> bytes:
    """Create a minimal ZIP with a single dummy text file."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "evidence/test.txt",
            "FortiDLP test fixture — not real evidence.\nSafe to commit publicly.\n",
        )
    return buf.getvalue()


def main():
    FIXTURES.mkdir(parents=True, exist_ok=True)

    key_path = FIXTURES / "test_key.pem"
    evidence_path = FIXTURES / "test.evidence"

    print("Generating 4096-bit RSA test key (this takes a moment)...")
    private_key = generate_private_key(public_exponent=65537, key_size=4096)

    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path.write_bytes(key_pem)
    print(f"  Wrote {key_path}")

    zip_bytes = make_test_zip()
    evidence_bytes = encrypt_fortidlp(zip_bytes, private_key.public_key())
    evidence_path.write_bytes(evidence_bytes)
    print(f"  Wrote {evidence_path} ({len(evidence_bytes)} bytes)")
    print("Done. Commit both files — the key protects no real data.")


if __name__ == "__main__":
    main()
