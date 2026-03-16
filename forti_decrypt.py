#!/usr/bin/env python3
"""Decrypt FortiDLP (age.reveal.avasecurity.com/v1) evidence files."""

import argparse
import base64
import dataclasses
import getpass
import hmac as stdlib_hmac
import io
import os
import re
import sys
import zipfile
from pathlib import Path
from typing import List, NamedTuple, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

VERSION_LINE = "age.reveal.avasecurity.com/v1"
STANZA_RE = re.compile(r"^-> (\w+) (.+)$")


@dataclasses.dataclass
class DecryptResult:
    """Result of a successful decryption."""

    data: bytes
    matched_fingerprint: str
    stanza_count: int


class _ParsedHeader(NamedTuple):
    stanzas: list
    mac_bytes: bytes
    payload: bytes
    header_for_mac: bytes


def _is_encrypted_pem(key_pem: bytes) -> bool:
    """Return True if the PEM key is passphrase-protected."""
    # PKCS#8 encrypted format: -----BEGIN ENCRYPTED PRIVATE KEY-----
    if b"ENCRYPTED PRIVATE KEY" in key_pem:
        return True
    # Legacy OpenSSL/traditional format has this header inside the PEM block
    if b"Proc-Type: 4,ENCRYPTED" in key_pem:
        return True
    return False


def _parse_header(data: bytes) -> _ParsedHeader:
    """Parse the age header. Returns a _ParsedHeader namedtuple."""
    sep = b"\n---"
    sep_idx = data.index(sep)
    mac_line_start = sep_idx + 1  # skip the \n before ---
    mac_line_end = data.index(b"\n", mac_line_start)
    header_for_mac = data[: mac_line_start + 3]  # up to and including "---"

    mac_line = data[mac_line_start:mac_line_end].decode("ascii")
    mac_b64 = mac_line.split(" ", 1)[1]
    mac_bytes = base64.b64decode(mac_b64 + "==")

    payload = data[mac_line_end + 1 :]

    header_text = data[:sep_idx].decode("ascii")
    lines = header_text.split("\n")
    if lines[0] != VERSION_LINE:
        raise ValueError(f"Unexpected version: {lines[0]}")

    stanzas = []
    i = 1
    while i < len(lines):
        m = STANZA_RE.match(lines[i])
        if not m:
            raise ValueError(f"Expected stanza header at line {i}: {lines[i]}")
        stanza = {"type": m.group(1), "args": m.group(2), "body_lines": []}
        i += 1
        while i < len(lines) and not lines[i].startswith("-> "):
            stanza["body_lines"].append(lines[i])
            i += 1
        body_b64 = "".join(stanza["body_lines"])
        body_b64 += "=" * (-len(body_b64) % 4)
        stanza["body"] = base64.b64decode(body_b64)
        del stanza["body_lines"]
        stanzas.append(stanza)

    return _ParsedHeader(stanzas, mac_bytes, payload, header_for_mac)


def _recover_file_key(stanza_body: bytes, private_key) -> bytes:
    """RSA-OAEP-SHA256 decrypt the stanza body to get the 16-byte file key."""
    file_key = private_key.decrypt(
        stanza_body,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    if len(file_key) != 16:
        raise ValueError(f"Expected 16-byte file key, got {len(file_key)}")
    return file_key


def _verify_mac(file_key: bytes, header_bytes: bytes) -> bytes:
    """Verify the header MAC using HMAC-SHA256 with an HKDF-derived key."""
    mac_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=b"", info=b"header"
    ).derive(file_key)
    h = HMAC(mac_key, hashes.SHA256())
    h.update(header_bytes)
    return h.finalize()


_STREAM_CHUNK_PLAINTEXT = 64 * 1024
_STREAM_CHUNK_CIPHERTEXT = _STREAM_CHUNK_PLAINTEXT + 16  # + GCM tag


def _decrypt_payload(file_key: bytes, payload: bytes) -> bytes:
    """Derive payload key via HKDF and decrypt with AES-256-GCM (STREAM chunks)."""
    nonce_salt = payload[:16]
    ciphertext = payload[16:]
    payload_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=nonce_salt, info=b"payload"
    ).derive(file_key)
    aesgcm = AESGCM(payload_key)

    parts = []
    offset = 0
    counter = 0
    total = len(ciphertext)
    while offset < total:
        chunk = ciphertext[offset : offset + _STREAM_CHUNK_CIPHERTEXT]
        offset += _STREAM_CHUNK_CIPHERTEXT
        is_last = offset >= total
        nonce = counter.to_bytes(11, "big") + (b"\x01" if is_last else b"\x00")
        parts.append(aesgcm.decrypt(nonce, chunk, None))
        counter += 1
    return b"".join(parts)


def _zip_entries(data: bytes) -> List[Tuple[str, int]]:
    """Return list of (filename, uncompressed_size) from a ZIP."""
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        return [(zi.filename, zi.file_size) for zi in zf.infolist()]


def decrypt_evidence_bytes(
    data: bytes,
    key_pem: bytes,
    key_password: Optional[bytes] = None,
    verbose: bool = False,
) -> DecryptResult:
    """Core decryption operating on raw bytes. Returns a DecryptResult.

    Useful when data is already in memory (e.g. fetched from S3 or an API).
    """
    private_key = serialization.load_pem_private_key(key_pem, password=key_password)
    parsed = _parse_header(data)

    file_key = None
    matched_fingerprint = None
    rsa_stanza_count = 0
    for stanza in parsed.stanzas:
        if stanza["type"] != "rsa":
            continue
        rsa_stanza_count += 1
        try:
            file_key = _recover_file_key(stanza["body"], private_key)
            matched_fingerprint = stanza["args"]
            break
        except Exception as exc:
            if verbose:
                print(f"  [debug] stanza {stanza['args']}: {exc}", file=sys.stderr)

    if file_key is None:
        raise ValueError("Could not decrypt any RSA stanza with the provided key")

    computed_mac = _verify_mac(file_key, parsed.header_for_mac)
    if not stdlib_hmac.compare_digest(computed_mac, parsed.mac_bytes):
        raise ValueError("Header MAC verification failed")

    plaintext = _decrypt_payload(file_key, parsed.payload)
    return DecryptResult(
        data=plaintext,
        matched_fingerprint=matched_fingerprint or "",
        stanza_count=rsa_stanza_count,
    )


def decrypt_evidence(
    evidence_path: str,
    key_path: str,
    output_path: Optional[str] = None,
    key_password: Optional[bytes] = None,
) -> DecryptResult:
    """Decrypt a FortiDLP .evidence file. Returns a DecryptResult.

    If output_path is provided, also writes to disk.
    """
    data = Path(evidence_path).read_bytes()
    key_pem = Path(key_path).read_bytes()
    result = decrypt_evidence_bytes(data, key_pem, key_password)
    if output_path:
        Path(output_path).write_bytes(result.data)
    return result


def _resolve_key_path(cli_key: Optional[str]) -> str:
    """Resolve key path: --key arg > FORTI_KEY env var > default."""
    if cli_key is not None:
        return cli_key
    env_key = os.environ.get("FORTI_KEY")
    if env_key:
        return env_key
    return ".env/decrypted_key.pem"


def _resolve_key_password(
    key_pem: bytes,
    cli_password: Optional[str],
    key_path: str,
    password_file: Optional[str] = None,
) -> Optional[bytes]:
    """Resolve PEM passphrase: CLI arg > password file > FORTI_KEY_PASSWORD env var > interactive prompt."""
    if not _is_encrypted_pem(key_pem):
        return None
    if cli_password is not None:
        return cli_password.encode()
    if password_file is not None:
        return Path(password_file).read_text().rstrip("\n").encode()
    env_pass = os.environ.get("FORTI_KEY_PASSWORD")
    if env_pass:
        return env_pass.encode()
    return getpass.getpass(f"Passphrase for {key_path}: ").encode()


def main():
    parser = argparse.ArgumentParser(
        description="Decrypt FortiDLP evidence files"
    )
    parser.add_argument(
        "evidence_files", nargs="+", help="Evidence file(s) to decrypt"
    )
    parser.add_argument(
        "--key",
        default=None,
        help=(
            "RSA private key PEM file "
            "(default: FORTI_KEY env var, or .env/decrypted_key.pem)"
        ),
    )

    out_group = parser.add_mutually_exclusive_group()
    out_group.add_argument(
        "--output",
        help="Output path for the decrypted ZIP. Single file only.",
    )
    out_group.add_argument(
        "--output-dir",
        metavar="DIR",
        help="Directory for output ZIPs when processing multiple files.",
    )
    out_group.add_argument(
        "--stdout",
        action="store_true",
        help="Write decrypted bytes to stdout (useful for piping).",
    )
    out_group.add_argument(
        "--verify-only",
        action="store_true",
        help="Verify decryption succeeds without writing any output.",
    )
    out_group.add_argument(
        "--list",
        action="store_true",
        help="List ZIP contents without writing any output.",
    )

    parser.add_argument(
        "--extract",
        action="store_true",
        help=(
            "Extract ZIP contents to a directory instead of saving a .zip file. "
            "Output goes to <stem>/ or <output-dir>/<stem>/."
        ),
    )

    parser.add_argument(
        "--key-password",
        metavar="PASSWORD",
        help=(
            "Passphrase for encrypted PEM key. "
            "Prefer --key-password-file or FORTI_KEY_PASSWORD env var to avoid "
            "shell history exposure. Interactive prompt is used if none provided."
        ),
    )
    parser.add_argument(
        "--key-password-file",
        metavar="FILE",
        help="File containing the PEM passphrase (one line). Avoids shell quoting issues.",
    )

    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument(
        "--quiet", "-q", action="store_true", help="Suppress per-file success output."
    )
    verbosity.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Print fingerprint, stanza count, ZIP contents, and debug info per file.",
    )

    args = parser.parse_args()

    if args.output and len(args.evidence_files) > 1:
        parser.error("--output can only be used with a single evidence file")
    if args.extract and (args.stdout or args.verify_only or args.list):
        parser.error("--extract cannot be combined with --stdout, --verify-only, or --list")

    key_path = _resolve_key_path(args.key)
    key_pem = Path(key_path).read_bytes()
    key_password = _resolve_key_password(key_pem, args.key_password, key_path, args.key_password_file)

    if args.output_dir:
        Path(args.output_dir).mkdir(parents=True, exist_ok=True)

    errors: List[tuple] = []

    for evidence_file in args.evidence_files:
        stem = Path(evidence_file).stem
        try:
            result = decrypt_evidence(evidence_file, key_path, key_password=key_password)

            if args.stdout:
                sys.stdout.buffer.write(result.data)
                continue

            if args.verify_only:
                if not args.quiet:
                    print(f"OK: {evidence_file} (fingerprint: {result.matched_fingerprint})")
                continue

            entries = _zip_entries(result.data)

            if args.list:
                print(f"{evidence_file}:")
                for name, size in entries:
                    print(f"  {name}  ({size:,} bytes)")
                continue

            if args.extract:
                base = Path(args.output_dir) if args.output_dir else Path(".")
                extract_dir = base / stem
                extract_dir.mkdir(parents=True, exist_ok=True)
                with zipfile.ZipFile(io.BytesIO(result.data)) as zf:
                    zf.extractall(extract_dir)
                if not args.quiet:
                    msg = f"Extracted: {evidence_file} -> {extract_dir}/"
                    if args.verbose:
                        msg += f" (fingerprint: {result.matched_fingerprint}, stanzas: {result.stanza_count})"
                    print(msg)
                if args.verbose:
                    for name, size in entries:
                        print(f"  {name}  ({size:,} bytes)")
                continue

            # Default: write ZIP
            if args.output:
                out = args.output
            elif args.output_dir:
                out = str(Path(args.output_dir) / f"{stem}.zip")
            else:
                out = f"{stem}.zip"

            Path(out).write_bytes(result.data)
            if not args.quiet:
                msg = f"Decrypted: {evidence_file} -> {out}"
                if args.verbose:
                    msg += f" (fingerprint: {result.matched_fingerprint}, stanzas: {result.stanza_count})"
                print(msg)
            if args.verbose:
                for name, size in entries:
                    print(f"  {name}  ({size:,} bytes)")

        except Exception as exc:
            if args.verbose:
                import traceback
                traceback.print_exc(file=sys.stderr)
            errors.append((evidence_file, exc))

    if errors:
        for path, err in errors:
            err_type = type(err).__name__
            print(
                f"Error: {path}: {err_type}: {err}" if str(err) else f"Error: {path}: {err_type}",
                file=sys.stderr,
            )
        sys.exit(1)


if __name__ == "__main__":
    main()
