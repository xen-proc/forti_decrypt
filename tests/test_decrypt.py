"""Tests for forti_decrypt using pre-generated fixtures.

Fixtures are in tests/fixtures/ and are safe to commit publicly.
To regenerate: python tests/create_fixtures.py
"""

import io
import os
import zipfile
from pathlib import Path

import pytest

from forti_decrypt import DecryptResult, decrypt_evidence, decrypt_evidence_bytes

FIXTURES = Path(__file__).parent / "fixtures"
TEST_KEY = FIXTURES / "test_key.pem"
TEST_EVIDENCE = FIXTURES / "test.evidence"


@pytest.fixture(scope="module")
def key_pem() -> bytes:
    return TEST_KEY.read_bytes()


@pytest.fixture(scope="module")
def evidence_bytes() -> bytes:
    return TEST_EVIDENCE.read_bytes()


class TestDecryptEvidenceBytes:
    def test_returns_decrypt_result(self, evidence_bytes, key_pem):
        result = decrypt_evidence_bytes(evidence_bytes, key_pem)
        assert isinstance(result, DecryptResult)

    def test_output_is_valid_zip(self, evidence_bytes, key_pem):
        result = decrypt_evidence_bytes(evidence_bytes, key_pem)
        buf = io.BytesIO(result.data)
        assert zipfile.is_zipfile(buf)

    def test_zip_contains_expected_file(self, evidence_bytes, key_pem):
        result = decrypt_evidence_bytes(evidence_bytes, key_pem)
        with zipfile.ZipFile(io.BytesIO(result.data)) as zf:
            names = zf.namelist()
            assert "evidence/test.txt" in names
            content = zf.read("evidence/test.txt").decode()
            assert "FortiDLP test fixture" in content

    def test_result_has_fingerprint(self, evidence_bytes, key_pem):
        result = decrypt_evidence_bytes(evidence_bytes, key_pem)
        assert result.matched_fingerprint != ""

    def test_result_has_stanza_count(self, evidence_bytes, key_pem):
        result = decrypt_evidence_bytes(evidence_bytes, key_pem)
        assert result.stanza_count >= 1

    def test_wrong_key_raises(self, evidence_bytes):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

        other_key = generate_private_key(public_exponent=65537, key_size=2048)
        other_pem = other_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with pytest.raises(ValueError, match="Could not decrypt any RSA stanza"):
            decrypt_evidence_bytes(evidence_bytes, other_pem)

    def test_tampered_payload_raises(self, evidence_bytes, key_pem):
        # Flip a byte in the binary payload (after the ASCII header)
        sep = evidence_bytes.index(b"\n---")
        mac_end = evidence_bytes.index(b"\n", sep + 1)
        payload_start = mac_end + 1
        tampered = bytearray(evidence_bytes)
        tampered[payload_start + 20] ^= 0xFF
        with pytest.raises(Exception):
            decrypt_evidence_bytes(bytes(tampered), key_pem)


class TestDecryptEvidenceFile:
    def test_decrypt_to_file(self, tmp_path, key_pem):
        out = tmp_path / "out.zip"
        result = decrypt_evidence(str(TEST_EVIDENCE), str(TEST_KEY), str(out))
        assert out.exists()
        assert out.stat().st_size > 0
        assert isinstance(result, DecryptResult)

    def test_decrypt_no_output_path(self, key_pem):
        result = decrypt_evidence(str(TEST_EVIDENCE), str(TEST_KEY))
        assert isinstance(result, DecryptResult)
        assert len(result.data) > 0
