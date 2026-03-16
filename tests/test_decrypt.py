"""Tests for forti_decrypt using pre-generated fixtures.

Fixtures are in tests/fixtures/ and are safe to commit publicly.
To regenerate: python tests/create_fixtures.py
"""

import io
import os
import sys
import zipfile
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from forti_decrypt import (
    DecryptResult,
    _resolve_key_path,
    _zip_entries,
    decrypt_evidence,
    decrypt_evidence_bytes,
)

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


class TestMultiChunkPayload:
    def test_large_payload_decrypts(self, key_pem):
        """Payload spanning multiple 64 KB STREAM chunks must decrypt correctly."""
        from tests.create_fixtures import encrypt_fortidlp
        from cryptography.hazmat.primitives import serialization

        private_key = serialization.load_pem_private_key(key_pem, password=None)
        # 200 KB of data — crosses three 64 KB chunk boundaries
        plaintext = b"X" * (200 * 1024)
        evidence = encrypt_fortidlp(plaintext, private_key.public_key())
        result = decrypt_evidence_bytes(evidence, key_pem)
        assert result.data == plaintext


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


class TestResolveKeyPath:
    def test_cli_arg_wins(self):
        with mock.patch.dict(os.environ, {"FORTI_KEY": "/env/key.pem"}):
            assert _resolve_key_path("/cli/key.pem") == "/cli/key.pem"

    def test_env_var_used_when_no_cli_arg(self):
        with mock.patch.dict(os.environ, {"FORTI_KEY": "/env/key.pem"}):
            assert _resolve_key_path(None) == "/env/key.pem"

    def test_default_when_neither_set(self):
        env = {k: v for k, v in os.environ.items() if k != "FORTI_KEY"}
        with mock.patch.dict(os.environ, env, clear=True):
            assert _resolve_key_path(None) == ".env/decrypted_key.pem"


class TestZipEntries:
    def test_returns_name_and_size(self, evidence_bytes, key_pem):
        result = decrypt_evidence_bytes(evidence_bytes, key_pem)
        entries = _zip_entries(result.data)
        assert len(entries) >= 1
        names = [name for name, _ in entries]
        assert "evidence/test.txt" in names
        sizes = {name: size for name, size in entries}
        assert sizes["evidence/test.txt"] > 0


class TestCLI:
    """Tests for CLI flag behaviour via argparse / main()."""

    def _run(self, argv, env=None):
        """Run main() with the given argv, capturing stdout/stderr."""
        import forti_decrypt
        base_env = dict(os.environ)
        base_env.pop("FORTI_KEY", None)
        if env:
            base_env.update(env)
        with mock.patch.dict(os.environ, base_env, clear=True):
            with mock.patch("sys.argv", ["forti_decrypt.py"] + argv):
                forti_decrypt.main()

    def test_output_dir_creates_zip_in_dir(self, tmp_path):
        out_dir = tmp_path / "out"
        self._run([
            str(TEST_EVIDENCE),
            "--key", str(TEST_KEY),
            "--output-dir", str(out_dir),
        ])
        stem = TEST_EVIDENCE.stem
        expected = out_dir / f"{stem}.zip"
        assert expected.exists()
        assert zipfile.is_zipfile(expected)

    def test_output_dir_created_if_missing(self, tmp_path):
        out_dir = tmp_path / "nested" / "out"
        self._run([
            str(TEST_EVIDENCE),
            "--key", str(TEST_KEY),
            "--output-dir", str(out_dir),
        ])
        assert out_dir.is_dir()

    def test_extract_creates_directory(self, tmp_path):
        with mock.patch("sys.argv", [
            "forti_decrypt.py",
            str(TEST_EVIDENCE),
            "--key", str(TEST_KEY),
            "--extract",
            "--output-dir", str(tmp_path),
        ]):
            import forti_decrypt
            forti_decrypt.main()
        stem = TEST_EVIDENCE.stem
        extract_dir = tmp_path / stem
        assert extract_dir.is_dir()
        assert any(extract_dir.rglob("*"))

    def test_extract_contains_evidence_files(self, tmp_path):
        with mock.patch("sys.argv", [
            "forti_decrypt.py",
            str(TEST_EVIDENCE),
            "--key", str(TEST_KEY),
            "--extract",
            "--output-dir", str(tmp_path),
        ]):
            import forti_decrypt
            forti_decrypt.main()
        stem = TEST_EVIDENCE.stem
        txt = tmp_path / stem / "evidence" / "test.txt"
        assert txt.exists()
        assert "FortiDLP test fixture" in txt.read_text()

    def test_list_prints_zip_contents(self, tmp_path, capsys):
        self._run([
            str(TEST_EVIDENCE),
            "--key", str(TEST_KEY),
            "--list",
        ])
        captured = capsys.readouterr()
        assert "evidence/test.txt" in captured.out
        assert "bytes" in captured.out

    def test_list_writes_no_file(self, tmp_path):
        orig_cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            self._run([
                str(TEST_EVIDENCE),
                "--key", str(TEST_KEY),
                "--list",
            ])
        finally:
            os.chdir(orig_cwd)
        assert not any(tmp_path.glob("*.zip"))

    def test_verbose_prints_zip_entries(self, tmp_path, capsys):
        self._run([
            str(TEST_EVIDENCE),
            "--key", str(TEST_KEY),
            "--output-dir", str(tmp_path),
            "--verbose",
        ])
        captured = capsys.readouterr()
        assert "evidence/test.txt" in captured.out
        assert "bytes" in captured.out

    def test_forti_key_env_var(self, tmp_path):
        out_dir = tmp_path / "out"
        self._run(
            [str(TEST_EVIDENCE), "--output-dir", str(out_dir)],
            env={"FORTI_KEY": str(TEST_KEY)},
        )
        stem = TEST_EVIDENCE.stem
        assert (out_dir / f"{stem}.zip").exists()

    def test_extract_incompatible_with_list(self, capsys):
        with pytest.raises(SystemExit):
            self._run([
                str(TEST_EVIDENCE),
                "--key", str(TEST_KEY),
                "--extract",
                "--list",
            ])
