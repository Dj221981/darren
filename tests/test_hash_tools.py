"""Unit tests for cybersec_toolkit.modules.hash_tools"""

import hashlib
import tempfile
import os
import pytest

from cybersec_toolkit.modules.hash_tools import (
    hash_text,
    hash_all,
    verify_hash,
    hash_file,
    verify_file_hash,
    generate_hmac,
    verify_hmac,
    SUPPORTED_ALGORITHMS,
)


# ──────────────────────────────────────────────────────────────────────────────
# Test 1: hash_text returns correct SHA-256 digest
# ──────────────────────────────────────────────────────────────────────────────
class TestHashText:
    def test_sha256_digest_matches_stdlib(self):
        text = "hello world"
        expected = hashlib.sha256(text.encode()).hexdigest()
        result = hash_text(text, "sha256")
        assert result["digest"] == expected

    def test_md5_algorithm(self):
        text = "test"
        expected = hashlib.md5(text.encode()).hexdigest()
        result = hash_text(text, "md5")
        assert result["digest"] == expected

    def test_returns_correct_metadata_keys(self):
        result = hash_text("data", "sha256")
        for key in ("algorithm", "input_length", "digest", "digest_length_bits", "security_status", "security_note"):
            assert key in result

    def test_digest_length_bits_is_multiple_of_4(self):
        result = hash_text("any", "sha256")
        assert result["digest_length_bits"] % 4 == 0

    def test_algorithm_name_normalised(self):
        # Algorithm names are uppercased and underscores replaced with dashes in output
        result = hash_text("x", "sha256")
        assert result["algorithm"] == "SHA256"

    def test_unsupported_algorithm_raises(self):
        with pytest.raises(ValueError, match="Unsupported algorithm"):
            hash_text("data", "crc32")

    def test_empty_string(self):
        result = hash_text("", "sha256")
        assert result["input_length"] == 0
        assert len(result["digest"]) == 64  # SHA-256 is 64 hex chars

    def test_hash_all_returns_all_algorithms(self):
        results = hash_all("hello")
        assert len(results) == len(SUPPORTED_ALGORITHMS)


# ──────────────────────────────────────────────────────────────────────────────
# Test 2: verify_hash – constant-time comparison
# ──────────────────────────────────────────────────────────────────────────────
class TestVerifyHash:
    def test_correct_hash_returns_true(self):
        text = "correct horse battery staple"
        digest = hash_text(text, "sha256")["digest"]
        assert verify_hash(text, digest, "sha256") is True

    def test_wrong_hash_returns_false(self):
        assert verify_hash("hello", "0" * 64, "sha256") is False

    def test_case_insensitive_comparison(self):
        text = "CaseSensitive"
        digest = hash_text(text, "sha256")["digest"].upper()
        assert verify_hash(text, digest, "sha256") is True


# ──────────────────────────────────────────────────────────────────────────────
# Test 3: hash_file – file hashing
# ──────────────────────────────────────────────────────────────────────────────
class TestHashFile:
    def test_known_content(self, tmp_path):
        f = tmp_path / "sample.txt"
        content = b"file content for hashing"
        f.write_bytes(content)
        expected = hashlib.sha256(content).hexdigest()
        result = hash_file(str(f), "sha256")
        assert result["digest"] == expected

    def test_file_not_found_raises(self):
        with pytest.raises(FileNotFoundError):
            hash_file("/nonexistent/path/file.txt")

    def test_directory_raises(self, tmp_path):
        with pytest.raises(ValueError, match="Not a regular file"):
            hash_file(str(tmp_path))

    def test_verify_file_hash_true(self, tmp_path):
        f = tmp_path / "v.txt"
        f.write_bytes(b"verify me")
        digest = hash_file(str(f))["digest"]
        assert verify_file_hash(str(f), digest) is True

    def test_verify_file_hash_false_after_modification(self, tmp_path):
        f = tmp_path / "mod.txt"
        f.write_bytes(b"original")
        digest = hash_file(str(f))["digest"]
        f.write_bytes(b"tampered")
        assert verify_file_hash(str(f), digest) is False


# ──────────────────────────────────────────────────────────────────────────────
# Test 4: HMAC generation and verification
# ──────────────────────────────────────────────────────────────────────────────
class TestHMAC:
    def test_generate_hmac_produces_dict(self):
        result = generate_hmac("message", "secret", "sha256")
        assert "digest" in result
        assert result["algorithm"] == "HMAC-SHA256"

    def test_verify_hmac_correct_key_returns_true(self):
        msg, key = "auth me", "topsecret"
        digest = generate_hmac(msg, key, "sha256")["digest"]
        assert verify_hmac(msg, key, digest, "sha256") is True

    def test_verify_hmac_wrong_key_returns_false(self):
        msg = "auth me"
        digest = generate_hmac(msg, "correctkey", "sha256")["digest"]
        assert verify_hmac(msg, "wrongkey", digest, "sha256") is False

    def test_unsupported_hmac_algorithm_raises(self):
        with pytest.raises(ValueError, match="not supported for HMAC"):
            generate_hmac("msg", "key", "md5")
