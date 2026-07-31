"""Unit tests for cybersec_toolkit.modules.cipher_tools"""

import pytest

from cybersec_toolkit.modules.cipher_tools import (
    caesar_encrypt,
    caesar_decrypt,
    caesar_brute_force,
    vigenere_encrypt,
    vigenere_decrypt,
    xor_encrypt,
    xor_decrypt,
    rot13,
    base64_encode,
    base64_decode,
    url_encode,
    url_decode,
    to_hex,
    from_hex,
    otp_generate_key,
    otp_encrypt,
    otp_decrypt,
)


# ──────────────────────────────────────────────────────────────────────────────
# Caesar cipher
# ──────────────────────────────────────────────────────────────────────────────
class TestCaesarCipher:
    def test_encrypt_shift_3(self):
        assert caesar_encrypt("ABC", 3) == "DEF"

    def test_decrypt_reverses_encrypt(self):
        plain = "Hello, World!"
        shift = 7
        assert caesar_decrypt(caesar_encrypt(plain, shift), shift) == plain

    def test_non_alpha_unchanged(self):
        assert caesar_encrypt("123!@#", 5) == "123!@#"

    def test_shift_wraps_around(self):
        assert caesar_encrypt("Z", 1) == "A"

    def test_brute_force_length(self):
        results = caesar_brute_force("XYZ")
        assert len(results) == 25

    def test_brute_force_contains_original(self):
        plain = "HELLO"
        shift = 10
        cipher = caesar_encrypt(plain, shift)
        shifts = {r["shift"] for r in caesar_brute_force(cipher) if r["plaintext"] == plain}
        assert len(shifts) == 1


# ──────────────────────────────────────────────────────────────────────────────
# Vigenere cipher
# ──────────────────────────────────────────────────────────────────────────────
class TestVigenereCipher:
    def test_encrypt_decrypt_roundtrip(self):
        plain, key = "AttackAtDawn", "LEMON"
        assert vigenere_decrypt(vigenere_encrypt(plain, key), key) == plain

    def test_non_alpha_key_raises(self):
        with pytest.raises(ValueError, match="only alphabetic"):
            vigenere_encrypt("hello", "key123")

    def test_non_alpha_chars_preserved(self):
        result = vigenere_encrypt("Hello, World!", "KEY")
        assert result[5] == ","
        assert result[6] == " "


# ──────────────────────────────────────────────────────────────────────────────
# XOR encryption
# ──────────────────────────────────────────────────────────────────────────────
class TestXorEncryption:
    def test_encrypt_produces_hex(self):
        result = xor_encrypt("secret", "key")
        assert isinstance(result["ciphertext_hex"], str)
        assert all(c in "0123456789abcdef" for c in result["ciphertext_hex"])

    def test_decrypt_reverses_encrypt(self):
        text, key = "XOR test 123", "mykey"
        enc = xor_encrypt(text, key)
        assert xor_decrypt(enc["ciphertext_hex"], key) == text

    def test_different_keys_different_output(self):
        text = "same text"
        enc1 = xor_encrypt(text, "key1")["ciphertext_hex"]
        enc2 = xor_encrypt(text, "key2")["ciphertext_hex"]
        assert enc1 != enc2


# ──────────────────────────────────────────────────────────────────────────────
# ROT13
# ──────────────────────────────────────────────────────────────────────────────
class TestRot13:
    def test_self_inverse(self):
        text = "Hello World"
        assert rot13(rot13(text)) == text

    def test_known_value(self):
        assert rot13("abc") == "nop"


# ──────────────────────────────────────────────────────────────────────────────
# Base64
# ──────────────────────────────────────────────────────────────────────────────
class TestBase64:
    def test_encode_decode_roundtrip(self):
        text = "Hello, Base64!"
        encoded = base64_encode(text)["encoded"]
        assert base64_decode(encoded) == text

    def test_encode_returns_url_safe(self):
        result = base64_encode("test")
        assert "url_safe" in result

    def test_decode_handles_standard_padding(self):
        # "hello" base64 = "aGVsbG8="
        assert base64_decode("aGVsbG8=") == "hello"


# ──────────────────────────────────────────────────────────────────────────────
# URL encoding
# ──────────────────────────────────────────────────────────────────────────────
class TestUrlEncoding:
    def test_encode_decode_roundtrip(self):
        text = "hello world & more=yes"
        encoded = url_encode(text)["encoded"]
        assert url_decode(encoded) == text

    def test_spaces_encoded(self):
        result = url_encode("hello world")["encoded"]
        assert " " not in result

    def test_plus_variant(self):
        result = url_encode("hello world")
        assert "+" not in result["encoded"]  # quote() uses %20, not +


# ──────────────────────────────────────────────────────────────────────────────
# Hex encoding
# ──────────────────────────────────────────────────────────────────────────────
class TestHexEncoding:
    def test_to_and_from_hex_roundtrip(self):
        text = "cybersec!"
        assert from_hex(to_hex(text)) == text

    def test_known_hex_value(self):
        # "hi" → 68 69
        assert to_hex("hi") == "6869"


# ──────────────────────────────────────────────────────────────────────────────
# One-Time Pad
# ──────────────────────────────────────────────────────────────────────────────
class TestOneTimePad:
    def test_encrypt_decrypt_roundtrip(self):
        msg = "OTP test message"
        key = otp_generate_key(len(msg))
        enc = otp_encrypt(msg, key)
        assert otp_decrypt(enc["ciphertext_hex"], key) == msg

    def test_short_key_raises(self):
        msg = "longer message"
        key = otp_generate_key(2)  # too short
        with pytest.raises(ValueError, match="at least as long"):
            otp_encrypt(msg, key)

    def test_key_length(self):
        key = otp_generate_key(16)
        # token_hex(n) returns 2n hex chars
        assert len(key) == 32
