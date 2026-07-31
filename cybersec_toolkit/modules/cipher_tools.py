"""
Cipher Tools
Classical and modern-era encryption and encoding tools for educational and practical use.
Includes: Caesar cipher, Vigenere cipher, XOR encryption, Base64, ROT13, URL encoding.
"""

import base64
import urllib.parse
import os
import secrets


# ─── Caesar Cipher ────────────────────────────────────────────────────────────

def caesar_encrypt(text: str, shift: int) -> str:
    """Encrypt text using Caesar cipher with the given shift value."""
    shift = shift % 26
    result = []
    for char in text:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            result.append(chr((ord(char) - base + shift) % 26 + base))
        else:
            result.append(char)
    return "".join(result)


def caesar_decrypt(text: str, shift: int) -> str:
    """Decrypt Caesar cipher text."""
    return caesar_encrypt(text, -shift)


def caesar_brute_force(ciphertext: str) -> list[dict]:
    """Try all 25 possible Caesar cipher shifts and return all possibilities."""
    return [
        {"shift": shift, "plaintext": caesar_decrypt(ciphertext, shift)}
        for shift in range(1, 26)
    ]


# ─── Vigenere Cipher ──────────────────────────────────────────────────────────

def _vigenere(text: str, key: str, encrypt: bool = True) -> str:
    """Internal Vigenere cipher implementation."""
    if not key.isalpha():
        raise ValueError("Vigenere key must contain only alphabetic characters")
    key = key.upper()
    result = []
    key_index = 0
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord("A")
            if not encrypt:
                shift = -shift
            base = ord("A") if char.isupper() else ord("a")
            result.append(chr((ord(char) - base + shift) % 26 + base))
            key_index += 1
        else:
            result.append(char)
    return "".join(result)


def vigenere_encrypt(text: str, key: str) -> str:
    """Encrypt text using the Vigenere cipher."""
    return _vigenere(text, key, encrypt=True)


def vigenere_decrypt(text: str, key: str) -> str:
    """Decrypt text using the Vigenere cipher."""
    return _vigenere(text, key, encrypt=False)


# ─── XOR Encryption ──────────────────────────────────────────────────────────

def xor_encrypt(text: str, key: str, encoding: str = "utf-8") -> dict:
    """
    Encrypt text using XOR with a key.
    XOR encryption is symmetric: encrypt and decrypt use the same operation.
    The result is returned as a hex string.
    Note: XOR alone is not cryptographically secure. Use with a random key only once (OTP).
    """
    text_bytes = text.encode(encoding)
    key_bytes = key.encode(encoding)
    encrypted = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(text_bytes))
    return {
        "ciphertext_hex": encrypted.hex(),
        "ciphertext_b64": base64.b64encode(encrypted).decode(),
        "key": key,
        "note": "XOR alone is not secure for repeated key use. Use AES for production encryption.",
    }


def xor_decrypt(ciphertext_hex: str, key: str, encoding: str = "utf-8") -> str:
    """Decrypt XOR-encrypted hex data."""
    encrypted = bytes.fromhex(ciphertext_hex)
    key_bytes = key.encode(encoding)
    decrypted = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(encrypted))
    return decrypted.decode(encoding)


# ─── ROT13 ───────────────────────────────────────────────────────────────────

def rot13(text: str) -> str:
    """Apply ROT13 transformation (Caesar cipher with shift 13; self-inverse)."""
    return caesar_encrypt(text, 13)


# ─── Base64 ──────────────────────────────────────────────────────────────────

def base64_encode(text: str, encoding: str = "utf-8") -> dict:
    """Encode text to Base64."""
    data = text.encode(encoding)
    return {
        "encoded": base64.b64encode(data).decode(),
        "url_safe": base64.urlsafe_b64encode(data).decode(),
        "note": "Base64 is encoding, not encryption. Do not use to protect sensitive data.",
    }


def base64_decode(encoded: str) -> str:
    """Decode a Base64 string. Handles both standard and URL-safe variants."""
    # Try standard first, then URL-safe
    try:
        return base64.b64decode(encoded + "==").decode("utf-8")
    except Exception:
        return base64.urlsafe_b64decode(encoded + "==").decode("utf-8")


# ─── URL Encoding ─────────────────────────────────────────────────────────────

def url_encode(text: str) -> dict:
    """Encode a string for safe use in a URL."""
    return {
        "encoded": urllib.parse.quote(text, safe=""),
        "encoded_plus": urllib.parse.quote_plus(text),
    }


def url_decode(encoded: str) -> str:
    """Decode a URL-encoded string."""
    return urllib.parse.unquote_plus(encoded)


# ─── Hex Encoding ─────────────────────────────────────────────────────────────

def to_hex(text: str, encoding: str = "utf-8") -> str:
    """Convert text to its hexadecimal representation."""
    return text.encode(encoding).hex()


def from_hex(hex_str: str, encoding: str = "utf-8") -> str:
    """Convert a hex string back to text."""
    return bytes.fromhex(hex_str).decode(encoding)


# ─── One-Time Pad (OTP) ──────────────────────────────────────────────────────

def otp_generate_key(length: int) -> str:
    """
    Generate a cryptographically secure random key for One-Time Pad encryption.
    The key must be at least as long as the message and used only ONCE.
    """
    return secrets.token_hex(length)


def otp_encrypt(text: str, key_hex: str, encoding: str = "utf-8") -> dict:
    """
    Encrypt text using a One-Time Pad (OTP).
    OTP is theoretically unbreakable when the key is truly random, secret, and used only once.
    """
    data = text.encode(encoding)
    key_bytes = bytes.fromhex(key_hex)
    if len(key_bytes) < len(data):
        raise ValueError(f"OTP key must be at least as long as the message ({len(data)} bytes required)")
    encrypted = bytes(b ^ key_bytes[i] for i, b in enumerate(data))
    return {
        "ciphertext_hex": encrypted.hex(),
        "message_length": len(data),
        "key_used_hex": key_hex[:len(data)*2],
        "note": "Never reuse the key. Destroy the key after use for true OTP security.",
    }


def otp_decrypt(ciphertext_hex: str, key_hex: str, encoding: str = "utf-8") -> str:
    """Decrypt OTP-encrypted data (same operation as encryption)."""
    data = bytes.fromhex(ciphertext_hex)
    key_bytes = bytes.fromhex(key_hex)
    decrypted = bytes(b ^ key_bytes[i] for i, b in enumerate(data))
    return decrypted.decode(encoding)
