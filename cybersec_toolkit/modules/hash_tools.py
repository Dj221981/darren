"""
Hash Tools
Generate and verify cryptographic hashes. Supports MD5, SHA-1, SHA-256, SHA-512, SHA-3.
Also includes HMAC generation for message authentication.
"""

import hashlib
import hmac
import os
from pathlib import Path
from typing import Optional

SUPPORTED_ALGORITHMS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha224": hashlib.sha224,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
    "sha3_256": hashlib.sha3_256,
    "sha3_512": hashlib.sha3_512,
    "blake2b": hashlib.blake2b,
    "blake2s": hashlib.blake2s,
}

SECURITY_NOTES = {
    "md5": ("Broken", "MD5 is cryptographically broken. Do NOT use for security purposes."),
    "sha1": ("Deprecated", "SHA-1 is deprecated for most security uses due to collision attacks."),
    "sha224": ("Acceptable", "SHA-224 is acceptable but SHA-256 or higher is preferred."),
    "sha256": ("Recommended", "SHA-256 is widely used and recommended for most purposes."),
    "sha384": ("Strong", "SHA-384 provides excellent security for sensitive data."),
    "sha512": ("Strong", "SHA-512 is highly secure and recommended for passwords and signatures."),
    "sha3_256": ("Recommended", "SHA3-256 is a modern standard resistant to length-extension attacks."),
    "sha3_512": ("Strong", "SHA3-512 provides the highest security in the SHA-3 family."),
    "blake2b": ("Recommended", "BLAKE2b is faster than SHA-2 with equivalent security."),
    "blake2s": ("Recommended", "BLAKE2s is optimized for 32-bit platforms."),
}


def hash_text(text: str, algorithm: str = "sha256", encoding: str = "utf-8") -> dict:
    """
    Hash a string using the specified algorithm.

    Returns a dict with the hash digest and metadata.
    """
    algo = algorithm.lower().replace("-", "_")
    if algo not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm '{algorithm}'. Choose from: {', '.join(SUPPORTED_ALGORITHMS)}")

    data = text.encode(encoding)
    h = SUPPORTED_ALGORITHMS[algo](data)
    digest = h.hexdigest()
    status, note = SECURITY_NOTES.get(algo, ("Unknown", ""))

    return {
        "algorithm": algo.upper().replace("_", "-"),
        "input_length": len(data),
        "digest": digest,
        "digest_length_bits": len(digest) * 4,
        "security_status": status,
        "security_note": note,
    }


def hash_all(text: str, encoding: str = "utf-8") -> list:
    """Hash text with all supported algorithms and return results."""
    results = []
    for algo in SUPPORTED_ALGORITHMS:
        results.append(hash_text(text, algo, encoding))
    return results


def verify_hash(text: str, expected_hash: str, algorithm: str = "sha256", encoding: str = "utf-8") -> bool:
    """
    Verify that a text matches an expected hash.
    Uses constant-time comparison to prevent timing attacks.
    """
    result = hash_text(text, algorithm, encoding)
    # hmac.compare_digest prevents timing attacks
    return hmac.compare_digest(result["digest"].lower(), expected_hash.lower())


def hash_file(file_path: str, algorithm: str = "sha256", chunk_size: int = 65536) -> dict:
    """
    Compute the hash of a file.
    Reads in chunks to handle large files without loading them entirely into memory.
    """
    algo = algorithm.lower().replace("-", "_")
    if algo not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm '{algorithm}'")

    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    if not path.is_file():
        raise ValueError(f"Not a regular file: {file_path}")

    h = SUPPORTED_ALGORITHMS[algo]()
    file_size = path.stat().st_size

    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)

    status, note = SECURITY_NOTES.get(algo, ("Unknown", ""))

    return {
        "file": str(path.resolve()),
        "file_size_bytes": file_size,
        "algorithm": algo.upper().replace("_", "-"),
        "digest": h.hexdigest(),
        "security_status": status,
        "security_note": note,
    }


def verify_file_hash(file_path: str, expected_hash: str, algorithm: str = "sha256") -> bool:
    """Verify a file's hash matches the expected value. Uses constant-time comparison."""
    result = hash_file(file_path, algorithm)
    return hmac.compare_digest(result["digest"].lower(), expected_hash.lower())


def generate_hmac(message: str, secret_key: str, algorithm: str = "sha256", encoding: str = "utf-8") -> dict:
    """
    Generate an HMAC (Hash-based Message Authentication Code).
    HMACs are used to verify both the integrity and authenticity of a message.
    """
    algo = algorithm.lower().replace("-", "_")
    supported_hmac = {"sha256", "sha512", "sha1", "sha384", "sha3_256", "sha3_512"}
    if algo not in supported_hmac:
        raise ValueError(f"Algorithm '{algorithm}' not supported for HMAC. Use: {', '.join(supported_hmac)}")

    key = secret_key.encode(encoding)
    msg = message.encode(encoding)

    h = hmac.new(key, msg, getattr(hashlib, algo))
    digest = h.hexdigest()

    return {
        "algorithm": f"HMAC-{algo.upper().replace('_', '-')}",
        "message_length": len(msg),
        "digest": digest,
        "note": "Keep the secret key confidential. Share only the HMAC digest for verification.",
    }


def verify_hmac(message: str, secret_key: str, expected_hmac: str, algorithm: str = "sha256", encoding: str = "utf-8") -> bool:
    """Verify an HMAC in constant time to prevent timing attacks."""
    result = generate_hmac(message, secret_key, algorithm, encoding)
    return hmac.compare_digest(result["digest"].lower(), expected_hmac.lower())
