"""
File Integrity Checker
Generate, store, and verify file hashes to detect tampering or corruption.
"""

import json
import hashlib
import os
import time
from pathlib import Path
from typing import Optional
from .hash_tools import hash_file, verify_file_hash


DEFAULT_MANIFEST = "integrity_manifest.json"
DEFAULT_ALGORITHM = "sha256"


def create_manifest(paths: list[str], output_file: str = DEFAULT_MANIFEST, algorithm: str = DEFAULT_ALGORITHM) -> dict:
    """
    Create a file integrity manifest for one or more files/directories.
    The manifest stores hashes and metadata for later verification.

    Returns a summary of the manifest creation.
    """
    manifest = {
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "algorithm": algorithm.upper().replace("_", "-"),
        "files": {},
    }

    processed = 0
    errors = []

    for path_str in paths:
        path = Path(path_str)

        if path.is_file():
            _add_file_to_manifest(path, manifest, algorithm, errors)
            processed += 1
        elif path.is_dir():
            for file_path in sorted(path.rglob("*")):
                if file_path.is_file():
                    _add_file_to_manifest(file_path, manifest, algorithm, errors)
                    processed += 1
        else:
            errors.append(f"Path not found: {path_str}")

    output_path = Path(output_file)
    with open(output_path, "w") as f:
        json.dump(manifest, f, indent=2)

    return {
        "manifest_file": str(output_path.resolve()),
        "files_processed": processed,
        "algorithm": manifest["algorithm"],
        "created_at": manifest["created_at"],
        "errors": errors,
    }


def _add_file_to_manifest(file_path: Path, manifest: dict, algorithm: str, errors: list) -> None:
    """Helper: hash a single file and add its entry to the manifest."""
    try:
        result = hash_file(str(file_path), algorithm)
        manifest["files"][str(file_path.resolve())] = {
            "hash": result["digest"],
            "size_bytes": result["file_size_bytes"],
            "added_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
    except Exception as e:
        errors.append(f"{file_path}: {e}")


def verify_manifest(manifest_file: str = DEFAULT_MANIFEST) -> dict:
    """
    Verify all files in a manifest against their stored hashes.

    Returns a detailed report with passed, failed, and missing files.
    """
    manifest_path = Path(manifest_file)
    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifest file not found: {manifest_file}")

    with open(manifest_path) as f:
        manifest = json.load(f)

    algorithm = manifest.get("algorithm", "SHA-256").lower().replace("-", "_")
    files = manifest.get("files", {})

    passed = []
    failed = []
    missing = []

    for file_str, info in files.items():
        file_path = Path(file_str)
        expected_hash = info["hash"]

        if not file_path.exists():
            missing.append({"file": file_str, "reason": "File not found"})
            continue

        try:
            matches = verify_file_hash(str(file_path), expected_hash, algorithm)
            if matches:
                passed.append({"file": file_str, "hash": expected_hash})
            else:
                result = hash_file(str(file_path), algorithm)
                failed.append({
                    "file": file_str,
                    "expected": expected_hash,
                    "actual": result["digest"],
                    "reason": "Hash mismatch — file may have been tampered with",
                })
        except Exception as e:
            failed.append({"file": file_str, "expected": expected_hash, "actual": "", "reason": str(e)})

    return {
        "manifest_file": str(manifest_path.resolve()),
        "algorithm": manifest.get("algorithm", "Unknown"),
        "created_at": manifest.get("created_at", "Unknown"),
        "total_files": len(files),
        "passed": passed,
        "failed": failed,
        "missing": missing,
        "overall_status": "PASS" if not failed and not missing else "FAIL",
    }


def check_single_file(file_path: str, algorithm: str = DEFAULT_ALGORITHM) -> dict:
    """Compute and display hash info for a single file."""
    result = hash_file(file_path, algorithm)
    stat = Path(file_path).stat()
    return {
        **result,
        "modified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stat.st_mtime)),
    }
