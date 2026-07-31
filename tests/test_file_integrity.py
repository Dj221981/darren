"""Unit tests for cybersec_toolkit.modules.file_integrity"""

import json
import os
import pytest

from cybersec_toolkit.modules.file_integrity import (
    create_manifest,
    verify_manifest,
    check_single_file,
)


# ──────────────────────────────────────────────────────────────────────────────
# create_manifest
# ──────────────────────────────────────────────────────────────────────────────
class TestCreateManifest:
    def test_creates_manifest_file(self, tmp_path):
        f = tmp_path / "data.txt"
        f.write_bytes(b"some content")
        manifest_path = str(tmp_path / "manifest.json")
        create_manifest([str(f)], output_file=manifest_path)
        assert os.path.isfile(manifest_path)

    def test_manifest_contains_file_entry(self, tmp_path):
        f = tmp_path / "check.txt"
        f.write_bytes(b"hello")
        manifest_path = str(tmp_path / "manifest.json")
        create_manifest([str(f)], output_file=manifest_path)
        with open(manifest_path) as fp:
            manifest = json.load(fp)
        assert str(f.resolve()) in manifest["files"]

    def test_summary_files_processed_count(self, tmp_path):
        files = [tmp_path / f"f{i}.txt" for i in range(3)]
        for fi in files:
            fi.write_bytes(b"data")
        manifest_path = str(tmp_path / "m.json")
        summary = create_manifest([str(f) for f in files], output_file=manifest_path)
        assert summary["files_processed"] == 3

    def test_nonexistent_path_recorded_as_error(self, tmp_path):
        manifest_path = str(tmp_path / "m.json")
        summary = create_manifest(["/no/such/file.txt"], output_file=manifest_path)
        assert len(summary["errors"]) == 1

    def test_directory_scanned_recursively(self, tmp_path):
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "a.txt").write_bytes(b"a")
        (sub / "b.txt").write_bytes(b"b")
        manifest_path = str(tmp_path / "m.json")
        summary = create_manifest([str(sub)], output_file=manifest_path)
        assert summary["files_processed"] == 2


# ──────────────────────────────────────────────────────────────────────────────
# verify_manifest
# ──────────────────────────────────────────────────────────────────────────────
class TestVerifyManifest:
    def _make_manifest(self, tmp_path, files: dict) -> str:
        """Helper: write files and create manifest, return manifest path."""
        for name, content in files.items():
            (tmp_path / name).write_bytes(content)
        manifest_path = str(tmp_path / "m.json")
        create_manifest([str(tmp_path / n) for n in files], output_file=manifest_path)
        return manifest_path

    def test_all_pass_when_unmodified(self, tmp_path):
        manifest_path = self._make_manifest(tmp_path, {"ok.txt": b"original"})
        report = verify_manifest(manifest_path)
        assert report["overall_status"] == "PASS"
        assert len(report["passed"]) == 1
        assert len(report["failed"]) == 0

    def test_tampered_file_detected(self, tmp_path):
        f = tmp_path / "target.txt"
        manifest_path = self._make_manifest(tmp_path, {"target.txt": b"original content"})
        f.write_bytes(b"tampered content")
        report = verify_manifest(manifest_path)
        assert report["overall_status"] == "FAIL"
        assert len(report["failed"]) == 1

    def test_missing_file_detected(self, tmp_path):
        manifest_path = self._make_manifest(tmp_path, {"gone.txt": b"data"})
        (tmp_path / "gone.txt").unlink()
        report = verify_manifest(manifest_path)
        assert report["overall_status"] == "FAIL"
        assert len(report["missing"]) == 1

    def test_manifest_not_found_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            verify_manifest(str(tmp_path / "nonexistent_manifest.json"))

    def test_report_contains_required_keys(self, tmp_path):
        manifest_path = self._make_manifest(tmp_path, {"r.txt": b"x"})
        report = verify_manifest(manifest_path)
        for key in ("manifest_file", "algorithm", "created_at", "total_files", "passed", "failed", "missing", "overall_status"):
            assert key in report


# ──────────────────────────────────────────────────────────────────────────────
# check_single_file
# ──────────────────────────────────────────────────────────────────────────────
class TestCheckSingleFile:
    def test_returns_modified_at(self, tmp_path):
        f = tmp_path / "single.txt"
        f.write_bytes(b"check me")
        result = check_single_file(str(f))
        assert "modified_at" in result

    def test_returns_hash_digest(self, tmp_path):
        f = tmp_path / "hash.txt"
        f.write_bytes(b"hash me")
        result = check_single_file(str(f))
        assert "digest" in result
        assert len(result["digest"]) == 64  # SHA-256 hex length
