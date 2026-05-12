# SPDX-License-Identifier: MIT
"""Tests for imapcrutils.template — ima-ng template fields and template_hash."""

import hashlib
import struct

from imapcrutils import (
    IMALogEntry,
    build_template_fields,
    calculate_expected_template_hash,
    parse_ima_log_string,
    validate_ima_log_entry,
)

SAMPLE_LINE = "10 8facace9d7255a1985e976e9bb59675f211c82de ima-ng sha256:088faac4777b024045bd578c5c3f8efc4ac2cafb4af90a12832a762feb58eb88 boot_aggregate"  # noqa: E501


# ---------------------------------------------------------------------------
# build_template_fields
# ---------------------------------------------------------------------------


class TestBuildTemplateFields:
    """Tests for build_template_fields — ima-ng d-ng/n-ng field construction."""

    def test_first_entry(self):
        """Verify d-ng and n-ng field layout for the boot_aggregate entry."""
        entry = IMALogEntry.from_string(SAMPLE_LINE)
        d_ng_content, d_ng_field, n_ng_content, n_ng_field = build_template_fields(entry)

        # d-ng content: "sha256:\x00" + digest_bytes
        assert d_ng_content.startswith(b"sha256:\x00")
        assert d_ng_content[8:] == entry.file_hash

        # d-ng field: little-endian uint32 length prefix + content
        length = struct.unpack("<I", d_ng_field[:4])[0]
        assert length == len(d_ng_content)
        assert d_ng_field[4:] == d_ng_content

        # n-ng content: filepath + \x00
        assert n_ng_content == b"boot_aggregate\x00"

        # n-ng field: little-endian uint32 length prefix + content
        length = struct.unpack("<I", n_ng_field[:4])[0]
        assert length == len(n_ng_content)
        assert n_ng_field[4:] == n_ng_content


# ---------------------------------------------------------------------------
# calculate_expected_template_hash
# ---------------------------------------------------------------------------


class TestCalculateExpectedTemplateHash:
    """Tests for calculate_expected_template_hash — recomputing template_hash."""

    def test_sha1_matches_recorded(self):
        """Recomputed SHA-1 template hash must match the recorded value in the log."""
        entry = IMALogEntry.from_string(SAMPLE_LINE)
        expected = calculate_expected_template_hash(entry, hashlib.sha1)
        assert expected.hex() == "8facace9d7255a1985e976e9bb59675f211c82de"

    def test_sha256_different_from_sha1(self):
        """SHA-256 template hash must differ from SHA-1 and have the correct digest size."""
        entry = IMALogEntry.from_string(SAMPLE_LINE)
        sha1_hash = calculate_expected_template_hash(entry, hashlib.sha1)
        sha256_hash = calculate_expected_template_hash(entry, hashlib.sha256)
        assert sha1_hash != sha256_hash
        assert len(sha1_hash) == 20
        assert len(sha256_hash) == 32


# ---------------------------------------------------------------------------
# validate_ima_log_entry
# ---------------------------------------------------------------------------


class TestValidateImaLogEntry:
    """Tests for validate_ima_log_entry — checking template_hash integrity."""

    def test_valid_entry(self):
        """A genuine sample entry must pass validation."""
        entry = IMALogEntry.from_string(SAMPLE_LINE)
        assert validate_ima_log_entry(entry, hashlib.sha1) is True

    def test_all_sample_entries_valid(self, sample_ima_log):
        """Every entry in the sample log must pass SHA-1 template hash validation."""
        entries = parse_ima_log_string(sample_ima_log)
        for entry in entries:
            assert validate_ima_log_entry(entry, hashlib.sha1) is True

    def test_tampered_entry_invalid(self):
        """Tampering with file_path must cause validation to fail."""
        entry = IMALogEntry.from_string(SAMPLE_LINE)
        entry.file_path = "tampered_path"
        assert validate_ima_log_entry(entry, hashlib.sha1) is False

    def test_tampered_file_hash_invalid(self):
        """Tampering with file_hash must cause validation to fail."""
        entry = IMALogEntry.from_string(SAMPLE_LINE)
        entry.file_hash = b"\x00" * 32
        assert validate_ima_log_entry(entry, hashlib.sha1) is False
