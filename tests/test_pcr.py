# SPDX-License-Identifier: MIT
"""Tests for imapcrutils.pcr — PCR10 replay, log truncation, and boot_aggregate."""

import hashlib

import pytest

from imapcrutils import (
    calculate_boot_aggregate,
    calculate_expected_template_hash,
    calculate_pcr10,
    parse_ima_log_string,
    truncate_ima_log_by_pcr,
)

SAMPLE_LINE = "10 8facace9d7255a1985e976e9bb59675f211c82de ima-ng sha256:088faac4777b024045bd578c5c3f8efc4ac2cafb4af90a12832a762feb58eb88 boot_aggregate"  # noqa: E501


# ---------------------------------------------------------------------------
# calculate_pcr10  (known-answer tests against sample data)
# ---------------------------------------------------------------------------

EXPECTED_PCR10_SHA256 = "90e7c2df7e39d26d13a7f67f68ff3c92bb22abb7477322a96b314b98d82524ee"
EXPECTED_PCR10_SHA1 = "90bd4fd2f7584f4f86ca63937fb8360104e5d997"


class TestCalculatePcr10:
    """Tests for calculate_pcr10 — PCR10 replay from IMA log entries."""

    def test_sha256(self, sample_ima_log):
        """Known-answer test: SHA-256 PCR10 from the sample log."""
        entries = parse_ima_log_string(sample_ima_log)
        pcr10 = calculate_pcr10(entries, hashlib.sha256)
        assert pcr10.hex() == EXPECTED_PCR10_SHA256

    def test_sha1(self, sample_ima_log):
        """Known-answer test: SHA-1 PCR10 from the sample log."""
        entries = parse_ima_log_string(sample_ima_log)
        pcr10 = calculate_pcr10(entries, hashlib.sha1)
        assert pcr10.hex() == EXPECTED_PCR10_SHA1

    def test_pcr10_matches_pcr_blob(self, sample_ima_log, sample_pcr_blob):
        """PCR10 computed from IMA log must match PCR[10] in the PCR blob."""
        entries = parse_ima_log_string(sample_ima_log)
        pcr10 = calculate_pcr10(entries, hashlib.sha256)
        pcr10_from_blob = sample_pcr_blob[10 * 32 : 11 * 32]
        assert pcr10 == pcr10_from_blob

    def test_empty_entries(self):
        """No entries must return the initial all-zeros PCR value."""
        pcr10 = calculate_pcr10([], hashlib.sha256)
        assert pcr10 == bytes(32)

    def test_non_pcr10_entries_skipped(self):
        """Entries with pcr_idx != '10' must not affect the PCR10 value."""
        line = SAMPLE_LINE.replace("10 ", "11 ", 1)
        entries = parse_ima_log_string(line)
        pcr10 = calculate_pcr10(entries, hashlib.sha256)
        assert pcr10 == bytes(32)

    def test_non_ima_ng_template_skipped(self):
        """Entries with a template other than 'ima-ng' must not affect PCR10."""
        line = SAMPLE_LINE.replace("ima-ng", "ima-sig")
        entries = parse_ima_log_string(line)
        pcr10 = calculate_pcr10(entries, hashlib.sha256)
        assert pcr10 == bytes(32)

    def test_single_entry(self):
        """PCR10 from one entry must equal HASH(zeros || template_hash)."""
        entries = parse_ima_log_string(SAMPLE_LINE)
        pcr10 = calculate_pcr10(entries, hashlib.sha256)
        expected_template = calculate_expected_template_hash(entries[0], hashlib.sha256)
        expected_pcr10 = hashlib.sha256(bytes(32) + expected_template).digest()
        assert pcr10 == expected_pcr10


# ---------------------------------------------------------------------------
# calculate_boot_aggregate
# ---------------------------------------------------------------------------

EXPECTED_BOOT_AGGREGATE_SHA256 = "088faac4777b024045bd578c5c3f8efc4ac2cafb4af90a12832a762feb58eb88"


class TestCalculateBootAggregate:
    """Tests for calculate_boot_aggregate — HASH(PCR0 || ... || PCR9)."""

    def test_sha256(self, sample_pcr_blob):
        """Known-answer test: SHA-256 boot_aggregate from the sample PCR blob."""
        pcr_list = [sample_pcr_blob[i * 32 : (i + 1) * 32] for i in range(10)]
        ba = calculate_boot_aggregate(pcr_list, hashlib.sha256)
        assert ba.hex() == EXPECTED_BOOT_AGGREGATE_SHA256

    def test_matches_first_ima_entry(self, sample_ima_log, sample_pcr_blob):
        """boot_aggregate must equal the file_hash of the first IMA log entry."""
        entries = parse_ima_log_string(sample_ima_log)
        pcr_list = [sample_pcr_blob[i * 32 : (i + 1) * 32] for i in range(10)]
        ba = calculate_boot_aggregate(pcr_list, hashlib.sha256)
        assert ba == entries[0].file_hash

    def test_wrong_pcr_list_length_raises(self):
        """Fewer than 10 PCRs must raise ValueError."""
        with pytest.raises(ValueError, match="length of PCR list is expected to be 10"):
            calculate_boot_aggregate([b"\x00" * 32] * 9, hashlib.sha256)

    def test_wrong_pcr_list_length_too_many_raises(self):
        """More than 10 PCRs must raise ValueError."""
        with pytest.raises(ValueError, match="length of PCR list is expected to be 10"):
            calculate_boot_aggregate([b"\x00" * 32] * 11, hashlib.sha256)

    def test_all_zeros(self):
        """All-zero PCRs must produce SHA-256(320 zero bytes)."""
        pcr_list = [bytes(32)] * 10
        ba = calculate_boot_aggregate(pcr_list, hashlib.sha256)
        expected = hashlib.sha256(bytes(320)).digest()
        assert ba == expected


# ---------------------------------------------------------------------------
# truncate_ima_log_by_pcr
# ---------------------------------------------------------------------------

EXPECTED_PCR10_SHA256_2 = "c5bfcd40187bfc190fe9c584b8b2675f08180c0e9579255fa9eba91e7d18f678"


class TestTruncateImaLogByPcr:
    """Tests for truncate_ima_log_by_pcr — finding the matching PCR10 point."""

    def test_truncate_with_sample_2(self, sample_ima_log_2, sample_pcr_blob_2):
        """Truncate IMA log to find the matching PCR10 from sample_2."""
        entries = parse_ima_log_string(sample_ima_log_2)
        pcr10_reference = sample_pcr_blob_2[10 * 32 : 11 * 32]
        result = truncate_ima_log_by_pcr(entries, pcr10_reference, hashlib.sha256)
        assert result is not None
        # Verify the truncated list has PCR10 matching the reference
        computed_pcr10 = calculate_pcr10(result, hashlib.sha256)
        assert computed_pcr10 == pcr10_reference

    def test_truncate_returns_sublist(self, sample_ima_log_2, sample_pcr_blob_2):
        """Truncated result must be a sublist from the beginning."""
        entries = parse_ima_log_string(sample_ima_log_2)
        pcr10_reference = sample_pcr_blob_2[10 * 32 : 11 * 32]
        result = truncate_ima_log_by_pcr(entries, pcr10_reference, hashlib.sha256)
        assert result is not None
        # Result must be a prefix of the original entries (same sequence from start)
        assert result == entries[: len(result)]
        # First entry must be the same
        assert result[0].file_path == entries[0].file_path

    def test_truncate_not_found_returns_none(self, sample_ima_log):
        """Truncate with a non-matching PCR10 reference must return None."""
        entries = parse_ima_log_string(sample_ima_log)
        # Use a random PCR10 value that won't match
        fake_pcr10 = b"\x00" * 32
        result = truncate_ima_log_by_pcr(entries, fake_pcr10, hashlib.sha256)
        assert result is None

    def test_truncate_empty_entries_returns_none(self, sample_pcr_blob_2):
        """Truncate with empty entries must return None."""
        pcr10_reference = sample_pcr_blob_2[10 * 32 : 11 * 32]
        result = truncate_ima_log_by_pcr([], pcr10_reference, hashlib.sha256)
        assert result is None

    def test_truncate_single_entry_match(self):
        """Truncate with a single entry that matches must return that entry."""
        entries = parse_ima_log_string(SAMPLE_LINE)
        # Calculate what the PCR10 would be with just this one entry
        expected_template = calculate_expected_template_hash(entries[0], hashlib.sha256)
        pcr10_reference = hashlib.sha256(bytes(32) + expected_template).digest()
        result = truncate_ima_log_by_pcr(entries, pcr10_reference, hashlib.sha256)
        assert result is not None
        assert len(result) == 1
        assert result[0].file_path == "boot_aggregate"

    def test_truncate_pcr10_indices_only(self, sample_ima_log_2, sample_pcr_blob_2):
        """Only PCR 10 entries should be included in the calculation."""
        entries = parse_ima_log_string(sample_ima_log_2)
        # Filter to only PCR10 entries
        pcr10_reference = sample_pcr_blob_2[10 * 32 : 11 * 32]
        result = truncate_ima_log_by_pcr(entries, pcr10_reference, hashlib.sha256)
        assert result is not None
        # All entries in result must be PCR10
        for entry in result:
            assert entry.pcr_idx == "10"

    def test_truncate_ima_ng_template_only(self, sample_ima_log_2, sample_pcr_blob_2):
        """Only ima-ng template entries should be included."""
        entries = parse_ima_log_string(sample_ima_log_2)
        pcr10_reference = sample_pcr_blob_2[10 * 32 : 11 * 32]
        result = truncate_ima_log_by_pcr(entries, pcr10_reference, hashlib.sha256)
        assert result is not None
        # All entries in result must be ima-ng
        for entry in result:
            assert entry.template_name == "ima-ng"

    def test_truncate_with_sha1(self, sample_ima_log):
        """Truncate must work with SHA-1 hash function."""
        entries = parse_ima_log_string(sample_ima_log)
        # Calculate expected PCR10 with SHA-1
        pcr10_sha1 = calculate_pcr10(entries, hashlib.sha1)
        # Now use truncate to find it
        result = truncate_ima_log_by_pcr(entries, pcr10_sha1, hashlib.sha1)
        assert result is not None
        # The entire log should match (the final PCR10)
        assert len(result) == len(entries)
