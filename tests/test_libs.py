# SPDX-License-Identifier: MIT
"""Tests for imapcrutils.libs — parsing, PCR10 replay, validation, and boot_aggregate."""

import hashlib
import struct

import pytest

from imapcrutils import (
    IMALogEntry,
    build_template_fields,
    calculate_boot_aggregate,
    calculate_expected_template_hash,
    calculate_pcr10,
    parse_ima_log_string,
    validate_ima_log_entry,
)

SAMPLE_LINE = "10 8facace9d7255a1985e976e9bb59675f211c82de ima-ng sha256:088faac4777b024045bd578c5c3f8efc4ac2cafb4af90a12832a762feb58eb88 boot_aggregate"  # noqa: E501

SAMPLE_LINE_LONG_PATH = "10 842c66cec8b78a650d98e85cbbf0b67fc1a2a605 ima-ng sha256:cf06a09ff00ee3275779e83cf9a4037dd822ba9dc16442584212f605ba71e341 /usr/lib/modules/6.14.0-1017-azure-fde/kernel/fs/autofs/autofs4.ko.zst"  # noqa: E501


# ---------------------------------------------------------------------------
# IMALogEntry.from_string
# ---------------------------------------------------------------------------


class TestIMALogEntryFromString:
    """Tests for IMALogEntry.from_string — parsing a single IMA log line."""

    def test_basic(self):
        """Parse a well-formed boot_aggregate line and verify every field."""
        entry = IMALogEntry.from_string(SAMPLE_LINE)
        assert entry.pcr_idx == "10"
        assert entry.template_hash == "8facace9d7255a1985e976e9bb59675f211c82de"
        assert entry.template_name == "ima-ng"
        assert entry.hash_algo == "sha256"
        assert entry.file_hash == bytes.fromhex("088faac4777b024045bd578c5c3f8efc4ac2cafb4af90a12832a762feb58eb88")
        assert entry.file_path == "boot_aggregate"

    def test_long_file_path(self):
        """Parse a line with a long absolute file path."""
        entry = IMALogEntry.from_string(SAMPLE_LINE_LONG_PATH)
        assert entry.file_path == ("/usr/lib/modules/6.14.0-1017-azure-fde/kernel/fs/autofs/autofs4.ko.zst")

    def test_file_path_with_spaces(self):
        """Spaces after the 4th field are preserved as part of the file path."""
        line = "10 aaaa ima-ng sha256:bbbb /path/with spaces/file name.txt"
        entry = IMALogEntry.from_string(line)
        assert entry.file_path == "/path/with spaces/file name.txt"

    def test_too_few_parts_raises(self):
        """Fewer than 5 space-separated fields must raise ValueError."""
        with pytest.raises(ValueError, match="Invalid IMA log entry"):
            IMALogEntry.from_string("10 abc ima-ng")

    def test_bad_hash_format_raises(self):
        """file_data field without a colon separator must raise ValueError."""
        with pytest.raises(ValueError, match="Invalid file_hash format"):
            IMALogEntry.from_string("10 abc ima-ng nocolon /some/path")

    def test_bad_hex_digest_raises(self):
        """Non-hex characters in the digest portion must raise ValueError."""
        with pytest.raises(ValueError, match="Invalid file_hash format"):
            IMALogEntry.from_string("10 abc ima-ng sha256:ZZZZ /some/path")


# ---------------------------------------------------------------------------
# IMALogEntry.__str__  (round-trip)
# ---------------------------------------------------------------------------


class TestIMALogEntryStr:
    """Tests for IMALogEntry.__str__ — round-trip fidelity."""

    def test_round_trip(self):
        """str(from_string(line)) must reproduce the original line."""
        entry = IMALogEntry.from_string(SAMPLE_LINE)
        assert str(entry) == SAMPLE_LINE

    def test_round_trip_long_path(self):
        """Round-trip with a long absolute file path."""
        entry = IMALogEntry.from_string(SAMPLE_LINE_LONG_PATH)
        assert str(entry) == SAMPLE_LINE_LONG_PATH


# ---------------------------------------------------------------------------
# parse_ima_log_string
# ---------------------------------------------------------------------------


class TestParseImaLogString:
    """Tests for parse_ima_log_string — multi-line IMA log parsing."""

    def test_sample_file(self, sample_ima_log):
        """Parse the full 32-entry sample log and spot-check first/last entries."""
        entries = parse_ima_log_string(sample_ima_log)
        assert len(entries) == 32
        assert entries[0].file_path == "boot_aggregate"
        assert entries[-1].file_path.endswith("tls.ko.zst")

    def test_empty_string(self):
        """Empty input must produce an empty list."""
        assert not parse_ima_log_string("")

    def test_blank_lines_skipped(self):
        """Blank lines (leading, trailing, between entries) are ignored."""
        log = "\n" + SAMPLE_LINE + "\n\n" + SAMPLE_LINE_LONG_PATH + "\n\n"
        entries = parse_ima_log_string(log)
        assert len(entries) == 2

    def test_single_line(self):
        """A single line (no trailing newline) is parsed correctly."""
        entries = parse_ima_log_string(SAMPLE_LINE)
        assert len(entries) == 1
        assert entries[0].pcr_idx == "10"


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
