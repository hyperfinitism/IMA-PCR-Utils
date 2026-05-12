# SPDX-License-Identifier: MIT
"""Tests for imapcrutils.log — IMA log data model and parsing."""

import pytest

from imapcrutils import IMALogEntry, parse_ima_log_string

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
