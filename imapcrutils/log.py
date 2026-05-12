# SPDX-License-Identifier: MIT
"""
IMA log data model and parser.

Provides :class:`IMALogEntry` representing a single IMA log line and
:func:`parse_ima_log_string` for parsing a multi-line log into a list of
entries.
"""

__all__ = [
    "IMALogEntry",
    "parse_ima_log_string",
]

from dataclasses import dataclass


@dataclass
class IMALogEntry:
    """Structure representing a single IMA log entry."""

    # Fields
    pcr_idx: str
    template_hash: str
    template_name: str
    hash_algo: str
    file_hash: bytes
    file_path: str

    # Methods
    def __str__(self) -> str:
        """Return a string representation of the IMALogEntry."""
        return " ".join(
            [self.pcr_idx, self.template_hash, self.template_name, self.hash_algo + ":" + self.file_hash.hex(), self.file_path]
        )

    @classmethod
    def from_string(cls, line: str) -> "IMALogEntry":
        """
        Parse a single line from IMA log and convert it to IMALogEntry.

        Args:
            line: A line from IMA log file
            (format: "pcr_idx template_hash template_name file_data file_path")

        Returns:
            IMALogEntry
        """
        parts = line.strip().split(" ")
        if len(parts) < 5:
            raise ValueError(f"Invalid IMA log entry: {line}")
        pcr_idx = parts[0]
        template_hash = parts[1]
        template_name = parts[2]
        # format: "algo:hexdigest" e.g. "sha256:0123456789abcdef..."
        try:
            hash_algo, file_hash_hex = parts[3].split(":")
            file_hash = bytes.fromhex(file_hash_hex)
        except ValueError as e:
            raise ValueError(f"Invalid file_hash format: {parts[3]}") from e
        file_path = " ".join(parts[4:])
        return cls(pcr_idx, template_hash, template_name, hash_algo, file_hash, file_path)


def parse_ima_log_string(log_string: str) -> list[IMALogEntry]:
    """
    Parse a string of IMA log entries and convert it to a list of IMALogEntry.

    Args:
        log_string: A string of IMA log entries

    Returns:
        List of IMALogEntry
    """
    entries = []
    for line in log_string.split("\n"):
        if line.strip() == "":
            continue
        entry = IMALogEntry.from_string(line)
        entries.append(entry)
    return entries
