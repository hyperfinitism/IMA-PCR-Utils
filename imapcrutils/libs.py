"""
IMA log parsing, PCR10 calculation and boot_aggregate calculation library.

This module provides functions for parsing IMA log entries, calculating PCR10 values and boot_aggregate values.
"""

__all__ = [
    "IMALogEntry",
    "parse_ima_log_string",
    "build_template_fields",
    "calculate_expected_template_hash",
    "calculate_pcr10",
    "validate_ima_log_entry",
    "calculate_boot_aggregate",
]


import hashlib
import struct
from dataclasses import dataclass
from typing import Callable, List, Tuple


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
        return " ".join([self.pcr_idx, self.template_hash, self.template_name, self.hash_algo + ":" + self.file_hash.hex(), self.file_path])

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
            hash_algo, file_hash_hex = parts[3].split(':')
            file_hash = bytes.fromhex(file_hash_hex)
        except ValueError as e:
            raise ValueError(f"Invalid file_hash format: {parts[3]}") from e
        file_path = " ".join(parts[4:])
        return cls(pcr_idx, template_hash, template_name, hash_algo, file_hash, file_path)


def parse_ima_log_string(log_string: str) -> List[IMALogEntry]:
    """
    Parse a string of IMA log entries and convert it to a list of IMALogEntry.

    Args:
        log_string: A string of IMA log entries

    Returns:
        List of IMALogEntry
    """
    entries = []
    for line in log_string.split('\n'):
        if line.strip() == '':
            continue
        entry = IMALogEntry.from_string(line)
        entries.append(entry)
    return entries


def build_template_fields(entry: IMALogEntry) -> Tuple[bytes, bytes, bytes, bytes]:
    """
    Build d_ng_content, d_ng_field, n_ng_content, n_ng_field from IMA log entry.

    Args:
        entry: IMALogEntry structure

    Returns:
        Tuple of (d_ng_content, d_ng_field, n_ng_content, n_ng_field)

    Raises:
        ValueError: If file_data format is invalid
    """
    # 1. Create d-ng (Digest) field
    # Format: [Algo(string)] + [:] + [\0] + [digest_bytes]
    algo = entry.hash_algo
    digest_bytes = entry.file_hash
    # "algo:\0" + digest_bytes
    d_ng_content = algo.encode('ascii') + b':' + b'\x00' + digest_bytes
    d_ng_field = struct.pack('<I', len(d_ng_content)) + d_ng_content
    # 2. Create n-ng (Name) field
    # Format: [FilePath(string)] + [\0]
    # File path must end with null character
    n_ng_content = entry.file_path.encode('utf-8') + b'\x00'
    n_ng_field = struct.pack('<I', len(n_ng_content)) + n_ng_content
    return d_ng_content, d_ng_field, n_ng_content, n_ng_field


def calculate_expected_template_hash(
    entry: IMALogEntry,
    hash_func: Callable[[bytes], bytes] = hashlib.sha1
) -> bytes:
    """
    Calculate expected template hash from IMA log entry.

    Args:
        entry: IMALogEntry structure
        hash_func: Hash function to use (default: hashlib.sha1)
                 Should be a function that takes bytes and returns bytes digest

    Returns:
        Expected template hash as bytes
    """
    _d_ng_content, d_ng_field, _n_ng_content, n_ng_field = build_template_fields(
        entry)
    # Combine template data
    template_data = d_ng_field + n_ng_field
    # Calculate Template Hash
    expected_template_hash = hash_func(template_data).digest()

    return expected_template_hash


def calculate_pcr10(
    entries: List[IMALogEntry],
    hash_func: Callable[[bytes], bytes] = hashlib.sha256
) -> bytes:
    """
    Calculate PCR10 value from a list of IMA log entries.

    Args:
        entries: List of IMALogEntry structures
        hash_func: Hash function for PCR extension (default: hashlib.sha256)

    Returns:
        PCR10 value as bytes
    """
    # PCR initial value is all zeros
    pcr_value = bytes(hash_func().digest_size)
    for entry in entries:
        # Skip if PCR is not 10
        if entry.pcr_idx != "10":
            continue
        # Only support ima-ng template
        if entry.template_name != "ima-ng":
            continue
        # Calculate template hash using the specified hash function
        expected_template_hash = calculate_expected_template_hash(
            entry, hash_func)
        # PCR extension (Extend Operation)
        # PCR_new = HASH( PCR_old || Template_Hash )
        pcr_value = hash_func(pcr_value + expected_template_hash).digest()
    return pcr_value


def validate_ima_log_entry(entry: IMALogEntry, hash_func: Callable[[bytes], bytes] = hashlib.sha1) -> bool:
    """
    Validate IMA log entry. Template_hash must coincide with the hash of the file data.

    Args:
        entry: IMALogEntry structure
        hash_func: Hash function to use (default: hashlib.sha1)
    Returns:
        True if entry is valid, False otherwise
    """
    expected_template_hash = calculate_expected_template_hash(
        entry, hash_func)
    return entry.template_hash == expected_template_hash.hex()


def calculate_boot_aggregate(pcrlist: List[bytes], hash_func: Callable[[bytes], bytes] = hashlib.sha256) -> bytes:
    """
    Calculate boot aggregate from PCR0..PCR9.

    Args:
        pcrlist: List of PCR0..PCR9 byte strings
        hash_func: Hash function for boot aggregate calculation (default: hashlib.sha256)
    Returns:
        Boot aggregate as bytes
    """
    if len(pcrlist) != 10:
        raise ValueError(f"length of PCR list is expected to be 10: got {len(pcrlist)}")
    return hash_func(b''.join(pcrlist)).digest()
