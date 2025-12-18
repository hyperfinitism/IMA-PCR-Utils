"""
IMA log parsing and PCR10 calculation library.

This module provides functions for parsing IMA log entries and calculating PCR10 values.
"""

__all__ = [
    "IMALogEntry",
    "parse_ima_log_line",
    "parse_ima_logs",
    "build_template_fields",
    "calculate_expected_template_hash",
    "calculate_pcr10",
    "read_ima_log_file",
    "validate_ima_log_entry",
    "validate_ima_log_entries",
    "validate_ima_log_file",
]


import hashlib
import struct
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple


@dataclass
class IMALogEntry:
    """Structure representing a single IMA log entry."""
    pcr_idx: str
    template_hash: str
    template_name: str
    file_data: str  # Format: "algo:hexdigest"
    file_path: str


def parse_ima_log_line(line: str) -> Optional[IMALogEntry]:
    """
    Parse a single line from IMA log and convert it to IMALogEntry structure.

    Args:
        line: A line from IMA log file
        (format: PCR | Template_Hash | Template_Name | File_Data | File_Path)

    Returns:
        IMALogEntry if parsing succeeds, None otherwise
    """
    parts = line.strip().split()
    # Format: PCR | Template_Hash | Template_Name | File_Data | File_Path
    if len(parts) < 5:
        return None
    pcr_idx = parts[0]
    template_hash = parts[1]
    template_name = parts[2]
    file_data = parts[3]
    # File path may contain spaces, so join the remaining parts
    file_path = " ".join(parts[4:])
    return IMALogEntry(
        pcr_idx=pcr_idx,
        template_hash=template_hash,
        template_name=template_name,
        file_data=file_data,
        file_path=file_path
    )


def parse_ima_logs(log_string: str) -> List[IMALogEntry]:
    """
    Parse a string of IMA log entries and convert it to a list of IMALogEntry structures.

    Args:
        log_string: A string of IMA log entries

    Returns:
    """
    entries = []
    for line in log_string.split('\n'):
        entry = parse_ima_log_line(line)
        if entry is not None:
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
    try:
        algo, digest_hex = entry.file_data.split(':')
        digest_bytes = bytes.fromhex(digest_hex)
    except ValueError as e:
        raise ValueError(f"Invalid file_data format: {entry.file_data}") from e
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


def read_ima_log_file(
    file_path: str,
    encoding: str = 'utf-8',
    errors: str = 'ignore'
) -> List[IMALogEntry]:
    """
    Read IMA log file and convert to list of IMALogEntry.

    Args:
        file_path: Path to IMA log file
        encoding: File encoding (default: 'utf-8')
        errors: Error handling mode (default: 'ignore')

    Returns:
        List of IMALogEntry
    """
    with open(file_path, 'r', encoding=encoding, errors=errors) as f:
        lines = f.read()
        return parse_ima_logs(lines)


def validate_ima_log_entry(entry: IMALogEntry, hash_func: Callable[[bytes], bytes] = hashlib.sha1) -> bool:
    """
    Validate IMA log entry. Template_hash must coincide with SHA-1 hash of the file data.

    Args:
        entry: IMALogEntry structure
        hash_func: Hash function to use (default: hashlib.sha1)
    Returns:
        True if entry is valid, False otherwise
    """
    expected_template_hash = calculate_expected_template_hash(
        entry, hash_func)
    return entry.template_hash == expected_template_hash.hex()


def validate_ima_log_entries(entries: List[IMALogEntry], hash_func: Callable[[bytes], bytes] = hashlib.sha1) -> bool:
    """
    Validate a list of IMA log entries. All entries must be valid.

    Args:
        entries: List of IMALogEntry structures
        hash_func: Hash function to use (default: hashlib.sha1)
    Returns:
        True if all entries are valid, False otherwise  
    """
    for entry in entries:
        if not validate_ima_log_entry(entry, hash_func):
            return False
    return True


def validate_ima_log_file(file_path: str, hash_func: Callable[[bytes], bytes] = hashlib.sha1) -> bool:
    """
    Validate IMA log file. All entries must be valid.

    Args:
        file_path: Path to IMA log file
        hash_func: Hash function to use (default: hashlib.sha1)
    Returns:
        True if file is valid, False otherwise
    """
    entries = read_ima_log_file(file_path)
    return validate_ima_log_entries(entries, hash_func)
