# SPDX-License-Identifier: MIT
"""
ima-ng template serialization and template_hash recomputation.

Builds the d-ng (digest) and n-ng (name) fields that comprise an ima-ng
template, recomputes the expected template hash, and validates that the
recorded template_hash in a log entry matches the recomputed value.
"""

__all__ = [
    "build_template_fields",
    "calculate_expected_template_hash",
    "validate_ima_log_entry",
]

import hashlib
import struct
from collections.abc import Callable

from imapcrutils.log import IMALogEntry


def build_template_fields(entry: IMALogEntry) -> tuple[bytes, bytes, bytes, bytes]:
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
    d_ng_content = algo.encode("ascii") + b":" + b"\x00" + digest_bytes
    d_ng_field = struct.pack("<I", len(d_ng_content)) + d_ng_content
    # 2. Create n-ng (Name) field
    # Format: [FilePath(string)] + [\0]
    # File path must end with null character
    n_ng_content = entry.file_path.encode("utf-8") + b"\x00"
    n_ng_field = struct.pack("<I", len(n_ng_content)) + n_ng_content
    return d_ng_content, d_ng_field, n_ng_content, n_ng_field


def calculate_expected_template_hash(entry: IMALogEntry, hash_func: Callable[[bytes], bytes] = hashlib.sha1) -> bytes:
    """
    Calculate expected template hash from IMA log entry.

    Args:
        entry: IMALogEntry structure
        hash_func: Hash function to use (default: hashlib.sha1)
                 Should be a function that takes bytes and returns bytes digest

    Returns:
        Expected template hash as bytes
    """
    _d_ng_content, d_ng_field, _n_ng_content, n_ng_field = build_template_fields(entry)
    # Combine template data
    template_data = d_ng_field + n_ng_field
    # Calculate Template Hash
    expected_template_hash = hash_func(template_data).digest()

    return expected_template_hash


def validate_ima_log_entry(entry: IMALogEntry, hash_func: Callable[[bytes], bytes] = hashlib.sha1) -> bool:
    """
    Validate IMA log entry. Template_hash must coincide with the hash of the file data.

    Args:
        entry: IMALogEntry structure
        hash_func: Hash function to use (default: hashlib.sha1)
    Returns:
        True if entry is valid, False otherwise
    """
    expected_template_hash = calculate_expected_template_hash(entry, hash_func)
    return entry.template_hash == expected_template_hash.hex()
