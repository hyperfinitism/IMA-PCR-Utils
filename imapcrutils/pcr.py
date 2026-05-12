# SPDX-License-Identifier: MIT
"""
PCR value computations: PCR10 replay from IMA log entries and boot_aggregate
from PCR0..PCR9.

:func:`calculate_pcr10` and :func:`truncate_ima_log_by_pcr` replay the PCR
extension chain that IMA performs at runtime.  :func:`calculate_boot_aggregate`
computes the boot-time PCR digest used as the first IMA measurement.
"""

__all__ = [
    "calculate_pcr10",
    "truncate_ima_log_by_pcr",
    "calculate_boot_aggregate",
]

import hashlib
from collections.abc import Callable

from imapcrutils.log import IMALogEntry
from imapcrutils.template import calculate_expected_template_hash


def calculate_pcr10(entries: list[IMALogEntry], hash_func: Callable[[bytes], bytes] = hashlib.sha256) -> bytes:
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
        expected_template_hash = calculate_expected_template_hash(entry, hash_func)
        # PCR extension (Extend Operation)
        # PCR_new = HASH( PCR_old || Template_Hash )
        pcr_value = hash_func(pcr_value + expected_template_hash).digest()
    return pcr_value


def truncate_ima_log_by_pcr(
    entries: list[IMALogEntry], pcr: bytes, hash_func: Callable[[bytes], bytes] = hashlib.sha256
) -> list[IMALogEntry] | None:
    """
    Find the point in the IMA log where the calculated PCR10 matches the reference value.

    Filters IMA log entries for PCR index "10" and "ima-ng" template, then extends
    the PCR value incrementally. Returns the sublist of valid entries from the
    beginning up to and including the entry where the PCR value matches the reference.
    Returns None if no match is found.

    Args:
        entries: List of IMALogEntry objects to process
        pcr: Reference PCR value to match against
        hash_func: Hash function for PCR extension (default: hashlib.sha256)

    Returns:
        List of IMALogEntry objects from the beginning up to the matching entry,
        or None if the reference PCR value is not found
    """
    results = []
    pcr_value = bytes(hash_func().digest_size)
    for entry in entries:
        if entry.pcr_idx != "10":
            continue
        if entry.template_name != "ima-ng":
            continue
        results.append(entry)
        template_hash = calculate_expected_template_hash(entry, hash_func)
        pcr_value = hash_func(pcr_value + template_hash).digest()
        if pcr_value == pcr:
            return results
    return None


def calculate_boot_aggregate(pcrlist: list[bytes], hash_func: Callable[[bytes], bytes] = hashlib.sha256) -> bytes:
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
    return hash_func(b"".join(pcrlist)).digest()
