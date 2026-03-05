"""
IMA-PCR-Utils - Python Library

This package provides functions for parsing IMA log entries, calculating PCR10 values and boot_aggregate values.
"""

__version__ = "0.1.0"

from imapcrutils.libs import (
    IMALogEntry,
    parse_ima_log_string,
    build_template_fields,
    calculate_expected_template_hash,
    calculate_pcr10,
    validate_ima_log_entry,
    calculate_boot_aggregate,
)
