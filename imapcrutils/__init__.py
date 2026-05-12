# SPDX-License-Identifier: MIT
"""
IMA-PCR-Utils - Python Library

Parsing IMA log entries, replaying PCR10 / boot_aggregate, and appraising
IMA log entries against a YAML policy.

Modules:

- :mod:`imapcrutils.log` — IMA log data model and parser.
- :mod:`imapcrutils.template` — ima-ng template serialization and template_hash recomputation.
- :mod:`imapcrutils.pcr` — PCR10 replay and boot_aggregate.
- :mod:`imapcrutils.appraisal` — IMA log appraisal (policy model, YAML loader, evaluator).
"""

__version__ = "0.1.0"

from imapcrutils.appraisal import (
    AppraisalPolicy,
    AppraisalResult,
    PolicyComponent,
    appraise_ima_log,
    load_policy,
    load_policy_file,
    verify_ima_log,
)
from imapcrutils.log import IMALogEntry, parse_ima_log_string
from imapcrutils.pcr import calculate_boot_aggregate, calculate_pcr10, truncate_ima_log_by_pcr
from imapcrutils.template import build_template_fields, calculate_expected_template_hash, validate_ima_log_entry

__all__ = [
    # log
    "IMALogEntry",
    "parse_ima_log_string",
    # template
    "build_template_fields",
    "calculate_expected_template_hash",
    "validate_ima_log_entry",
    # pcr
    "calculate_pcr10",
    "truncate_ima_log_by_pcr",
    "calculate_boot_aggregate",
    # appraisal
    "AppraisalResult",
    "PolicyComponent",
    "AppraisalPolicy",
    "load_policy",
    "load_policy_file",
    "appraise_ima_log",
    "verify_ima_log",
]
