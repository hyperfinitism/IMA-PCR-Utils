# SPDX-License-Identifier: MIT
"""
IMA log appraisal against a YAML policy.

The package is split into three modules:

- :mod:`imapcrutils.appraisal.policy` — policy data model (no I/O).
- :mod:`imapcrutils.appraisal.loader` — YAML → :class:`AppraisalPolicy`.
- :mod:`imapcrutils.appraisal.appraise` — apply a policy to IMA log entries.
"""

from imapcrutils.appraisal.appraise import appraise_ima_log, verify_ima_log
from imapcrutils.appraisal.loader import load_policy, load_policy_file
from imapcrutils.appraisal.policy import AppraisalPolicy, AppraisalResult, PolicyComponent

__all__ = [
    "AppraisalResult",
    "PolicyComponent",
    "AppraisalPolicy",
    "load_policy",
    "load_policy_file",
    "appraise_ima_log",
    "verify_ima_log",
]
