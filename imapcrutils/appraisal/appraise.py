# SPDX-License-Identifier: MIT
"""
Apply an appraisal policy to IMA log entries.

For every IMA log entry, the first matching component (in declaration order)
decides the verdict: Allow, Deny, or Neutral.  :func:`appraise_ima_log`
returns the per-entry verdicts; :func:`verify_ima_log` collapses them to a
single pass/fail boolean.
"""

__all__ = [
    "appraise_ima_log",
    "verify_ima_log",
]

from imapcrutils.appraisal.policy import AppraisalPolicy, AppraisalResult
from imapcrutils.log import IMALogEntry


def appraise_ima_log(entries: list[IMALogEntry], policy: AppraisalPolicy) -> list[tuple[IMALogEntry, AppraisalResult]]:
    """
    Classify each IMA log entry against the appraisal policy.

    Args:
        entries: IMA log entries to classify.
        policy: Appraisal policy.

    Returns:
        A list of (entry, verdict) pairs in the same order as entries.
    """
    return [(entry, policy.appraise(entry)) for entry in entries]


def verify_ima_log(entries: list[IMALogEntry], policy: AppraisalPolicy) -> bool:
    """
    Verify that no IMA log entry is denied by the policy.

    Returns True when every entry's verdict is Allow or Neutral. Returns
    False as soon as any entry hits a deny/denylist rule.
    """
    return all(policy.appraise(entry) is not AppraisalResult.DENY for entry in entries)
