# SPDX-License-Identifier: MIT
"""
Appraisal policy data model.

Defines :class:`AppraisalResult`, :class:`PolicyComponent`, and
:class:`AppraisalPolicy` — the in-memory representation of an IMA log
appraisal policy.  No file-format dependencies live here; YAML parsing
is provided separately by :mod:`imapcrutils.appraisal.loader`.
"""

__all__ = [
    "AppraisalResult",
    "PolicyComponent",
    "AppraisalPolicy",
]

import fnmatch
from dataclasses import dataclass, field
from enum import Enum

from imapcrutils.log import IMALogEntry


class AppraisalResult(Enum):
    """Verdict for a single IMA log entry against an appraisal policy."""

    ALLOW = "allow"
    DENY = "deny"
    NEUTRAL = "neutral"


@dataclass
class PolicyComponent:
    """A single named component of an appraisal policy."""

    name: str
    path: str
    allow: set[str] | None = None
    deny: set[str] | None = None

    def matches_path(self, file_path: str) -> bool:
        """Return True if file_path matches this component's path glob."""
        return fnmatch.fnmatchcase(file_path, self.path)

    def appraise_hash(self, file_hash_hex: str) -> AppraisalResult:
        """Classify a hex-encoded file hash against this component's rules."""
        normalized = file_hash_hex.lower()
        if self.deny is not None:
            if normalized in self.deny:
                return AppraisalResult.DENY
            return AppraisalResult.ALLOW
        if self.allow is not None:
            if normalized in self.allow:
                return AppraisalResult.ALLOW
            return AppraisalResult.DENY
        return AppraisalResult.NEUTRAL


@dataclass
class AppraisalPolicy:
    """An ordered collection of policy components."""

    components: list[PolicyComponent] = field(default_factory=list)

    def appraise(self, entry: IMALogEntry) -> AppraisalResult:
        """Return the verdict for entry from the first matching component."""
        file_hash_hex = entry.file_hash.hex()
        for component in self.components:
            if component.matches_path(entry.file_path):
                return component.appraise_hash(file_hash_hex)
        return AppraisalResult.NEUTRAL
