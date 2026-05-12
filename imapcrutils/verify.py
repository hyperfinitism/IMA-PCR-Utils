# SPDX-License-Identifier: MIT
"""
IMA log appraisal against a YAML policy.

Each policy component declares a file-path glob and one or more allow/deny
hash rules. For every IMA log entry the first matching component (in
declaration order) decides the verdict: Allow, Deny, or Neutral.

Policy format (YAML)::

    component1:
        path: <glob>
        allow: [<hex-hash>...] # optional
    component2:
        path: <glob>
        deny: [<hex-hash>...]  # optional
        ...
"""

__all__ = [
    "AppraisalResult",
    "PolicyComponent",
    "AppraisalPolicy",
    "load_policy",
    "load_policy_file",
    "appraise_ima_log",
    "verify_ima_log",
]

import fnmatch
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import yaml

from imapcrutils.libs import IMALogEntry


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


def _coerce_hash_set(name: str, single: object, many: object) -> set[str]:
    result: set[str] = set()
    if single is not None:
        if not isinstance(single, str):
            raise ValueError(f"component '{name}': scalar hash must be a string")
        result.add(single.lower())
    if many is not None:
        if not isinstance(many, list) or not all(isinstance(h, str) for h in many):
            raise ValueError(f"component '{name}': list hash field must be a list of strings")
        result.update(h.lower() for h in many)
    return result


def load_policy(yaml_string: str) -> AppraisalPolicy:
    """
    Parse a YAML appraisal policy string into an AppraisalPolicy.

    Args:
        yaml_string: YAML document mapping component names to rule dicts.

    Returns:
        AppraisalPolicy with components in declaration order.

    Raises:
        ValueError: if the document is not a mapping or a component is malformed.
    """
    data = yaml.safe_load(yaml_string)
    if data is None:
        return AppraisalPolicy(components=[])
    if not isinstance(data, dict):
        raise ValueError("policy root must be a mapping of component names to rules")

    components: list[PolicyComponent] = []
    for name, rules in data.items():
        if not isinstance(rules, dict):
            raise ValueError(f"component '{name}': rules must be a mapping")
        path = rules.get("path")
        if not isinstance(path, str):
            raise ValueError(f"component '{name}': 'path' is required and must be a string")
        allowlist = rules.get("allow")
        if isinstance(allowlist, list) and all(map(lambda x: isinstance(x, str), allowlist)):
            allow = list(map(lambda x: x.lower(), allowlist))
        elif allowlist is None:
            allow = None
        else:
            raise ValueError(f"component '{name}': 'allow' must be a list of strings")
        denylist = rules.get("deny")
        if isinstance(denylist, list) and all(map(lambda x: isinstance(x, str), denylist)):
            deny = list(map(lambda x: x.lower(), denylist))
        elif denylist is None:
            deny = None
        else:
            raise ValueError(f"component '{name}': 'deny' must be a list of strings")
        components.append(PolicyComponent(name=str(name), path=path, allow=allow, deny=deny))
    return AppraisalPolicy(components=components)


def load_policy_file(path: str | Path) -> AppraisalPolicy:
    """Load an appraisal policy from a YAML file on disk."""
    return load_policy(Path(path).read_text())


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
