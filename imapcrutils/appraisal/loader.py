# SPDX-License-Identifier: MIT
"""
YAML appraisal policy loader.

Parses a YAML document into an :class:`AppraisalPolicy`.  This is the only
module that depends on ``pyyaml``; the policy model itself
(:mod:`imapcrutils.appraisal.policy`) is format-agnostic.

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
    "load_policy",
    "load_policy_file",
]

from pathlib import Path

import yaml

from imapcrutils.appraisal.policy import AppraisalPolicy, PolicyComponent


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
