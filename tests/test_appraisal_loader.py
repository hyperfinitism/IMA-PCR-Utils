# SPDX-License-Identifier: MIT
"""Tests for imapcrutils.appraisal.loader — parsing YAML into AppraisalPolicy."""

import textwrap

import pytest

from imapcrutils import load_policy, load_policy_file


class TestLoadPolicy:
    """Tests for load_policy — parsing YAML into AppraisalPolicy."""

    def test_full_policy(self):
        """Parse a policy with all four rule fields and preserve component order."""
        yaml_str = textwrap.dedent(
            """
            kernel:
                path: /usr/lib/modules/*
                allow: [aaaa, bbbb, cccc]
            userland:
                path: /usr/bin/*
                allow: [dddd]
            userland2:
                path: /usr/local/bin/*
                deny: [eeee]
            """
        )
        policy = load_policy(yaml_str)
        assert [c.name for c in policy.components] == ["kernel", "userland", "userland2"]
        kernel = policy.components[0]
        assert kernel.path == "/usr/lib/modules/*"
        assert kernel.allow == ["aaaa", "bbbb", "cccc"]
        assert kernel.deny is None
        userland = policy.components[1]
        assert userland.path == "/usr/bin/*"
        assert userland.allow == ["dddd"]
        assert userland.deny is None
        userland2 = policy.components[2]
        assert userland2.path == "/usr/local/bin/*"
        assert userland2.allow is None
        assert userland2.deny == ["eeee"]

    def test_lowercases_hashes(self):
        """Hashes are normalized to lowercase so callers can mix cases."""
        policy = load_policy("c:\n  path: /x\n  allow: [ABCDEF]\n")
        assert policy.components[0].allow == ["abcdef"]

    def test_empty_yaml(self):
        """An empty document is a policy with zero components."""
        assert load_policy("").components == []

    def test_root_must_be_mapping(self):
        """A non-mapping root document is rejected."""
        with pytest.raises(ValueError, match="root must be a mapping"):
            load_policy("- not a mapping\n")

    def test_component_rules_must_be_mapping(self):
        """Component rules must be a mapping."""
        with pytest.raises(ValueError, match="rules must be a mapping"):
            load_policy("c: not-a-mapping\n")

    def test_missing_path(self):
        """A component without 'path' is rejected."""
        with pytest.raises(ValueError, match="'path' is required"):
            load_policy("c:\n  allow: [abcd]\n")

    def test_allowlist_must_be_list_of_strings(self):
        """allowlist must be a list of strings."""
        with pytest.raises(ValueError, match="'allow' must be a list of strings"):
            load_policy("c:\n  path: /x\n  allow: 'not-a-list'\n")

    def test_load_policy_file(self, tmp_path):
        """load_policy_file reads from disk and parses the same way."""
        f = tmp_path / "policy.yaml"
        f.write_text("c:\n  path: /x\n  allow: [abcd]\n")
        policy = load_policy_file(f)
        assert policy.components[0].allow == ["abcd"]
