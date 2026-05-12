# SPDX-License-Identifier: MIT
"""Tests for imapcrutils.verify — appraisal of IMA log entries against a YAML policy."""

import textwrap

import pytest

from imapcrutils import (
    AppraisalPolicy,
    AppraisalResult,
    IMALogEntry,
    PolicyComponent,
    appraise_ima_log,
    load_policy,
    load_policy_file,
    parse_ima_log_string,
    verify_ima_log,
)

SAMPLE_LINE = "10 8facace9d7255a1985e976e9bb59675f211c82de ima-ng sha256:088faac4777b024045bd578c5c3f8efc4ac2cafb4af90a12832a762feb58eb88 boot_aggregate"  # noqa: E501
SAMPLE_HASH = "088faac4777b024045bd578c5c3f8efc4ac2cafb4af90a12832a762feb58eb88"
OTHER_HASH = "00" * 32


def _entry(path: str, hash_hex: str = SAMPLE_HASH) -> IMALogEntry:
    return IMALogEntry(
        pcr_idx="10",
        template_hash="8facace9d7255a1985e976e9bb59675f211c82de",
        template_name="ima-ng",
        hash_algo="sha256",
        file_hash=bytes.fromhex(hash_hex),
        file_path=path,
    )


# ---------------------------------------------------------------------------
# load_policy
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# PolicyComponent / AppraisalPolicy.appraise
# ---------------------------------------------------------------------------


class TestPolicyComponentAppraise:
    """Tests for the per-component verdict logic."""

    def test_allow_hit(self):
        """A hash in the allow set yields ALLOW."""
        c = PolicyComponent(name="c", path="*", allow={SAMPLE_HASH})
        assert c.appraise_hash(SAMPLE_HASH) is AppraisalResult.ALLOW

    def test_allow_unhit(self):
        """A hash outside the allow set yields DENY."""
        c = PolicyComponent(name="c", path="*", allow={OTHER_HASH})
        assert c.appraise_hash(SAMPLE_HASH) is AppraisalResult.DENY

    def test_deny_hit(self):
        """A hash in the deny set yields DENY."""
        c = PolicyComponent(name="c", path="*", deny={SAMPLE_HASH})
        assert c.appraise_hash(SAMPLE_HASH) is AppraisalResult.DENY

    def test_deny_unhit(self):
        """A hash outside the deny set yields ALLOW."""
        c = PolicyComponent(name="c", path="*", deny={OTHER_HASH})
        assert c.appraise_hash(SAMPLE_HASH) is AppraisalResult.ALLOW


class TestAppraisalPolicy:
    """Tests for AppraisalPolicy.appraise — path matching and ordering."""

    def test_first_match_wins(self):
        """The first component whose path matches decides the verdict."""
        first = PolicyComponent(name="first", path="/usr/*", allow={SAMPLE_HASH})
        second = PolicyComponent(name="second", path="/usr/bin/*", deny={SAMPLE_HASH})
        policy = AppraisalPolicy(components=[first, second])
        assert policy.appraise(_entry("/usr/bin/foo")) is AppraisalResult.ALLOW

    def test_first_match_wins_reverse_order(self):
        """Reversing component order flips the verdict — confirms order matters."""
        first = PolicyComponent(name="first", path="/usr/bin/*", deny={SAMPLE_HASH})
        second = PolicyComponent(name="second", path="/usr/*", allow={SAMPLE_HASH})
        policy = AppraisalPolicy(components=[first, second])
        assert policy.appraise(_entry("/usr/bin/foo")) is AppraisalResult.DENY

    def test_no_matching_component_is_neutral(self):
        """An entry whose path matches no component is NEUTRAL."""
        policy = AppraisalPolicy(components=[PolicyComponent(name="c", path="/etc/*", allow={SAMPLE_HASH})])
        assert policy.appraise(_entry("/usr/bin/foo")) is AppraisalResult.NEUTRAL

    def test_glob_question_mark(self):
        """fnmatch '?' wildcards match a single character."""
        c = PolicyComponent(name="c", path="/a/?.bin", allow={SAMPLE_HASH})
        policy = AppraisalPolicy(components=[c])
        assert policy.appraise(_entry("/a/x.bin")) is AppraisalResult.ALLOW
        assert policy.appraise(_entry("/a/xx.bin")) is AppraisalResult.NEUTRAL

    def test_empty_policy_is_neutral(self):
        """An empty policy yields NEUTRAL for every entry."""
        assert AppraisalPolicy().appraise(_entry("/anything")) is AppraisalResult.NEUTRAL


# ---------------------------------------------------------------------------
# appraise_ima_log / verify_ima_log
# ---------------------------------------------------------------------------


class TestAppraiseImaLog:
    """Tests for appraise_ima_log — classifying a list of entries."""

    def test_returns_pairs_in_order(self):
        """Result preserves input order and pairs each entry with its verdict."""
        entries = [
            _entry("/usr/bin/a"),
            _entry("/usr/bin/b", OTHER_HASH),
            _entry("/etc/x"),
        ]
        policy = AppraisalPolicy(components=[PolicyComponent(name="bin", path="/usr/bin/*", allow=[SAMPLE_HASH])])
        result = appraise_ima_log(entries, policy)
        assert [r[0].file_path for r in result] == ["/usr/bin/a", "/usr/bin/b", "/etc/x"]
        assert [r[1] for r in result] == [
            AppraisalResult.ALLOW,
            AppraisalResult.DENY,
            AppraisalResult.NEUTRAL,
        ]

    def test_empty_entries(self):
        """No entries yields an empty result list."""
        assert appraise_ima_log([], AppraisalPolicy()) == []


class TestVerifyImaLog:
    """Tests for verify_ima_log — boolean pass/fail across all entries."""

    def test_all_allow_returns_true(self):
        """All-allow log passes."""
        entries = [_entry("/usr/bin/a"), _entry("/usr/bin/b")]
        policy = AppraisalPolicy(components=[PolicyComponent(name="bin", path="/usr/bin/*", allow={SAMPLE_HASH})])
        assert verify_ima_log(entries, policy) is True

    def test_neutral_entries_pass(self):
        """Neutral entries (no matching component) do not fail verification."""
        entries = [_entry("/etc/x"), _entry("/usr/bin/a")]
        policy = AppraisalPolicy(components=[PolicyComponent(name="bin", path="/usr/bin/*", allow={SAMPLE_HASH})])
        assert verify_ima_log(entries, policy) is True

    def test_single_deny_returns_false(self):
        """A single deny in the log fails verification."""
        entries = [
            _entry("/usr/bin/good"),
            _entry("/usr/bin/bad", OTHER_HASH),
        ]
        policy = AppraisalPolicy(
            components=[PolicyComponent(name="bin", path="/usr/bin/*", allow={SAMPLE_HASH}, deny={OTHER_HASH})]
        )
        assert verify_ima_log(entries, policy) is False

    def test_empty_log_passes(self):
        """An empty log trivially passes."""
        assert verify_ima_log([], AppraisalPolicy()) is True

    def test_real_sample_with_wildcard_allowlist(self, sample_ima_log):
        """A policy that allows every path/hash from the sample log passes."""
        entries = parse_ima_log_string(sample_ima_log)
        all_hashes = {e.file_hash.hex() for e in entries}
        policy = AppraisalPolicy(components=[PolicyComponent(name="all", path="*", allow=all_hashes)])
        assert verify_ima_log(entries, policy) is True
        results = appraise_ima_log(entries, policy)
        assert all(v is AppraisalResult.ALLOW for _, v in results)

    def test_real_sample_with_one_denied_hash(self, sample_ima_log):
        """Denying any hash present in the sample log fails verification."""
        entries = parse_ima_log_string(sample_ima_log)
        target_hash = entries[5].file_hash.hex()
        policy = AppraisalPolicy(components=[PolicyComponent(name="all", path="*", deny={target_hash})])
        assert verify_ima_log(entries, policy) is False

    def test_load_policy_end_to_end(self, sample_ima_log):
        """YAML-loaded policy integrates with parse_ima_log_string + verify."""
        entries = parse_ima_log_string(sample_ima_log)
        boot_hash = entries[0].file_hash.hex()
        yaml_str = textwrap.dedent(
            f"""
            boot:
                path: boot_aggregate
                allow: [{boot_hash}]
            """
        )
        policy = load_policy(yaml_str)
        results = dict((e.file_path, v) for e, v in appraise_ima_log(entries, policy))
        assert results["boot_aggregate"] is AppraisalResult.ALLOW
