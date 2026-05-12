# SPDX-License-Identifier: MIT
"""Tests for imapcrutils.appraisal.appraise — appraise_ima_log and verify_ima_log."""

import textwrap

from imapcrutils import (
    AppraisalPolicy,
    AppraisalResult,
    IMALogEntry,
    PolicyComponent,
    appraise_ima_log,
    load_policy,
    parse_ima_log_string,
    verify_ima_log,
)

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
# appraise_ima_log
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


# ---------------------------------------------------------------------------
# verify_ima_log
# ---------------------------------------------------------------------------


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
