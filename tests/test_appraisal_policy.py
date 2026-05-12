# SPDX-License-Identifier: MIT
"""Tests for imapcrutils.appraisal.policy — policy data model and per-entry verdict."""

from imapcrutils import (
    AppraisalPolicy,
    AppraisalResult,
    IMALogEntry,
    PolicyComponent,
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
# PolicyComponent.appraise_hash
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


# ---------------------------------------------------------------------------
# AppraisalPolicy.appraise — path matching and component ordering
# ---------------------------------------------------------------------------


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
