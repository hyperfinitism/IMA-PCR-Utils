# SPDX-License-Identifier: MIT
"""Tests for the CLI example scripts (pcr10.py, boot_aggregate.py, appraise.py) via subprocess."""

import pathlib
import subprocess
import sys

EXAMPLES_DIR = pathlib.Path(__file__).resolve().parent.parent / "examples"
PCR10_SCRIPT = EXAMPLES_DIR / "pcr10.py"
BOOT_AGG_SCRIPT = EXAMPLES_DIR / "boot_aggregate.py"
APPRAISE_SCRIPT = EXAMPLES_DIR / "appraise.py"
SAMPLE_IMA_LOG = EXAMPLES_DIR / "sample_input" / "ascii_runtime_measurements"
SAMPLE_PCR_LIST = EXAMPLES_DIR / "sample_input" / "pcrlist.bin"
SAMPLE_POLICY = EXAMPLES_DIR / "sample_input" / "appraise_policy.yaml"

EXPECTED_PCR10_SHA256 = "90E7C2DF7E39D26D13A7F67F68FF3C92BB22ABB7477322A96B314B98D82524EE"
EXPECTED_BOOT_AGGREGATE_SHA256 = "088faac4777b024045bd578c5c3f8efc4ac2cafb4af90a12832a762feb58eb88"


def run_script(script: pathlib.Path, *args: str) -> subprocess.CompletedProcess:
    """Run a Python script as a subprocess and return the CompletedProcess."""
    return subprocess.run(
        [sys.executable, str(script), *args],
        capture_output=True,
        text=True,
        check=True,
    )


# ---------------------------------------------------------------------------
# pcr10.py
# ---------------------------------------------------------------------------


class TestPcr10Cli:
    """Tests for examples/pcr10.py CLI."""

    def test_default_sha256_hex(self):
        """Default output must be uppercase hex SHA-256 PCR10."""
        result = run_script(PCR10_SCRIPT, "-i", str(SAMPLE_IMA_LOG))
        assert result.stdout.strip() == EXPECTED_PCR10_SHA256

    def test_sha256_lowercase_hex(self):
        """'-f hex' must output lowercase hex."""
        result = run_script(PCR10_SCRIPT, "-i", str(SAMPLE_IMA_LOG), "-f", "hex")
        assert result.stdout.strip() == EXPECTED_PCR10_SHA256.lower()

    def test_sha1(self):
        """'-a sha1' must produce a 40-character hex digest."""
        result = run_script(PCR10_SCRIPT, "-i", str(SAMPLE_IMA_LOG), "-a", "sha1")
        assert len(result.stdout.strip()) == 40

    def test_output_to_file(self, tmp_path):
        """'-o' must write the hex string to the specified file."""
        out_file = tmp_path / "pcr10.txt"
        run_script(PCR10_SCRIPT, "-i", str(SAMPLE_IMA_LOG), "-o", str(out_file))
        assert out_file.read_text() == EXPECTED_PCR10_SHA256

    def test_binary_output_to_file(self, tmp_path):
        """'-f binary -o' must write raw 32-byte digest to file."""
        out_file = tmp_path / "pcr10.bin"
        run_script(
            PCR10_SCRIPT,
            "-i",
            str(SAMPLE_IMA_LOG),
            "-f",
            "binary",
            "-o",
            str(out_file),
        )
        data = out_file.read_bytes()
        assert data.hex().upper() == EXPECTED_PCR10_SHA256
        assert len(data) == 32

    def test_invalid_hash_algorithm(self):
        """An unsupported algorithm like 'md5' must cause a non-zero exit."""
        result = subprocess.run(
            [sys.executable, str(PCR10_SCRIPT), "-i", str(SAMPLE_IMA_LOG), "-a", "md5"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode != 0


# ---------------------------------------------------------------------------
# boot_aggregate.py
# ---------------------------------------------------------------------------

PCR_SELECTOR = "sha256:0,1,2,3,4,5,6,7,8,9,10,12,14,23"


class TestBootAggregateCli:
    """Tests for examples/boot_aggregate.py CLI."""

    def test_default_hex(self):
        """Default output must be lowercase hex boot_aggregate."""
        result = run_script(
            BOOT_AGG_SCRIPT,
            "--in",
            str(SAMPLE_PCR_LIST),
            "-s",
            PCR_SELECTOR,
        )
        assert result.stdout.strip() == EXPECTED_BOOT_AGGREGATE_SHA256

    def test_uppercase_hex(self):
        """'-f HEX' must output uppercase hex."""
        result = run_script(
            BOOT_AGG_SCRIPT,
            "--in",
            str(SAMPLE_PCR_LIST),
            "-s",
            PCR_SELECTOR,
            "-f",
            "HEX",
        )
        assert result.stdout.strip() == EXPECTED_BOOT_AGGREGATE_SHA256.upper()

    def test_output_to_file(self, tmp_path):
        """'-o' must write the hex string to the specified file."""
        out_file = tmp_path / "ba.txt"
        run_script(
            BOOT_AGG_SCRIPT,
            "--in",
            str(SAMPLE_PCR_LIST),
            "-s",
            PCR_SELECTOR,
            "-o",
            str(out_file),
        )
        assert out_file.read_text() == EXPECTED_BOOT_AGGREGATE_SHA256

    def test_binary_output_to_file(self, tmp_path):
        """'-f binary -o' must write raw 32-byte digest to file."""
        out_file = tmp_path / "ba.bin"
        run_script(
            BOOT_AGG_SCRIPT,
            "--in",
            str(SAMPLE_PCR_LIST),
            "-s",
            PCR_SELECTOR,
            "-f",
            "binary",
            "-o",
            str(out_file),
        )
        data = out_file.read_bytes()
        assert data.hex() == EXPECTED_BOOT_AGGREGATE_SHA256
        assert len(data) == 32

    def test_missing_required_args(self):
        """Omitting required --in and -s must cause a non-zero exit."""
        result = subprocess.run(
            [sys.executable, str(BOOT_AGG_SCRIPT)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode != 0

    def test_selector_missing_pcr0_to_9(self):
        """A selector that doesn't include all of PCR 0-9 must cause a non-zero exit."""
        result = subprocess.run(
            [
                sys.executable,
                str(BOOT_AGG_SCRIPT),
                "--in",
                str(SAMPLE_PCR_LIST),
                "-s",
                "sha256:0,1,2",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode != 0


# ---------------------------------------------------------------------------
# appraise.py
# ---------------------------------------------------------------------------

# Hash of `boot_aggregate` in the sample IMA log; used to build a deny policy.
SAMPLE_BOOT_AGGREGATE_HASH = "088faac4777b024045bd578c5c3f8efc4ac2cafb4af90a12832a762feb58eb88"
# Total IMA log entries in the sample ascii_runtime_measurements file.
SAMPLE_IMA_LOG_ENTRY_COUNT = 32


def _write_deny_policy(tmp_path: pathlib.Path, file_hash_hex: str) -> pathlib.Path:
    """Write a minimal deny policy targeting boot_aggregate by hash and return its path."""
    policy_path = tmp_path / "deny_policy.yaml"
    policy_path.write_text(f"boot_aggregate:\n  path: boot_aggregate\n  deny: [{file_hash_hex}]\n")
    return policy_path


class TestAppraiseCli:
    """Tests for examples/appraise.py CLI."""

    def test_default_show_deny_on_clean_log_is_empty_and_exit_zero(self):
        """With the sample allow-only policy, default '-s deny' prints nothing and exits 0."""
        result = run_script(
            APPRAISE_SCRIPT,
            "-i",
            str(SAMPLE_IMA_LOG),
            "-p",
            str(SAMPLE_POLICY),
        )
        assert result.stdout == ""
        # summary always goes to stderr
        assert "0 deny" in result.stderr

    def test_show_all_lists_every_entry(self):
        """'-s all' must emit one tab-separated line per IMA log entry."""
        result = run_script(
            APPRAISE_SCRIPT,
            "-i",
            str(SAMPLE_IMA_LOG),
            "-p",
            str(SAMPLE_POLICY),
            "-s",
            "all",
        )
        lines = result.stdout.strip().splitlines()
        assert len(lines) == SAMPLE_IMA_LOG_ENTRY_COUNT
        # boot_aggregate is the first entry and should be classified as allow under the sample policy
        first_verdict, first_hash, first_path = lines[0].split("\t")
        assert first_verdict == "allow"
        assert first_hash == SAMPLE_BOOT_AGGREGATE_HASH
        assert first_path == "boot_aggregate"

    def test_show_non_allow_excludes_allowed_entries(self):
        """'-s non-allow' must omit allow verdicts but include neutral and deny."""
        result = run_script(
            APPRAISE_SCRIPT,
            "-i",
            str(SAMPLE_IMA_LOG),
            "-p",
            str(SAMPLE_POLICY),
            "-s",
            "non-allow",
        )
        verdicts = [line.split("\t", 1)[0] for line in result.stdout.strip().splitlines()]
        assert verdicts  # the sample log has neutral entries
        assert "allow" not in verdicts

    def test_deny_exits_one_and_prints_denied_entry(self, tmp_path):
        """A deny policy that hits an entry must print it and exit with status 1."""
        policy_path = _write_deny_policy(tmp_path, SAMPLE_BOOT_AGGREGATE_HASH)
        result = subprocess.run(
            [
                sys.executable,
                str(APPRAISE_SCRIPT),
                "-i",
                str(SAMPLE_IMA_LOG),
                "-p",
                str(policy_path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 1
        lines = result.stdout.strip().splitlines()
        assert len(lines) == 1
        verdict, file_hash, file_path = lines[0].split("\t")
        assert verdict == "deny"
        assert file_hash == SAMPLE_BOOT_AGGREGATE_HASH
        assert file_path == "boot_aggregate"

    def test_output_to_file(self, tmp_path):
        """'-o' must write the verdict lines to the specified file."""
        out_file = tmp_path / "verdicts.tsv"
        run_script(
            APPRAISE_SCRIPT,
            "-i",
            str(SAMPLE_IMA_LOG),
            "-p",
            str(SAMPLE_POLICY),
            "-s",
            "all",
            "-o",
            str(out_file),
        )
        lines = out_file.read_text().strip().splitlines()
        assert len(lines) == SAMPLE_IMA_LOG_ENTRY_COUNT

    def test_missing_policy_arg(self):
        """Omitting required --policy must cause a non-zero exit."""
        result = subprocess.run(
            [sys.executable, str(APPRAISE_SCRIPT), "-i", str(SAMPLE_IMA_LOG)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode != 0

    def test_policy_file_not_found(self, tmp_path):
        """A nonexistent policy path must exit with status 2."""
        missing = tmp_path / "does_not_exist.yaml"
        result = subprocess.run(
            [
                sys.executable,
                str(APPRAISE_SCRIPT),
                "-i",
                str(SAMPLE_IMA_LOG),
                "-p",
                str(missing),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 2

    def test_malformed_policy_file(self, tmp_path):
        """A policy missing 'path' on a component must exit with status 2."""
        policy_path = tmp_path / "bad_policy.yaml"
        policy_path.write_text("missing_path:\n  allow: [abc]\n")
        result = subprocess.run(
            [
                sys.executable,
                str(APPRAISE_SCRIPT),
                "-i",
                str(SAMPLE_IMA_LOG),
                "-p",
                str(policy_path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 2
