# SPDX-License-Identifier: MIT
"""Tests for the CLI example scripts (pcr10.py, boot_aggregate.py) via subprocess."""

import pathlib
import subprocess
import sys

EXAMPLES_DIR = pathlib.Path(__file__).resolve().parent.parent / "examples"
PCR10_SCRIPT = EXAMPLES_DIR / "pcr10.py"
BOOT_AGG_SCRIPT = EXAMPLES_DIR / "boot_aggregate.py"
SAMPLE_IMA_LOG = EXAMPLES_DIR / "ascii_runtime_measurements"
SAMPLE_PCR_LIST = EXAMPLES_DIR / "pcr_list.bin"

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
