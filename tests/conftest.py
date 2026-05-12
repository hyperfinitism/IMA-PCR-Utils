# SPDX-License-Identifier: MIT
# pylint: disable=redefined-outer-name
"""Shared pytest fixtures providing sample IMA log and PCR blob data from examples/."""

import pathlib

import pytest

EXAMPLES_DIR = pathlib.Path(__file__).resolve().parent.parent / "examples" / "sample_input"


@pytest.fixture
def sample_ima_log_path():
    """Path to the sample ascii_runtime_measurements file."""
    return EXAMPLES_DIR / "ascii_runtime_measurements"


@pytest.fixture
def sample_ima_log(sample_ima_log_path):
    """Contents of the sample IMA log as a string."""
    return sample_ima_log_path.read_text()


@pytest.fixture
def sample_pcr_list_path():
    """Path to the sample pcrlist.bin file."""
    return EXAMPLES_DIR / "pcrlist.bin"


@pytest.fixture
def sample_pcr_blob(sample_pcr_list_path):
    """Raw bytes of the sample PCR list blob (concatenated SHA-256 digests for 14 PCRs)."""
    return sample_pcr_list_path.read_bytes()


@pytest.fixture
def sample_ima_log_2_path():
    """Path to the second sample ascii_runtime_measurements_2 file."""
    return EXAMPLES_DIR / "ascii_runtime_measurements_2"


@pytest.fixture
def sample_ima_log_2(sample_ima_log_2_path):
    """Contents of the second sample IMA log as a string."""
    return sample_ima_log_2_path.read_text()


@pytest.fixture
def sample_pcr_list_2_path():
    """Path to the second sample pcrlist_2.bin file."""
    return EXAMPLES_DIR / "pcrlist_2.bin"


@pytest.fixture
def sample_pcr_blob_2(sample_pcr_list_2_path):
    """Raw bytes of the second sample PCR list blob (concatenated SHA-256 digests for 24 PCRs)."""
    return sample_pcr_list_2_path.read_bytes()
