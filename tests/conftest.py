# SPDX-License-Identifier: MIT
# pylint: disable=redefined-outer-name
"""Shared pytest fixtures providing sample IMA log and PCR blob data from examples/."""

import pathlib

import pytest

EXAMPLES_DIR = pathlib.Path(__file__).resolve().parent.parent / "examples"


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
    """Path to the sample pcr_list.bin file."""
    return EXAMPLES_DIR / "pcr_list.bin"


@pytest.fixture
def sample_pcr_blob(sample_pcr_list_path):
    """Raw bytes of the sample PCR list blob (concatenated SHA-256 digests for 14 PCRs)."""
    return sample_pcr_list_path.read_bytes()
