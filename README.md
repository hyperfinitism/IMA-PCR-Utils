# IMA-PCR-Utils

![SemVer](https://img.shields.io/badge/imapcrutils-0.1.0-blue)
![Python Version](https://img.shields.io/badge/Python-3.10+-blue)
[![License](https://img.shields.io/badge/License-MIT-red)](/LICENSE)

**IMA-PCR-Utils** (`imapcrutils`) is a Python library for Integrity Measurement
Architecture (IMA) and Platform Configuration Register (PCR), providing
functionality for parsing IMA log entries, calculating PCR10 hash values and
boot_aggregate values.

## Installation

### Requirements

- Python 3.10+

### Install from repository

```bash
pip install git+https://github.com/acompany-develop/IMA-PCR-Utils
```

## What's inside

### Module

The `imapcrutils` module consists of the following public types and functions:

| Name | Description |
| ---- | ----------- |
| `IMALogEntry` | Represents a single IMA log entry (`pcr_idx`, `template_hash`, `template_name`, `hash_algo`, `file_hash`, `file_path`). |
| `parse_ima_log_string` | Parse an ASCII IMA log string into a list of `IMALogEntry`. |
| `build_template_fields` | Build `ima-ng` template fields (digest/name) from an `IMALogEntry`. |
| `calculate_expected_template_hash` | Recompute the expected template hash for an entry (default: SHA-1). |
| `calculate_pcr10` | Replay PCR10 by extending PCR10 with each `ima-ng` entry (default chain hash: SHA-256). |
| `validate_ima_log_entry` | Validate a single entry by comparing the template hash with the recomputed value. |
| `calculate_boot_aggregate` | Calculate `boot_aggregate` from PCR0..PCR9 values. |

### CLI Tools / Example Scripts

The `examples/` directory contains scripts that serve as both usage examples
and command-line tools. Sample IMA log and PCR list files are also available.

| Script | Description |
| ------ | ----------- |
| `pcr10.py` | Calculate PCR10 from input IMA log |
| `boot_aggregate.py` | Calculate boot_aggregate from PCR list file including PCR[0-9] |

### Compare with the true PCR10 hash value

```bash
# Install TPM2 Tools
sudo apt update
sudo apt install -y tpm2-tools

# Grant permission to access TPM driver
sudo usermod -aG tss $USER
newgrp tss
```

```bash
# Read PCR bank
tpm2_pcrread sha1:10
tpm2_pcrread sha256:10
tpm2_pcrread sha384:10
```

## Setting custom IMA policy

### Create/update IMA policy

The bundled policy `config/ima-policy` is configured to measure executable
files when they are run.

```bash
# Make IMA directory if absent
ls -l /etc/ima
sudo mkdir -p /etc/ima

# Create or update IMA policy
sudo cp config/ima-policy /etc/ima/ima-policy

# Reboot
sudo reboot
```

In the bundled policy, the following rule is commented out:

```plaintext
measure func=FILE_CHECK mask=MAY_READ uid=0
```

This rule would generate an enormous volume of IMA logs, as it would measure
all files read by `uid=0` (root).

### Check if the updated policy is in effect

```bash
# Read initial IMA logs
sudo cat /sys/kernel/security/ima/ascii_runtime_measurements

# Execute any binary (triggering measurement)
sudo tpm2_pcrread sha256:10

# Read IMA logs again
# Executed files are measured
sudo cat /sys/kernel/security/ima/ascii_runtime_measurements
```

### Measuring scripts

In order to perform runtime measurement on programmes written in scripting
languages (e.g. Python) under the bundled policy, they must be pre-compiled
into executable files.

For example, you can use [nuitka](https://github.com/Nuitka/Nuitka) to compile
Python scripts:

```bash
# Install Nuitka
pip install nuitka

nuitka <PYTHON_SCRIPT_FILE>.py
# => <PYTHON_SCRIPT_FILE>.bin
```

## Trouble Shooting

### Boot failure after setting IMA policy

Open the serial console for the VM instance and (re)boot. If the error message
like the following appears in the serial console, the IMA policy may be invalid.

```console
[!!!!!!] Failed to load IMA policy.
[    3.027439] systemd[1]: Freezing execution.
```

Create a new VM instance and check whether the IMA policy is valid on that VM:

```bash
sudo -i
mkdir -p /etc/ima
touch /etc/ima/ima-policy
touch /sys/kernel/security/ima/policy

cat $IMA_POLICY_PATH > /sys/kernel/security/ima/policy
```

If the policy is valid, the IMA policy will be loaded successfully. Otherwise,
the IMA policy is invalid. Check syntax, measured items, etc.

## Test Environments

### Environment 1

- CSP: Microsoft Azure
- Machine: DCasv6 (AMD Genoa)
- Security
  - Security type: Confidential (SEV-SNP)
  - Enable secure boot: Enabled
  - Enable vTPM: Enabled
  - Integrity monitoring: Enabled
- OS Image: Ubuntu Server 24.04 LTS (Confidential VM) - x64 Gen2
- Diagnostics
  - Boot diagnostics: Enable with managed storage account

### Environment 2

- CSP: Google Cloud Platform
- Machine: N2D (AMD Milan)
- Security
  - Confidential VM service: Enabled (AMD SEV-SNP)
  - Secure Boot: Enabled
  - vTPM: Enabled
  - Integrity Monitoring: Enabled
- OS Image: Ubuntu 24.04 LTS NVIDIA version: 580
