# IMA PCR10 Utils

**IMA PCR10 Utils** (`imapcr10`) is a Python library for Integrity Measurement Architecture (IMA), providing functionality for parsing IMA log entries and calculating PCR10 hash values.

## Installation

### Requirements

- Python 3.7+ (Tested with Python 3.12.3)

### Install from repository

```bash
git clone https://github.com/acompany-develop/IMA-PCR10-Utils
cd IMA-PCR10-Utils
pip install -e .
```

## Usage

The Python module `imapcr10` provides functionality for parsing IMA logs and calculating PCR10 from the IMA logs. It can be used as follows:

### Example Code

```python
import hashlib
from imapcr10 import parse_ima_log_string, calculate_pcr10, calculate_boot_aggregate

# parse IMA logs
with open(ima_log_path, 'r') as f:
    lines = f.read()
entries = parse_ima_log_string(lines)

# calculate PCR10 hash
pcr_value = calculate_pcr10(entries, hash_func=hashlib.sha256)

# calculate boot_aggregate
pcrlist = [
    bytes.fromhex("50597A27846E91D025EEF597ABBC89F72BFF9AF849094DB97B0684D8BC4C515E"),
    bytes.fromhex("3A1F7B51E23F50DED05B83A880850913657A9AB4EBC8B0CAA574D46B2E39A864"),
    bytes.fromhex("3D458CFE55CC03EA1F443F1562BEEC8DF51C75E14A9FCF9A7234A13F198E7969"),
    bytes.fromhex("3D458CFE55CC03EA1F443F1562BEEC8DF51C75E14A9FCF9A7234A13F198E7969"),
    bytes.fromhex("A274E8CAD520128A8B8E607F7216645A288E81E09F3F130186EC4EF84754B7B7"),
    bytes.fromhex("CC39B36D65EC93BB33B631B75E43AACF35BCF872C78BA312263FC0022422C107"),
    bytes.fromhex("3D458CFE55CC03EA1F443F1562BEEC8DF51C75E14A9FCF9A7234A13F198E7969"),
    bytes.fromhex("A11C5239A222BB78072C2C73CAA691BB9A0F118DE2D95CDCE1FCE06711E4D3ED"),
    bytes.fromhex("D2B43B51A68170474AA807E80A08D1971177BB8B137C0E84301D008D1BB03CCF"),
    bytes.fromhex("DA94827889CCEDE4CB7BBE3BF720BD4DBFCAD7434A9C2D068CCC2CEF58903F27"),
]
boot_aggregate = calculate_boot_aggregate(pcrlist)
```

### CLI Tools / Example Scripts

You can calculate PCR10 values from IMA log files using the example script.

```bash
# Calculate PCR10 from input IMA logs
# Default:
# /sys/kernel/security/ima/ascii_runtime_measurements
# sha256 for PCR10 hash chain
sudo python3 examples/pcr10.py
```

When using the default input, please run it in an Azure VM (i.e. attester) environment where vTPM is available.

Sample input IMA logs located within the `examples/` directory are also available.

### Compare with the true PCR10 hash value

Run on the attester environment (Azure VM with vTPM):

```bash
sudo apt update
sudo apt install -y tpm2-tools

sudo usermod -aG tss $USER
newgrp tss
```

```bash
tpm2_pcrread sha1:10
tpm2_pcrread sha256:10
tpm2_pcrread sha384:10
```

## Setting custom IMA policy

### Create/update IMA policy
The bundled policy `config/ima-policy` is configured to measure executable files when they are run.

```bash
# Make IMA directory if absent
ls -l /etc/ima
sudo mkdir -p /etc/ima

# Create/Update IMA Policy
sudo cp config/ima-policy /etc/ima/ima-policy

# Reboot
sudo reboot
```

In the bundled policy, the following rule is commented out:

```plaintext
measure func=FILE_CHECK mask=MAY_READ uid=0
```

This rule would generate an enormous volume of IMA logs, as it would measure all files read by `uid=0` (root).

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

In order to perform runtime measurement on programmes written in scripting languages (e.g. Python) under the bundled policy, they must be pre-compiled into executable files.

For example, you can use [nuitka](https://github.com/Nuitka/Nuitka) to compile Python scripts:

```bash
# Install Nuitka
sudo apt install -y pipx
pipx install nuitka
pipx ensurepath

nuitka <PYTHON_SCRIPT_FILE>.py
# => <PYTHON_SCRIPT_FILE>.bin
```

The example directory contains the IMA logs before and after running `pcr10.bin` (built from `examples/pcr10.py`).

```bash
# pcr10.py => pcr10.bin
nuitka examples/pcr10.py
sudo reboot

# Copy IMA logs before execution
(sudo cat /sys/kernel/security/ima/ascii_runtime_measurements) > ascii_runtime_measurements_policy_before_exec

# Execute
sudo ./pcr10.bin

# Copy IMA logs after execution
(sudo cat /sys/kernel/security/ima/ascii_runtime_measurements) > ascii_runtime_measurements_policy_after_exec

# Check SHA-256 checksum of pcr10.bin
sha256sum ./pcr10.bin
```

## Trouble Shooting

### Boot failure after setting IMA policy

Open the serial console for the VM instance in the Azure Portal (boot diagnostics must be enabled). Then retry the procedure that caused the issue. If the following error message appears in the serial console, the IMA policy may be invalid.

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

If the policy is valid, the IMA policy will be loaded successfully. Otherwise, the IMA policy is invalid. Check syntax, measured items, etc.

## Test Environments

### Environment 1

- CSP: Azure
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


