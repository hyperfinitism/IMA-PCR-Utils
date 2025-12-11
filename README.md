# IMA PCR10 Utils

This project includes the Python libraries for parsing IMA log entries and calculating PCR10 values.

## Project structure

```
IMA-PCR10-Utils/
├── imapcr10/		# Python module
└── samples/     	# Example scripts and IMA logs
```

## Usage

### Requirements

- Python 3.7+ (Tested with Python 3.12.3)

### Calculating PCR10 from IMA logs

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

### Using as a Python module

The Python module `imapcr10` provides functionality for parsing IMA logs and calculating PCR10. It can be used as follows:

```python
import hashlib
from imapcr10 import read_ima_log_file, calculate_pcr10

entries = read_ima_log_file("/sys/kernel/security/ima/ascii_runtime_measurements")
pcr_value = calculate_pcr10(entries, hash_func=hashlib.sha256)
print(f"PCR 10: {pcr_value.hex().upper()}")
```

### Comparing with the actual PCR10

Run on the attester environment (Azure VM with vTPM):

```bash
sudo apt update
sudo apt install -y tpm2-tools
```

```bash
sudo tpm2_pcrread sha1:10
sudo tpm2_pcrread sha256:10
sudo tpm2_pcrread sha384:10
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

## Test Environment

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
