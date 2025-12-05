# IMA PCR10 Utils

This project includes the Python libraries for parsing IMA log entries and calculating PCR10 values.

## Project Structure

```
IMA-PCR10-Utils/
├── imapcr10/		# Python module with example script
└── samples/     	# Sample IMA files
```

## Usage

### Requirements
- Python 3.7+ (Tested with Python 3.12.3)

### Calculating PCR10 from IMA logs

Run on the attester environment (Azure VM with vTPM):

```bash
# Calculate PCR10 from input IMA logs
# Default:
# /sys/kernel/security/ima/ascii_runtime_measurements
# sha256 for PCR10 hash chain
sudo python3 imapcr10/examples/pcr10.py
```

When using the default input, please run it in an Azure VM (i.e. attester) environment where vTPM is available.

Sample IMA log files located within the `samples/` directory are also available.

### Using as a library

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

## Setting Custom IMA Policy

### Create/Update IMA Policy
The bundled policy `config/ima-policy` is configured to measure files executed at runtime.

```bash
# Make IMA directory if absent
ls -l /etc/ima
sudo mkdir -p /etc/ima

# Create/Update IMA Policy
sudo cp config/ima-policy /etc/ima/ima-policy

# Reboot
sudo reboot
```

### Verify Policy Update
```bash
# Read initial IMA logs
sudo cat /sys/kernel/security/ima/ascii_runtime_measurements

# Run (triggering measurement)
sudo tpm2_pcrread sha256:10

# Read IMA logs again
# files related to tpm2-tools are measured
sudo cat /sys/kernel/security/ima/ascii_runtime_measurements
```

### Compile Python scripts
In the bundled policy file, the following rule is commented out:

```plaintext
measure func=FILE_CHECK mask=MAY_READ uid=0
```

This rule would generate an enormous volume of IMA logs, as it would measure every file read by `uid=0` (root).

To measure Python scripts (at runtime) with the bundled policy, the script must be pre-compiled to generate an executable file.

```bash
# Install Nuitka
sudo apt install -y pipx
pipx install nuitka

nuitka imapcr10/examples/pcr10.py
# => pcr10.bin
```

The sample directory contains the IMA logs before and after running `pcr10.bin`.

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
