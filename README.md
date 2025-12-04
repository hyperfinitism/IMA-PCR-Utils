# IMA PCR10 Utils

This project includes the libraries for parsing IMA log entries and calculating PCR10 values.

## Project Structure

```
IMA-PCR10-Utils/
├── py/          # Python implementation
└── samples/     # Sample IMA files
```

## Python Usage

### Requirements
- Python 3.7+ (Tested with Python 3.12.3)

### Calculate PCR10 from IMA log

Run on the attester environment (Azure VM with vTPM):

```bash
# Calculate PCR10 from input IMA log
# Default:
# /sys/kernel/security/ima/ascii_runtime_measurements
# sha256 for PCR10 hash chain
sudo python3 py/examples/pcr10.py
```

When using the default input, please run it in an Azure VM (i.e. attester) environment where vTPM is available.

Sample IMA log files located within the `samples/` directory are also available.

### Using as a library

```python
import hashlib
from py.ima_lib import read_ima_log_file, calculate_pcr10

entries = read_ima_log_file("/sys/kernel/security/ima/ascii_runtime_measurements")
pcr_value = calculate_pcr10(entries, hash_func=hashlib.sha256, template_hash_func=hashlib.sha256)
print(f"PCR 10: {pcr_value.hex().upper()}")
```

### Compare with the actual PCR10

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
