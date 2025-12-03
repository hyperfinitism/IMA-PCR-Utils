# IMA PCR10 Utils

## Usage

### Calculate PCR10 from IMA log

Run on the attester environment (Azure VM with vTPM):

```bash
# Calculate PCR10 from IMA log:
# /sys/kernel/security/ima/ascii_runtime_measurements
sudo python3 pcr10-calc/main.py
```

or run on the verifier environment with the received IMA log file:

```python
import pcr10_calc.calculate_pcr10 as pcr10_calc
pcr_value_sha256 = pcr10_calc.get_pcr10_sha256(input_path)
print(f"PCR 10 value (SHA-256): {pcr_value_sha256.hex().upper()}")
```

### Compare with the actual PCR10

Run on the attester environment (Azure VM with vTPM):

```bash
sudo apt update
sudo apt install -y tpm2-tools
```

```bash
sudo tpm2_pcrread sha256:10
```
