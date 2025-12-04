import hashlib
import sys
import os

# Add parent directory to path to import from py package
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))
from py.ima_lib import read_ima_log_file, calculate_pcr10, validate_ima_log_entries

DEFAULT_IMA_LOG_PATH = "/sys/kernel/security/ima/ascii_runtime_measurements"

def main():
    input_path = input("Enter the path to the IMA log (press Enter for default): ") or DEFAULT_IMA_LOG_PATH
    print(f"Using IMA log path: {input_path}")
    
    # Read IMA log entries
    entries = read_ima_log_file(input_path, as_stream=False)

    # Validate IMA log entries
    if validate_ima_log_entries(entries):
        print("IMA log entries are consistent")
    else:
        print("IMA log entries are inconsistent")
        return False
    
    # Calculate PCR10 using SHA-256 for both PCR extension and template hash
    pcr_value_sha256 = calculate_pcr10(
        entries,
        hash_func=hashlib.sha256,
        template_hash_func=hashlib.sha256
    )
    
    print(f"Simulated PCR 10 value (SHA-256): {pcr_value_sha256.hex().upper()}")

    return True

if __name__ == "__main__":
    main()
