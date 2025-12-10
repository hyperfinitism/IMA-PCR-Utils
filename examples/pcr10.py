import hashlib
import sys
import os

# Add parent directory to path to import from py package
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from imapcr10 import read_ima_log_file, calculate_pcr10

DEFAULT_IMA_LOG_PATH = "/sys/kernel/security/ima/ascii_runtime_measurements"

def set_hash_function(hash_type: str):
    match hash_type:
        case "sha1":
            return hashlib.sha1
        case "sha256":
            return hashlib.sha256
        case "sha384":
            return hashlib.sha384
        case "sha512":
            return hashlib.sha512
        case _:
            print(f"Invalid hash type: {hash_type}")
            return None

def main():
    input_path = input("Enter the path to the IMA log (press Enter for default): ") or DEFAULT_IMA_LOG_PATH
    print(f"Using IMA log path: {input_path}")
    pcr_hash_type = input("Enter the hash function to use for the PCR10 (default: sha256): ") or "sha256"
    
    # Set hash function for PCR10 hash chain
    pcr_hash_func = set_hash_function(pcr_hash_type)

    # Read IMA log entries
    entries = read_ima_log_file(input_path)
    
    # Calculate PCR10
    pcr_value = calculate_pcr10(
        entries,
        hash_func=pcr_hash_func,
    )
    
    print(f"Simulated PCR 10 value ({pcr_hash_type}): {pcr_value.hex().upper()}")
    
    return True

if __name__ == "__main__":
    main()
