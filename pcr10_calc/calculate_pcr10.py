import hashlib
import struct
import binascii

def get_pcr10_sha256(file_path):
    """Calculate the current PCR 10 value by simulation"""
    
    # PCR initial value is all zeros (SHA-256 = 32 bytes)
    pcr_value = bytes(32)
    
    print(f"[*] Reading IMA log from: {file_path}")
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except PermissionError:
        print("Error: Permission denied. Please run with sudo.")
        return

    for i, line in enumerate(lines):
        parts = line.strip().split()
        
        # Format: PCR | Template_Hash | Template_Name | File_Data | File_Path
        if len(parts) < 5:
            continue
            
        pcr_idx = parts[0]
        log_template_hash = parts[1]
        template_name = parts[2]
        file_data = parts[3]
        # File path may contain spaces, so join the remaining parts
        file_path = " ".join(parts[4:])

        # Skip if PCR is not 10
        if pcr_idx!= "10":
            continue

        # Only support ima-ng template
        if template_name!= "ima-ng":
            print(f"Skipping unsupported template: {template_name}")
            continue

        # ---------------------------------------------------------
        # Reconstruct binary template data (Reconstruction)
        # ---------------------------------------------------------
        
        # 1. Create d-ng (Digest) field
        # Format: + [Algo(string)] + [:] + [\0] +
        try:
            algo, digest_hex = file_data.split(':')
            digest_bytes = bytes.fromhex(digest_hex)
        except ValueError:
            print(f"Skipping malformed data line {i+1}")
            continue

        # "sha256:\0" + digest_bytes
        d_ng_content = algo.encode('ascii') + b':' + b'\x00' + digest_bytes
        d_ng_field = struct.pack('<I', len(d_ng_content)) + d_ng_content

        # 2. Create n-ng (Name) field
        # Format: + [FilePath(string)] + [\0]
        # File path must end with null character
        n_ng_content = file_path.encode('utf-8') + b'\x00'
        n_ng_field = struct.pack('<I', len(n_ng_content)) + n_ng_content

        # 3. Combine template data
        template_data = d_ng_field + n_ng_field

        # 4. Calculate Template Hash (SHA-1 and SHA-256)
        expected_template_hash = hashlib.sha1(template_data).digest()
        expected_template_hash_sha256 = hashlib.sha256(template_data).digest()

        # (Optional) Check if the hash in the log matches the calculated result
        if expected_template_hash.hex()!= log_template_hash:
            print(f"Warning: Line {i+1} hash mismatch!")
            print(f"  Log:  {log_template_hash}")
            print(f"  Calc: {expected_template_hash.hex()}")
            # Even if they don't match, PCR extension calculation continues (for log tampering detection)

        # ---------------------------------------------------------
        # PCR extension (Extend Operation)
        # PCR_new = SHA256( PCR_old || Template_Hash_SHA256 )
        # ---------------------------------------------------------
        pcr_value = hashlib.sha256(pcr_value + expected_template_hash_sha256).digest()

    print("-" * 60)
    print(f"Calculated PCR 10 (SHA-256):")
    print(f"0x{pcr_value.hex().upper()}")
    print("-" * 60)

    return pcr_value
