#!/usr/bin/env python3
"""
CLI tool for calculating PCR10 from IMA log file.
"""
import argparse
import hashlib
import sys
from imapcrutils import parse_ima_log_string, calculate_pcr10

DEFAULT_IMA_LOG_PATH = "/sys/kernel/security/ima/ascii_runtime_measurements"

def select_hash_function(hash_algorithm: str):
    """
    Select hash function based on the hash algorithm.
    """
    match hash_algorithm:
        case "sha1":
            return hashlib.sha1
        case "sha256":
            return hashlib.sha256
        case "sha384":
            return hashlib.sha384
        case "sha512":
            return hashlib.sha512
        case _:
            # will not reach here
            raise ValueError(f"Invalid hash algorithm: {hash_algorithm}")


def output_pcr10(pcr_value: bytes, output_format: str) -> str | bytes:
    """
    Output PCR10 value in the specified format.
    """
    match output_format:
        case "HEX":
            return pcr_value.hex().upper()
        case "hex":
            return pcr_value.hex().lower()
        case "binary":
            return pcr_value
        case _:
            # will not reach here
            raise ValueError(f"Invalid output format: {output_format}")


def output_pcr10_to_file(pcr_value: str | bytes, output_path: str) -> None:
    """
    Output PCR10 value to the specified file.
    """
    if isinstance(pcr_value, str):
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(pcr_value)
    else:
        with open(output_path, 'wb') as f:
            f.write(pcr_value)


def main():
    """
    Main function.
    """
    parser = argparse.ArgumentParser(
        description="Calculate PCR10 from IMA log file."
    )
    parser.add_argument(
        "-i", "--in",
        dest="input_path",
        default=DEFAULT_IMA_LOG_PATH,
        help=f"Path to the IMA log file (default: {DEFAULT_IMA_LOG_PATH})"
    )
    parser.add_argument(
        "-a", "--hash-algorithm",
        dest="hash_algorithm",
        type=str.lower,
        default="sha256",
        choices=["sha1", "sha256", "sha384", "sha512"],
        help="Hash algorithm to use for PCR10 calculation (default: sha256)"
    )
    parser.add_argument(
        "-o", "--out",
        dest="output_path",
        default=None,
        help="Path to the output file (default: stdout)"
    )
    parser.add_argument(
        "-f", "--format",
        dest="output_format",
        default="HEX",
        choices=["HEX", "hex", "binary"],
        help="Output format (default: HEX)"
    )

    args = parser.parse_args()

    # Select hash function for PCR10 hash chain
    pcr_hash_func = select_hash_function(args.hash_algorithm)

    # Read IMA log entries
    with open(args.input_path, 'r', encoding='utf-8') as f:
        lines = f.read()

    entries = parse_ima_log_string(lines)

    # Calculate PCR10
    pcr_value = calculate_pcr10(entries, pcr_hash_func)

    if args.output_path is None:
        print(output_pcr10(pcr_value, args.output_format))
    else:
        output_pcr10_to_file(output_pcr10(pcr_value, args.output_format), args.output_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
