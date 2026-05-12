#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
CLI tool for truncating IMA log entries to find the point where PCR matches a reference value.
"""

import argparse
import hashlib
import sys

from imapcrutils.log import parse_ima_log_string
from imapcrutils.pcr import truncate_ima_log_by_pcr

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
            # will not reach here (choices enforced by argparse)
            raise ValueError(f"Invalid hash algorithm: {hash_algorithm}")


def output_truncated_log(entries: list, output_path: str | None) -> None:
    """
    Output truncated IMA log entries to file or stdout.
    """
    output_lines = [str(entry) for entry in entries]
    output_text = "\n".join(output_lines) + "\n"
    if output_path is None:
        print(output_text, end="")
    else:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(output_text)


def main() -> int:
    """
    Main function.
    """
    parser = argparse.ArgumentParser(description="Truncate IMA log to find the point where PCR matches a reference value.")
    parser.add_argument(
        "-i",
        "--in",
        dest="input_path",
        default=DEFAULT_IMA_LOG_PATH,
        help=f"Path to the IMA log file (default: {DEFAULT_IMA_LOG_PATH})",
    )
    parser.add_argument(
        "-p",
        "--pcr",
        dest="pcr_hex",
        required=True,
        help="Reference PCR value in hex format (e.g., c5bfcd40187bfc190fe9c584b8b2675f08180c0e9579255fa9eba91e7d18f678)",
    )
    parser.add_argument(
        "-a",
        "--hash-algorithm",
        dest="hash_algorithm",
        type=str.lower,
        default="sha256",
        choices=["sha1", "sha256", "sha384", "sha512"],
        help="Hash algorithm used for PCR calculation (default: sha256)",
    )
    parser.add_argument(
        "-o",
        "--out",
        dest="output_path",
        default=None,
        help="Path to the output file (default: stdout)",
    )

    args = parser.parse_args()

    # Parse the hex-encoded PCR reference
    try:
        pcr_reference = bytes.fromhex(args.pcr_hex)
    except ValueError:
        print(f"Error: Invalid hex value for PCR10: {args.pcr_hex}", file=sys.stderr)
        return 1

    # Verify the PCR value has the correct length based on hash algorithm
    hash_func = select_hash_function(args.hash_algorithm)
    expected_length = hash_func().digest_size
    if len(pcr_reference) != expected_length:
        print(
            f"Error: PCR10 length mismatch. Expected {expected_length} bytes for {args.hash_algorithm}, "
            f"got {len(pcr_reference)} bytes",
            file=sys.stderr,
        )
        return 1

    # Read IMA log entries
    try:
        with open(args.input_path, encoding="utf-8") as f:
            lines = f.read()
    except FileNotFoundError:
        print(f"Error: IMA log file not found: {args.input_path}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"Error reading IMA log file: {e}", file=sys.stderr)
        return 1

    entries = parse_ima_log_string(lines)

    # Truncate the log to find the matching PCR
    result = truncate_ima_log_by_pcr(entries, pcr_reference, hash_func)

    if result is None:
        print(
            "Error: The reference PCR10 does not match any point in the IMA log.",
            file=sys.stderr,
        )
        return 1

    # Output the truncated log
    output_truncated_log(result, args.output_path)
    print(f"Successfully truncated IMA log to {len(result)} entries", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
