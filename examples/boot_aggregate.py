#!/usr/bin/env python3
"""
CLI tool for calculating boot_aggregate from a PCR0..PCR9 binary blob.
"""

import argparse
import hashlib
import sys

from imapcrutils import calculate_boot_aggregate


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


def output_digest(digest: bytes, output_format: str) -> str | bytes:
    """
    Output digest in the specified format.
    """
    match output_format:
        case "HEX":
            return digest.hex().upper()
        case "hex":
            return digest.hex().lower()
        case "binary":
            return digest
        case _:
            # will not reach here (choices enforced by argparse)
            raise ValueError(f"Invalid output format: {output_format}")


def output_to_file(value: str | bytes, output_path: str) -> None:
    """
    Output value to the specified file.
    """
    if isinstance(value, str):
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(value)
    else:
        with open(output_path, "wb") as f:
            f.write(value)


def parse_selector_str(selector_str: str) -> tuple[str, list[int]]:
    """
    Parse PCR selector string and return hash algorithm and PCR indices list.

    Args:
        selector_str: PCR selector string
        (format: "<hash_algorithm>:indices")
        - "<hash_algorithm>:all": all PCR indices
        - "<hash_algorithm>:0,1,2": specific PCR indices
    Returns:
        hash algorithm, PCR indices list
    """
    hash_algorithm, indices = selector_str.split(":")
    if indices == "all":
        return hash_algorithm, list(range(24))
    return hash_algorithm, list(map(int, indices.split(",")))


def split_pcr_blob(pcr_blob: bytes, pcr_digest_size: int) -> list[bytes]:
    """
    Split PCR list concatenated blob into a list of PCR byte strings.

    Args:
        pcr_blob: PCR list concatenated blob
        pcr_digest_size: Digest size of the PCR hash algorithm
    Returns:
        List of PCR byte strings
    """
    if len(pcr_blob) % pcr_digest_size != 0:
        raise ValueError(
            "Invalid PCR list length: "
            f"expected length to be divisible by pcr_digest_size {pcr_digest_size}, got {len(pcr_blob)} bytes"
        )
    number_of_pcrs = len(pcr_blob) // pcr_digest_size
    return [pcr_blob[i * pcr_digest_size:(i + 1) * pcr_digest_size] for i in range(number_of_pcrs)]


def main() -> int:
    """
    Main function.
    """
    parser = argparse.ArgumentParser(
        description="Calculate boot_aggregate from PCR0..PCR9 binary blob."
    )
    parser.add_argument(
        "-i",
        "--in",
        dest="input_path",
        required=True,
        help="Path to the PCR list file consisting of binary blob of PCR0...PCR9 in this order",
    )
    parser.add_argument(
        "-s",
        "--selector",
        dest="selector_str",
        required=True,
        help="PCR selector string (format: <hash_algorithm>:all or <hash_algorithm>:0,1,2,...)",
    )
    parser.add_argument(
        "-a",
        "--hash-algorithm",
        dest="hash_algorithm",
        type=str.lower,
        default="sha256",
        choices=["sha1", "sha256", "sha384", "sha512"],
        help="Hash algorithm to use to calculate boot_aggregate (default: sha256)",
    )
    parser.add_argument(
        "-o",
        "--out",
        dest="output_path",
        default=None,
        help="Path to the output file (default: stdout)",
    )
    parser.add_argument(
        "-f",
        "--format",
        dest="output_format",
        default="hex",
        choices=["HEX", "hex", "binary"],
        help="Output format (default: hex)",
    )

    args = parser.parse_args()

    # Parse PCR selector string
    hash_algorithm, pcr_indices = parse_selector_str(args.selector_str)
    if not all(i in pcr_indices for i in range(10)):
        raise ValueError(f"PCR selector must includes 0-9: got {pcr_indices}")

    # Determine PCR digest length
    pcr_hash_func = select_hash_function(hash_algorithm)
    pcr_digest_size = pcr_hash_func().digest_size

    # Determine boot aggregate hash function
    ba_hash_func = select_hash_function(args.hash_algorithm)

    # Read PCR list blob
    with open(args.input_path, "rb") as f:
        pcr_blob = f.read()

    # Split PCR list blob into a list of PCR byte strings
    pcr_list = split_pcr_blob(pcr_blob, pcr_digest_size)
    if len(pcr_list) != len(pcr_indices):
        raise ValueError(f"PCR list length does not match PCR selector: got {len(pcr_list)} PCR(s), expected {len(pcr_indices)} PCR(s)")

    # Select PCR list for boot time
    boot_time_pcr_indices = [i for i in range(10) if i in pcr_indices]
    boot_time_pcr_list = [pcr_list[i] for i in boot_time_pcr_indices]

    # Calculate boot aggregate
    boot_aggregate = calculate_boot_aggregate(boot_time_pcr_list, hash_func=ba_hash_func)

    # Output
    rendered = output_digest(boot_aggregate, args.output_format)
    if args.output_path is None:
        if isinstance(rendered, bytes):
            sys.stdout.buffer.write(rendered)
        else:
            print(rendered)
    else:
        output_to_file(rendered, args.output_path)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
