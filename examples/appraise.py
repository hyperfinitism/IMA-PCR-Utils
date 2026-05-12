#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
CLI tool for appraising IMA log entries against a YAML policy.
"""

import argparse
import sys

from imapcrutils.appraisal import AppraisalResult, appraise_ima_log, load_policy_file
from imapcrutils.log import parse_ima_log_string

DEFAULT_IMA_LOG_PATH = "/sys/kernel/security/ima/ascii_runtime_measurements"

SHOW_CHOICES = ["all", "deny", "non-allow"]


def filter_results(results, show: str):
    """
    Filter (entry, verdict) pairs by --show mode.
    """
    match show:
        case "all":
            return results
        case "deny":
            return [(e, v) for e, v in results if v is AppraisalResult.DENY]
        case "non-allow":
            return [(e, v) for e, v in results if v is not AppraisalResult.ALLOW]
        case _:
            # will not reach here (choices enforced by argparse)
            raise ValueError(f"Invalid show mode: {show}")


def format_results(results) -> str:
    """
    Format (entry, verdict) pairs as tab-separated lines.
    """
    lines = [f"{verdict.value}\t{entry.file_hash.hex()}\t{entry.file_path}" for entry, verdict in results]
    return "\n".join(lines) + "\n" if lines else ""


def write_output(text: str, output_path: str | None) -> None:
    """
    Write text to file or stdout.
    """
    if output_path is None:
        print(text, end="")
    else:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(text)


def main() -> int:
    """
    Main function.
    """
    parser = argparse.ArgumentParser(description="Appraise IMA log entries against a YAML policy.")
    parser.add_argument(
        "-i",
        "--in",
        dest="input_path",
        default=DEFAULT_IMA_LOG_PATH,
        help=f"Path to the IMA log file (default: {DEFAULT_IMA_LOG_PATH})",
    )
    parser.add_argument(
        "-p",
        "--policy",
        dest="policy_path",
        required=True,
        help="Path to the YAML appraisal policy file",
    )
    parser.add_argument(
        "-s",
        "--show",
        dest="show",
        type=str.lower,
        default="deny",
        choices=SHOW_CHOICES,
        help="Which verdicts to print: all entries, deny only, or non-allow (deny + neutral) (default: deny)",
    )
    parser.add_argument(
        "-o",
        "--out",
        dest="output_path",
        default=None,
        help="Path to the output file (default: stdout)",
    )

    args = parser.parse_args()

    # Load the appraisal policy
    try:
        policy = load_policy_file(args.policy_path)
    except FileNotFoundError:
        print(f"Error: policy file not found: {args.policy_path}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"Error: invalid policy: {e}", file=sys.stderr)
        return 2

    # Read IMA log entries
    try:
        with open(args.input_path, encoding="utf-8") as f:
            lines = f.read()
    except FileNotFoundError:
        print(f"Error: IMA log file not found: {args.input_path}", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"Error reading IMA log file: {e}", file=sys.stderr)
        return 2

    entries = parse_ima_log_string(lines)
    results = appraise_ima_log(entries, policy)

    write_output(format_results(filter_results(results, args.show)), args.output_path)

    deny_count = sum(1 for _, v in results if v is AppraisalResult.DENY)
    allow_count = sum(1 for _, v in results if v is AppraisalResult.ALLOW)
    neutral_count = len(results) - deny_count - allow_count
    print(
        f"Appraised {len(results)} entries: {allow_count} allow, {deny_count} deny, {neutral_count} neutral",
        file=sys.stderr,
    )

    return 1 if deny_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
