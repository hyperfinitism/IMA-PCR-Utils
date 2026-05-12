# Example CLI tools using imapcr10

## Usage

### Common

```shell
python $SCRIPT_PATH [OPTIONS...]
```

or

```shell
$SCRIPT_PATH [OPTIONS...]
```

## pcr10

### Usage

```shell
python pcr10.py [-i $IMA_LOG_PATH] [-a $HASH_ALGORITHM] [-o $OUTPUT_PATH] [-f $OUTPUT_FORMAT]
```

```shell
python pcr10.py [--in $IMA_LOG_PATH] [--hash-algorithm $HASH_ALGORITHM] [--out $OUTPUT_PATH] [--format $OUTPUT_FORMAT]
```

### Options

- `-i, --in`: Path to the IMA log file (default: `/sys/kernel/security/ima/ascii_runtime_measurements`)
- `-a, --hash-algorithm`: Hash algorithm to use for PCR10 calculation: `sha1`,
  `sha256`, `sha384`, `sha512` (default: `sha256`)
- `-o, --out`: Path to the output file (default: stdout)
- `-f, --format`: Output format: `HEX`, `hex`, `binary` (default: `HEX`)

When using the default input, please run with root privileges in an environment
where vTPM is available.

### Example

```shell
# Replay PCR10 from the IMA logs of the current system
python pcr10.py

# Replay PCR10 from the sample IMA log file
python pcr10.py -i ascii_runtime_measurements
```

## truncate_log

### Usage

```shell
python truncate_log.py [-i $IMA_LOG_PATH] -p $PCR_HEX [-a $HASH_ALGORITHM] [-o $OUTPUT_PATH]
```

```shell
python truncate_log.py [--in $IMA_LOG_PATH] --pcr10 $PCR_HEX [--hash-algorithm $HASH_ALGORITHM] [--out $OUTPUT_PATH]
```

### Options

- `-i, --in`: Path to the IMA log file (default: `/sys/kernel/security/ima/ascii_runtime_measurements`)
- `-p, --pcr`: Reference PCR value in hex format (required)
- `-a, --hash-algorithm`: Hash algorithm used for PCR calculation: `sha1`, `sha256`, `sha384`, `sha512` (default: `sha256`)
- `-o, --out`: Path to the output file (default: stdout)

### Description

This tool truncates an IMA log to find the point where the calculated PCR value
matches a reference PCR value. It's useful for identifying which IMA log entries
are relevant to a particular PCR measurement from a TPM.

The function filters entries for PCR index "10" and "ima-ng" template only, then
extends the PCR value incrementally until it finds a match with the reference.
Returns the sublist of entries from the beginning up to and including
the matching entry.

### Example

```shell
# Truncate IMA log using reference PCR10 from pcrlist_2.bin
python truncate_pcr10.py -i ascii_runtime_measurements_2 -p c5bfcd40187bfc190fe9c584b8b2675f08180c0e9579255fa9eba91e7d18f678

# Save truncated log to file
python truncate_pcr10.py -i ascii_runtime_measurements_2 \
  -p c5bfcd40187bfc190fe9c584b8b2675f08180c0e9579255fa9eba91e7d18f678 \
  -o truncated_measurements.txt
```

## boot-aggregate

### Usage

```shell
python boot_aggregate.py -i $PCR_LIST_PATH -s $SELECTOR [-a $HASH_ALGORITHM] [-o $OUTPUT_PATH] [-f $OUTPUT_FORMAT]
```

```shell
python boot_aggregate.py --in $PCR_LIST_PATH --selector $SELECTOR [--hash-algorithm $HASH_ALGORITHM] [--out $OUTPUT_PATH] [--format $OUTPUT_FORMAT]
```

### Required Arguments

- `-i, --in`: Path to the PCR list file (raw blob). The file must be the
  concatenation of PCR digests for the indices specified by `--selector`, in
  the same order (each digest size is determined by the selector's hash
  algorithm)
- `-s, --selector`: PCR selector string: `<hash_algorithm>:all` or
  `<hash_algorithm>:0,1,2,...` (must include 0 to 9)

### Options

- `-a, --hash-algorithm`: Hash algorithm to use to calculate boot_aggregate:
  `sha1`, `sha256`, `sha384`, `sha512` (default: `sha256`)
- `-o, --out`: Path to the output file (default: stdout)
- `-f, --format`: Output format: `HEX`, `hex`, `binary` (default: `hex`)

### Example

```shell
# Calculate boot_aggregate from the sample PCR list file
python boot_aggregate.py --in pcr_list.bin -s sha256:0,1,2,3,4,5,6,7,8,9,10,12,14,23
```
