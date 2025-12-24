# Example CLI tools using imapcr10

## Usage

### Common

```shell
python $SCRIPT_PATH [OPTIONS...]
```

or

```shell
# grant permission to execute
# chmod +x $SCRIPT_PATH
$SCRIPT_PATH [OPTIONS...]
```

## pcr10

```shell
python pcr10.py [-i $IMA_LOG_PATH] [-a $HASH_ALGORITHM] [-o $OUTPUT_PATH] [-f $OUTPUT_FORMAT]
```

```shell
python pcr10.py [--in $IMA_LOG_PATH] [--hash-algorithm $HASH_ALGORITHM] [--out $OUTPUT_PATH] [--format $OUTPUT_FORMAT]
```

- `-i, --input`: Path to the IMA log file (default: `/sys/kernel/security/ima/ascii_runtime_measurements`)
- `-h, --hash-algorithm`: Hash algorithm to use for PCR10 calculation: `sha1`, `sha256`, `sha384`, `sha512` (default: `sha256`)
- `-o, --out`: Path to the output file (default: stdout)
- `-f, --format`: Output format: `HEX`, `hex`, `binary` (default: `HEX`)

When using the default input, please run with root privileges in an environment where vTPM is available.
