# Batch analyzer

## Usage

```
./fw_analyzer.py --help
```

```
Usage: fw_analyzer.py [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  analyze-fw     Analyze UEFI firmware with IDA in batch mode.
  analyze-image  Analyze UEFI module with IDA in batch mode.
```

### Analyze UEFI firmware with IDA in batch mode

```
./fw_analyzer.py analyze-fw --help
```

```
Usage: fw_analyzer.py analyze-fw [OPTIONS] FIRMWARE_PATH

  Analyze UEFI firmware with IDA in batch mode.

Options:
  -w, --workers INTEGER  Number of workers (8 by default).
  --idat TEXT            Path to idat executable.
  --idat64 TEXT          Path to idat64 executable.
  --help                 Show this message and exit
```

### Analyze UEFI module with IDA in batch mode

```
./fw_analyzer.py analyze-image --help
```

```
Usage: fw_analyzer.py analyze-image [OPTIONS] IMAGE_PATH

  Analyze UEFI module with IDA in batch mode. The analysis result is saved
  to .json file.

Options:
  --idat64 TEXT  Path to idat64 executable.
  --help         Show this message and exit.
```

## Example (tested on Linux)

```
./fw_analyzer.py analyze-fw -w 4 --idat ~/idapro-7.4/idat --idat64 ~/idapro-7.4/idat64 /tmp/fw.bin
```
