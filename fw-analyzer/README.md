# Batch analyzer

## Installation

* install `efiXplorer` plugin
* copy `efixplorer_start.idc` file to `<IDA_DIR>/idc` directory
* add `<IDA_DIR>` to `$PATH`

## Usage

```
python .\fw_analyzer.py
```

```
Usage: fw_analyzer.py [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  analyze-fw        Analyze UEFI firmware with IDA in batch mode.
  analyze-image     Analyze UEFI module with IDA in batch mode.
  get-images        Extract efi images from UEFI firmware.
  get-swsmi-images  Find modules with swsmi handlers.
```

*Tested on Windows and Linux with python3.7 and IDA 7.5*
