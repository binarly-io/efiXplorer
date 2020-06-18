# FLIRT signatures generator

## Installation

* install [flair75](https://www.hex-rays.com/products/ida/support/ida/flair75.zip) toolkit
* add `flair75` binaries to `$PATH`
* copy `ida2pat.py` file to `<IDA_DIR>/idc` directory
* add `<IDA_DIR>` to `$PATH`
* install `dos2unix` if you work under Linux

## Usage

1. build modules with debug information using [edk2](https://github.com/tianocore/edk2)

2. generate .pat files from modules with debug information

    ```bash
    python get_sig.py analyze MODULES_DIR
    ```

3. generate efixplorer.sig file from .pat files

    ```bash
    python get_sig.py get-sig MODULES_DIR
    # out: efixplorer.sig file
    ```

    ```bash
    # optional
    python get_sig.py clear MODULES_DIR
    ```

4. move `efixplorer.sig` file to `<IDA_DIR>/sig/pc` directory

*Tested on Windows and Linux with python3.7 and IDA 7.5*
