# FLIRT signatures generator

## Installation

* install [flair75](https://www.hex-rays.com/products/ida/support/ida/flair75.zip) toolkit
* add `flair75` binaries to `$PATH`
* copy `ida2pat.py` file to `<IDA_DIR>/idc` directory
* add `<IDA_DIR>` to `$PATH`
* install `dos2unix` if you work under Linux

## Usage

1. generate .pat files from modules with debug information

```
.\get_sig.py analyze MODULES_DIR
```

2. generate efixplorer.sig file from .pat files

```
.\get_sig.py get-sig MODULES_DIR
```

3. move `efixplorer.sig` file to `<IDA_DIR>/sig/pc` directory
