# FLIRT generator

## Installation

* install [flair75](https://www.hex-rays.com/products/ida/support/ida/flair75.zip) toolkit
* add `flair75` binaries to `$PATH`
* copy `ida2pat.py` file to `<IDA_DIR>/idc` directory
* add `<IDA_DIR>` to `$PATH`

## Usage

First step:

```
.\get_sig.py analyze MODULES_DIR
```

Second step:

```
.\get_sig.py get-sig MODULES_DIR
```
