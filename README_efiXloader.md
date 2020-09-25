# efiXloader

## Description

`efiXloader` is an IDA Pro loader module, responsible for processing UEFI drivers within single IDA Pro instance.

![loader_1.gif](pics/loader_1.gif)

## Features

### UEFI drivers entry points identification

During UEFI drivers analysis `efiXloader` identifies each driver's entry.

![loader_2.gif](pics/loader_6.gif)

### Navigation between different UEFI drivers

Each UEFI driver is accessible within single IDA Pro instance for reverse-engineering.

![loader_3.gif](pics/loader_3.gif)

### UEFI drivers extraction

All processed UEFI drivers are dropped into prepared folder.

![loader_4.gif](pics/loader_4.gif)

### efiXplorer + efiXloader in action

All `efiXplorer` analysis capabilities can be applied to the whole UEFI firmware image.

![loader_5.gif](pics/loader_5.gif)

## Compilation

The common steps are next.

```bash
git clone git@github.com:binarly-io/efiXplorer.git
cd efiXplorer
git submodule update --init --recursive
cd efiXplorer/efiXloader/3rd/uefitool
git checkout new_engine
cd -
mkdir build
cd build
cmake .. -DIdaSdk_ROOT_DIR="/path/to/idasdk"
cmake --build . --config Release
```

## Limitations

- supports only `x64` UEFI drivers
