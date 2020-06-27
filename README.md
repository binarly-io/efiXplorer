# efiXplorer

### Build script

```
Usage: build.py [OPTIONS] IDASDK_DIR

Options:
  -c, --copy TEXT  path to IDA plugins directory
  --help           Show this message and exit.
```

### Build example

```bash
./build.py <IDASDK_DIR>
```

### Build and copy example

```bash
./build.py -c ~/idapro-7.4/plugins ~/sdk/idasdk74
```
