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

### Log example on IDA output window

```
        __ ___   __      _
       / _(_) \ / /     | |
   ___| |_ _ \ V / _ __ | | ___  _ __ ___ _ __
  / _ \  _| | > < | '_ \| |/ _ \| '__/ _ \ '__|
 |  __/ | | |/ . \| |_) | | (_) | | |  __/ |
  \___|_| |_/_/ \_\ .__/|_|\___/|_|  \___|_|
                  | |
                  |_|
(c) 2020, binarly-io - https://github.com/binarly-io/efiXplorer

...

[efiXplorer] ========================================================
[efiXplorer] plugin run
[efiXplorer] input file is portable executable for AMD64 (PE)
[efiXplorer] ========================================================
[efiXplorer] ImageHandle finding
[efiXplorer] ========================================================
[efiXplorer] SystemTable finding
[efiXplorer] ========================================================
[efiXplorer] BootServices table finding from 0x280 to 0x168d
[efiXplorer] found BootServices table at 0x323, address = 0x1848
[efiXplorer] ========================================================
[efiXplorer] RuntimeServices table finding from 0x280 to 0x168d
[efiXplorer] ========================================================
[efiXplorer] BootServices finding from 0x280 to 0x168d
[efiXplorer] 0x32a : LocateProtocol
[efiXplorer] 0x357 : LocateProtocol
[efiXplorer] 0x6d1 : LocateHandleBuffer
[efiXplorer] 0x719 : HandleProtocol
[efiXplorer] Boot services:
+-----------+----------------------+
|  Address  |  Service             |
+-----------+----------------------+
|  0x32a    |  LocateProtocol      |
|  0x357    |  LocateProtocol      |
|  0x6d1    |  LocateHandleBuffer  |
|  0x719    |  HandleProtocol      |
+-----------+----------------------+
[efiXplorer] ========================================================
[efiXplorer] protocols finding
[efiXplorer] looking for protocols in the 0x719 area
[efiXplorer] found protocol GUID parameter at 0x712
[efiXplorer] looking for protocols in the 0x6d1 area
[efiXplorer] found protocol GUID parameter at 0x6c8
[efiXplorer] looking for protocols in the 0x32a area
[efiXplorer] found protocol GUID parameter at 0x31a
[efiXplorer] looking for protocols in the 0x357 area
[efiXplorer] found protocol GUID parameter at 0x34e
[efiXplorer] ========================================================
[efiXplorer] protocols names finding
[efiXplorer] Protocols:
+----------------------------------------+---------------------------------+-----------+----------------------+
|  GUID                                  |  Protocol name                  |  Address  |  Service             |
+----------------------------------------+---------------------------------+-----------+----------------------+
|  2B2F68D6-0CD2-44CF-8E8B-BBA20B1B5B75  |  EFI_USB_IO_PROTOCOL_GUID       |  0x1720   |  HandleProtocol      |
|  2B2F68D6-0CD2-44CF-8E8B-BBA20B1B5B75  |  EFI_USB_IO_PROTOCOL_GUID       |  0x1720   |  LocateHandleBuffer  |
|  F4CCBFB7-F6E0-47FD-9DD4-10A8F150C191  |  EFI_SMM_BASE2_PROTOCOL_GUID    |  0x16e0   |  LocateProtocol      |
|  C2702B74-800C-4131-8746-8FB5B89CE4AC  |  EFI_SMM_ACCESS2_PROTOCOL_GUID  |  0x1740   |  LocateProtocol      |
+----------------------------------------+---------------------------------+-----------+----------------------+
[efiXplorer] ========================================================
[efiXplorer] protocols marking
[efiXplorer] address: 0x1720, comment: EFI_GUID *EFI_USB_IO_PROTOCOL_GUID
[efiXplorer] address: 0x16e0, comment: EFI_GUID *EFI_SMM_BASE2_PROTOCOL_GUID
[efiXplorer] address: 0x1740, comment: EFI_GUID *EFI_SMM_ACCESS2_PROTOCOL_GUID
[efiXplorer] ========================================================
[efiXplorer] .data and GUIDs marking
[efiXplorer] address: 0x16e0, comment: EFI_GUID *EFI_SMM_BASE2_PROTOCOL_GUID
[efiXplorer] address: 0x16f0, comment: EFI_GUID *EFI_SMM_SW_DISPATCH2_PROTOCOL_GUID
[efiXplorer] address: 0x1710, comment: EFI_GUID *EFI_SMM_CPU_PROTOCOL_GUID
[efiXplorer] address: 0x1720, comment: EFI_GUID *EFI_USB_IO_PROTOCOL_GUID
[efiXplorer] address: 0x1740, comment: EFI_GUID *EFI_SMM_ACCESS2_PROTOCOL_GUID
[efiXplorer] address: 0x1750, comment: EFI_GUID *gPhoenixEfiSmmSwSmiProtocolGuid
[efiXplorer] ========================================================
[efiXplorer] SMM callouts finding (gBS = 0x1848)
[efiXplorer] SW SMI handler finding (using EFI_SMM_CPU_PROTOCOL_GUID)
[efiXplorer] EFI_SMM_CPU_PROTOCOL_GUID address: 0x1710
[efiXplorer] EFI_SMM_CPU_PROTOCOL_GUID xref address: 0xc25
[efiXplorer] gEfiSmmCpuProtocol interface address: 0x1988
[efiXplorer] address from SmiHandler function: 0x82f
[efiXplorer] SmiHandler function address: 0x808
[efiXplorer] current function address: 0x808
[efiXplorer] current function address: 0x107c
[efiXplorer] current function address: 0xf34
[efiXplorer] current function address: 0xdf0
[efiXplorer] current function address: 0x3e4
[efiXplorer] current function address: 0x1670
[efiXplorer] SMM callout finded: 0x6b9
[efiXplorer] ========================================================
[efiXplorer] log file: /tmp/smm-test/SmmOEMInt15.json
[efiXplorer] ========================================================
[efiXplorer] analyzer destruction
```
