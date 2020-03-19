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

[efiXplorer] plugin run
[efiXplorer] found ImageHandle at 0x2a4, address = 0x62820
[efiXplorer] BootServices table finding from 0x2a0 to 0x4030e
[efiXplorer] RuntimeServices table finding from 0x2a0 to 0x4030e
[efiXplorer] BootServices finding from 0x2a0 to 0x4030e
[efiXplorer] 0x671 : InstallMultipleProtocolInterfaces
[efiXplorer] 0x1709 : HandleProtocol
[efiXplorer] 0x3a50 : OpenProtocol
[efiXplorer] 0xcf6e : RegisterProtocolNotify
[efiXplorer] 0xf36a : HandleProtocol
[efiXplorer] 0xf443 : HandleProtocol
[efiXplorer] 0xf637 : HandleProtocol
[efiXplorer] 0xf6db : HandleProtocol
[efiXplorer] 0x10114 : LocateHandleBuffer
[efiXplorer] 0x1014f : HandleProtocol
[efiXplorer] 0x1056e : LocateProtocol
[efiXplorer] 0x3978c : ReinstallProtocolInterface
Boot services:
+-----------+-------------------------------------+
|  Address  |  Service                            |
+-----------+-------------------------------------+
|  0x671    |  InstallMultipleProtocolInterfaces  |
|  0x1709   |  HandleProtocol                     |
|  0x3a50   |  OpenProtocol                       |
|  0xcf6e   |  RegisterProtocolNotify             |
|  0xf36a   |  HandleProtocol                     |
|  0xf443   |  HandleProtocol                     |
|  0xf637   |  HandleProtocol                     |
|  0xf6db   |  HandleProtocol                     |
|  0x10114  |  LocateHandleBuffer                 |
|  0x1014f  |  HandleProtocol                     |
|  0x1056e  |  LocateProtocol                     |
|  0x3978c  |  ReinstallProtocolInterface         |
+-----------+-------------------------------------+
[efiXplorer] protocols finding
[efiXplorer] looking for protocols in the 0x3978c area
[efiXplorer] looking for protocols in the 0x1709 area
[efiXplorer] found protocol GUID parameter at 0x16ff
[efiXplorer] looking for protocols in the 0xf36a area
[efiXplorer] found protocol GUID parameter at 0xf363
[efiXplorer] looking for protocols in the 0xf443 area
[efiXplorer] found protocol GUID parameter at 0xf43c
[efiXplorer] looking for protocols in the 0xf637 area
[efiXplorer] found protocol GUID parameter at 0xf630
[efiXplorer] looking for protocols in the 0xf6db area
[efiXplorer] found protocol GUID parameter at 0xf6d4
[efiXplorer] looking for protocols in the 0x1014f area
[efiXplorer] found protocol GUID parameter at 0x10148
[efiXplorer] looking for protocols in the 0xcf6e area
[efiXplorer] looking for protocols in the 0x3a50 area
[efiXplorer] found protocol GUID parameter at 0x3a46
[efiXplorer] looking for protocols in the 0x10114 area
[efiXplorer] looking for protocols in the 0x1056e area
[efiXplorer] found protocol GUID parameter at 0x1055e
[efiXplorer] looking for protocols in the 0x671 area
[efiXplorer] found protocol GUID parameter at 0x663
[efiXplorer] protocols names finding
Protocols:
+----------------------------------------+----------------------------------------+-----------+-------------------------------------+
|  GUID                                  |  Protocol name                         |  Address  |  Service                            |
+----------------------------------------+----------------------------------------+-----------+-------------------------------------+
|  09576E91-6D3F-11D2-8E39-00A0C969723B  |  EFI_DEVICE_PATH_PROTOCOL_GUID         |  0x40448  |  HandleProtocol                     |
|  220E73B6-6BDB-4413-8405-B974B108619A  |  EFI_FIRMWARE_VOLUME2_PROTOCOL_GUID    |  0x404c8  |  HandleProtocol                     |
|  964E5B22-6459-11D2-8E39-00A0C969723B  |  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID  |  0x40498  |  HandleProtocol                     |
|  4006C0C1-FCB3-403E-996D-4A6C8724E06D  |  EFI_LOAD_FILE2_PROTOCOL_GUID          |  0x40428  |  HandleProtocol                     |
|  56EC3091-954C-11D2-8E3F-00A0C969723B  |  EFI_LOAD_FILE_PROTOCOL_GUID           |  0x406d8  |  HandleProtocol                     |
|  5B1B31A1-9562-11D2-8E3F-00A0C969723B  |  EFI_LOADED_IMAGE_PROTOCOL_GUID        |  0x40548  |  OpenProtocol                       |
|  78E4D245-CD4D-4A05-A2BA-4743E86CFCAB  |  EFI_SECURITY_POLICY_PROTOCOL_GUID     |  0x40578  |  LocateProtocol                     |
|  76B6BDFA-2ACD-4462-9E3F-CB58C969D937  |  PERFORMANCE_PROTOCOL_GUID             |  0x40528  |  InstallMultipleProtocolInterfaces  |
+----------------------------------------+----------------------------------------+-----------+-------------------------------------+
[efiXplorer] protocols marking
[efiXplorer] address: 0x40448, comment: EFI_GUID *EFI_DEVICE_PATH_PROTOCOL_GUID
[efiXplorer] address: 0x404c8, comment: EFI_GUID *EFI_FIRMWARE_VOLUME2_PROTOCOL_GUID
[efiXplorer] address: 0x40498, comment: EFI_GUID *EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID
[efiXplorer] address: 0x40428, comment: EFI_GUID *EFI_LOAD_FILE2_PROTOCOL_GUID
[efiXplorer] address: 0x406d8, comment: EFI_GUID *EFI_LOAD_FILE_PROTOCOL_GUID
[efiXplorer] address: 0x40548, comment: EFI_GUID *EFI_LOADED_IMAGE_PROTOCOL_GUID
[efiXplorer] address: 0x40578, comment: EFI_GUID *EFI_SECURITY_POLICY_PROTOCOL_GUID
[efiXplorer] address: 0x40528, comment: EFI_GUID *PERFORMANCE_PROTOCOL_GUID
[efiXplorer] .data GUIDs marking
[efiXplorer] address: 0x40368, comment: EFI_GUID *gEfiEventVirtualAddressChangeGuid
[efiXplorer] address: 0x40398, comment: EFI_GUID *EFI_FIRMWARE_FILE_SYSTEM3_GUID
[efiXplorer] address: 0x403f8, comment: EFI_GUID *gEfiHobMemoryAllocModuleGuid
[efiXplorer] address: 0x40438, comment: EFI_GUID *EFI_CRC32_GUIDED_SECTION_EXTRACTION_GUID
[efiXplorer] address: 0x40468, comment: EFI_GUID *EFI_RUNTIME_ARCH_PROTOCOL_GUID
[efiXplorer] address: 0x40488, comment: EFI_GUID *gEfiEventExitBootServicesGuid
[efiXplorer] address: 0x40518, comment: EFI_GUID *DXE_CORE_FILE_NAME_GUID
[efiXplorer] address: 0x40568, comment: EFI_GUID *LZMA_CUSTOM_DECOMPRESS_GUID
[efiXplorer] address: 0x40658, comment: EFI_GUID *EFI_STATUS_CODE_SPECIFIC_DATA_GUID
[efiXplorer] address: 0x406c8, comment: EFI_GUID *EFI_FIRMWARE_FILE_SYSTEM2_GUID
[efiXplorer] address: 0x406e8, comment: EFI_GUID *EFI_TIMER_ARCH_PROTOCOL_GUID
[efiXplorer] address: 0x418f8, comment: EFI_GUID *EFI_FIRMWARE_CONTENTS_SIGNED_GUID
[efiXplorer] analyzer destruction
```
