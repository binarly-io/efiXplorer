/*
 *        __ ___   __      _
 *       / _(_) \ / /     | |
 *   ___| |_ _ \ V / _ __ | | ___  _ __ ___ _ __
 *  / _ \  _| | > < | '_ \| |/ _ \| '__/ _ \ '__|
 * |  __/ | | |/ . \| |_) | | (_) | | |  __/ |
 *  \___|_| |_/_/ \_\ .__/|_|\___/|_|  \___|_|
 *                  | |
 *                  |_|
 *
 * efiXplorer
 * Copyright (C) 2020  Binarly
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * efi_services.h
 *
 */

/* boot services offsets (X64) */
#define x64RaiseTPLOffset 0x18
#define x64RestoreTPLOffset 0x20
#define x64AllocatePagesOffset 0x28
#define x64FreePagesOffset 0x30
#define x64GetMemoryMapOffset 0x38
#define x64AllocatePoolOffset 0x40
#define x64FreePoolOffset 0x48
#define x64CreateEventOffset 0x50
#define x64SetTimerOffset 0x58
#define x64WaitForEventOffset 0x60
#define x64SignalEventOffset 0x68
#define x64CloseEventOffset 0x70
#define x64CheckEventOffset 0x78
#define x64InstallProtocolInterfaceOffset 0x80
#define x64RenstallProtocolInterfaceOffset 0x88
#define x64UninstallProtocolInterfaceOffset 0x90
#define x64HandleProtocolOffset 0x98
#define x64RegisterProtocolNotifyOffset 0xa8
#define x64LocateHandleOffset 0xb0
#define x64LocateDevicePathOffset 0xb8
#define x64InstallConfigurationTableOffset 0xc0
#define x64LoadImageOffset 0xc8
#define x64StartImageOffset 0xd0
#define x64ExitOffset 0xd8
#define x64UnloadImageOffset 0xe0
#define x64ExitBootServicesOffset 0xe8
#define x64GetNextMonotonicCountOffset 0xf0
#define x64StallOffset 0xf0
#define x64SetWatchdogTimerOffset 0x100
#define x64ConnectControllerOffset 0x108
#define x64DisconnectControllerOffset 0x110
#define x64OpenProtocolOffset 0x118
#define x64CloseProtocolOffset 0x120
#define x64OpenProtocolInformationOffset 0x128
#define x64ProtocolsPerHandleOffset 0x130
#define x64LocateHandleBufferOffset 0x138
#define x64LocateProtocolOffset 0x140
#define x64InstallMultipleProtocolInterfacesOffset 0x148
#define x64UninstallMultipleProtocolInterfacesOffset 0x150
#define x64CalculateCrc32Offset 0x158
#define x64CopyMemOffset 0x160
#define x64SetMemOffset 0x168
#define x64CreateEventExOffset 0x170
/* boot services offsets (X86) */
#define x86RaiseTPLOffset 0x18
#define x86RestoreTPLOffset 0x1c
#define x86AllocatePagesOffset 0x20
#define x86FreePagesOffset 0x24
#define x86GetMemoryMapOffset 0x28
#define x86AllocatePoolOffset 0x2c
#define x86FreePoolOffset 0x30
#define x86CreateEventOffset 0x34
#define x86SetTimerOffset 0x38
#define x86WaitForEventOffset 0x3c
#define x86SignalEventOffset 0x40
#define x86CloseEventOffset 0x44
#define x86CheckEventOffset 0x48
#define x86InstallProtocolInterfaceOffset 0x4c
#define x86RenstallProtocolInterfaceOffset 0x50
#define x86UninstallProtocolInterfaceOffset 0x54
#define x86HandleProtocolOffset 0x58
#define x86RegisterProtocolNotifyOffset 0x60
#define x86LocateHandleOffset 0x64
#define x86LocateDevicePathOffset 0x68
#define x86InstallConfigurationTableOffset 0x6c
#define x86LoadImageOffset 0x70
#define x86StartImageOffset 0x74
#define x86ExitOffset 0x78
#define x86UnloadImageOffset 0x7c
#define x86ExitBootServicesOffset 0x80
#define x86GetNextMonotonicCountOffset 0x84
#define x86StallOffset 0x88
#define x86SetWatchdogTimerOffset 0x8c
#define x86ConnectControllerOffset 0x90
#define x86DisconnectControllerOffset 0x94
#define x86OpenProtocolOffset 0x98
#define x86CloseProtocolOffset 0x9c
#define x86OpenProtocolInformationOffset 0xa0
#define x86ProtocolsPerHandleOffset 0xa4
#define x86LocateHandleBufferOffset 0xa8
#define x86LocateProtocolOffset 0xac
#define x86InstallMultipleProtocolInterfacesOffset 0xb0
#define x86UninstallMultipleProtocolInterfacesOffset 0xb4
#define x86CalculateCrc32Offset 0xb8
#define x86CopyMemOffset 0xbc
#define x86SetMemOffset 0xc0
#define x86CreateEventExOffset 0xc4

/* runtime services offsets (X64) */
#define x64GetTimeOffset 0x18
#define x64SetTimeOffset 0x20
#define x64GetWakeupTimeOffset 0x28
#define x64SetWakeupTimeOffset 0x30
#define x64SetVirtualAddressMapOffset 0x38
#define x64ConvertPointerOffset 0x40
#define x64GetVariableOffset 0x48
#define x64GetNextVariableNameOffset 0x50
#define x64SetVariableOffset 0x58
#define x64GetNextHighMonotonicCountOffset 0x60
#define x64ResetSystemOffset 0x68
#define x64UpdateCapsuleOffset 0x70
#define x64QueryCapsuleCapabilitiesOffset 0x78
#define x64QueryVariableInfoOffset 0x80
/* runtime services offsets (X86) */
#define x86GetTimeOffset 0x18
#define x86SetTimeOffset 0x1c
#define x86GetWakeupTimeOffset 0x20
#define x86SetWakeupTimeOffset 0x24
#define x86SetVirtualAddressMapOffset 0x28
#define x86ConvertPointerOffset 0x2c
#define x86GetVariableOffset 0x30
#define x86GetNextVariableNameOffset 0x34
#define x86SetVariableOffset 0x38
#define x86GetNextHighMonotonicCountOffset 0x3c
#define x86ResetSystemOffset 0x40
#define x86UpdateCapsuleOffset 0x44
#define x86QueryCapsuleCapabilitiesOffset 0x48
#define x86QueryVariableInfoOffset 0x4c

/* smm services offsets (X64) */
#define x64SmmInstallConfigurationTableOffset 0x28
#define x64SmmAllocatePoolOffset 0x50
#define x64SmmFreePoolOffset 0x58
#define x64SmmAllocatePagesOffset 0x60
#define x64SmmFreePagesOffset 0x68
#define x64SmmStartupThisApOffset 0x70
#define x64SmmInstallProtocolInterfaceOffset 0xa8
#define x64SmmUninstallProtocolInterfaceOffset 0xb0
#define x64SmmHandleProtocolOffset 0xb8
#define x64SmmRegisterProtocolNotifyOffset 0xc0
#define x64SmmLocateHandleOffset 0xc8
#define x64SmmLocateProtocolOffset 0xd0
#define x64SmiManageOffset 0xd8
#define x64SmiHandlerRegisterOffset 0xe0
#define x64SmiHandlerUnRegisterOffset 0xe8
/* smm services offsets (X86) */
#define x86SmmInstallConfigurationTableOffset 0x20
#define x86SmmAllocatePoolOffset 0x34
#define x86SmmFreePoolOffset 0x38
#define x86SmmAllocatePagesOffset 0x3c
#define x86SmmFreePagesOffset 0x40
#define x86SmmStartupThisApOffset 0x44
#define x86SmmInstallProtocolInterfaceOffset 0x60
#define x86SmmUninstallProtocolInterfaceOffset 0x64
#define x86SmmHandleProtocolOffset 0x68
#define x86SmmRegisterProtocolNotifyOffset 0x6c
#define x86SmmLocateHandleOffset 0x70
#define x86SmmLocateProtocolOffset 0x74
#define x86SmiManageOffset 0x78
#define x86SmiHandlerRegisterOffset 0x7c
#define x86SmiHandlerUnRegisterOffset 0x80

struct pServiceReg {
    char service_name[64];
    size_t offset;
    size_t reg;
};

struct pServicePush {
    char service_name[64];
    size_t offset;
    uint16_t push_number;
};

struct service {
    char service_name[64];
    size_t offset64;
    size_t offset86;
};

struct pServiceReg bootServicesTableX64[] = {
    {"InstallProtocolInterface", x64InstallProtocolInterfaceOffset, REG_RDX},
    {"ReinstallProtocolInterface", x64RenstallProtocolInterfaceOffset, REG_RDX},
    {"UninstallProtocolInterface", x64UninstallProtocolInterfaceOffset,
     REG_RDX},
    {"HandleProtocol", x64HandleProtocolOffset, REG_RDX},
    {"RegisterProtocolNotify", x64RegisterProtocolNotifyOffset, REG_RCX},
    {"OpenProtocol", x64OpenProtocolOffset, REG_RDX},
    {"CloseProtocol", x64CloseProtocolOffset, REG_RDX},
    {"OpenProtocolInformation", x64OpenProtocolInformationOffset, REG_RDX},
    {"LocateHandleBuffer", x64LocateHandleBufferOffset, REG_RDX},
    {"LocateProtocol", x64LocateProtocolOffset, REG_RCX},
    {"InstallMultipleProtocolInterfaces",
     x64InstallMultipleProtocolInterfacesOffset, REG_RDX},
    {"UninstallMultipleProtocolInterfaces",
     x64UninstallMultipleProtocolInterfacesOffset, REG_RDX}};
size_t bootServicesTableX64Length =
    sizeof(bootServicesTableX64) / sizeof(pServiceReg);

struct pServicePush bootServicesTableX86[] = {
    {"InstallProtocolInterface", x86InstallProtocolInterfaceOffset, 2},
    {"ReinstallProtocolInterface", x86RenstallProtocolInterfaceOffset, 2},
    {"UninstallProtocolInterface", x86UninstallProtocolInterfaceOffset, 2},
    {"HandleProtocol", x86HandleProtocolOffset, 2},
    {"RegisterProtocolNotify", x86RegisterProtocolNotifyOffset, 1},
    {"OpenProtocol", x86OpenProtocolOffset, 2},
    {"CloseProtocol", x86CloseProtocolOffset, 2},
    {"OpenProtocolInformation", x86OpenProtocolInformationOffset, 2},
    {"LocateHandleBuffer", x86LocateHandleBufferOffset, 2},
    {"LocateProtocol", x86LocateProtocolOffset, 1},
    {"InstallMultipleProtocolInterfaces",
     x86InstallMultipleProtocolInterfacesOffset, 2},
    {"UninstallMultipleProtocolInterfaces",
     x86UninstallMultipleProtocolInterfacesOffset, 2}};
size_t bootServicesTableX86Length =
    sizeof(bootServicesTableX86) / sizeof(pServicePush);

struct service bootServicesTableAll[] = {
    {"RaiseTPL", x64RaiseTPLOffset, x86RaiseTPLOffset},
    {"RestoreTPL", x64RestoreTPLOffset, x86RestoreTPLOffset},
    {"AllocatePages", x64AllocatePagesOffset, x86AllocatePagesOffset},
    {"FreePages", x64FreePagesOffset, x86FreePagesOffset},
    {"GetMemoryMap", x64GetMemoryMapOffset, x86GetMemoryMapOffset},
    {"AllocatePool", x64AllocatePoolOffset, x86AllocatePoolOffset},
    {"FreePool", x64FreePoolOffset, x86FreePoolOffset},
    {"CreateEvent", x64CreateEventOffset, x86CreateEventOffset},
    {"SetTimer", x64SetTimerOffset, x86SetTimerOffset},
    {"WaitForEvent", x64WaitForEventOffset, x86WaitForEventOffset},
    {"SignalEvent", x64SignalEventOffset, x86SignalEventOffset},
    {"CloseEvent", x64CloseEventOffset, x86CloseEventOffset},
    {"CheckEvent", x64CheckEventOffset, x86CheckEventOffset},
    {"InstallProtocolInterface", x64InstallProtocolInterfaceOffset,
     x86InstallProtocolInterfaceOffset},
    {"ReinstallProtocolInterface", x64RenstallProtocolInterfaceOffset,
     x86RenstallProtocolInterfaceOffset},
    {"UninstallProtocolInterface", x64UninstallProtocolInterfaceOffset,
     x86UninstallProtocolInterfaceOffset},
    {"HandleProtocol", x64HandleProtocolOffset, x86HandleProtocolOffset},
    {"RegisterProtocolNotify", x64RegisterProtocolNotifyOffset,
     x86RegisterProtocolNotifyOffset},
    {"LocateHandle", x64LocateHandleOffset, x86LocateHandleOffset},
    {"LocateDevicePath", x64LocateDevicePathOffset, x86LocateDevicePathOffset},
    {"InstallConfigurationTable", x64InstallConfigurationTableOffset,
     x86InstallConfigurationTableOffset},
    {"LoadImage", x64LoadImageOffset, x86LoadImageOffset},
    {"StartImage", x64StartImageOffset, x86StartImageOffset},
    {"Exit", x64ExitOffset, x86ExitOffset},
    {"UnloadImage", x64UnloadImageOffset, x86UnloadImageOffset},
    {"ExitBootServices", x64ExitBootServicesOffset, x86ExitBootServicesOffset},
    {"GetNextMonotonicCount", x64GetNextMonotonicCountOffset,
     x86GetNextMonotonicCountOffset},
    {"Stall", x64StallOffset, x86StallOffset},
    {"SetWatchdogTimer", x64SetWatchdogTimerOffset, x86SetWatchdogTimerOffset},
    {"ConnectController", x64ConnectControllerOffset,
     x86ConnectControllerOffset},
    {"DisconnectController", x64DisconnectControllerOffset,
     x86DisconnectControllerOffset},
    {"OpenProtocol", x64OpenProtocolOffset, x86OpenProtocolOffset},
    {"CloseProtocol", x64CloseProtocolOffset, x86CloseProtocolOffset},
    {"OpenProtocolInformation", x64OpenProtocolInformationOffset,
     x86OpenProtocolInformationOffset},
    {"ProtocolsPerHandle", x64ProtocolsPerHandleOffset,
     x86ProtocolsPerHandleOffset},
    {"LocateHandleBuffer", x64LocateHandleBufferOffset,
     x86LocateHandleBufferOffset},
    {"LocateProtocol", x64LocateProtocolOffset, x86LocateProtocolOffset},
    {"InstallMultipleProtocolInterfaces",
     x64InstallMultipleProtocolInterfacesOffset,
     x86InstallMultipleProtocolInterfacesOffset},
    {"UninstallMultipleProtocolInterfaces",
     x64UninstallMultipleProtocolInterfacesOffset,
     x86UninstallMultipleProtocolInterfacesOffset},
    {"CalculateCrc32", x64CalculateCrc32Offset, x86CalculateCrc32Offset},
    {"CopyMem", x64CopyMemOffset, x86CopyMemOffset},
    {"SetMem", x64SetMemOffset, x86SetMemOffset},
    {"CreateEventEx", x64CreateEventExOffset, x86CreateEventExOffset}};
size_t bootServicesTableAllLength =
    sizeof(bootServicesTableAll) / sizeof(service);

struct service runtimeServicesTableAll[] = {
    {"GetTime", x64GetTimeOffset, x86GetTimeOffset},
    {"SetTime", x64SetTimeOffset, x86SetTimeOffset},
    {"GetWakeupTime", x64GetWakeupTimeOffset, x86GetWakeupTimeOffset},
    {"SetWakeupTime", x64SetWakeupTimeOffset, x86SetWakeupTimeOffset},
    {"SetVirtualAddressMap", x64SetVirtualAddressMapOffset,
     x86SetVirtualAddressMapOffset},
    {"ConvertPointer", x64ConvertPointerOffset, x86ConvertPointerOffset},
    {"GetVariable", x64GetVariableOffset, x86GetVariableOffset},
    {"GetNextVariableName", x64GetNextVariableNameOffset,
     x86GetNextVariableNameOffset},
    {"SetVariable", x64SetVariableOffset, x86SetVariableOffset},
    {"GetNextHighMonotonicCount", x64GetNextHighMonotonicCountOffset,
     x86GetNextHighMonotonicCountOffset},
    {"ResetSystem", x64ResetSystemOffset, x86ResetSystemOffset},
    {"UpdateCapsule", x64UpdateCapsuleOffset, x86UpdateCapsuleOffset},
    {"QueryCapsuleCapabilities", x64QueryCapsuleCapabilitiesOffset,
     x86QueryCapsuleCapabilitiesOffset},
    {"QueryVariableInfo", x64QueryVariableInfoOffset,
     x86QueryVariableInfoOffset}};
size_t runtimeServicesTableAllLength =
    sizeof(runtimeServicesTableAll) / sizeof(service);

struct pServiceReg smmServicesProtX64[] = {
    {"SmmInstallProtocolInterface", x64SmmInstallProtocolInterfaceOffset,
     REG_RDX},
    {"SmmUninstallProtocolInterface", x64SmmUninstallProtocolInterfaceOffset,
     REG_RDX},
    {"SmmHandleProtocol", x64SmmHandleProtocolOffset, REG_RDX},
    {"SmmRegisterProtocolNotify", x64SmmRegisterProtocolNotifyOffset, REG_RCX},
    {"SmmLocateHandle", x64SmmLocateHandleOffset, REG_RDX},
    {"SmmLocateProtocol", x64SmmLocateProtocolOffset, REG_RCX}};
size_t smmServicesProtX64Length =
    sizeof(smmServicesProtX64) / sizeof(pServiceReg);

struct service smmServicesTableAll[] = {
    {"SmmInstallConfigurationTable", x64SmmInstallConfigurationTableOffset,
     x86SmmInstallConfigurationTableOffset},
    {"SmmAllocatePool", x64SmmAllocatePoolOffset, x86SmmAllocatePoolOffset},
    {"SmmFreePool", x64SmmFreePoolOffset, x86SmmFreePoolOffset},
    {"SmmAllocatePages", x64SmmAllocatePagesOffset, x86SmmAllocatePagesOffset},
    {"SmmFreePages", x64SmmFreePagesOffset, x86SmmFreePagesOffset},
    {"SmmStartupThisAp", x64SmmStartupThisApOffset, x86SmmStartupThisApOffset},
    {"SmmInstallProtocolInterface", x64SmmInstallProtocolInterfaceOffset,
     x86SmmInstallProtocolInterfaceOffset},
    {"SmmUninstallProtocolInterface", x64SmmUninstallProtocolInterfaceOffset,
     x86SmmUninstallProtocolInterfaceOffset},
    {"SmmHandleProtocol", x64SmmHandleProtocolOffset,
     x86SmmHandleProtocolOffset},
    {"SmmRegisterProtocolNotify", x64SmmRegisterProtocolNotifyOffset,
     x86SmmRegisterProtocolNotifyOffset},
    {"SmmLocateHandle", x64SmmLocateHandleOffset, x86SmmLocateHandleOffset},
    {"SmmLocateProtocol", x64SmmLocateProtocolOffset,
     x86SmmLocateProtocolOffset},
    {"SmiManage", x64SmiManageOffset, x86SmiManageOffset},
    {"SmiHandlerRegister", x64SmiHandlerRegisterOffset,
     x86SmiHandlerRegisterOffset},
    {"SmiHandlerUnRegister", x64SmiHandlerUnRegisterOffset,
     x86SmiHandlerUnRegisterOffset}};
size_t smmServicesTableAllLength =
    sizeof(smmServicesTableAll) / sizeof(service);
