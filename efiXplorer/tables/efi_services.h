/*
 * efiXplorer
 * Copyright (C) 2020-2022  Binarly
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

// Boot services offsets (64-bit)
#define RaiseTPLOffset64 0x18
#define RestoreTPLOffset64 0x20
#define AllocatePagesOffset64 0x28
#define FreePagesOffset64 0x30
#define GetMemoryMapOffset64 0x38
#define AllocatePoolOffset64 0x40
#define FreePoolOffset64 0x48
#define CreateEventOffset64 0x50
#define SetTimerOffset64 0x58
#define WaitForEventOffset64 0x60
#define SignalEventOffset64 0x68
#define CloseEventOffset64 0x70
#define CheckEventOffset64 0x78
#define InstallProtocolInterfaceOffset64 0x80
#define RenstallProtocolInterfaceOffset64 0x88
#define UninstallProtocolInterfaceOffset64 0x90
#define HandleProtocolOffset64 0x98
#define RegisterProtocolNotifyOffset64 0xa8
#define LocateHandleOffset64 0xb0
#define LocateDevicePathOffset64 0xb8
#define InstallConfigurationTableOffset64 0xc0
#define LoadImageOffset64 0xc8
#define StartImageOffset64 0xd0
#define ExitOffset64 0xd8
#define UnloadImageOffset64 0xe0
#define ExitBootServicesOffset64 0xe8
#define GetNextMonotonicCountOffset64 0xf0
#define StallOffset64 0xf0
#define SetWatchdogTimerOffset64 0x100
#define ConnectControllerOffset64 0x108
#define DisconnectControllerOffset64 0x110
#define OpenProtocolOffset64 0x118
#define CloseProtocolOffset64 0x120
#define OpenProtocolInformationOffset64 0x128
#define ProtocolsPerHandleOffset64 0x130
#define LocateHandleBufferOffset64 0x138
#define LocateProtocolOffset64 0x140
#define InstallMultipleProtocolInterfacesOffset64 0x148
#define UninstallMultipleProtocolInterfacesOffset64 0x150
#define CalculateCrc32Offset64 0x158
#define CopyMemOffset64 0x160
#define SetMemOffset64 0x168
#define CreateEventExOffset64 0x170

// Boot services offsets (32-bit) */
#define RaiseTPLOffset32 0x18
#define RestoreTPLOffset32 0x1c
#define AllocatePagesOffset32 0x20
#define FreePagesOffset32 0x24
#define GetMemoryMapOffset32 0x28
#define AllocatePoolOffset32 0x2c
#define FreePoolOffset32 0x30
#define CreateEventOffset32 0x34
#define SetTimerOffset32 0x38
#define WaitForEventOffset32 0x3c
#define SignalEventOffset32 0x40
#define CloseEventOffset32 0x44
#define CheckEventOffset32 0x48
#define InstallProtocolInterfaceOffset32 0x4c
#define RenstallProtocolInterfaceOffset32 0x50
#define UninstallProtocolInterfaceOffset32 0x54
#define HandleProtocolOffset32 0x58
#define RegisterProtocolNotifyOffset32 0x60
#define LocateHandleOffset32 0x64
#define LocateDevicePathOffset32 0x68
#define InstallConfigurationTableOffset32 0x6c
#define LoadImageOffset32 0x70
#define StartImageOffset32 0x74
#define ExitOffset32 0x78
#define UnloadImageOffset32 0x7c
#define ExitBootServicesOffset32 0x80
#define GetNextMonotonicCountOffset32 0x84
#define StallOffset32 0x88
#define SetWatchdogTimerOffset32 0x8c
#define ConnectControllerOffset32 0x90
#define DisconnectControllerOffset32 0x94
#define OpenProtocolOffset32 0x98
#define CloseProtocolOffset32 0x9c
#define OpenProtocolInformationOffset32 0xa0
#define ProtocolsPerHandleOffset32 0xa4
#define LocateHandleBufferOffset32 0xa8
#define LocateProtocolOffset32 0xac
#define InstallMultipleProtocolInterfacesOffset32 0xb0
#define UninstallMultipleProtocolInterfacesOffset32 0xb4
#define CalculateCrc32Offset32 0xb8
#define CopyMemOffset32 0xbc
#define SetMemOffset32 0xc0
#define CreateEventExOffset32 0xc4

// Runtime services offsets (64-bit)
#define GetTimeOffset64 0x18
#define SetTimeOffset64 0x20
#define GetWakeupTimeOffset64 0x28
#define SetWakeupTimeOffset64 0x30
#define SetVirtualAddressMapOffset64 0x38
#define ConvertPointerOffset64 0x40
#define GetVariableOffset64 0x48
#define GetNextVariableNameOffset64 0x50
#define SetVariableOffset64 0x58
#define GetNextHighMonotonicCountOffset64 0x60
#define ResetSystemOffset64 0x68
#define UpdateCapsuleOffset64 0x70
#define QueryCapsuleCapabilitiesOffset64 0x78
#define QueryVariableInfoOffset64 0x80

// Runtime services offsets (32-bit)
#define GetTimeOffset32 0x18
#define SetTimeOffset32 0x1c
#define GetWakeupTimeOffset32 0x20
#define SetWakeupTimeOffset32 0x24
#define SetVirtualAddressMapOffset32 0x28
#define ConvertPointerOffset32 0x2c
#define GetVariableOffset32 0x30
#define GetNextVariableNameOffset32 0x34
#define SetVariableOffset32 0x38
#define GetNextHighMonotonicCountOffset32 0x3c
#define ResetSystemOffset32 0x40
#define UpdateCapsuleOffset32 0x44
#define QueryCapsuleCapabilitiesOffset32 0x48
#define QueryVariableInfoOffset32 0x4c

// SMM services offsets (64-bit)
#define SmmInstallConfigurationTableOffset64 0x28
#define SmmAllocatePoolOffset64 0x50
#define SmmFreePoolOffset64 0x58
#define SmmAllocatePagesOffset64 0x60
#define SmmFreePagesOffset64 0x68
#define SmmStartupThisApOffset64 0x70
#define SmmInstallProtocolInterfaceOffset64 0xa8
#define SmmUninstallProtocolInterfaceOffset64 0xb0
#define SmmHandleProtocolOffset64 0xb8
#define SmmRegisterProtocolNotifyOffset64 0xc0
#define SmmLocateHandleOffset64 0xc8
#define SmmLocateProtocolOffset64 0xd0
#define SmiManageOffset64 0xd8
#define SmiHandlerRegisterOffset64 0xe0
#define SmiHandlerUnRegisterOffset64 0xe8

// SMM services offsets (32-bit)
#define SmmInstallConfigurationTableOffset32 0x20
#define SmmAllocatePoolOffset32 0x34
#define SmmFreePoolOffset32 0x38
#define SmmAllocatePagesOffset32 0x3c
#define SmmFreePagesOffset32 0x40
#define SmmStartupThisApOffset32 0x44
#define SmmInstallProtocolInterfaceOffset32 0x60
#define SmmUninstallProtocolInterfaceOffset32 0x64
#define SmmHandleProtocolOffset32 0x68
#define SmmRegisterProtocolNotifyOffset32 0x6c
#define SmmLocateHandleOffset32 0x70
#define SmmLocateProtocolOffset32 0x74
#define SmiManageOffset32 0x78
#define SmiHandlerRegisterOffset32 0x7c
#define SmiHandlerUnRegisterOffset32 0x80

struct pServiceReg {
    char service_name[64];
    uint32_t offset;
    uint32_t reg;
};

struct pServicePush {
    char service_name[64];
    uint32_t offset;
    uint16_t push_number;
};

struct service {
    char service_name[64];
    uint32_t offset64;
    uint32_t offset32;
};

struct pServiceReg bootServicesTable64[] = {
    {"InstallProtocolInterface", InstallProtocolInterfaceOffset64, REG_RDX},
    {"ReinstallProtocolInterface", RenstallProtocolInterfaceOffset64, REG_RDX},
    {"UninstallProtocolInterface", UninstallProtocolInterfaceOffset64, REG_RDX},
    {"HandleProtocol", HandleProtocolOffset64, REG_RDX},
    {"RegisterProtocolNotify", RegisterProtocolNotifyOffset64, REG_RCX},
    {"OpenProtocol", OpenProtocolOffset64, REG_RDX},
    {"CloseProtocol", CloseProtocolOffset64, REG_RDX},
    {"OpenProtocolInformation", OpenProtocolInformationOffset64, REG_RDX},
    {"LocateHandleBuffer", LocateHandleBufferOffset64, REG_RDX},
    {"LocateProtocol", LocateProtocolOffset64, REG_RCX},
    {"InstallMultipleProtocolInterfaces", InstallMultipleProtocolInterfacesOffset64,
     REG_RDX},
    {"UninstallMultipleProtocolInterfaces", UninstallMultipleProtocolInterfacesOffset64,
     REG_RDX}};
size_t bootServicesTable64Length = sizeof(bootServicesTable64) / sizeof(pServiceReg);

struct pServicePush bootServicesTable32[] = {
    {"InstallProtocolInterface", InstallProtocolInterfaceOffset32, 2},
    {"ReinstallProtocolInterface", RenstallProtocolInterfaceOffset32, 2},
    {"UninstallProtocolInterface", UninstallProtocolInterfaceOffset32, 2},
    {"HandleProtocol", HandleProtocolOffset32, 2},
    {"RegisterProtocolNotify", RegisterProtocolNotifyOffset32, 1},
    {"OpenProtocol", OpenProtocolOffset32, 2},
    {"CloseProtocol", CloseProtocolOffset32, 2},
    {"OpenProtocolInformation", OpenProtocolInformationOffset32, 2},
    {"LocateHandleBuffer", LocateHandleBufferOffset32, 2},
    {"LocateProtocol", LocateProtocolOffset32, 1},
    {"InstallMultipleProtocolInterfaces", InstallMultipleProtocolInterfacesOffset32, 2},
    {"UninstallMultipleProtocolInterfaces", UninstallMultipleProtocolInterfacesOffset32,
     2}};
size_t bootServicesTable32Length = sizeof(bootServicesTable64) / sizeof(pServicePush);

struct service bootServicesTableAll[] = {
    // difficult to check false positives
    // {"RaiseTPL", RaiseTPLOffset64, RaiseTPLOffset32},
    // {"RestoreTPL", RestoreTPLOffset64, RestoreTPLOffset32},
    {"AllocatePages", AllocatePagesOffset64, AllocatePagesOffset32},
    {"FreePages", FreePagesOffset64, FreePagesOffset32},
    {"GetMemoryMap", GetMemoryMapOffset64, GetMemoryMapOffset32},
    {"AllocatePool", AllocatePoolOffset64, AllocatePoolOffset32},
    {"FreePool", FreePoolOffset64, FreePoolOffset32},
    {"CreateEvent", CreateEventOffset64, CreateEventOffset32},
    {"SetTimer", SetTimerOffset64, SetTimerOffset32},
    {"WaitForEvent", WaitForEventOffset64, WaitForEventOffset32},
    {"SignalEvent", SignalEventOffset64, SignalEventOffset32},
    {"CloseEvent", CloseEventOffset64, CloseEventOffset32},
    {"CheckEvent", CheckEventOffset64, CheckEventOffset32},
    {"InstallProtocolInterface", InstallProtocolInterfaceOffset64,
     InstallProtocolInterfaceOffset32},
    {"ReinstallProtocolInterface", RenstallProtocolInterfaceOffset64,
     RenstallProtocolInterfaceOffset32},
    {"UninstallProtocolInterface", UninstallProtocolInterfaceOffset64,
     UninstallProtocolInterfaceOffset32},
    {"HandleProtocol", HandleProtocolOffset64, HandleProtocolOffset32},
    {"RegisterProtocolNotify", RegisterProtocolNotifyOffset64,
     RegisterProtocolNotifyOffset32},
    {"LocateHandle", LocateHandleOffset64, LocateHandleOffset32},
    {"LocateDevicePath", LocateDevicePathOffset64, LocateDevicePathOffset32},
    {"InstallConfigurationTable", InstallConfigurationTableOffset64,
     InstallConfigurationTableOffset32},
    {"LoadImage", LoadImageOffset64, LoadImageOffset32},
    {"StartImage", StartImageOffset64, StartImageOffset32},
    {"Exit", ExitOffset64, ExitOffset32},
    {"UnloadImage", UnloadImageOffset64, UnloadImageOffset32},
    {"ExitBootServices", ExitBootServicesOffset64, ExitBootServicesOffset32},
    {"GetNextMonotonicCount", GetNextMonotonicCountOffset64,
     GetNextMonotonicCountOffset32},
    {"Stall", StallOffset64, StallOffset32},
    {"SetWatchdogTimer", SetWatchdogTimerOffset64, SetWatchdogTimerOffset32},
    {"ConnectController", ConnectControllerOffset64, ConnectControllerOffset32},
    {"DisconnectController", DisconnectControllerOffset64, DisconnectControllerOffset32},
    {"OpenProtocol", OpenProtocolOffset64, OpenProtocolOffset32},
    {"CloseProtocol", CloseProtocolOffset64, CloseProtocolOffset32},
    {"OpenProtocolInformation", OpenProtocolInformationOffset64,
     OpenProtocolInformationOffset32},
    {"ProtocolsPerHandle", ProtocolsPerHandleOffset64, ProtocolsPerHandleOffset32},
    {"LocateHandleBuffer", LocateHandleBufferOffset64, LocateHandleBufferOffset32},
    {"LocateProtocol", LocateProtocolOffset64, LocateProtocolOffset32},
    {"InstallMultipleProtocolInterfaces", InstallMultipleProtocolInterfacesOffset64,
     InstallMultipleProtocolInterfacesOffset32},
    {"UninstallMultipleProtocolInterfaces", UninstallMultipleProtocolInterfacesOffset64,
     UninstallMultipleProtocolInterfacesOffset32},
    {"CalculateCrc32", CalculateCrc32Offset64, CalculateCrc32Offset32},
    {"CopyMem", CopyMemOffset64, CopyMemOffset32},
    {"SetMem", SetMemOffset64, SetMemOffset32},
    {"CreateEventEx", CreateEventExOffset64, CreateEventExOffset32}};
size_t bootServicesTableAllLength = sizeof(bootServicesTableAll) / sizeof(service);

struct service runtimeServicesTableAll[] = {
    {"GetTime", GetTimeOffset64, GetTimeOffset32},
    {"SetTime", SetTimeOffset64, SetTimeOffset32},
    {"GetWakeupTime", GetWakeupTimeOffset64, GetWakeupTimeOffset32},
    {"SetWakeupTime", SetWakeupTimeOffset64, SetWakeupTimeOffset32},
    {"SetVirtualAddressMap", SetVirtualAddressMapOffset64, SetVirtualAddressMapOffset32},
    {"ConvertPointer", ConvertPointerOffset64, ConvertPointerOffset32},
    {"GetVariable", GetVariableOffset64, GetVariableOffset32},
    {"GetNextVariableName", GetNextVariableNameOffset64, GetNextVariableNameOffset32},
    {"SetVariable", SetVariableOffset64, SetVariableOffset32},
    {"GetNextHighMonotonicCount", GetNextHighMonotonicCountOffset64,
     GetNextHighMonotonicCountOffset32},
    {"ResetSystem", ResetSystemOffset64, ResetSystemOffset32},
    {"UpdateCapsule", UpdateCapsuleOffset64, UpdateCapsuleOffset32},
    {"QueryCapsuleCapabilities", QueryCapsuleCapabilitiesOffset64,
     QueryCapsuleCapabilitiesOffset32},
    {"QueryVariableInfo", QueryVariableInfoOffset64, QueryVariableInfoOffset32}};
size_t runtimeServicesTableAllLength = sizeof(runtimeServicesTableAll) / sizeof(service);

struct pServiceReg smmServicesProt64[] = {
    {"SmmInstallProtocolInterface", SmmInstallProtocolInterfaceOffset64, REG_RDX},
    {"SmmUninstallProtocolInterface", SmmUninstallProtocolInterfaceOffset64, REG_RDX},
    {"SmmHandleProtocol", SmmHandleProtocolOffset64, REG_RDX},
    {"SmmRegisterProtocolNotify", SmmRegisterProtocolNotifyOffset64, REG_RCX},
    {"SmmLocateHandle", SmmLocateHandleOffset64, REG_RDX},
    {"SmmLocateProtocol", SmmLocateProtocolOffset64, REG_RCX}};
size_t smmServicesProt64Length = sizeof(smmServicesProt64) / sizeof(pServiceReg);

struct service smmServicesTableAll[] = {
    {"SmmInstallConfigurationTable", SmmInstallConfigurationTableOffset64,
     SmmInstallConfigurationTableOffset32},
    {"SmmAllocatePool", SmmAllocatePoolOffset64, SmmAllocatePoolOffset32},
    {"SmmFreePool", SmmFreePoolOffset64, SmmFreePoolOffset32},
    {"SmmAllocatePages", SmmAllocatePagesOffset64, SmmAllocatePagesOffset32},
    {"SmmFreePages", SmmFreePagesOffset64, SmmFreePagesOffset32},
    {"SmmStartupThisAp", SmmStartupThisApOffset64, SmmStartupThisApOffset32},
    {"SmmInstallProtocolInterface", SmmInstallProtocolInterfaceOffset64,
     SmmInstallProtocolInterfaceOffset32},
    {"SmmUninstallProtocolInterface", SmmUninstallProtocolInterfaceOffset64,
     SmmUninstallProtocolInterfaceOffset32},
    {"SmmHandleProtocol", SmmHandleProtocolOffset64, SmmHandleProtocolOffset32},
    {"SmmRegisterProtocolNotify", SmmRegisterProtocolNotifyOffset64,
     SmmRegisterProtocolNotifyOffset32},
    {"SmmLocateHandle", SmmLocateHandleOffset64, SmmLocateHandleOffset32},
    {"SmmLocateProtocol", SmmLocateProtocolOffset64, SmmLocateProtocolOffset32},
    {"SmiManage", SmiManageOffset64, SmiManageOffset32},
    {"SmiHandlerRegister", SmiHandlerRegisterOffset64, SmiHandlerRegisterOffset32},
    {"SmiHandlerUnRegister", SmiHandlerUnRegisterOffset64, SmiHandlerUnRegisterOffset32}};
size_t smmServicesTableAllLength = sizeof(smmServicesTableAll) / sizeof(service);
