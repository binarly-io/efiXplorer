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

#pragma once

enum BootServicesOffsets64bit {
    RaiseTPLOffset64 = 0x18,
    RestoreTPLOffset64 = 0x20,
    AllocatePagesOffset64 = 0x28,
    FreePagesOffset64 = 0x30,
    GetMemoryMapOffset64 = 0x38,
    AllocatePoolOffset64 = 0x40,
    FreePoolOffset64 = 0x48,
    CreateEventOffset64 = 0x50,
    SetTimerOffset64 = 0x58,
    WaitForEventOffset64 = 0x60,
    SignalEventOffset64 = 0x68,
    CloseEventOffset64 = 0x70,
    CheckEventOffset64 = 0x78,
    InstallProtocolInterfaceOffset64 = 0x80,
    RenstallProtocolInterfaceOffset64 = 0x88,
    UninstallProtocolInterfaceOffset64 = 0x90,
    HandleProtocolOffset64 = 0x98,
    RegisterProtocolNotifyOffset64 = 0xa8,
    LocateHandleOffset64 = 0xb0,
    LocateDevicePathOffset64 = 0xb8,
    InstallConfigurationTableOffset64 = 0xc0,
    LoadImageOffset64 = 0xc8,
    StartImageOffset64 = 0xd0,
    ExitOffset64 = 0xd8,
    UnloadImageOffset64 = 0xe0,
    ExitBootServicesOffset64 = 0xe8,
    GetNextMonotonicCountOffset64 = 0xf0,
    StallOffset64 = 0xf0,
    SetWatchdogTimerOffset64 = 0x100,
    ConnectControllerOffset64 = 0x108,
    DisconnectControllerOffset64 = 0x110,
    OpenProtocolOffset64 = 0x118,
    CloseProtocolOffset64 = 0x120,
    OpenProtocolInformationOffset64 = 0x128,
    ProtocolsPerHandleOffset64 = 0x130,
    LocateHandleBufferOffset64 = 0x138,
    LocateProtocolOffset64 = 0x140,
    InstallMultipleProtocolInterfacesOffset64 = 0x148,
    UninstallMultipleProtocolInterfacesOffset64 = 0x150,
    CalculateCrc32Offset64 = 0x158,
    CopyMemOffset64 = 0x160,
    SetMemOffset64 = 0x168,
    CreateEventExOffset64 = 0x170,
};

enum BootServicesOffsets32bit {
    RaiseTPLOffset32 = 0x18,
    RestoreTPLOffset32 = 0x1c,
    AllocatePagesOffset32 = 0x20,
    FreePagesOffset32 = 0x24,
    GetMemoryMapOffset32 = 0x28,
    AllocatePoolOffset32 = 0x2c,
    FreePoolOffset32 = 0x30,
    CreateEventOffset32 = 0x34,
    SetTimerOffset32 = 0x38,
    WaitForEventOffset32 = 0x3c,
    SignalEventOffset32 = 0x40,
    CloseEventOffset32 = 0x44,
    CheckEventOffset32 = 0x48,
    InstallProtocolInterfaceOffset32 = 0x4c,
    RenstallProtocolInterfaceOffset32 = 0x50,
    UninstallProtocolInterfaceOffset32 = 0x54,
    HandleProtocolOffset32 = 0x58,
    RegisterProtocolNotifyOffset32 = 0x60,
    LocateHandleOffset32 = 0x64,
    LocateDevicePathOffset32 = 0x68,
    InstallConfigurationTableOffset32 = 0x6c,
    LoadImageOffset32 = 0x70,
    StartImageOffset32 = 0x74,
    ExitOffset32 = 0x78,
    UnloadImageOffset32 = 0x7c,
    ExitBootServicesOffset32 = 0x80,
    GetNextMonotonicCountOffset32 = 0x84,
    StallOffset32 = 0x88,
    SetWatchdogTimerOffset32 = 0x8c,
    ConnectControllerOffset32 = 0x90,
    DisconnectControllerOffset32 = 0x94,
    OpenProtocolOffset32 = 0x98,
    CloseProtocolOffset32 = 0x9c,
    OpenProtocolInformationOffset32 = 0xa0,
    ProtocolsPerHandleOffset32 = 0xa4,
    LocateHandleBufferOffset32 = 0xa8,
    LocateProtocolOffset32 = 0xac,
    InstallMultipleProtocolInterfacesOffset32 = 0xb0,
    UninstallMultipleProtocolInterfacesOffset32 = 0xb4,
    CalculateCrc32Offset32 = 0xb8,
    CopyMemOffset32 = 0xbc,
    SetMemOffset32 = 0xc0,
    CreateEventExOffset32 = 0xc4,
};

enum RuntimeServicesOffsets64bit {
    GetTimeOffset64 = 0x18,
    SetTimeOffset64 = 0x20,
    GetWakeupTimeOffset64 = 0x28,
    SetWakeupTimeOffset64 = 0x30,
    SetVirtualAddressMapOffset64 = 0x38,
    ConvertPointerOffset64 = 0x40,
    GetVariableOffset64 = 0x48,
    GetNextVariableNameOffset64 = 0x50,
    SetVariableOffset64 = 0x58,
    GetNextHighMonotonicCountOffset64 = 0x60,
    ResetSystemOffset64 = 0x68,
    UpdateCapsuleOffset64 = 0x70,
    QueryCapsuleCapabilitiesOffset64 = 0x78,
    QueryVariableInfoOffset64 = 0x80,
};

enum RuntimeServicesOffsets32bit {
    GetTimeOffset32 = 0x18,
    SetTimeOffset32 = 0x1c,
    GetWakeupTimeOffset32 = 0x20,
    SetWakeupTimeOffset32 = 0x24,
    SetVirtualAddressMapOffset32 = 0x28,
    ConvertPointerOffset32 = 0x2c,
    GetVariableOffset32 = 0x30,
    GetNextVariableNameOffset32 = 0x34,
    SetVariableOffset32 = 0x38,
    GetNextHighMonotonicCountOffset32 = 0x3c,
    ResetSystemOffset32 = 0x40,
    UpdateCapsuleOffset32 = 0x44,
    QueryCapsuleCapabilitiesOffset32 = 0x48,
    QueryVariableInfoOffset32 = 0x4c,
};

enum SmmServicesOffsets64bit {
    SmmInstallConfigurationTableOffset64 = 0x28,
    SmmAllocatePoolOffset64 = 0x50,
    SmmFreePoolOffset64 = 0x58,
    SmmAllocatePagesOffset64 = 0x60,
    SmmFreePagesOffset64 = 0x68,
    SmmStartupThisApOffset64 = 0x70,
    SmmInstallProtocolInterfaceOffset64 = 0xa8,
    SmmUninstallProtocolInterfaceOffset64 = 0xb0,
    SmmHandleProtocolOffset64 = 0xb8,
    SmmRegisterProtocolNotifyOffset64 = 0xc0,
    SmmLocateHandleOffset64 = 0xc8,
    SmmLocateProtocolOffset64 = 0xd0,
    SmiManageOffset64 = 0xd8,
    SmiHandlerRegisterOffset64 = 0xe0,
    SmiHandlerUnRegisterOffset64 = 0xe8,
};

enum SmmServicesOffsets32bit {
    SmmInstallConfigurationTableOffset32 = 0x20,
    SmmAllocatePoolOffset32 = 0x34,
    SmmFreePoolOffset32 = 0x38,
    SmmAllocatePagesOffset32 = 0x3c,
    SmmFreePagesOffset32 = 0x40,
    SmmStartupThisApOffset32 = 0x44,
    SmmInstallProtocolInterfaceOffset32 = 0x60,
    SmmUninstallProtocolInterfaceOffset32 = 0x64,
    SmmHandleProtocolOffset32 = 0x68,
    SmmRegisterProtocolNotifyOffset32 = 0x6c,
    SmmLocateHandleOffset32 = 0x70,
    SmmLocateProtocolOffset32 = 0x74,
    SmiManageOffset32 = 0x78,
    SmiHandlerRegisterOffset32 = 0x7c,
    SmiHandlerUnRegisterOffset32 = 0x80,
};

struct service_info_64bit {
    char service_name[64];
    uint32_t offset;
    uint32_t reg;
    uint16_t arg_number;
};

struct service_info_32bit {
    char service_name[64];
    uint32_t offset;
    uint16_t push_number;
};

struct service {
    char service_name[64];
    uint32_t offset64;
    uint32_t offset32;
};

struct service_info_64bit bootServicesTable64[] = {
    {"InstallProtocolInterface", InstallProtocolInterfaceOffset64, REG_RDX, 2},
    {"ReinstallProtocolInterface", RenstallProtocolInterfaceOffset64, REG_RDX, 2},
    {"UninstallProtocolInterface", UninstallProtocolInterfaceOffset64, REG_RDX, 2},
    {"HandleProtocol", HandleProtocolOffset64, REG_RDX, 2},
    {"RegisterProtocolNotify", RegisterProtocolNotifyOffset64, REG_RCX, 1},
    {"OpenProtocol", OpenProtocolOffset64, REG_RDX, 2},
    {"CloseProtocol", CloseProtocolOffset64, REG_RDX, 2},
    {"ProtocolsPerHandle", ProtocolsPerHandleOffset64, REG_RDX, 2},
    {"OpenProtocolInformation", OpenProtocolInformationOffset64, REG_RDX, 2},
    {"LocateHandleBuffer", LocateHandleBufferOffset64, REG_RDX, 2},
    {"LocateProtocol", LocateProtocolOffset64, REG_RCX, 1},
    {"InstallMultipleProtocolInterfaces", InstallMultipleProtocolInterfacesOffset64,
     REG_RDX, 2},
    {"UninstallMultipleProtocolInterfaces", UninstallMultipleProtocolInterfacesOffset64,
     REG_RDX, 2}};
size_t bootServicesTable64Length =
    sizeof(bootServicesTable64) / sizeof(service_info_64bit);

struct service_info_32bit bootServicesTable32[] = {
    {"InstallProtocolInterface", InstallProtocolInterfaceOffset32, 2},
    {"ReinstallProtocolInterface", RenstallProtocolInterfaceOffset32, 2},
    {"UninstallProtocolInterface", UninstallProtocolInterfaceOffset32, 2},
    {"HandleProtocol", HandleProtocolOffset32, 2},
    {"RegisterProtocolNotify", RegisterProtocolNotifyOffset32, 1},
    {"OpenProtocol", OpenProtocolOffset32, 2},
    {"CloseProtocol", CloseProtocolOffset32, 2},
    {"ProtocolsPerHandle", ProtocolsPerHandleOffset32, 2},
    {"OpenProtocolInformation", OpenProtocolInformationOffset32, 2},
    {"LocateHandleBuffer", LocateHandleBufferOffset32, 2},
    {"LocateProtocol", LocateProtocolOffset32, 1},
    {"InstallMultipleProtocolInterfaces", InstallMultipleProtocolInterfacesOffset32, 2},
    {"UninstallMultipleProtocolInterfaces", UninstallMultipleProtocolInterfacesOffset32,
     2}};
size_t bootServicesTable32Length =
    sizeof(bootServicesTable64) / sizeof(service_info_32bit);

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

struct service_info_64bit smmServicesProt64[] = {
    {"SmmInstallProtocolInterface", SmmInstallProtocolInterfaceOffset64, REG_RDX},
    {"SmmUninstallProtocolInterface", SmmUninstallProtocolInterfaceOffset64, REG_RDX},
    {"SmmHandleProtocol", SmmHandleProtocolOffset64, REG_RDX},
    {"SmmRegisterProtocolNotify", SmmRegisterProtocolNotifyOffset64, REG_RCX},
    {"SmmLocateHandle", SmmLocateHandleOffset64, REG_RDX},
    {"SmmLocateProtocol", SmmLocateProtocolOffset64, REG_RCX}};
size_t smmServicesProt64Length = sizeof(smmServicesProt64) / sizeof(service_info_64bit);

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
