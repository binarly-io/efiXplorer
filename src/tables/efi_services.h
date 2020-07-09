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

#define x86InstallProtocolInterfaceOffset 0x4c
#define x86RenstallProtocolInterfaceOffset 0x50
#define x86UninstallProtocolInterfaceOffset 0x54
#define x86HandleProtocolOffset 0x58
#define x86RegisterProtocolNotifyOffset 0x60
#define x86OpenProtocolOffset 0x98
#define x86CloseProtocolOffset 0x9c
#define x86OpenProtocolInformationOffset 0xa0
#define x86ProtocolsPerHandleOffset 0xa4
#define x86LocateHandleBufferOffset 0xa8
#define x86LocateProtocolOffset 0xac
#define x86InstallMultipleProtocolInterfacesOffset 0xb0
#define x86UninstallMultipleProtocolInterfacesOffset 0xb4

struct bootServiceX64 {
    char service_name[64];
    size_t offset;
    size_t reg;
};

struct bootServiceX86 {
    char service_name[64];
    size_t offset;
    uint16_t push_number;
};

struct service {
    char service_name[64];
    size_t offset;
};

size_t bootServicesTableX64Length = 12;
struct bootServiceX64 bootServicesTableX64[] = {
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

size_t bootServicesTableX86Length = 12;
struct bootServiceX86 bootServicesTableX86[] = {
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

size_t bootServicesX64AllLength = 43;
struct service bootServicesX64All[] = {
    {"RaiseTPL", x64RaiseTPLOffset},
    {"RestoreTPL", x64RestoreTPLOffset},
    {"AllocatePages", x64AllocatePagesOffset},
    {"FreePages", x64FreePagesOffset},
    {"GetMemoryMap", x64GetMemoryMapOffset},
    {"AllocatePool", x64AllocatePoolOffset},
    {"FreePool", x64FreePoolOffset},
    {"CreateEvent", x64CreateEventOffset},
    {"SetTimer", x64SetTimerOffset},
    {"WaitForEvent", x64WaitForEventOffset},
    {"SignalEvent", x64SignalEventOffset},
    {"CloseEvent", x64CloseEventOffset},
    {"CheckEvent", x64CheckEventOffset},
    {"InstallProtocolInterface", x64InstallProtocolInterfaceOffset},
    {"ReinstallProtocolInterface", x64RenstallProtocolInterfaceOffset},
    {"UninstallProtocolInterface", x64UninstallProtocolInterfaceOffset},
    {"HandleProtocol", x64HandleProtocolOffset},
    {"RegisterProtocolNotify", x64RegisterProtocolNotifyOffset},
    {"LocateHandle", x64LocateHandleOffset},
    {"LocateDevicePath", x64LocateDevicePathOffset},
    {"InstallConfigurationTable", x64InstallConfigurationTableOffset},
    {"LoadImage", x64LoadImageOffset},
    {"StartImage", x64StartImageOffset},
    {"Exit", x64ExitOffset},
    {"UnloadImage", x64UnloadImageOffset},
    {"ExitBootServices", x64ExitBootServicesOffset},
    {"GetNextMonotonicCount", x64GetNextMonotonicCountOffset},
    {"Stall", x64StallOffset},
    {"SetWatchdogTimer", x64SetWatchdogTimerOffset},
    {"ConnectController", x64ConnectControllerOffset},
    {"DisconnectController", x64DisconnectControllerOffset},
    {"OpenProtocol", x64OpenProtocolOffset},
    {"CloseProtocol", x64CloseProtocolOffset},
    {"OpenProtocolInformation", x64OpenProtocolInformationOffset},
    {"ProtocolsPerHandle", x64ProtocolsPerHandleOffset},
    {"LocateHandleBuffer", x64LocateHandleBufferOffset},
    {"LocateProtocol", x64LocateProtocolOffset},
    {"InstallMultipleProtocolInterfaces",
     x64InstallMultipleProtocolInterfacesOffset},
    {"UninstallMultipleProtocolInterfaces",
     x64UninstallMultipleProtocolInterfacesOffset},
    {"CalculateCrc32", x64CalculateCrc32Offset},
    {"CopyMem", x64CopyMemOffset},
    {"SetMem", x64SetMemOffset},
    {"CreateEventEx", x64CreateEventExOffset}};

size_t runtimeServicesX64AllLength = 14;
struct service runtimeServicesX64All[] = {
    {"GetTime", x64GetTimeOffset},
    {"SetTime", x64SetTimeOffset},
    {"GetWakeupTime", x64GetWakeupTimeOffset},
    {"SetWakeupTime", x64SetWakeupTimeOffset},
    {"SetVirtualAddressMap", x64SetVirtualAddressMapOffset},
    {"ConvertPointer", x64ConvertPointerOffset},
    {"GetVariable", x64GetVariableOffset},
    {"GetNextVariableName", x64GetNextVariableNameOffset},
    {"SetVariable", x64SetVariableOffset},
    {"GetNextHighMonotonicCount", x64GetNextHighMonotonicCountOffset},
    {"ResetSystem", x64ResetSystemOffset},
    {"UpdateCapsule", x64UpdateCapsuleOffset},
    {"QueryCapsuleCapabilities", x64QueryCapsuleCapabilitiesOffset},
    {"QueryVariableInfo", x64QueryVariableInfoOffset}};
