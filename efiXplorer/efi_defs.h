/*
 * efiXplorer
 * Copyright (C) 2020-2024  Binarly
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
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#define COPYRIGHT "(C) 2020-2024  Binarly - https://github.com/binarly-io/efiXplorer"

#define BTOA(x) ((x) ? "true" : "false")

#define VZ 0x5A56
#define MZ 0x5A4D

#define BS_OFFSET_64 0x60
#define BS_OFFSET_32 0x3c
#define RT_OFFSET_64 0x58
#define RT_OFFSET_32 0x38

enum class ModuleType { DxeSmm = 0, Pei = 1 };

enum class ArchFileType { Unsupported, X8632, X8664, Uefi, Aarch64 };

enum class FfsFileType { Unsupported = 0, Pei = 6, DxeAndTheLike = 7 };

enum MachineType { AMD64 = 0x8664, I386 = 0x014C, AARCH64 = 0xaa64 };

enum RegsAmd32 {
  REG_EAX,
  REG_ECX,
  REG_EDX,
  REG_EBX,
  REG_ESP,
  REG_EBP,
  REG_ESI,
  REG_EDI,
  REG_AL = 0x10,
  REG_DL = 0x12
};

enum RegsI386 {
  REG_RAX,
  REG_RCX,
  REG_RDX,
  REG_RBX,
  REG_RSP,
  REG_RBP,
  REG_RSI,
  REG_RDI,
  REG_R8,
  REG_R9,
  REG_R10,
  REG_R11,
  REG_R12,
  REG_R13,
  REG_R14,
};

enum RegsAarch4 {
  REG_C0 = 0,
  REG_C13 = 13,
  REG_X0 = 129,
  REG_X1,
  REG_X2,
  REG_X3,
  REG_X4,
  REG_X5,
  REG_X6,
  REG_X7,
  REG_X8,
  REG_X9,
  REG_X10,
  REG_X11,
  REG_X12,
  REG_X13,
  REG_X14,
  REG_X15,
  REG_X16,
  REG_X17,
  REG_X18,
  REG_X19,
  REG_X20,
  REG_X21,
  REG_X22,
  REG_X23,
  REG_X24,
  REG_X25,
  REG_X26,
  REG_X27,
  REG_X28,
  REG_X29,
  REG_X30,
  REG_XZR,
  REG_XSP,
  REG_XPC,
};

enum HelperValues {
  OFFSET_NONE = 0xffff,
  PUSH_NONE = 0xffff,
  BAD_REG = 0xffff,
};

typedef struct service_info_64 {
  char name[64];
  uint32_t offset;
  uint32_t reg;
  uint16_t arg_index;
} service_info_64_t;

typedef struct service_info_32 {
  char name[64];
  uint32_t offset;
  uint16_t push_number;
} service_info_32_t;

typedef struct service {
  char name[64];
  uint32_t offset64;
  uint32_t offset32;
} service_t;

enum BootServicesOffsets64 {
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

enum BootServicesOffsets32 {
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

enum RuntimeServicesOffsets64 {
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

enum RuntimeServicesOffsets32 {
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

enum SmmServicesOffsets64 {
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

enum SmmServicesOffsets32 {
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

extern service_info_64_t g_boot_services_table64[];
extern size_t g_boot_services_table64_count;

extern service_info_32_t g_boot_services_table32[];
extern size_t g_boot_services_table32_count;

extern service_t g_boot_services_table_all[];
extern size_t g_boot_services_table_all_count;

extern service_t g_runtime_services_table_all[];
extern size_t g_runtime_services_table_all_count;

extern service_info_64_t g_smm_services_prot64[];
extern size_t g_smm_services_prot64_count;

extern service_t g_smm_services_table_all[];
extern size_t g_smm_services_table_all_count;

extern service_info_32_t g_pei_services_table32[];
extern size_t g_pei_services_table32_count;

extern service_t g_pei_services_table_all[];
extern size_t g_pei_services_table_all_count;

extern service_t g_variable_ppi_table_all[];
extern size_t g_variable_ppi_table_all_count;

extern const char *g_plugin_name;
