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

#include "efi_defs.h"

const char *g_plugin_name = "efiXplorer";

service_info_64_t g_boot_services_table64[] = {
    {"InstallProtocolInterface", InstallProtocolInterfaceOffset64, REG_RDX, 1},
    {"ReinstallProtocolInterface", RenstallProtocolInterfaceOffset64, REG_RDX, 1},
    {"UninstallProtocolInterface", UninstallProtocolInterfaceOffset64, REG_RDX, 1},
    {"HandleProtocol", HandleProtocolOffset64, REG_RDX, 1},
    {"RegisterProtocolNotify", RegisterProtocolNotifyOffset64, REG_RCX, 0},
    {"OpenProtocol", OpenProtocolOffset64, REG_RDX, 1},
    {"CloseProtocol", CloseProtocolOffset64, REG_RDX, 1},
    {"ProtocolsPerHandle", ProtocolsPerHandleOffset64, REG_RDX, 1},
    {"OpenProtocolInformation", OpenProtocolInformationOffset64, REG_RDX, 1},
    {"LocateHandleBuffer", LocateHandleBufferOffset64, REG_RDX, 1},
    {"LocateProtocol", LocateProtocolOffset64, REG_RCX, 0},
    {"InstallMultipleProtocolInterfaces", InstallMultipleProtocolInterfacesOffset64,
     REG_RDX, 1},
    {"UninstallMultipleProtocolInterfaces", UninstallMultipleProtocolInterfacesOffset64,
     REG_RDX, 1}};
size_t g_boot_services_table64_count =
    sizeof(g_boot_services_table64) / sizeof(service_info_64_t);

service_info_32_t g_boot_services_table32[] = {
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
size_t g_boot_services_table32_count =
    sizeof(g_boot_services_table32) / sizeof(service_info_32_t);

service_t g_boot_services_table_all[] = {
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
size_t g_boot_services_table_all_count =
    sizeof(g_boot_services_table_all) / sizeof(service_t);

service_t g_runtime_services_table_all[] = {
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
size_t g_runtime_services_table_all_count =
    sizeof(g_runtime_services_table_all) / sizeof(service_t);

service_info_64_t g_smm_services_prot64[] = {
    {"SmmInstallProtocolInterface", SmmInstallProtocolInterfaceOffset64, REG_RDX},
    {"SmmUninstallProtocolInterface", SmmUninstallProtocolInterfaceOffset64, REG_RDX},
    {"SmmHandleProtocol", SmmHandleProtocolOffset64, REG_RDX},
    {"SmmRegisterProtocolNotify", SmmRegisterProtocolNotifyOffset64, REG_RCX},
    {"SmmLocateHandle", SmmLocateHandleOffset64, REG_RDX},
    {"SmmLocateProtocol", SmmLocateProtocolOffset64, REG_RCX}};
size_t g_smm_services_prot64_count =
    sizeof(g_smm_services_prot64) / sizeof(service_info_64_t);

service_t g_smm_services_table_all[] = {
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
size_t g_smm_services_table_all_count =
    sizeof(g_smm_services_table_all) / sizeof(service_t);

service_info_32_t g_pei_services_table32[] = {{"InstallPpi", 0x18, 2},
                                              {"ReInstallPpi", 0x1c, 3},
                                              {"LocatePpi", 0x20, 2},
                                              {"NotifyPpi", 0x24, PUSH_NONE},
                                              {"GetBootMode", 0x28, PUSH_NONE},
                                              {"SetBootMode", 0x2c, PUSH_NONE},
                                              {"GetHobList", 0x30, PUSH_NONE},
                                              {"CreateHob", 0x34, PUSH_NONE},
                                              {"FfsFindNextVolume", 0x38, PUSH_NONE},
                                              {"FfsFindNextFile", 0x3c, PUSH_NONE},
                                              {"FfsFindSectionData", 0x40, PUSH_NONE},
                                              {"InstallPeiMemory", 0x44, PUSH_NONE},
                                              {"AllocatePages", 0x48, PUSH_NONE},
                                              {"AllocatePool", 0x4c, PUSH_NONE},
                                              {"CopyMem", 0x50, PUSH_NONE},
                                              {"SetMem", 0x54, PUSH_NONE},
                                              {"ReportStatusCode", 0x58, PUSH_NONE},
                                              {"ResetSystem", 0x5c, PUSH_NONE},
                                              {"CpuIo", 0x60, PUSH_NONE},
                                              {"PciCfg", 0x64, PUSH_NONE},
                                              {"FfsFindFileByName", 0x68, PUSH_NONE},
                                              {"FfsGetFileInfo", 0x6c, PUSH_NONE},
                                              {"FfsGetVolumeInfo", 0x70, PUSH_NONE},
                                              {"RegisterForShadow", 0x74, PUSH_NONE},
                                              {"FindSectionData3", 0x78, PUSH_NONE},
                                              {"FfsGetFileInfo2", 0x7c, PUSH_NONE},
                                              {"ResetSystem2", 0x80, PUSH_NONE}};
size_t g_pei_services_table32_count =
    sizeof(g_pei_services_table32) / sizeof(service_info_32_t);

service_t g_pei_services_table_all[] = {{"InstallPpi", 0x18, 0x18},
                                        {"ReInstallPpi", 0x20, 0x1c},
                                        {"LocatePpi", 0x28, 0x20},
                                        {"NotifyPpi", 0x30, 0x24},
                                        {"GetBootMode", 0x38, 0x28},
                                        {"SetBootMode", 0x40, 0x2c},
                                        {"GetHobList", 0x48, 0x30},
                                        {"CreateHob", 0x50, 0x34},
                                        {"FfsFindNextVolume", 0x58, 0x38},
                                        {"FfsFindNextFile", 0x60, 0x3c},
                                        {"FfsFindSectionData", 0x68, 0x40},
                                        {"InstallPeiMemory", 0x70, 0x44},
                                        {"AllocatePages", 0x78, 0x48},
                                        {"AllocatePool", 0x80, 0x4c},
                                        {"CopyMem", 0x88, 0x50},
                                        {"SetMem", 0x90, 0x54},
                                        {"ReportStatusCode", 0x98, 0x58},
                                        {"ResetSystem", 0xa0, 0x5c},
                                        {"CpuIo", 0xa8, 0x60},
                                        {"PciCfg", 0xb0, 0x64},
                                        {"FfsFindFileByName", 0xb8, 0x68},
                                        {"FfsGetFileInfo", 0xc0, 0x6c},
                                        {"FfsGetVolumeInfo", 0xc8, 0x70},
                                        {"RegisterForShadow", 0xd0, 0x74},
                                        {"FindSectionData3", 0xc8, 0x78},
                                        {"FfsGetFileInfo2", 0xe0, 0x7c},
                                        {"ResetSystem2", 0xe8, 0x80}};
size_t g_pei_services_table_all_count =
    sizeof(g_pei_services_table_all) / sizeof(service_t);

service_t g_variable_ppi_table_all[] = {{"GetVariable", 0, 0},
                                        {"NextVariableName", 8, 4}};
size_t g_variable_ppi_table_all_count =
    sizeof(g_variable_ppi_table_all) / sizeof(service_t);
