// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2020-2026 Binarly

#include "efi_defs.h"

const char *g_plugin_name = "efiXplorer";

service_info_64_t g_boot_services_table_aarch64[] = {
    {"InstallProtocolInterface", 0x80, R_X1, 1},
    {"ReinstallProtocolInterface", 0x88, R_X1, 1},
    {"UninstallProtocolInterface", 0x90, R_X1, 1},
    {"HandleProtocol", 0x98, R_X1, 1},
    {"RegisterProtocolNotify", 0xA8, R_X0, 0},
    {"OpenProtocol", 0x118, R_X1, 1},
    {"CloseProtocol", 0x120, R_X1, 1},
    {"ProtocolsPerHandle", 0x128, R_X1, 1},
    {"OpenProtocolInformation", 0x130, R_X1, 1},
    {"LocateHandleBuffer", 0x138, R_X1, 1},
    {"LocateProtocol", 0x140, R_X0, 1},
    {"InstallMultipleProtocolInterfaces", 0x148, R_X1, 1},
    {"UninstallMultipleProtocolInterfaces", 0x150, R_X1, 1}};
size_t g_boot_services_table_aarch64_count =
    sizeof(g_boot_services_table_aarch64) / sizeof(service_info_64_t);

service_info_64_t g_boot_services_table64[] = {
    {"InstallProtocolInterface", 0x80, R_RDX, 1},
    {"ReinstallProtocolInterface", 0x88, R_RDX, 1},
    {"UninstallProtocolInterface", 0x90, R_RDX, 1},
    {"HandleProtocol", 0x98, R_RDX, 1},
    {"RegisterProtocolNotify", 0xa8, R_RCX, 0},
    {"OpenProtocol", 0x118, R_RDX, 1},
    {"CloseProtocol", 0x120, R_RDX, 1},
    {"ProtocolsPerHandle", 0x130, R_RDX, 1},
    {"OpenProtocolInformation", 0x128, R_RDX, 1},
    {"LocateHandleBuffer", 0x138, R_RDX, 1},
    {"LocateProtocol", 0x140, R_RCX, 0},
    {"InstallMultipleProtocolInterfaces", 0x148, R_RDX, 1},
    {"UninstallMultipleProtocolInterfaces", 0x150, R_RDX, 1}};
size_t g_boot_services_table64_count =
    sizeof(g_boot_services_table64) / sizeof(service_info_64_t);

service_info_32_t g_boot_services_table32[] = {
    {"InstallProtocolInterface", 0x4c, 2},
    {"ReinstallProtocolInterface", 0x50, 2},
    {"UninstallProtocolInterface", 0x54, 2},
    {"HandleProtocol", 0x58, 2},
    {"RegisterProtocolNotify", 0x60, 1},
    {"OpenProtocol", 0x98, 2},
    {"CloseProtocol", 0x9c, 2},
    {"ProtocolsPerHandle", 0xa4, 2},
    {"OpenProtocolInformation", 0xa0, 2},
    {"LocateHandleBuffer", 0xa8, 2},
    {"LocateProtocol", 0xac, 1},
    {"InstallMultipleProtocolInterfaces", 0xb0, 2},
    {"UninstallMultipleProtocolInterfaces", 0xb4, 2}};
size_t g_boot_services_table32_count =
    sizeof(g_boot_services_table32) / sizeof(service_info_32_t);

service_t g_boot_services_table_all[] = {
    // skip RaiseTPL and RestoreTPL to avoid FPs
    {"AllocatePages", 0x28, 0x20},
    {"FreePages", 0x30, 0x24},
    {"GetMemoryMap", 0x38, 0x28},
    {"AllocatePool", 0x40, 0x2c},
    {"FreePool", 0x48, 0x30},
    {"CreateEvent", 0x50, 0x34},
    {"SetTimer", 0x58, 0x38},
    {"WaitForEvent", 0x60, 0x3c},
    {"SignalEvent", 0x68, 0x40},
    {"CloseEvent", 0x70, 0x44},
    {"CheckEvent", 0x78, 0x48},
    {"InstallProtocolInterface", 0x80, 0x4c},
    {"ReinstallProtocolInterface", 0x88, 0x50},
    {"UninstallProtocolInterface", 0x90, 0x54},
    {"HandleProtocol", 0x98, 0x58},
    {"RegisterProtocolNotify", 0xa8, 0x60},
    {"LocateHandle", 0xb0, 0x64},
    {"LocateDevicePath", 0xb8, 0x68},
    {"InstallConfigurationTable", 0xc0, 0x6c},
    {"LoadImage", 0xc8, 0x70},
    {"StartImage", 0xd0, 0x74},
    {"Exit", 0xd8, 0x78},
    {"UnloadImage", 0xe0, 0x7c},
    {"ExitBootServices", 0xe8, 0x80},
    {"GetNextMonotonicCount", 0xf0, 0x84},
    {"Stall", 0xf8, 0x88},
    {"SetWatchdogTimer", 0x100, 0x8c},
    {"ConnectController", 0x108, 0x90},
    {"DisconnectController", 0x110, 0x94},
    {"OpenProtocol", 0x118, 0x98},
    {"CloseProtocol", 0x120, 0x9c},
    {"OpenProtocolInformation", 0x128, 0xa0},
    {"ProtocolsPerHandle", 0x130, 0xa4},
    {"LocateHandleBuffer", 0x138, 0xa8},
    {"LocateProtocol", 0x140, 0xac},
    {"InstallMultipleProtocolInterfaces", 0x148, 0xb0},
    {"UninstallMultipleProtocolInterfaces", 0x150, 0xb4},
    {"CalculateCrc32", 0x158, 0xb8},
    {"CopyMem", 0x160, 0xbc},
    {"SetMem", 0x168, 0xc0},
    {"CreateEventEx", 0x170, 0xc4}};
size_t g_boot_services_table_all_count =
    sizeof(g_boot_services_table_all) / sizeof(service_t);

service_t g_runtime_services_table_all[] = {
    {"GetTime", 0x18, 0x18},
    {"SetTime", 0x20, 0x1c},
    {"GetWakeupTime", 0x28, 0x20},
    {"SetWakeupTime", 0x30, 0x24},
    {"SetVirtualAddressMap", 0x38, 0x28},
    {"ConvertPointer", 0x40, 0x2c},
    {"GetVariable", 0x48, 0x30},
    {"GetNextVariableName", 0x50, 0x34},
    {"SetVariable", 0x58, 0x38},
    {"GetNextHighMonotonicCount", 0x60, 0x3c},
    {"ResetSystem", 0x68, 0x40},
    {"UpdateCapsule", 0x70, 0x44},
    {"QueryCapsuleCapabilities", 0x78, 0x48},
    {"QueryVariableInfo", 0x80, 0x4c}};
size_t g_runtime_services_table_all_count =
    sizeof(g_runtime_services_table_all) / sizeof(service_t);

service_info_64_t g_smm_services_prot64[] = {
    {"SmmInstallProtocolInterface", 0xa8, R_RDX},
    {"SmmUninstallProtocolInterface", 0xb0, R_RDX},
    {"SmmHandleProtocol", 0xb8, R_RDX},
    {"SmmRegisterProtocolNotify", 0xc0, R_RCX},
    {"SmmLocateHandle", 0xc8, R_RDX},
    {"SmmLocateProtocol", 0xd0, R_RCX}};
size_t g_smm_services_prot64_count =
    sizeof(g_smm_services_prot64) / sizeof(service_info_64_t);

service_t g_smm_services_table_all[] = {
    {"SmmInstallConfigurationTable", 0x28, 0x20},
    {"SmmAllocatePool", 0x50, 0x34},
    {"SmmFreePool", 0x58, 0x38},
    {"SmmAllocatePages", 0x60, 0x3c},
    {"SmmFreePages", 0x68, 0x40},
    {"SmmStartupThisAp", 0x70, 0x44},
    {"SmmInstallProtocolInterface", 0xa8, 0x60},
    {"SmmUninstallProtocolInterface", 0xb0, 0x64},
    {"SmmHandleProtocol", 0xb8, 0x68},
    {"SmmRegisterProtocolNotify", 0xc0, 0x6c},
    {"SmmLocateHandle", 0xc8, 0x70},
    {"SmmLocateProtocol", 0xd0, 0x74},
    {"SmiManage", 0xd8, 0x78},
    {"SmiHandlerRegister", 0xe0, 0x7c},
    {"SmiHandlerUnRegister", 0xe8, 0x80}};
size_t g_smm_services_table_all_count =
    sizeof(g_smm_services_table_all) / sizeof(service_t);

service_info_32_t g_pei_services_table32[] = {
    {"InstallPpi", 0x18, 2},
    {"ReInstallPpi", 0x1c, 3},
    {"LocatePpi", 0x20, 2},
    {"NotifyPpi", 0x24, NONE_PUSH},
    {"GetBootMode", 0x28, NONE_PUSH},
    {"SetBootMode", 0x2c, NONE_PUSH},
    {"GetHobList", 0x30, NONE_PUSH},
    {"CreateHob", 0x34, NONE_PUSH},
    {"FfsFindNextVolume", 0x38, NONE_PUSH},
    {"FfsFindNextFile", 0x3c, NONE_PUSH},
    {"FfsFindSectionData", 0x40, NONE_PUSH},
    {"InstallPeiMemory", 0x44, NONE_PUSH},
    {"AllocatePages", 0x48, NONE_PUSH},
    {"AllocatePool", 0x4c, NONE_PUSH},
    {"CopyMem", 0x50, NONE_PUSH},
    {"SetMem", 0x54, NONE_PUSH},
    {"ReportStatusCode", 0x58, NONE_PUSH},
    {"ResetSystem", 0x5c, NONE_PUSH},
    {"CpuIo", 0x60, NONE_PUSH},
    {"PciCfg", 0x64, NONE_PUSH},
    {"FfsFindFileByName", 0x68, NONE_PUSH},
    {"FfsGetFileInfo", 0x6c, NONE_PUSH},
    {"FfsGetVolumeInfo", 0x70, NONE_PUSH},
    {"RegisterForShadow", 0x74, NONE_PUSH},
    {"FindSectionData3", 0x78, NONE_PUSH},
    {"FfsGetFileInfo2", 0x7c, NONE_PUSH},
    {"ResetSystem2", 0x80, NONE_PUSH}};
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
