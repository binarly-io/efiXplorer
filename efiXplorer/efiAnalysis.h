/*
 * efiXplorer
 * Copyright (C) 2020-2022 Binarly
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
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * efiAnalysis.h
 *
 */

#pragma once

#include "efiSmmUtils.h"
#include "efiUtils.h"

namespace EfiAnalysis {

class EfiAnalyzer {
  public:
    std::vector<json> allGuids;
    std::vector<json> allProtocols;
    std::vector<json> allPPIs;
    std::vector<json> allServices;
    std::vector<func_t *> smiHandlers;
    uint8_t arch;

    void getSegments();
    void setStrings();

    bool findImageHandleX64();
    bool findSystemTableX64();
    bool findBootServicesTables();
    bool findRuntimeServicesTables();
    bool findSmstX64();
    void findOtherBsTablesX64();

    void getProtBootServicesX64();
    void getProtBootServicesX86();
    void getAllBootServices();
    void getAllRuntimeServices();
    void getAllSmmServicesX64();

    void getBsProtNamesX64();
    void getBsProtNamesX86();
    void getSmmProtNamesX64();

    void getAllPeiServicesX86();
    void getPpiNamesX86();
    void getAllVariablePPICallsX86();

    void printInterfaces();
    void markInterfaces();
    void markDataGuids();
    void markLocalGuidsX64();

    bool efiSmmCpuProtocolResolver();
    void findSwSmiHandlers();
    bool findGetVariableOveflow(std::vector<json> allServices);
    bool findPPIGetVariableStackOveflow();
    bool findSmmGetVariableOveflow();
    bool findSmmCallout();
    bool analyzeNvramVariables();
    void dumpInfo();

    EfiAnalyzer();
    ~EfiAnalyzer();

    uint8_t fileType = 0;

  private:
    ea_t base;
    ea_t startAddress = 0;
    ea_t endAddress = 0;
    ea_t mainAddress{};
    std::filesystem::path guidsJsonPath;
    json bootServices;
    json peiServices;
    json peiServicesAll;
    json ppiCallsAll;
    json runtimeServicesAll;
    json smmServices;
    json smmServicesAll;
    json dbProtocols;
    std::vector<json>
        nvramVariables; // [{"addr": ..., "VariableName": ..., "VendorGuid"}, ...]
    std::map<json, std::string> dbProtocolsMap; // a map to look up a GUID name by value
    std::vector<ea_t> markedInterfaces;

    // Set boot services that work with protocols
    std::vector<std::string> protBsNames = {"InstallProtocolInterface",
                                            "ReinstallProtocolInterface",
                                            "UninstallProtocolInterface",
                                            "HandleProtocol",
                                            "RegisterProtocolNotify",
                                            "OpenProtocol",
                                            "CloseProtocol",
                                            "OpenProtocolInformation",
                                            "ProtocolsPerHandle",
                                            "LocateHandleBuffer",
                                            "LocateProtocol",
                                            "InstallMultipleProtocolInterfaces",
                                            "UninstallMultipleProtocolInterfaces"};

    // Set smm services that work with protocols
    std::vector<std::string> protSmmNames = {"SmmInstallProtocolInterface",
                                             "SmmUninstallProtocolInterface",
                                             "SmmHandleProtocol",
                                             "SmmRegisterProtocolNotify",
                                             "SmmLocateHandle",
                                             "SmmLocateProtocol"};

    // Set of PEI services that work with PPI
    std::vector<std::string> ppiPEINames = {"InstallPpi", "ReInstallPpi", "LocatePpi",
                                            "NotifyPpi"};

    // Format-dependent interface-related settings (protocols for DXE, PPIs for PEI)
    char *if_name;
    char *if_pl;
    char *if_key;
    std::vector<json> *if_tbl;
    void AddProtocol(std::string serviceName, ea_t guidAddress, ea_t xrefAddress,
                     ea_t callAddress);
    bool InstallMultipleProtocolInterfacesHandler();

    // EFI_SMM_SW_DISPATCH2_PROTOCOL_GUID
    EfiGuid sw_guid2 = {
        0x18a3c6dc, 0x5eea, 0x48c8, {0xa1, 0xc1, 0xb5, 0x33, 0x89, 0xf9, 0x89, 0x99}};
    // EFI_SMM_SW_DISPATCH_PROTOCOL_GUID
    EfiGuid sw_guid = {
        0xe541b773, 0xdd11, 0x420c, {0xb0, 0x26, 0xdf, 0x99, 0x36, 0x53, 0xf8, 0xbf}};
    // EFI_SMM_SX_DISPATCH2_PROTOCOL_GUID
    EfiGuid sx_guid2 = {
        0x456d2859, 0xa84b, 0x4e47, {0xa2, 0xee, 0x32, 0x76, 0xd8, 0x86, 0x99, 0x7d}};
    // EFI_SMM_SX_DISPATCH_PROTOCOL_GUID
    EfiGuid sx_guid = {
        0x456D2859, 0xA84B, 0x4E47, {0xA2, 0xEE, 0x32, 0x76, 0xD8, 0x86, 0x99, 0x7D}};
    // EFI_SMM_IO_TRAP_DISPATCH2_PROTOCOL_GUID
    EfiGuid io_trap_guid2 = {
        0x58DC368D, 0x7BFA, 0x4E77, {0xAB, 0xBC, 0x0E, 0x29, 0x41, 0x8D, 0xF9, 0x30}};
    // EFI_SMM_IO_TRAP_DISPATCH_PROTOCOL_GUID
    EfiGuid io_trap_guid = {
        0xDB7F536B, 0xEDE4, 0x4714, {0xA5, 0xC8, 0xE3, 0x46, 0xEB, 0xAA, 0x20, 0x1D}};
    // EFI_SMM_GPI_DISPATCH2_PROTOCOL_GUID
    EfiGuid gpi_guid2 = {
        0x25566B03, 0xB577, 0x4CBF, {0x95, 0x8C, 0xED, 0x66, 0x3E, 0xA2, 0x43, 0x80}};
    // EFI_SMM_GPI_DISPATCH_PROTOCOL_GUID
    EfiGuid gpi_guid = {
        0xE0744B81, 0x9513, 0x49CD, {0x8C, 0xEA, 0xE9, 0x24, 0x5E, 0x70, 0x39, 0xDA}};
    // EFI_SMM_USB_DISPATCH2_PROTOCOL_GUID
    EfiGuid usb_guid2 = {
        0xEE9B8D90, 0xC5A6, 0x40A2, {0xBD, 0xE2, 0x52, 0x55, 0x8D, 0x33, 0xCC, 0xA1}};
    // EFI_SMM_USB_DISPATCH_PROTOCOL_GUID
    EfiGuid usb_guid = {
        0xA05B6FFD, 0x87AF, 0x4E42, {0x95, 0xC9, 0x62, 0x28, 0xB6, 0x3C, 0xF3, 0xF3}};
    // EFI_SMM_STANDBY_BUTTON_DISPATCH2_PROTOCOL_GUID
    EfiGuid standby_button_guid2 = {
        0x7300C4A1, 0x43F2, 0x4017, {0xA5, 0x1B, 0xC8, 0x1A, 0x7F, 0x40, 0x58, 0x5B}};
    // EFI_SMM_STANDBY_BUTTON_DISPATCH_PROTOCOL_GUID
    EfiGuid standby_button_guid = {
        0x78965B98, 0xB0BF, 0x449E, {0x8B, 0x22, 0xD2, 0x91, 0x4E, 0x49, 0x8A, 0x98}};
    // EFI_SMM_PERIODIC_TIMER_DISPATCH2_PROTOCOL_GUID
    EfiGuid periodic_timer_guid2 = {
        0x4CEC368E, 0x8E8E, 0x4D71, {0x8B, 0xE1, 0x95, 0x8C, 0x45, 0xFC, 0x8A, 0x53}};
    // EFI_SMM_PERIODIC_TIMER_DISPATCH_PROTOCOL_GUID
    EfiGuid periodic_timer_guid = {
        0x9CCA03FC, 0x4C9E, 0x4A19, {0x9B, 0x06, 0xED, 0x7B, 0x47, 0x9B, 0xDE, 0x55}};
    // EFI_SMM_POWER_BUTTON_DISPATCH2_PROTOCOL_GUID
    EfiGuid power_button_guid2 = {
        0x1B1183FA, 0x1823, 0x46A7, {0x88, 0x72, 0x9C, 0x57, 0x87, 0x55, 0x40, 0x9D}};
    // EFI_SMM_POWER_BUTTON_DISPATCH_PROTOCOL_GUID
    EfiGuid power_button_guid = {
        0xB709EFA0, 0x47A6, 0x4B41, {0xB9, 0x31, 0x12, 0xEC, 0xE7, 0xA8, 0xEE, 0x56}};
};

bool efiAnalyzerMainX64();
bool efiAnalyzerMainX86();
}; // namespace EfiAnalysis

void showAllChoosers(EfiAnalysis::EfiAnalyzer analyzer);
