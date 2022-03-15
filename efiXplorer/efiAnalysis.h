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
};

bool efiAnalyzerMainX64();
bool efiAnalyzerMainX86();
}; // namespace EfiAnalysis

void showAllChoosers(EfiAnalysis::EfiAnalyzer analyzer);
