/*
 * efiXplorer
 * Copyright (C) 2020-2021 Binarly
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
 * efiAnalysis.cpp
 *
 */

#include "efiAnalysis.h"
#include "efiPluginArgs.h"
#include "efiUi.h"
#include "tables/efi_pei_tables.h"
#include "tables/efi_services.h"

#ifdef HEX_RAYS
#include "efiHexRays.h"
#endif

using namespace EfiAnalysis;

static const char plugin_name[] = "efiXplorer";

std::vector<ea_t> gStList;
std::vector<ea_t> gPeiSvcList;
std::vector<ea_t> gBsList;
std::vector<ea_t> gRtList;
std::vector<ea_t> gSmstList;
std::vector<ea_t> gImageHandleList;
std::vector<ea_t> gRtServicesList;
std::vector<json> stackGuids;
std::vector<json> dataGuids;

// all .text and .data segments for compatibility with the efiLoader
std::vector<segment_t *> textSegments;
std::vector<segment_t *> dataSegments;

// for smm callouts finding
std::vector<ea_t> calloutAddrs;
std::vector<func_t *> excFunctions;
std::vector<func_t *> childSmiHandlers;
std::vector<ea_t> readSaveStateCalls;

// for GetVariable stack overflow finding
std::vector<ea_t> peiGetVariableOverflow;
std::vector<ea_t> getVariableOverflow;
std::vector<ea_t> smmGetVariableOverflow;

EfiAnalysis::EfiAnalyzer::EfiAnalyzer() {
    // 32-bit, 64-bit or UEFI (in loader instance)
    arch = getArch();

    // get guids.json path
    guidsJsonPath /= getGuidsJsonFile();

    // get base address
    base = get_imagebase();

    func_t *start_func = nullptr;
    func_t *end_func = nullptr;

    // get start address for scan
    start_func = getn_func(0);
    if (start_func) {
        startAddress = start_func->start_ea;
    }

    // get end address for scan
    end_func = getn_func(get_func_qty() - 1);
    if (end_func) {
        endAddress = end_func->end_ea;
    }

    std::vector<ea_t> addrs;
    for (auto service : protBsNames) {
        bootServices[service] = addrs;
    }

    for (auto service : protSmmNames) {
        smmServices[service] = addrs;
    }

    // load protocols from guids/guids.json file
    std::ifstream in(guidsJsonPath);
    in >> dbProtocols;

    // get reverse dictionary
    for (auto g = dbProtocols.begin(); g != dbProtocols.end(); ++g) {
        dbProtocolsMap[static_cast<json>(g.value())] = static_cast<std::string>(g.key());
    }

    // import necessary types
    const til_t *idati = get_idati();
    import_type(idati, -1, "EFI_GUID");
    import_type(idati, -1, "EFI_SYSTEM_TABLE");
    import_type(idati, -1, "EFI_BOOT_SERVICES");
    import_type(idati, -1, "EFI_RUNTIME_SERVICES");
    import_type(idati, -1, "_EFI_SMM_SYSTEM_TABLE2");
    import_type(idati, -1, "EFI_PEI_SERVICES");
    import_type(idati, -1, "EFI_PEI_READ_ONLY_VARIABLE2_PPI");
    import_type(idati, -1, "EFI_SMM_VARIABLE_PROTOCOL");
}

EfiAnalysis::EfiAnalyzer::~EfiAnalyzer() {
    gStList.clear();
    gPeiSvcList.clear();
    gBsList.clear();
    gRtList.clear();
    gSmstList.clear();
    gImageHandleList.clear();
    gRtServicesList.clear();
    stackGuids.clear();
    dataGuids.clear();

    textSegments.clear();
    dataSegments.clear();

    calloutAddrs.clear();
    excFunctions.clear();
    readSaveStateCalls.clear();

    peiGetVariableOverflow.clear();
    getVariableOverflow.clear();
    smmGetVariableOverflow.clear();
}

void EfiAnalysis::EfiAnalyzer::setStrings() {

    if (fileType == FTYPE_DXE_AND_THE_LIKE) {
        if_name = " Protocol name ";
        if_pl = "protocols";
        if_key = "prot_name";
        if_tbl = &allProtocols;

    } else if (fileType == FTYPE_PEI) {
        if_name = " PPI name ";
        if_pl = "PPIs";
        if_key = "ppi_name";
        if_tbl = &allPPIs;
    }
}

//--------------------------------------------------------------------------
// Get all .text and .data segments
void EfiAnalysis::EfiAnalyzer::getSegments() {
    for (segment_t *s = get_first_seg(); s != NULL; s = get_next_seg(s->start_ea)) {
        qstring seg_name;
        get_segm_name(&seg_name, s);

        std::vector<std::string> codeSegNames{
            ".text", ".code"}; // for compatibility with ida-efitools2
        for (auto name : codeSegNames) {
            auto index = seg_name.find(name.c_str());
            if (index != std::string::npos) {
                textSegments.push_back(s);
                continue;
            }
        }

        auto index = seg_name.find(".data");
        if (index != std::string::npos) {
            dataSegments.push_back(s);
            continue;
        }
    }

    // print all .text and .code segments addresses
    for (auto seg : textSegments) {
        segment_t *s = seg;
        msg("[%s] code segment: 0x%016llX\n", plugin_name,
            static_cast<uint64_t>(s->start_ea));
    }

    // print all .data segments addresses
    for (auto seg : dataSegments) {
        segment_t *s = seg;
        msg("[%s] data segment: 0x%016llX\n", plugin_name,
            static_cast<uint64_t>(s->start_ea));
    }
}

//--------------------------------------------------------------------------
// Find `gImageHandle` address for X64 modules
bool EfiAnalysis::EfiAnalyzer::findImageHandleX64() {
    msg("[%s] gImageHandle finding\n", plugin_name);
    insn_t insn;
    for (int idx = 0; idx < get_entry_qty(); idx++) {

        // get address of entry point
        uval_t ord = get_entry_ordinal(idx);
        ea_t ea = get_entry(ord);

        // EFI_IMAGE_HANDLE finding, first 8 instructions checking
        for (auto i = 0; i < 8; i++) {
            decode_insn(&insn, ea);
            if (insn.itype == NN_mov && insn.ops[1].type == o_reg &&
                insn.ops[1].reg == REG_RCX && insn.ops[0].type == o_mem) {
                msg("[%s] found ImageHandle at 0x%016llX, address = 0x%016llX\n",
                    plugin_name, static_cast<uint64_t>(ea),
                    static_cast<uint64_t>(insn.ops[0].addr));
                set_cmt(ea, "EFI_IMAGE_HANDLE gImageHandle", true);

                // set type and name
                setTypeAndName(insn.ops[0].addr, "gImageHandle", "EFI_IMAGE_HANDLE");
                gImageHandleList.push_back(insn.ops[0].addr);
                break;
            }
            ea = next_head(ea, endAddress);
        }
    }
    return true;
}

//--------------------------------------------------------------------------
// Find gST address for X64 modules
bool EfiAnalysis::EfiAnalyzer::findSystemTableX64() {
    msg("[%s] gEfiSystemTable finding\n", plugin_name);
    insn_t insn;
    for (int idx = 0; idx < get_entry_qty(); idx++) {

        // get address of entry point
        uval_t ord = get_entry_ordinal(idx);
        ea_t ea = get_entry(ord);

        // EFI_SYSTEM_TABLE finding, first 16 instructions checking
        for (int i = 0; i < 16; i++) {
            decode_insn(&insn, ea);
            if (insn.itype == NN_mov && insn.ops[1].type == o_reg &&
                insn.ops[1].reg == REG_RDX && insn.ops[0].type == o_mem) {
                set_cmt(ea, "EFI_SYSTEM_TABLE *gST", true);
                setPtrTypeAndName(insn.ops[0].addr, "gST", "EFI_SYSTEM_TABLE");
                gStList.push_back(insn.ops[0].addr);
                return true;
            }
            ea = next_head(ea, BADADDR);
        }
    }
    return false;
}

//--------------------------------------------------------------------------
// Find and mark gSmst global variable address for X64 module
bool EfiAnalysis::EfiAnalyzer::findSmstX64() {
    msg("[%s] gSmst finding\n", plugin_name);
    std::vector<ea_t> gSmstListSmmBase = findSmstSmmBase(gBsList, dataSegments);
    std::vector<ea_t> gSmstListSwDispatch = findSmstSwDispatch(gBsList, dataSegments);
    gSmstList.insert(gSmstList.end(), gSmstListSwDispatch.begin(),
                     gSmstListSwDispatch.end());
    gSmstList.insert(gSmstList.end(), gSmstListSmmBase.begin(), gSmstListSmmBase.end());
    return gSmstList.size();
}

//--------------------------------------------------------------------------
// Find gBS addresses for X86/X64 modules
bool EfiAnalysis::EfiAnalyzer::findBootServicesTables() {
    // init architecture-specific constants
    auto BS_OFFSET = BS_OFFSET_64BIT;
    auto REG_SP = REG_RSP;
    if (arch == X86) {
        BS_OFFSET = BS_OFFSET_32BIT;
        REG_SP = REG_ESP;
    }

    insn_t insn;
    for (auto seg : textSegments) {
        segment_t *s = seg;
        msg("[%s] gEfiBootServices finding from 0x%016llX to 0x%016llX\n", plugin_name,
            static_cast<uint64_t>(s->start_ea), static_cast<uint64_t>(s->end_ea));
        ea_t ea = s->start_ea;
        uint16_t bsRegister = 0;
        uint16_t stRegister = 0;
        ea_t varAddr = BADADDR; // current global variable address
        while (ea <= s->end_ea) {
            decode_insn(&insn, ea);
            if (insn.itype == NN_mov && insn.ops[1].type == o_displ &&
                insn.ops[1].phrase != REG_SP) {
                if (insn.ops[0].type == o_reg && insn.ops[1].addr == BS_OFFSET) {
                    bsRegister = insn.ops[0].reg;
                    stRegister = insn.ops[1].phrase;
                    auto bsFound = false;
                    auto stFound = false;
                    ea_t baseInsnAddr;

                    // found `BS_OFFSET`, need to check 10 instructions below
                    for (auto i = 0; i < 10; i++) {
                        decode_insn(&insn, ea);
                        if (insn.itype == NN_mov && insn.ops[1].type == o_reg &&
                            insn.ops[0].type == o_mem) {
                            if (insn.ops[1].reg == bsRegister && !bsFound) {
                                baseInsnAddr = ea;
                                varAddr = insn.ops[0].addr;
                                if (!addrInVec(gBsList, varAddr)) {
                                    set_cmt(ea, "EFI_BOOT_SERVICES *gBS", true);
                                    setPtrTypeAndName(varAddr, "gBS",
                                                      "EFI_BOOT_SERVICES");
                                    gBsList.push_back(varAddr);
                                }
                                bsFound = true;
                            }

                            // here you can also find `gST`
                            if (insn.ops[1].reg == stRegister && !stFound &&
                                stRegister != bsRegister) {
                                varAddr = insn.ops[0].addr;
                                if (!addrInTables(gStList, gBsList, gRtList, varAddr)) {
                                    set_cmt(ea, "EFI_SYSTEM_TABLE *gST", true);
                                    setPtrTypeAndName(varAddr, "gST", "EFI_SYSTEM_TABLE");
                                    gStList.push_back(varAddr);
                                }
                                stFound = true;
                            }
                        }

                        if (bsFound && stFound) {
                            break;
                        }

                        if (bsFound && !stFound) {
                            // check 8 instructions above `baseInsnAddr`
                            ea_t addr = prev_head(baseInsnAddr, startAddress);
                            for (auto i = 0; i < 8; i++) {
                                decode_insn(&insn, addr);
                                if (insn.itype == NN_mov && insn.ops[1].type == o_reg &&
                                    insn.ops[1].reg == stRegister &&
                                    insn.ops[0].type == o_mem) {
                                    varAddr = insn.ops[0].addr;
                                    if (!addrInTables(gStList, gBsList, gRtList,
                                                      varAddr)) {
                                        set_cmt(addr, "EFI_SYSTEM_TABLE *gST", true);
                                        setPtrTypeAndName(varAddr, "gST",
                                                          "EFI_SYSTEM_TABLE");
                                        gStList.push_back(varAddr);
                                    }
                                    stFound = true;
                                    break;
                                }
                                addr = prev_head(addr, startAddress);
                            }
                        }
                        ea = next_head(ea, endAddress);
                    }
                }
            }
            ea = next_head(ea, endAddress);
        }
    }
    return (gBsList.size() != 0);
}

//--------------------------------------------------------------------------
// Find gRT addresses for X86/X64 modules
bool EfiAnalysis::EfiAnalyzer::findRuntimeServicesTables() {
    // init architecture-specific constants
    auto RT_OFFSET = RT_OFFSET_64BIT;
    auto REG_SP = REG_RSP;

    if (arch == X86) {
        RT_OFFSET = RT_OFFSET_32BIT;
        REG_SP = REG_ESP;
    }

    insn_t insn;
    for (auto seg : textSegments) {
        segment_t *s = seg;
        msg("[%s] gEfiRuntimeServices finding from 0x%016llX to 0x%016llX\n", plugin_name,
            static_cast<uint64_t>(s->start_ea), static_cast<uint64_t>(s->end_ea));
        ea_t ea = s->start_ea;
        uint16_t rtRegister = 0;
        uint16_t stRegister = 0;
        ea_t varAddr = BADADDR; // current global variable address
        while (ea <= s->end_ea) {
            decode_insn(&insn, ea);
            if (insn.itype == NN_mov && insn.ops[1].type == o_displ &&
                insn.ops[1].phrase != REG_SP) {
                if (insn.ops[0].type == o_reg && insn.ops[1].addr == RT_OFFSET) {
                    rtRegister = insn.ops[0].reg;
                    stRegister = insn.ops[1].phrase;
                    auto rtFound = false;
                    auto stFound = false;
                    ea_t baseInsnAddr;

                    // found `RT_OFFSET`, need to check 10 instructions below
                    for (auto i = 0; i < 10; i++) {
                        decode_insn(&insn, ea);
                        if (insn.itype == NN_mov && insn.ops[1].type == o_reg &&
                            insn.ops[0].type == o_mem) {
                            if (insn.ops[1].reg == rtRegister && !rtFound) {
                                baseInsnAddr = ea;
                                varAddr = insn.ops[0].addr;
                                if (!addrInVec(gRtList, varAddr)) {
                                    set_cmt(ea, "EFI_RUNTIME_SERVICES *gRT", true);
                                    setPtrTypeAndName(varAddr, "gRT",
                                                      "EFI_RUNTIME_SERVICES");
                                    gRtList.push_back(varAddr);
                                }
                                rtFound = true;
                            }

                            // here you can also find `gST`
                            if (insn.ops[1].reg == stRegister && !stFound &&
                                stRegister != rtRegister) {
                                varAddr = insn.ops[0].addr;
                                if (!addrInTables(gStList, gBsList, gRtList, varAddr)) {
                                    set_cmt(ea, "EFI_SYSTEM_TABLE *gST", true);
                                    setPtrTypeAndName(insn.ops[0].addr, "gST",
                                                      "EFI_SYSTEM_TABLE");
                                    gStList.push_back(insn.ops[0].addr);
                                }
                                stFound = true;
                            }
                        }

                        if (rtFound && stFound) {
                            break;
                        }

                        if (rtFound && !stFound) {
                            // check 8 instructions above `baseInsnAddr`
                            ea_t addr = prev_head(baseInsnAddr, startAddress);
                            for (auto i = 0; i < 8; i++) {
                                decode_insn(&insn, addr);
                                if (insn.itype == NN_mov && insn.ops[1].type == o_reg &&
                                    insn.ops[1].reg == stRegister &&
                                    insn.ops[0].type == o_mem) {
                                    if (!addrInTables(gStList, gBsList, gRtList,
                                                      varAddr)) {
                                        set_cmt(addr, "EFI_SYSTEM_TABLE *gST", true);
                                        setPtrTypeAndName(varAddr, "gST",
                                                          "EFI_SYSTEM_TABLE");
                                        gStList.push_back(varAddr);
                                    }
                                    stFound = true;
                                    break;
                                }
                                addr = prev_head(addr, startAddress);
                            }
                        }
                        ea = next_head(ea, endAddress);
                    }
                }
            }
            ea = next_head(ea, endAddress);
        }
    }
    return (gRtList.size() != 0);
}

//--------------------------------------------------------------------------
// Get all boot services for X86/X64 modules
void EfiAnalysis::EfiAnalyzer::getAllBootServices() {
    msg("[%s] BootServices finding (all)\n", plugin_name);

    if (!gBsList.size()) {
        return;
    }

    // init architecture-specific constants
    auto REG_AX = REG_RAX;
    if (arch == X86) {
        REG_AX = REG_EAX;
    }

    insn_t insn;
    auto found = false;
    for (auto seg : textSegments) {
        segment_t *s = seg;
        ea_t ea = s->start_ea;
        while (ea <= s->end_ea) {
            decode_insn(&insn, ea);
            for (auto bs : gBsList) {
                if (insn.itype == NN_mov && insn.ops[0].reg == REG_AX &&
                    insn.ops[1].type == o_mem && insn.ops[1].addr == bs) {
                    ea_t addr = next_head(ea, BADADDR);

                    // 16 instructions below
                    for (auto i = 0; i < 16; i++) {
                        decode_insn(&insn, addr);
                        if (insn.itype == NN_callni && insn.ops[0].reg == REG_AX) {
                            for (int j = 0; j < bootServicesTableAllLength; j++) {

                                // architecture-specific variables
                                auto offset = bootServicesTableAll[j].offset64;
                                if (arch == X86) {
                                    offset = bootServicesTableAll[j].offset32;
                                }

                                if (insn.ops[0].addr == static_cast<uint32_t>(offset)) {

                                    // additional check for gBS->RegisterProtocolNotify
                                    // (can be confused with
                                    // gSmst->SmmInstallProtocolInterface)
                                    if (static_cast<uint32_t>(offset) ==
                                        RegisterProtocolNotifyOffset64) {
                                        if (!bootServiceProtCheck(addr)) {
                                            break;
                                        }
                                    }

                                    found = true;
                                    std::string cmt =
                                        getBsComment(static_cast<uint32_t>(offset), arch);
                                    set_cmt(addr, cmt.c_str(), true);
                                    opStroff(addr, "EFI_BOOT_SERVICES");
                                    msg("[%s] 0x%016llX : %s\n", plugin_name,
                                        static_cast<uint64_t>(addr),
                                        static_cast<char *>(
                                            bootServicesTableAll[j].service_name));
                                    bootServicesAll[static_cast<std::string>(
                                                        bootServicesTableAll[j]
                                                            .service_name)]
                                        .push_back(addr);

                                    // add item to allBootServices
                                    json bsItem;
                                    bsItem["address"] = addr;
                                    bsItem["service_name"] = static_cast<std::string>(
                                        bootServicesTableAll[j].service_name);
                                    bsItem["table_name"] =
                                        static_cast<std::string>("EFI_BOOT_SERVICES");
                                    bsItem["offset"] = offset;
                                    if (find(allServices.begin(), allServices.end(),
                                             bsItem) == allServices.end()) {
                                        allServices.push_back(bsItem);
                                    }
                                    break;
                                }
                            }
                        }
                        addr = next_head(addr, BADADDR);
                    }
                }
            }
            ea = next_head(ea, BADADDR);
        }
    }
}

//--------------------------------------------------------------------------
// Get all runtime services for X86/X64 modules
void EfiAnalysis::EfiAnalyzer::getAllRuntimeServices() {
    msg("[%s] RuntimeServices finding (all)\n", plugin_name);

    if (!gRtList.size()) {
        return;
    }

    insn_t insn;
    auto found = false;
    for (auto seg : textSegments) {
        segment_t *s = seg;
        msg("[%s] RuntimeServices finding from 0x%016llX to 0x%016llX\n", plugin_name,
            static_cast<uint64_t>(s->start_ea), static_cast<uint64_t>(s->end_ea));
        ea_t ea = s->start_ea;
        while (ea <= s->end_ea) {
            decode_insn(&insn, ea);
            for (auto rt : gRtList) {
                if (insn.itype == NN_mov && insn.ops[0].reg == REG_RAX &&
                    insn.ops[1].type == o_mem && insn.ops[1].addr == rt) {
                    ea_t addr = next_head(ea, BADADDR);

                    // 16 instructions below
                    for (int i = 0; i < 16; i++) {
                        decode_insn(&insn, addr);
                        if (insn.itype == NN_callni && insn.ops[0].reg == REG_RAX) {
                            for (int j = 0; j < runtimeServicesTableAllLength; j++) {

                                // architecture-specific variables
                                auto offset = runtimeServicesTableAll[j].offset64;
                                if (arch == X86) {
                                    offset = runtimeServicesTableAll[j].offset32;
                                }
                                if (insn.ops[0].addr == static_cast<uint32_t>(offset)) {
                                    found = true;
                                    std::string cmt =
                                        getRtComment(static_cast<uint32_t>(offset), arch);
                                    set_cmt(addr, cmt.c_str(), true);
                                    opStroff(addr, "EFI_RUNTIME_SERVICES");
                                    msg("[%s] 0x%016llX : %s\n", plugin_name,
                                        static_cast<uint64_t>(addr),
                                        static_cast<char *>(
                                            runtimeServicesTableAll[j].service_name));
                                    runtimeServicesAll[static_cast<std::string>(
                                                           runtimeServicesTableAll[j]
                                                               .service_name)]
                                        .push_back(addr);

                                    // add item to allRuntimeServices
                                    json rtItem;
                                    rtItem["address"] = addr;
                                    rtItem["service_name"] = static_cast<std::string>(
                                        runtimeServicesTableAll[j].service_name);
                                    rtItem["table_name"] =
                                        static_cast<std::string>("EFI_RUNTIME_SERVICES");
                                    rtItem["offset"] = offset;
                                    if (find(allServices.begin(), allServices.end(),
                                             rtItem) == allServices.end()) {
                                        allServices.push_back(rtItem);
                                    }
                                    gRtServicesList.push_back(addr);
                                    break;
                                }
                            }
                        }
                        addr = next_head(addr, BADADDR);
                    }
                }
            }
            ea = next_head(ea, BADADDR);
        }
    }
}

//--------------------------------------------------------------------------
// Get all smm services for X64 modules
void EfiAnalysis::EfiAnalyzer::getAllSmmServicesX64() {
    msg("[%s] SmmServices finding (all)\n", plugin_name);

    if (!gSmstList.size()) {
        return;
    }

    insn_t insn;
    auto found = false;
    for (auto seg : textSegments) {
        segment_t *s = seg;
        msg("[%s] SmmServices finding from 0x%016llX to 0x%016llX\n", plugin_name,
            static_cast<uint64_t>(s->start_ea), static_cast<uint64_t>(s->end_ea));
        ea_t ea = s->start_ea;
        while (ea <= s->end_ea) {
            decode_insn(&insn, ea);
            for (auto smms : gSmstList) {
                if (insn.itype == NN_mov && insn.ops[0].reg == REG_RAX &&
                    insn.ops[1].type == o_mem && insn.ops[1].addr == smms) {
                    ea_t addr = ea;

                    // 10 instructions below
                    for (auto i = 0; i < 10; i++) {
                        decode_insn(&insn, addr);
                        if (insn.itype == NN_callni && insn.ops[0].reg == REG_RAX) {
                            for (int j = 0; j < smmServicesTableAllLength; j++) {
                                if (insn.ops[0].addr ==
                                    static_cast<uint32_t>(
                                        smmServicesTableAll[j].offset64)) {

                                    if (static_cast<uint32_t>(
                                            smmServicesTableAll[j].offset64) ==
                                        SmiHandlerRegisterOffset64) {
                                        // set name for `Handler` argument
                                        auto smiHandlerAddr = markSmiHandler(addr);
                                        // save SMI handler
                                        func_t *childSmiHandler =
                                            get_func(smiHandlerAddr);
                                        if (childSmiHandler != nullptr) {
                                            childSmiHandlers.push_back(childSmiHandler);
                                        }
                                    }

                                    found = true;
                                    std::string cmt =
                                        "gSmst->" +
                                        static_cast<std::string>(
                                            smmServicesTableAll[j].service_name);
                                    set_cmt(addr, cmt.c_str(), true);
                                    opStroff(addr, "_EFI_SMM_SYSTEM_TABLE2");
                                    msg("[%s] 0x%016llX : %s\n", plugin_name,
                                        static_cast<uint64_t>(addr),
                                        static_cast<char *>(
                                            smmServicesTableAll[j].service_name));

                                    // add address to `smmServices[...]`
                                    if (find(protSmmNames.begin(), protSmmNames.end(),
                                             smmServicesTableAll[j].service_name) !=
                                        protSmmNames.end()) {
                                        smmServices[smmServicesTableAll[j].service_name]
                                            .push_back(addr);
                                    }
                                    smmServicesAll[static_cast<std::string>(
                                                       smmServicesTableAll[j]
                                                           .service_name)]
                                        .push_back(addr);

                                    // add item to allSmmServices
                                    json smmsItem;
                                    smmsItem["address"] = addr;
                                    smmsItem["service_name"] = static_cast<std::string>(
                                        smmServicesTableAll[j].service_name);
                                    smmsItem["table_name"] = static_cast<std::string>(
                                        "_EFI_SMM_SYSTEM_TABLE2");
                                    smmsItem["offset"] = smmServicesTableAll[j].offset64;
                                    if (find(allServices.begin(), allServices.end(),
                                             smmsItem) == allServices.end()) {
                                        allServices.push_back(smmsItem);
                                    }
                                    break;
                                }
                            }
                        }
                        addr = next_head(addr, BADADDR);
                    }
                }
            }
            ea = next_head(ea, BADADDR);
        }
    }
}

//--------------------------------------------------------------------------
// Get all Pei services for X86 modules
// Currently should cover all PeiServices except EFI_PEI_COPY_MEM,
// EFI_PEI_SET_MEM, EFI_PEI_RESET2_SYSTEM, and "Future Installed Services"
// (EFI_PEI_FFS_FIND_BY_NAME, etc.)
void EfiAnalysis::EfiAnalyzer::getAllPeiServicesX86() {
    msg("[%s] PeiServices finding from 0x%016llX to 0x%016llX (all)\n", plugin_name,
        static_cast<uint64_t>(startAddress), static_cast<uint64_t>(endAddress));
    ea_t ea = startAddress;
    insn_t insn;
    auto found = false;
    while (ea <= endAddress) {
        decode_insn(&insn, ea);
        if (insn.itype == NN_callni &&
            (insn.ops[0].reg == REG_EAX || insn.ops[0].reg == REG_ECX ||
             insn.ops[0].reg == REG_EDX)) {
            for (int j = 0; j < pei_services_table_size; j++) {
                if (insn.ops[0].addr ==
                    static_cast<uint32_t>(pei_services_table[j].offset)) {
                    bool found_src_reg = false;
                    ea_t address = ea;
                    insn_t aboveInst;
                    uint16_t src_reg = 0xffff;

                    // 15 instructions above
                    for (auto j = 0; j < 15; j++) {
                        address = prev_head(address, startAddress);
                        decode_insn(&aboveInst, address);
                        if (aboveInst.itype == NN_mov && aboveInst.ops[0].type == o_reg &&
                            aboveInst.ops[0].reg == insn.ops[0].reg &&
                            aboveInst.ops[1].type == o_phrase) {
                            found_src_reg = true;
                            src_reg = aboveInst.ops[1].reg;
                        }
                    }

                    bool found_push = false;

                    // 15 instructions above
                    address = ea;
                    for (auto j = 0; j < 15; j++) {
                        address = prev_head(address, startAddress);
                        decode_insn(&aboveInst, address);
                        if (aboveInst.itype == NN_push) {
                            if (aboveInst.ops[0].type == o_reg &&
                                aboveInst.ops[0].reg == src_reg) {
                                found_push = true;
                            }
                            break;
                        }
                    }

                    if (found_src_reg && found_push) {
                        std::string cmt = getPeiSvcComment(
                            static_cast<uint32_t>(pei_services_table[j].offset));
                        set_cmt(ea, cmt.c_str(), true);
                        opStroff(ea, "EFI_PEI_SERVICES");
                        msg("[%s] 0x%016llX : %s\n", plugin_name,
                            static_cast<uint64_t>(ea),
                            static_cast<char *>(pei_services_table[j].name));
                        peiServicesAll[static_cast<std::string>(
                                           pei_services_table[j].name)]
                            .push_back(ea);
                        json psItem;
                        psItem["address"] = ea;
                        psItem["service_name"] =
                            static_cast<std::string>(pei_services_table[j].name);
                        psItem["table_name"] =
                            static_cast<std::string>("EFI_PEI_SERVICES");
                        psItem["offset"] = pei_services_table[j].offset;
                        if (find(allServices.begin(), allServices.end(), psItem) ==
                            allServices.end()) {
                            allServices.push_back(psItem);
                        }
                    }
                    break;
                }
            }
        }
        ea = next_head(ea, BADADDR);
    }
}

//--------------------------------------------------------------------------
// Get all EFI_PEI_READ_ONLY_VARIABLE2_PPI (GetVariable, NextVariableName)
void EfiAnalysis::EfiAnalyzer::getAllVariablePPICallsX86() {
    msg("[%s] Variable PPI calls finding from 0x%016llX to 0x%016llX (all)\n",
        plugin_name, static_cast<uint64_t>(startAddress),
        static_cast<uint64_t>(endAddress));
    ea_t ea = startAddress;
    insn_t insn;
    auto found = false;
    while (ea <= endAddress) {
        decode_insn(&insn, ea);
        if (insn.itype == NN_callni && insn.ops[0].type == o_phrase) {
            for (int j = 0; j < variable_ppi_table_size; j++) {
                if (insn.ops[0].addr ==
                    static_cast<uint32_t>(variable_ppi_table[j].offset)) {
                    uint16_t ppi_reg = insn.ops[0].reg;
                    insn_t aboveInst;
                    ea_t address = ea;
                    bool found_push = false;

                    for (auto j = 0; j < 15; j++) {
                        address = prev_head(address, startAddress);
                        decode_insn(&aboveInst, address);
                        if (aboveInst.itype == NN_push) {
                            if (aboveInst.ops[0].type == o_reg &&
                                aboveInst.ops[0].reg == ppi_reg) {
                                found_push = true;
                            }
                            break;
                        }
                    }

                    if (found_push) {
                        std::string cmt = getPPICallComment(
                            static_cast<uint32_t>(variable_ppi_table[j].offset),
                            static_cast<std::string>(variable_ppi_name));
                        set_cmt(ea, cmt.c_str(), true);
                        opStroff(ea, "EFI_PEI_READ_ONLY_VARIABLE2_PPI");
                        msg("[%s] 0x%016llX : %s\n", plugin_name,
                            static_cast<uint64_t>(ea),
                            static_cast<char *>(variable_ppi_table[j].name));
                        std::string ppi_call =
                            static_cast<std::string>(variable_ppi_name) + "." +
                            static_cast<std::string>(variable_ppi_table[j].name);
                        ppiCallsAll[ppi_call].push_back(ea);

                        // Injecting PPI call as service
                        json ppiItem;
                        ppiItem["address"] = ea;
                        ppiItem["service_name"] = ppi_call;
                        ppiItem["table_name"] =
                            static_cast<std::string>("EFI_PEI_READ_ONLY_VARIABLE2_PPI");
                        ppiItem["offset"] = variable_ppi_table[j].offset;
                        if (find(allServices.begin(), allServices.end(), ppiItem) ==
                            allServices.end()) {
                            allServices.push_back(ppiItem);
                        }
                    }
                    break;
                }
            }
        }
        ea = next_head(ea, BADADDR);
    }
}

//--------------------------------------------------------------------------
// Get PPI names for X86 PEI modules
void EfiAnalysis::EfiAnalyzer::getPpiNamesX86() {
    msg("[%s] PPI finding (PEI services)\n", plugin_name);
    ea_t start = startAddress;
    segment_t *seg_info = get_segm_by_name(".text");
    if (seg_info != nullptr) {
        start = seg_info->start_ea;
    }
    for (int i = 0; i < pei_services_table_size; i++) {
        if (pei_services_table[i].ppi_guid_push_number == PUSH_NONE ||
            !peiServicesAll.contains(pei_services_table[i].name)) {
            continue;
        }

        std::vector<ea_t> addrs = peiServicesAll[pei_services_table[i].name];

        // for each PEI service
        for (auto ea : addrs) {
            ea_t address = ea;

            insn_t insn;
            ea_t guidCodeAddress = 0;
            ea_t guidDataAddress = 0;
            auto found = false;
            uint16_t pushNumber = pei_services_table[i].ppi_guid_push_number;

            // 10 instructions above
            uint16_t pushCounter = 0;
            msg("[%s] looking for PPIs in the 0x%016llX area\n", plugin_name,
                static_cast<uint64_t>(address));
            for (auto j = 0; j < 10; j++) {
                address = prev_head(address, startAddress);
                decode_insn(&insn, address);
                if (insn.itype == NN_push) {
                    pushCounter += 1;
                    if (pushCounter > pushNumber) {
                        break;
                    }
                    if (pushCounter == pushNumber) {
                        uint32_t g_offset = pei_services_table[i].guid_offset;
                        if (g_offset == GUID_OFFSET_NONE) {
                            guidCodeAddress = address;
                            guidDataAddress =
                                truncImmToDtype(insn.ops[0].value, insn.ops[0].dtype);
                        } else {
                            guidCodeAddress = address;
                            ea_t guidDataAddressXref =
                                truncImmToDtype(insn.ops[0].value, insn.ops[0].dtype);
                            guidDataAddress =
                                get_wide_dword(guidDataAddressXref + g_offset);
                        }
                        if (guidDataAddress >= start && guidDataAddress != BADADDR) {
                            found = true;
                            break;
                        }
                    }
                }
            }

            if (found) {
                msg("[%s] found PPI GUID parameter at 0x%016llX\n", plugin_name,
                    static_cast<uint64_t>(guidCodeAddress));
                auto guid = getGuidByAddr(guidDataAddress);
                if (!checkGuid(guid)) {
                    msg("[%s] Incorrect GUID at 0x%016llX\n", plugin_name,
                        static_cast<uint64_t>(guidCodeAddress));
                    continue;
                }

                // get PPI item
                json ppiItem;
                ppiItem["address"] = guidDataAddress;
                ppiItem["xref"] = guidCodeAddress;
                ppiItem["service"] = pei_services_table[i].name;
                ppiItem["guid"] = getGuidFromValue(guid);

                // find GUID name
                auto it = dbProtocolsMap.find(guid);
                if (it != dbProtocolsMap.end()) {
                    std::string name = it->second;
                    ppiItem["ppi_name"] = name;

                    // check if item already exists
                    if (find(allPPIs.begin(), allPPIs.end(), ppiItem) == allPPIs.end()) {
                        allPPIs.push_back(ppiItem);
                    }
                    continue;
                }

                // proprietary PPI
                if (ppiItem["ppi_name"].is_null()) {
                    ppiItem["ppi_name"] = "ProprietaryPpi";

                    // check if item already exists
                    if (find(allPPIs.begin(), allPPIs.end(), ppiItem) == allPPIs.end()) {
                        allPPIs.push_back(ppiItem);
                    }
                    continue;
                }
            }
        }
    }
}

//--------------------------------------------------------------------------
// Get boot services by protocols for X64 modules
void EfiAnalysis::EfiAnalyzer::getProtBootServicesX64() {
    insn_t insn;
    for (auto seg : textSegments) {
        segment_t *s = seg;
        msg("[%s] BootServices finding from 0x%016llX to 0x%016llX (protocols)\n",
            plugin_name, static_cast<uint64_t>(s->start_ea),
            static_cast<uint64_t>(s->end_ea));
        ea_t ea = s->start_ea;
        uint16_t bsRegister = 0;
        while (ea <= s->end_ea) {
            decode_insn(&insn, ea);
            if (insn.itype == NN_callni && insn.ops[0].reg == REG_RAX) {
                for (auto i = 0; i < bootServicesTable64Length; i++) {
                    if (insn.ops[0].addr ==
                        static_cast<uint32_t>(bootServicesTable64[i].offset)) {

                        // additional check for gBS->RegisterProtocolNotify
                        // (can be confused with gSmst->SmmInstallProtocolInterface)
                        if (static_cast<uint32_t>(bootServicesTable64[i].offset) ==
                            RegisterProtocolNotifyOffset64) {
                            if (!bootServiceProtCheck(ea)) {
                                break;
                            }
                        }

                        std::string cmt = getBsComment(
                            static_cast<uint32_t>(bootServicesTable64[i].offset), X64);
                        set_cmt(ea, cmt.c_str(), true);
                        opStroff(ea, "EFI_BOOT_SERVICES");
                        msg("[%s] 0x%016llX : %s\n", plugin_name,
                            static_cast<uint64_t>(ea),
                            static_cast<char *>(bootServicesTable64[i].service_name));
                        bootServices[static_cast<std::string>(
                                         bootServicesTable64[i].service_name)]
                            .push_back(ea);

                        // add item to `allBootServices`
                        json bsItem;
                        bsItem["address"] = ea;
                        bsItem["service_name"] =
                            static_cast<std::string>(bootServicesTable64[i].service_name);
                        bsItem["table_name"] =
                            static_cast<std::string>("EFI_BOOT_SERVICES");
                        bsItem["offset"] = bootServicesTable64[i].offset;
                        if (find(allServices.begin(), allServices.end(), bsItem) ==
                            allServices.end()) {
                            allServices.push_back(bsItem);
                        }
                        break;
                    }
                }
            }
            ea = next_head(ea, endAddress);
        }
    }
}

//--------------------------------------------------------------------------
// Get boot services by protocols for X86 modules
void EfiAnalysis::EfiAnalyzer::getProtBootServicesX86() {
    msg("[%s] BootServices finding from 0x%016llX to 0x%016llX (protocols)\n",
        plugin_name, static_cast<uint64_t>(startAddress),
        static_cast<uint64_t>(endAddress));
    ea_t ea = startAddress;
    insn_t insn;
    uint16_t bsRegister = 0;
    while (ea <= endAddress) {
        decode_insn(&insn, ea);
        if (insn.itype == NN_callni && insn.ops[0].reg == REG_EAX) {
            for (auto i = 0; i < bootServicesTable32Length; i++) {
                if (insn.ops[0].addr ==
                    static_cast<uint32_t>(bootServicesTable32[i].offset)) {
                    std::string cmt = getBsComment(
                        static_cast<uint32_t>(bootServicesTable32[i].offset), X86);
                    set_cmt(ea, cmt.c_str(), true);
                    opStroff(ea, "EFI_BOOT_SERVICES");
                    msg("[%s] 0x%016llX : %s\n", plugin_name, static_cast<uint64_t>(ea),
                        static_cast<char *>(bootServicesTable32[i].service_name));
                    bootServices[static_cast<std::string>(
                                     bootServicesTable32[i].service_name)]
                        .push_back(ea);

                    // add item to `allBootServices`
                    json bsItem;
                    bsItem["address"] = ea;
                    bsItem["service_name"] =
                        static_cast<std::string>(bootServicesTable32[i].service_name);
                    bsItem["table_name"] = static_cast<std::string>("EFI_BOOT_SERVICES");
                    bsItem["offset"] = bootServicesTable32[i].offset;
                    if (find(allServices.begin(), allServices.end(), bsItem) ==
                        allServices.end()) {
                        allServices.push_back(bsItem);
                    }
                    break;
                }
            }
        }
        ea = next_head(ea, endAddress);
    }
}

//--------------------------------------------------------------------------
// find other addresses of global gBS vars for X64 modules
void EfiAnalysis::EfiAnalyzer::findOtherBsTablesX64() {
    msg("[%s] Finding of other addresses of global gBS variables\n", plugin_name);
    for (auto s : allServices) {
        json jService = s;
        std::string table_name = jService["table_name"];
        if (table_name.compare(static_cast<std::string>("EFI_BOOT_SERVICES"))) {
            continue;
        }
        auto offset = static_cast<uint32_t>(jService["offset"]);
        if (offset < 0xf0) {
            continue;
        }
        ea_t addr = static_cast<ea_t>(jService["address"]);
        msg("[%s] current service: 0x%016llX\n", plugin_name,
            static_cast<uint64_t>(addr));
        ea_t addrBs = findUnknownBsVarX64(addr);
        if (!addrBs || !(find(gBsList.begin(), gBsList.end(), addrBs) == gBsList.end())) {
            continue;
        }
        msg("[%s] found BootServices table at 0x%016llX, address = 0x%016llX\n",
            plugin_name, static_cast<uint64_t>(addr), static_cast<uint64_t>(addrBs));
        setPtrTypeAndName(addrBs, "gBS", "EFI_BOOT_SERVICES");
        if (find(gRtList.begin(), gRtList.end(), addrBs) == gRtList.end()) {
            gBsList.push_back(addrBs);
        }
    }
}

void EfiAnalysis::EfiAnalyzer::AddProtocol(std::string serviceName, ea_t guidAddress,
                                           ea_t xrefAddress, ea_t callAddress) {
    json protocol;
    auto guid = getGuidByAddr(guidAddress);
    protocol["address"] = guidAddress;
    protocol["xref"] = xrefAddress;
    protocol["service"] = serviceName;
    protocol["guid"] = getGuidFromValue(guid);
    protocol["ea"] = callAddress;

    qstring moduleName("Current");
    if (getArch() == UEFI) {
        moduleName = getModuleNameLoader(callAddress);
    }
    protocol["module"] = static_cast<std::string>(moduleName.c_str());

    // find GUID name
    auto it = dbProtocolsMap.find(guid);
    if (it != dbProtocolsMap.end()) {
        std::string name = it->second;
        protocol["prot_name"] = name;
    } else {
        protocol["prot_name"] = "ProprietaryProtocol";
    }
    if (!jsonInVec(allProtocols, protocol)) {
        allProtocols.push_back(protocol);
    }
}

//--------------------------------------------------------------------------
// Extract protocols from InstallMultipleProtocolInterfaces service call
bool EfiAnalysis::EfiAnalyzer::InstallMultipleProtocolInterfacesHandler() {
    std::vector<ea_t> addrs = bootServices["InstallMultipleProtocolInterfaces"];
    std::map<ea_t, ea_t> stack_params;
    insn_t insn;

    for (auto ea : addrs) {
        ea_t address = ea;
        bool found = false;
        bool check_stack = true;
        ea_t handle_arg = BADADDR;
        stack_params.clear();

        // Check current basic block
        while (true) {
            address = prev_head(address, startAddress);
            decode_insn(&insn, address);

            if (!check_stack && found) {
                break; // installed only one protocol
            }

            // Exit loop if end of previous basic block found
            if (is_basic_block_end(insn, false)) {
                break;
            }

            // Get handle stack/data parameter
            if (handle_arg == BADADDR && insn.itype == NN_lea &&
                insn.ops[0].reg == REG_RCX) {
                switch (insn.ops[1].type) {
                case o_displ:
                    if (insn.ops[1].reg == REG_RSP || insn.ops[1].reg == REG_RBP) {
                        handle_arg = insn.ops[1].addr;
                    }
                    break;
                case o_mem:
                    handle_arg = insn.ops[1].addr;
                    break;
                }
            }

            // Exit from loop if found last argument (NULL)
            if (insn.itype == NN_xor && insn.ops[0].reg == REG_R9 &&
                insn.ops[1].reg == REG_R9) {
                check_stack = false;
            }

            if (insn.itype == NN_and && insn.ops[0].type == o_displ &&
                (insn.ops[0].reg == REG_RSP || insn.ops[0].reg == REG_RBP) &&
                insn.ops[0].addr != handle_arg && insn.ops[1].type == o_imm &&
                insn.ops[1].value == 0) {
                check_stack = false;
                break;
            }

            if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
                insn.ops[1].type == o_mem) {

                switch (insn.ops[0].reg) {
                case REG_RDX:
                case REG_R9:
                    AddProtocol("InstallMultipleProtocolInterfaces", insn.ops[1].addr,
                                address, ea);
                    found = true;
                    break;
                case REG_RAX:
                    stack_params.insert(std::make_pair(address, insn.ops[1].addr));
                    break;
                }
            }
        }

        // Enumerate all stack params
        auto index = 0;
        for (auto const &param : stack_params) {
            if (index++ % 2) {
                AddProtocol("InstallMultipleProtocolInterfaces", param.second,
                            param.first, ea);
            }
        }
    }

    return true;
}

//--------------------------------------------------------------------------
// Get boot services protocols names for X64 modules
void EfiAnalysis::EfiAnalyzer::getBsProtNamesX64() {
    if (!textSegments.size()) {
        return;
    }
    segment_t *s = textSegments.at(0);
    ea_t start = s->start_ea;
    msg("[%s] protocols finding (boot services, start address = 0x%016llX)\n",
        plugin_name, static_cast<uint64_t>(start));

    InstallMultipleProtocolInterfacesHandler();
    for (int i = 0; i < bootServicesTable64Length; i++) {

        if (bootServicesTable64[i].offset == InstallMultipleProtocolInterfacesOffset64) {
            // Handle InstallMultipleProtocolInterfaces separately
            continue;
        }

        std::vector<ea_t> addrs = bootServices[bootServicesTable64[i].service_name];
        for (auto ea : addrs) {
            ea_t address = ea;
            msg("[%s] looking for protocols in the 0x%016llX area\n", plugin_name,
                static_cast<uint64_t>(address));
            insn_t insn;
            ea_t guidCodeAddress = 0;
            ea_t guidDataAddress = 0;
            auto found = false;

            // check current basic block
            while (true) {
                address = prev_head(address, startAddress);
                decode_insn(&insn, address);

                // exit from loop if end of previous basic block found
                if (is_basic_block_end(insn, false)) {
                    break;
                }

                if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
                    insn.ops[0].reg == bootServicesTable64[i].reg) {
                    guidCodeAddress = address;
                    guidDataAddress = insn.ops[1].addr;
                    if (insn.ops[1].addr > start && insn.ops[1].addr != BADADDR) {
                        found = true;
                        break;
                    }
                }
            }

            if (found) {
                msg("[%s] found protocol GUID parameter at 0x%016llX\n", plugin_name,
                    static_cast<uint64_t>(guidCodeAddress));
                auto guid = getGuidByAddr(guidDataAddress);
                if (!checkGuid(guid)) {
                    msg("[%s] Incorrect GUID at 0x%016llX\n", plugin_name,
                        static_cast<uint64_t>(guidCodeAddress));
                    continue;
                }

                AddProtocol(bootServicesTable64[i].service_name, guidDataAddress,
                            guidCodeAddress, ea);
            }
        }
    }
}

//--------------------------------------------------------------------------
// Get boot services protocols names for X86 modules
void EfiAnalysis::EfiAnalyzer::getBsProtNamesX86() {
    msg("[%s] protocols finding (boot services)\n", plugin_name);
    ea_t start = startAddress;
    segment_t *seg_info = get_segm_by_name(".text");
    if (seg_info != nullptr) {
        start = seg_info->start_ea;
    }
    for (int i = 0; i < bootServicesTable32Length; i++) {
        std::vector<ea_t> addrs = bootServices[bootServicesTable32[i].service_name];

        // for each boot service
        for (auto ea : addrs) {
            ea_t address = ea;
            msg("[%s] looking for protocols in the 0x%016llX area\n", plugin_name,
                static_cast<uint64_t>(address));
            insn_t insn;
            ea_t guidCodeAddress = 0;
            ea_t guidDataAddress = 0;
            auto found = false;
            uint16_t pushNumber = bootServicesTable32[i].push_number;

            // if service is not currently being processed
            if (pushNumber == PUSH_NONE) {
                break;
            }

            // check current basic block
            uint16_t pushCounter = 0;
            while (true) {
                address = prev_head(address, startAddress);
                decode_insn(&insn, address);

                // exit from loop if end of previous basic block found
                if (is_basic_block_end(insn, false)) {
                    break;
                }

                if (insn.itype == NN_push) {
                    pushCounter += 1;
                    if (pushCounter > pushNumber) {
                        break;
                    }
                    if (pushCounter == pushNumber) {
                        guidCodeAddress = address;
                        guidDataAddress = insn.ops[0].value;
                        if (insn.ops[0].value > start && insn.ops[0].value != BADADDR) {
                            found = true;
                            break;
                        }
                    }
                }
            }

            if (found) {
                msg("[%s] found protocol GUID parameter at 0x%016llX\n", plugin_name,
                    static_cast<uint64_t>(guidCodeAddress));
                auto guid = getGuidByAddr(guidDataAddress);
                if (!checkGuid(guid)) {
                    msg("[%s] Incorrect GUID at 0x%016llX\n", plugin_name,
                        static_cast<uint64_t>(guidCodeAddress));
                    continue;
                }

                AddProtocol(bootServicesTable32[i].service_name, guidDataAddress,
                            guidCodeAddress, ea);
            }
        }
    }
}

//--------------------------------------------------------------------------
// Get smm services protocols names for X64 modules
void EfiAnalysis::EfiAnalyzer::getSmmProtNamesX64() {
    if (!textSegments.size()) {
        return;
    }
    segment_t *s = textSegments.at(0);
    ea_t start = s->start_ea;
    msg("[%s] protocols finding (smm services, start address = 0x%016llX)\n", plugin_name,
        static_cast<uint64_t>(start));
    for (int i = 0; i < smmServicesProt64Length; i++) {
        auto addrs = smmServices[smmServicesProt64[i].service_name];

        // for each SMM service
        for (auto ea : addrs) {
            ea_t address = ea;
            msg("[%s] looking for protocols in the 0x%016llX area\n", plugin_name,
                static_cast<uint64_t>(address));
            insn_t insn;
            ea_t guidCodeAddress = 0;
            ea_t guidDataAddress = 0;
            auto found = false;

            // check current basic block
            while (true) {
                address = prev_head(address, startAddress);
                decode_insn(&insn, address);

                // exit from loop if end of previous basic block found
                if (is_basic_block_end(insn, false)) {
                    break;
                }

                if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
                    insn.ops[0].reg == smmServicesProt64[i].reg) {
                    guidCodeAddress = address;
                    guidDataAddress = insn.ops[1].addr;
                    if (insn.ops[1].addr > start && insn.ops[1].addr != BADADDR) {
                        found = true;
                        break;
                    }
                }
            }

            if (found) {
                msg("[%s] found protocol GUID parameter at 0x%016llX\n", plugin_name,
                    static_cast<uint64_t>(guidCodeAddress));
                auto guid = getGuidByAddr(guidDataAddress);
                if (!checkGuid(guid)) {
                    msg("[%s] Incorrect GUID at 0x%016llX\n", plugin_name,
                        static_cast<uint64_t>(guidCodeAddress));
                    continue;
                }

                AddProtocol(smmServicesProt64[i].service_name, guidDataAddress,
                            guidCodeAddress, ea);
            }
        }
    }
}

//--------------------------------------------------------------------------
// Mark protocols
void EfiAnalysis::EfiAnalyzer::markInterfaces() {
    msg("[%s] %s marking\n", plugin_name, if_pl);
    for (auto ifItemIt = if_tbl->begin(); ifItemIt != if_tbl->end(); ++ifItemIt) {
        json ifItem = *ifItemIt;
        ea_t address = static_cast<ea_t>(ifItem["address"]);

        // check if guid on this address already marked
        bool marked = false;
        for (auto markedAddress = markedInterfaces.begin();
             markedAddress != markedInterfaces.end(); ++markedAddress) {
            if (*markedAddress == address) {
                marked = true;
                break;
            }
        }

        if (!marked) {
            std::string svcName = static_cast<std::string>(ifItem[if_key]);
            set_name(address, svcName.c_str(), SN_FORCE);
            setGuidType(address);
            std::string comment = "EFI_GUID " + svcName;
            markedInterfaces.push_back(address);
            msg("[%s] address: 0x%016llX, comment: %s\n", plugin_name,
                static_cast<uint64_t>(address), comment.c_str());
        }
    }
}

//--------------------------------------------------------------------------
// Mark GUIDs found in the .data segment
void EfiAnalysis::EfiAnalyzer::markDataGuids() {
    for (auto seg : dataSegments) {
        segment_t *s = seg;
        msg("[%s] marking .data GUIDs from 0x%016llX to 0x%016llX\n", plugin_name,
            static_cast<uint64_t>(s->start_ea), static_cast<uint64_t>(s->end_ea));
        ea_t ea = s->start_ea;
        while (ea != BADADDR && ea <= s->end_ea - 15) {
            if (get_wide_dword(ea) == 0x00000000 || get_wide_dword(ea) == 0xffffffff) {
                ea += 1;
                continue;
            }
            auto guid = getGuidByAddr(ea);

            // find GUID name
            auto it = dbProtocolsMap.find(guid);
            if (it != dbProtocolsMap.end()) {
                std::string guidName = it->second;
                set_name(ea, guidName.c_str(), SN_FORCE);
                setGuidType(ea);

                std::string comment = "EFI_GUID " + guidName;
                msg("[%s] address: 0x%016llX, comment: %s\n", plugin_name,
                    static_cast<uint64_t>(ea), comment.c_str());

                json guidItem;
                guidItem["address"] = ea;
                guidItem["name"] = guidName;
                guidItem["guid"] = getGuidFromValue(guid);
                allGuids.push_back(guidItem);
                dataGuids.push_back(guidItem);
            }
            ea += 1;
        }
    }
}

//--------------------------------------------------------------------------
// Mark GUIDs found in local variables for X64 modules
void EfiAnalysis::EfiAnalyzer::markLocalGuidsX64() {
    for (auto seg : textSegments) {
        segment_t *s = seg;
        ea_t ea = s->start_ea;
        insn_t insn;
        insn_t insnNext;
        msg("[%s] local GUIDs finding from 0x%016llX to 0x%016llX\n", plugin_name,
            static_cast<uint64_t>(s->start_ea), static_cast<uint64_t>(s->end_ea));
        while (ea <= s->end_ea) {
            decode_insn(&insn, ea);

            // check if insn like `mov dword ptr [...], gData1`
            if (insn.itype == NN_mov && insn.ops[0].type == o_displ &&
                insn.ops[1].type == o_imm) {

                // get guid->data1 value
                uint32_t gData1 = static_cast<uint32_t>(insn.ops[1].value);
                if (gData1 == 0x00000000 || gData1 == 0xffffffff) {
                    ea = next_head(ea, BADADDR);
                    continue;
                }
                ea_t eaNext = next_head(ea, BADADDR);
                decode_insn(&insnNext, eaNext);

                // check if insn like `mov dword ptr [...], gData2`
                if (insnNext.itype == NN_mov && insnNext.ops[0].type == o_displ &&
                    insnNext.ops[1].type == o_imm) {

                    // get guid->data2 value
                    uint16_t gData2 = static_cast<uint16_t>(insnNext.ops[1].value);
                    if (gData2 == 0x0000 || gData2 == 0xffff) {
                        ea = next_head(ea, BADADDR);
                        continue;
                    }

                    // found guid->data1 and guid->data2 values, try to get
                    // guid name
                    for (auto dbItem = dbProtocols.begin(); dbItem != dbProtocols.end();
                         ++dbItem) {
                        auto guid = dbItem.value();
                        if (gData1 == static_cast<uint32_t>(guid[0]) &&
                            gData2 == static_cast<uint16_t>(guid[1])) {

                            // mark local GUID
                            std::string comment = "EFI_GUID " + dbItem.key();
                            msg("[%s] address: 0x%016llX, comment: %s\n", plugin_name,
                                static_cast<uint64_t>(ea), comment.c_str());
                            set_cmt(ea, comment.c_str(), true);

                            json guidItem;
                            guidItem["address"] = ea;
                            guidItem["name"] = dbItem.key();
                            guidItem["guid"] = getGuidFromValue(guid);
                            allGuids.push_back(guidItem);
                            stackGuids.push_back(guidItem);
                            break;
                        }
                    }
                }
            }
            ea = next_head(ea, BADADDR);
        }
    }
}

//--------------------------------------------------------------------------
// Search for callouts recursively
void findCalloutRec(func_t *func) {
    insn_t insn;
    for (ea_t ea = func->start_ea; ea < func->end_ea; ea = next_head(ea, BADADDR)) {
        decode_insn(&insn, ea);
        if (insn.itype == NN_call) {
            ea_t nextFuncAddr = insn.ops[0].addr;
            func_t *nextFunc = get_func(nextFuncAddr);
            if (nextFunc) {
                auto it = std::find(excFunctions.begin(), excFunctions.end(), nextFunc);
                if (it == excFunctions.end()) {
                    excFunctions.push_back(nextFunc);
                    findCalloutRec(nextFunc);
                }
            }
        }

        // find callouts with `gBS`
        for (auto bs : gBsList) {

            // check if insn is `mov rax, cs:gBS`
            if (insn.itype == NN_mov && insn.ops[0].reg == REG_RAX &&
                insn.ops[1].type == o_mem && insn.ops[1].addr == bs) {
                msg("[%s] SMM callout found: 0x%016llX\n", plugin_name,
                    static_cast<uint64_t>(ea));
                calloutAddrs.push_back(ea);
            }
        }

        // find callouts with `gRT`
        for (auto rt : gRtList) {

            // check if insn is `mov rax, cs:gRT`
            if (insn.itype == NN_mov && insn.ops[0].reg == REG_RAX &&
                insn.ops[1].type == o_mem && insn.ops[1].addr == rt) {
                msg("[%s] SMM callout found: 0x%016llX\n", plugin_name,
                    static_cast<uint64_t>(ea));
                calloutAddrs.push_back(ea);
            }
        }
    }
}

//--------------------------------------------------------------------------
// Find SwSmiHandler function inside SMM drivers
void EfiAnalysis::EfiAnalyzer::findSwSmiHandlers() {
    smiHandlers = findSmiHandlersSmmSwDispatch(dataSegments, stackGuids);
}

//--------------------------------------------------------------------------
// Find callouts inside SwSmiHandler function:
//  * find SwSmiHandler function
//  * find gBS->service_name and gRT->service_name inside SmiHandler function
bool EfiAnalysis::EfiAnalyzer::findSmmCallout() {
    msg("[%s] Looking for SMM callout\n", plugin_name);
    if (!gBsList.size() && !gRtList.size()) {
        return false;
    }
    if (!smiHandlers.size() && !childSmiHandlers.size()) {
        msg("[%s] can't find a SwSmiHandler functions\n", plugin_name);
        return false;
    }
    for (auto func : smiHandlers) {
        findCalloutRec(func);
    }
    for (auto func : childSmiHandlers) {
        findCalloutRec(func);
    }
    return true;
}

bool EfiAnalysis::EfiAnalyzer::findPPIGetVariableStackOveflow() {
    msg("[%s] Looking for PPI GetVariable buffer overflow, "
        "allServices.size() = %lu\n",
        plugin_name, allServices.size());
    std::vector<ea_t> getVariableServicesCalls;
    std::string getVariableStr("VariablePPI.GetVariable");
    for (auto j_service : allServices) {
        json service = j_service;
        std::string service_name = static_cast<std::string>(service["service_name"]);
        std::string table_name = static_cast<std::string>(service["table_name"]);
        ea_t addr = static_cast<ea_t>(service["address"]);
        if (service_name.compare(getVariableStr) == 0) {
            getVariableServicesCalls.push_back(addr);
        }
    }
    msg("[%s] Finished iterating over allServices, "
        "getVariableServicesCalls.size() = "
        "%lu\n",
        plugin_name, getVariableServicesCalls.size());
    sort(getVariableServicesCalls.begin(), getVariableServicesCalls.end());
    if (getVariableServicesCalls.size() < 2) {
        msg("[%s] less than 2 VariablePPI.GetVariable calls found\n", plugin_name);
        return false;
    }
    ea_t prev_addr = getVariableServicesCalls.at(0);
    for (auto i = 1; i < getVariableServicesCalls.size(); ++i) {
        ea_t curr_addr = getVariableServicesCalls.at(i);
        msg("[%s] VariablePPI.GetVariable_1: 0x%016llX, "
            "VariablePPI.GetVariable_2: "
            "0x%016llX\n",
            plugin_name, static_cast<uint64_t>(prev_addr),
            static_cast<uint64_t>(curr_addr));

        // check code from `GetVariable_1` to `GetVariable_2`
        ea_t ea = next_head(static_cast<ea_t>(prev_addr), BADADDR);
        bool ok = true;
        insn_t insn;
        while (ea < curr_addr) {
            decode_insn(&insn, ea);
            if (insn.itype == NN_callni || insn.itype == NN_call ||
                insn.itype == NN_retn) {
                ok = false;
                break;
            }
            ea = next_head(ea, BADADDR);
        }
        if (ok) {
            bool same_datasize = false;
            uint16_t pushNumber = 5;
            uint16_t pushCounter = 0;
            uint16_t arg5_reg = 0xffff;
            ea_t curr_datasize_addr = 0xffff;
            bool datasize_addr_found = false;
            ea_t address = curr_addr;
            for (auto j = 0; j < 15; j++) {
                address = prev_head(address, startAddress);
                decode_insn(&insn, address);
                if (insn.itype == NN_push) {
                    pushCounter += 1;
                    if (pushCounter == pushNumber) {
                        if (insn.ops[0].type == o_reg) {
                            arg5_reg = insn.ops[0].reg;
                        } else {
                            // if it's not push <reg>, just let the pattern
                            // trigger - for manual review
                            same_datasize = true;
                        }
                        break;
                    }
                }
            }

            if (same_datasize) {
                peiGetVariableOverflow.push_back(curr_addr);
                msg("[%s] overflow can occur here: 0x%016llX\n", plugin_name,
                    static_cast<uint64_t>(curr_addr));
                continue;
            }

            for (auto j = 0; j < 15; j++) {
                address = prev_head(address, startAddress);
                decode_insn(&insn, address);
                if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
                    insn.ops[0].reg == arg5_reg && insn.ops[1].type == o_displ) {
                    curr_datasize_addr = insn.ops[1].addr;
                    datasize_addr_found = true;
                    break;
                }
            }

            msg("[%s] curr_datasize_addr = 0x%016llx, datasize_addr_found = "
                "%d\n",
                plugin_name, static_cast<uint64_t>(curr_datasize_addr),
                datasize_addr_found);

            if (!datasize_addr_found) {
                // if datasize wasn't found, just let the pattern
                // trigger - for manual review
                peiGetVariableOverflow.push_back(curr_addr);
                msg("[%s] overflow can occur here: 0x%016llX\n", plugin_name,
                    static_cast<uint64_t>(curr_addr));
                continue;
            }

            pushCounter = 0;
            arg5_reg = 0xffff;
            ea_t prev_datasize_addr = 0xffff;
            datasize_addr_found = false;
            address = prev_addr;
            for (auto j = 0; j < 15; j++) {
                address = prev_head(address, startAddress);
                decode_insn(&insn, address);
                if (insn.itype == NN_push) {
                    pushCounter += 1;
                    if (pushCounter == pushNumber) {
                        if (insn.ops[0].type == o_reg) {
                            arg5_reg = insn.ops[0].reg;
                        } else {
                            // if it's not push <reg>, just let the pattern
                            // trigger - for manual review
                            same_datasize = true;
                        }
                        break;
                    }
                }
            }

            if (same_datasize) {
                peiGetVariableOverflow.push_back(curr_addr);
                msg("[%s] overflow can occur here: 0x%016llX\n", plugin_name,
                    static_cast<uint64_t>(curr_addr));
                continue;
            }

            for (auto j = 0; j < 15; j++) {
                address = prev_head(address, startAddress);
                decode_insn(&insn, address);
                if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
                    insn.ops[0].reg == arg5_reg && insn.ops[1].type == o_displ) {
                    prev_datasize_addr = insn.ops[1].addr;
                    datasize_addr_found = true;
                    break;
                }
            }

            msg("[%s] prev_datasize_addr = 0x%016llX, datasize_addr_found = "
                "%d, "
                "(prev_datasize_addr == curr_datasize_addr) = %d\n",
                plugin_name, static_cast<uint64_t>(prev_datasize_addr),
                datasize_addr_found, (prev_datasize_addr == curr_datasize_addr));

            if (!datasize_addr_found) {
                peiGetVariableOverflow.push_back(curr_addr);
                msg("[%s] overflow can occur here: 0x%016llX\n", plugin_name,
                    static_cast<uint64_t>(curr_addr));
            } else if (prev_datasize_addr == curr_datasize_addr) {
                peiGetVariableOverflow.push_back(curr_addr);
                msg("[%s] overflow can occur here: 0x%016llX "
                    "(prev_datasize_addr == "
                    "curr_datasize_addr)\n",
                    plugin_name, static_cast<uint64_t>(curr_addr));
            }
        }
        prev_addr = curr_addr;
    }
    return (peiGetVariableOverflow.size() > 0);
}

//--------------------------------------------------------------------------
// Find potential stack/heap overflow with double GetVariable calls
bool EfiAnalysis::EfiAnalyzer::findGetVariableOveflow(std::vector<json> allServices) {
    msg("[%s] Looking for GetVariable stack/heap overflow\n", plugin_name);
    std::vector<ea_t> getVariableServicesCalls;
    std::string getVariableStr("GetVariable");
    for (auto j_service : allServices) {
        json service = j_service;
        std::string service_name = static_cast<std::string>(service["service_name"]);
        ea_t addr = static_cast<ea_t>(service["address"]);
        if (service_name.compare(getVariableStr) == 0) {
            getVariableServicesCalls.push_back(addr);
        }
    }
    sort(getVariableServicesCalls.begin(), getVariableServicesCalls.end());
    if (getVariableServicesCalls.size() < 2) {
        msg("[%s] less than 2 GetVariable calls found\n", plugin_name);
        return false;
    }
    ea_t prev_addr = getVariableServicesCalls.at(0);
    ea_t ea;
    insn_t insn;
    for (auto i = 1; i < getVariableServicesCalls.size(); ++i) {
        ea_t curr_addr = getVariableServicesCalls.at(i);
        msg("[%s] GetVariable_1: 0x%016llX, GetVariable_2: 0x%016llX\n", plugin_name,
            static_cast<uint64_t>(prev_addr), static_cast<uint64_t>(curr_addr));

        // get `dataSizeStackAddr`
        int dataSizeStackAddr = 0;
        ea = prev_head(static_cast<ea_t>(curr_addr), 0);
        for (auto i = 0; i < 10; ++i) {
            decode_insn(&insn, ea);
            if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
                insn.ops[0].reg == REG_R9) {
                dataSizeStackAddr = insn.ops[1].addr;
                break;
            }
            ea = prev_head(ea, 0);
        }

        // check code from `GetVariable_1` to `GetVariable_2`
        ea = next_head(static_cast<ea_t>(prev_addr), BADADDR);
        bool ok = true;
        size_t dataSizeUseCounter = 0;
        while (ea < curr_addr) {
            decode_insn(&insn, ea);
            if (dataSizeStackAddr == insn.ops[1].addr ||
                dataSizeStackAddr == insn.ops[0].addr) {
                dataSizeUseCounter++;
            }
            if (insn.itype == NN_callni || insn.itype == NN_retn ||
                dataSizeUseCounter > 1) {
                ok = false;
                break;
            }
            ea = next_head(ea, BADADDR);
        }
        if (ok) {

            // check for wrong GetVariable detection
            bool wrong_detection = false;
            ea = prev_head(static_cast<ea_t>(curr_addr), 0);
            for (auto i = 0; i < 8; ++i) {
                decode_insn(&insn, ea);
                if (insn.itype == NN_mov && insn.ops[0].type == o_reg &&
                    insn.ops[1].type == o_mem) {
                    ea_t mem_addr = static_cast<ea_t>(insn.ops[1].addr);
                    if (find(gBsList.begin(), gBsList.end(), mem_addr) != gBsList.end()) {
                        wrong_detection = true;
                        break;
                    }
                }
                ea = prev_head(ea, 0);
            }

            // check `DataSize` initialization
            bool init_ok = false;
            decode_insn(&insn, prev_head(curr_addr, 0));
            if (!wrong_detection &&
                !(insn.itype == NN_mov && insn.ops[0].type == o_displ &&
                  (insn.ops[0].phrase == REG_RSP || insn.ops[0].phrase == REG_RBP))) {
                init_ok = true;
            }

            // check that the DataSize argument variable is the same for two
            // calls
            if (init_ok) {
                ea = prev_head(static_cast<ea_t>(prev_addr), 0);
                for (auto i = 0; i < 10; ++i) {
                    decode_insn(&insn, ea);
                    if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
                        insn.ops[0].reg == REG_R9) {
                        if (dataSizeStackAddr == insn.ops[1].addr) {
                            getVariableOverflow.push_back(curr_addr);
                            msg("[%s] \toverflow can occur here: 0x%016llX\n",
                                plugin_name, static_cast<uint64_t>(curr_addr));
                            break;
                        }
                    }
                    ea = prev_head(ea, 0);
                }
            }
        }
        prev_addr = curr_addr;
    }
    return (getVariableOverflow.size() > 0);
}

//--------------------------------------------------------------------------
// Find potential stack/heap overflow with double SmmGetVariable calls
bool EfiAnalysis::EfiAnalyzer::findSmmGetVariableOveflow() {
    msg("[%s] Looking for SmmGetVariable stack/heap overflow\n", plugin_name);
    std::vector<ea_t> smmGetVariableCalls =
        findSmmGetVariableCalls(dataSegments, &allServices);
    sort(smmGetVariableCalls.begin(), smmGetVariableCalls.end());
    if (smmGetVariableCalls.size() < 2) {
        msg("[%s] less than 2 GetVariable calls found\n", plugin_name);
        return false;
    }
    ea_t prev_addr = smmGetVariableCalls.at(0);
    ea_t ea;
    insn_t insn;
    for (auto i = 1; i < smmGetVariableCalls.size(); ++i) {
        ea_t curr_addr = smmGetVariableCalls.at(i);
        msg("[%s] SmmGetVariable_1: 0x%016llX, SmmGetVariable_2: 0x%016llX\n",
            plugin_name, static_cast<uint64_t>(prev_addr),
            static_cast<uint64_t>(curr_addr));

        // get `dataSizeStackAddr`
        uint32_t dataSizeStackAddr = 0xffffffff;
        ea = prev_head(static_cast<ea_t>(curr_addr), 0);
        for (auto i = 0; i < 10; ++i) {
            decode_insn(&insn, ea);
            if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
                insn.ops[0].reg == REG_R9) {
                dataSizeStackAddr = insn.ops[1].addr;
                break;
            }
            ea = prev_head(ea, 0);
        }

        // check code from `SmmGetVariable_1` to `SmmGetVariable_2`
        ea = next_head(static_cast<ea_t>(prev_addr), BADADDR);
        bool ok = true;
        size_t dataSizeUseCounter = 0;
        while (ea < curr_addr) {
            decode_insn(&insn, ea);
            if (insn.itype == NN_callni || insn.itype == NN_retn) {
                ok = false;
                break;
            }
            ea = next_head(ea, BADADDR);
        }

        if (ok) {

            // check DataSize initialization
            bool init_ok = false;
            decode_insn(&insn, prev_head(curr_addr, 0));
            if (!(insn.itype == NN_mov && insn.ops[0].type == o_displ &&
                  (insn.ops[0].phrase == REG_RSP || insn.ops[0].phrase == REG_RBP))) {
                init_ok = true;
            }

            // check that the `DataSize` argument variable is the same for two
            // calls
            if (init_ok) {
                ea = prev_head(static_cast<ea_t>(prev_addr), 0);
                for (auto i = 0; i < 10; ++i) {
                    decode_insn(&insn, ea);
                    if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
                        insn.ops[0].reg == REG_R9) {
                        if (dataSizeStackAddr == insn.ops[1].addr) {
                            smmGetVariableOverflow.push_back(curr_addr);
                            msg("[%s] \toverflow can occur here: 0x%016llX\n",
                                plugin_name, static_cast<uint64_t>(curr_addr));
                            break;
                        }
                        msg("[%s] \tDataSize argument variable is not the "
                            "same: 0x%016llX\n",
                            plugin_name, static_cast<uint64_t>(curr_addr));
                    }
                    ea = prev_head(ea, 0);
                }
            }
        }
        prev_addr = curr_addr;
    }
    return (smmGetVariableOverflow.size() > 0);
}

//--------------------------------------------------------------------------
// Resolve EFI_SMM_CPU_PROTOCOL
bool EfiAnalysis::EfiAnalyzer::efiSmmCpuProtocolResolver() {
    readSaveStateCalls = resolveEfiSmmCpuProtocol(stackGuids, dataGuids, &allServices);
    return true;
}

//--------------------------------------------------------------------------
// Dump all info to JSON file
void EfiAnalysis::EfiAnalyzer::dumpInfo() {
    json info;
    if (gStList.size()) {
        info["gStList"] = gStList;
    }
    if (gBsList.size()) {
        info["gBsList"] = gBsList;
    }
    if (gRtList.size()) {
        info["gRtList"] = gRtList;
    }
    if (gSmstList.size()) {
        info["gSmstList"] = gSmstList;
    }
    if (gImageHandleList.size()) {
        info["gImageHandleList"] = gImageHandleList;
    }
    if (allPPIs.size()) {
        info["allPPIs"] = allPPIs;
    }
    if (allProtocols.size()) {
        info["allProtocols"] = allProtocols;
    }
    if (allServices.size()) {
        info["allServices"] = allServices;
    }
    if (allGuids.size()) {
        info["allGuids"] = allGuids;
    }
    if (readSaveStateCalls.size()) {
        info["readSaveStateCalls"] = readSaveStateCalls;
    }
    if (calloutAddrs.size()) {
        info["vulns"]["smm_callout"] = calloutAddrs;
    }
    if (peiGetVariableOverflow.size()) {
        info["vulns"]["pei_get_variable_buffer_overflow"] = peiGetVariableOverflow;
    }
    if (getVariableOverflow.size()) {
        info["vulns"]["get_variable_buffer_overflow"] = getVariableOverflow;
    }
    if (smmGetVariableOverflow.size()) {
        info["vulns"]["smm_get_variable_buffer_overflow"] = smmGetVariableOverflow;
    }

    std::vector<json> smiHandlersAddrs;
    if (smiHandlers.size() > 0) {
        for (auto f : smiHandlers) {
            func_t *func = f;
            smiHandlersAddrs.push_back(func->start_ea);
        }
    }
    info["smiHandlersAddrs"] = smiHandlersAddrs;

    std::string idbPath;
    idbPath = get_path(PATH_TYPE_IDB);
    std::filesystem::path logFile;
    logFile /= idbPath;
    logFile.replace_extension(".json");
    std::ofstream out(logFile);
    out << std::setw(4) << info << std::endl;
    msg("[%s] the log is saved in a JSON file\n", plugin_name);
}

//--------------------------------------------------------------------------
// Show all non-empty choosers windows
void showAllChoosers(EfiAnalysis::EfiAnalyzer analyzer) {
    qstring title;

    // open window with all services
    if (analyzer.allServices.size()) {
        title = "efiXplorer: services";
        services_show(analyzer.allServices, title);
    }

    // open window with protocols
    if (analyzer.fileType == FTYPE_PEI) {
        if (analyzer.allPPIs.size()) {
            title = "efiXplorer: PPIs";
            ppis_show(analyzer.allPPIs, title);
        }

    } else { // FTYPE_DXE_AND_THE_LIKE
        if (analyzer.allProtocols.size()) {
            title = "efiXplorer: protocols";
            protocols_show(analyzer.allProtocols, title);
        }
    }

    // open window with data guids
    if (analyzer.allGuids.size()) {
        qstring title = "efiXplorer: GUIDs";
        guids_show(analyzer.allGuids, title);
    }

    // open window with vulnerabilities
    if (calloutAddrs.size() + peiGetVariableOverflow.size() + getVariableOverflow.size() +
        smmGetVariableOverflow.size()) {
        std::vector<json> vulns;

        // TODO: use map to avoid duplicate code
        for (auto addr : calloutAddrs) {
            json item;
            item["type"] = "smm_callout";
            item["address"] = addr;
            vulns.push_back(item);
        }

        for (auto addr : peiGetVariableOverflow) {
            json item;
            item["type"] = "pei_get_variable_buffer_overflow";
            item["address"] = addr;
            vulns.push_back(item);
        }

        for (auto addr : getVariableOverflow) {
            json item;
            item["type"] = "get_variable_buffer_overflow";
            item["address"] = addr;
            vulns.push_back(item);
        }

        for (auto addr : smmGetVariableOverflow) {
            json item;
            item["type"] = "smm_get_variable_buffer_overflow";
            item["address"] = addr;
            vulns.push_back(item);
        }
        qstring title = "efiXplorer: vulns";
        vulns_show(vulns, title);
    }
}

//--------------------------------------------------------------------------
// Main function for X64 modules
bool EfiAnalysis::efiAnalyzerMainX64() {
    EfiAnalysis::EfiAnalyzer analyzer;

    while (!auto_is_ok()) {
        auto_wait();
    };

    // find .text and .data segments
    analyzer.getSegments();

    // TODO: add conditional analysis
    // analyze all
    if (analyzer.arch == UEFI && textSegments.size() && dataSegments.size()) {
        segment_t *start_seg = textSegments.at(0);
        segment_t *end_seg = dataSegments.at(dataSegments.size() - 1);
        ea_t start_ea = start_seg->start_ea;
        ea_t end_ea = end_seg->end_ea;
        auto_mark_range(start_ea, end_ea, AU_USED);
        plan_and_wait(start_ea, end_ea, 1);
    }

    // mark GUIDs
    analyzer.markDataGuids();
    analyzer.markLocalGuidsX64();

    analyzer.fileType = getFileType(&analyzer.allGuids);

    analyzer.setStrings();

    // find global vars for `gImageHandle`, `gST`, `gBS`, `gRT`, `gSmst`
    if (analyzer.fileType == FTYPE_DXE_AND_THE_LIKE) {
        analyzer.findImageHandleX64();
        analyzer.findSystemTableX64();
        analyzer.findBootServicesTables();
        analyzer.findRuntimeServicesTables();
        analyzer.findSmstX64();

        // find Boot services and Runtime services
        analyzer.getProtBootServicesX64();
        analyzer.findOtherBsTablesX64();
        analyzer.getAllBootServices();
        analyzer.getAllRuntimeServices();

        // find SMM services
        analyzer.getAllSmmServicesX64();

        // print and mark protocols
        analyzer.getBsProtNamesX64();
        analyzer.getSmmProtNamesX64();
        analyzer.markInterfaces();

        // search for copies of global variables
        markCopiesForGlobalVars(gSmstList, "gSmst");
        markCopiesForGlobalVars(gBsList, "gBS");
        markCopiesForGlobalVars(gRtList, "gRT");

        // search for vulnerabilities
        if (!g_args.disable_vuln_hunt) {

            // find potential SMM callouts
            analyzer.findSwSmiHandlers();
            analyzer.findSmmCallout();

            // find potential OOB RW with `GetVariable` function
            analyzer.findGetVariableOveflow(analyzer.allServices);

            // find potential OOB RW with `SmmGetVariable` function
            analyzer.findSmmGetVariableOveflow();
            analyzer.efiSmmCpuProtocolResolver();
        }

    } else {
        msg("[%s] Parsing of 64-bit PEI files is not supported yet\n", plugin_name);
    }

    // dump info to JSON file
    analyzer.dumpInfo();

    // show all choosers windows
    if (!g_args.disable_ui) {
        showAllChoosers(analyzer);
    }

#ifdef HEX_RAYS
    applyAllTypesForInterfaces(analyzer.allProtocols);
#endif

    return true;
}

//--------------------------------------------------------------------------
// Main function for X86 modules
bool EfiAnalysis::efiAnalyzerMainX86() {
    EfiAnalysis::EfiAnalyzer analyzer;

    while (!auto_is_ok()) {
        auto_wait();
    };

    // find .text and .data segments
    analyzer.getSegments();

    // mark GUIDs
    analyzer.markDataGuids();

    analyzer.fileType = getFileType(&analyzer.allGuids);

    analyzer.setStrings();

    if (analyzer.fileType == FTYPE_DXE_AND_THE_LIKE) {

        // find global vars for `gST`, `gBS`, `gRT`
        analyzer.findBootServicesTables();
        analyzer.findRuntimeServicesTables();

        // find boot services and runtime services
        analyzer.getAllRuntimeServices();
        analyzer.getProtBootServicesX86();
        analyzer.getAllBootServices();

        // print and mark protocols
        analyzer.getBsProtNamesX86();
        analyzer.markInterfaces();

    } else if (analyzer.fileType == FTYPE_PEI) {
        setEntryArgToPeiSvc();
        analyzer.getAllPeiServicesX86();
        analyzer.getPpiNamesX86();
        analyzer.getAllVariablePPICallsX86();
        analyzer.markInterfaces();

        // search for vulnerabilities
        if (!g_args.disable_vuln_hunt) {
            analyzer.findPPIGetVariableStackOveflow();
        }
    }

    // dump info to JSON file
    analyzer.dumpInfo();

    // show all choosers windows
    if (!g_args.disable_ui) {
        showAllChoosers(analyzer);
    }

#ifdef HEX_RAYS
    applyAllTypesForInterfaces(analyzer.allProtocols);
#endif

    return true;
}
