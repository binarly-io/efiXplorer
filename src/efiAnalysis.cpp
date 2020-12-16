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
 * efiAnalysis.cpp
 *
 */

#include "efiAnalysis.h"
#include "efiUi.h"
#include "tables/efi_pei_tables.h"
#include "tables/efi_services.h"
#include "thirdparty/libfort/fort.h"

using namespace efiAnalysis;

static const char plugin_name[] = "efiXplorer";

vector<ea_t> gStList;
vector<ea_t> gPeiSvcList;
vector<ea_t> gBsList;
vector<ea_t> gRtList;
vector<ea_t> gSmstList;
vector<ea_t> gImageHandleList;
vector<ea_t> gRtServicesList;
vector<json> stackGuids;
vector<json> dataGuids;

/* all .text and .data segments for compatibility with the efiLoader */
vector<segment_t *> textSegments;
vector<segment_t *> dataSegments;

/* for smm callouts finding */
vector<ea_t> calloutAddrs;
vector<func_t *> excFunctions;
vector<ea_t> readSaveStateCalls;

/* for GetVariable stack overflow finding */
vector<ea_t> getVariableStackOverflow;
vector<ea_t> getVariableOverflow;
vector<ea_t> smmGetVariableOverflow;

efiAnalysis::efiAnalyzer::efiAnalyzer() {
    /* get guids.json path */
    guidsJsonPath /= idadir("plugins");
    guidsJsonPath /= "guids";
    guidsJsonPath /= "guids.json";

    /* get base address */
    base = get_imagebase();

    func_t *start_func = nullptr;
    func_t *end_func = nullptr;

    /* get start address for scan */
    start_func = getn_func(0);
    if (start_func) {
        startAddress = start_func->start_ea;
    }
    /* get end address for scan */
    end_func = getn_func(get_func_qty() - 1);
    if (end_func) {
        endAddress = end_func->end_ea;
    }

    vector<ea_t> addrs;
    for (auto service = begin(protBsNames); service != end(protBsNames);
         ++service) {
        bootServices[*service] = addrs;
    }

    for (auto service = begin(protSmmNames); service != end(protSmmNames);
         ++service) {
        smmServices[*service] = addrs;
    }

    /* load protocols from guids/guids.json file */
    ifstream in(guidsJsonPath);
    in >> dbProtocols;

    /* import necessary types */
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

efiAnalysis::efiAnalyzer::~efiAnalyzer() {
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

    getVariableStackOverflow.clear();
    getVariableOverflow.clear();
    smmGetVariableOverflow.clear();
}

void efiAnalysis::efiAnalyzer::setStrings() {
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
void efiAnalysis::efiAnalyzer::getSegments() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    for (segment_t *s = get_first_seg(); s != NULL;
         s = get_next_seg(s->start_ea)) {
        qstring seg_name;
        get_segm_name(&seg_name, s);
        size_t index = seg_name.find(".text");
        if (index != string::npos) {
            /* found .text segment */
            textSegments.push_back(s);
            continue;
        }
        index = seg_name.find(".data");
        if (index != string::npos) {
            /* found .data segment */
            dataSegments.push_back(s);
            continue;
        }
    }
    /* print all .text segments addresses */
    for (vector<segment_t *>::iterator seg = textSegments.begin();
         seg != textSegments.end(); ++seg) {
        segment_t *s = *seg;
        DEBUG_MSG("[%s] .text segment: 0x%016x\n", plugin_name, s->start_ea);
    }
    /* print all .data segments addresses */
    for (vector<segment_t *>::iterator seg = dataSegments.begin();
         seg != dataSegments.end(); ++seg) {
        segment_t *s = *seg;
        DEBUG_MSG("[%s] .data segment: 0x%016x\n", plugin_name, s->start_ea);
    }
}

//--------------------------------------------------------------------------
// Find gImageHandle address for X64 modules
bool efiAnalysis::efiAnalyzer::findImageHandleX64() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] ImageHandle finding\n", plugin_name);
    insn_t insn;
    for (int idx = 0; idx < get_entry_qty(); idx++) {
        /* get address of entry point */
        uval_t ord = get_entry_ordinal(idx);
        ea_t ea = get_entry(ord);
        /* ImageHandle finding, first 8 instructions checking */
        for (auto i = 0; i < 8; i++) {
            decode_insn(&insn, ea);
            if (insn.itype == NN_mov && insn.ops[1].type == o_reg &&
                insn.ops[1].reg == REG_RCX && insn.ops[0].type == o_mem) {
                DEBUG_MSG("[%s] found ImageHandle at 0x%016X, address = "
                          "0x%016X\n",
                          plugin_name, ea, insn.ops[0].addr);
                char hexAddr[21] = {};
                snprintf(hexAddr, 21, "%llX",
                         static_cast<uint64_t>(insn.ops[0].addr));
                set_cmt(ea, "EFI_IMAGE_HANDLE gImageHandle", true);
                string name = "gImageHandle_" + static_cast<string>(hexAddr);
                /* set type and name */
                setTypeAndName(insn.ops[0].addr, name, "EFI_IMAGE_HANDLE");
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
bool efiAnalysis::efiAnalyzer::findSystemTableX64() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] SystemTable finding\n", plugin_name);
    insn_t insn;
    for (int idx = 0; idx < get_entry_qty(); idx++) {
        /* get address of entry point */
        uval_t ord = get_entry_ordinal(idx);
        ea_t ea = get_entry(ord);
        /* SystemTable finding, first 16 instructions checking */
        for (int i = 0; i < 16; i++) {
            decode_insn(&insn, ea);
            if (insn.itype == NN_mov && insn.ops[1].type == o_reg &&
                insn.ops[1].reg == REG_RDX && insn.ops[0].type == o_mem) {
                DEBUG_MSG("[%s] found SystemTable at 0x%016X, address = "
                          "0x%016X\n",
                          plugin_name, ea, insn.ops[0].addr);
                char hexAddr[21] = {};
                snprintf(hexAddr, 21, "%llX",
                         static_cast<uint64_t>(insn.ops[0].addr));
                set_cmt(ea, "EFI_SYSTEM_TABLE *gST", true);
                string name = "gST_" + static_cast<string>(hexAddr);
                /* set type and name */
                setPtrTypeAndName(insn.ops[0].addr, name, "EFI_SYSTEM_TABLE");
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
bool efiAnalysis::efiAnalyzer::findSmstX64() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] SMST finding\n", plugin_name);
    vector<ea_t> gSmstListSmmBase = findSmstSmmBase(gBsList, dataSegments);
    vector<ea_t> gSmstListSwDispatch =
        findSmstSwDispatch(gBsList, dataSegments);
    gSmstList.insert(gSmstList.end(), gSmstListSwDispatch.begin(),
                     gSmstListSwDispatch.end());
    gSmstList.insert(gSmstList.end(), gSmstListSmmBase.begin(),
                     gSmstListSmmBase.end());
    return gSmstList.size();
}

//--------------------------------------------------------------------------
// Find gBS addresses for X86/X64 modules
bool efiAnalysis::efiAnalyzer::findBootServicesTables(uint8_t arch) {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    /* init architecture-specific constants */
    auto BS_OFFSET = BS_OFFSET_X64;
    auto REG_SP = REG_RSP;
    if (arch == X86) {
        BS_OFFSET = BS_OFFSET_X86;
        REG_SP = REG_ESP;
    }
    insn_t insn;
    for (vector<segment_t *>::iterator seg = textSegments.begin();
         seg != textSegments.end(); ++seg) {
        segment_t *s = *seg;
        DEBUG_MSG("[%s] BootServices tables finding from 0x%016X to 0x%016X\n",
                  plugin_name, s->start_ea, s->end_ea);
        ea_t ea = s->start_ea;
        uint16_t bsRegister = 0;
        uint16_t stRegister = 0;
        while (ea <= s->end_ea) {
            decode_insn(&insn, ea);
            if (insn.itype == NN_mov && insn.ops[1].type == o_displ &&
                insn.ops[1].phrase != REG_SP) {
                if (insn.ops[0].type == o_reg &&
                    insn.ops[1].addr == BS_OFFSET) {
                    bsRegister = insn.ops[0].reg;
                    stRegister = insn.ops[1].phrase;
                    auto bsFound = false;
                    auto stFound = false;
                    ea_t baseInsnAddr;
                    /* found BS_OFFSET, need to check 10 instructions below */
                    for (auto i = 0; i < 10; i++) {
                        decode_insn(&insn, ea);
                        if (insn.itype == NN_mov && insn.ops[1].type == o_reg &&
                            insn.ops[0].type == o_mem) {
                            if (insn.ops[1].reg == bsRegister && !bsFound) {
                                DEBUG_MSG(
                                    "[%s] found BootServices table at 0x%016X, "
                                    "address = "
                                    "0x%016X\n",
                                    plugin_name, ea, insn.ops[0].addr);
                                baseInsnAddr = ea;
                                if (find(gBsList.begin(), gBsList.end(),
                                         insn.ops[0].addr) == gBsList.end()) {
                                    char hexAddr[21] = {};
                                    snprintf(hexAddr, 21, "%llX",
                                             static_cast<uint64_t>(
                                                 insn.ops[0].addr));
                                    set_cmt(ea, "EFI_BOOT_SERVICES *gBS", true);
                                    string name =
                                        "gBS_" + static_cast<string>(hexAddr);
                                    setPtrTypeAndName(insn.ops[0].addr, name,
                                                      "EFI_BOOT_SERVICES");
                                    gBsList.push_back(insn.ops[0].addr);
                                }
                                bsFound = true;
                            }
                            /* here you can also find gST */
                            if (insn.ops[1].reg == stRegister && !stFound &&
                                stRegister != bsRegister) {
                                DEBUG_MSG("[%s] found SystemTable at 0x%016X, "
                                          "address = "
                                          "0x%016X\n",
                                          plugin_name, ea, insn.ops[0].addr);
                                if (find(gStList.begin(), gStList.end(),
                                         insn.ops[0].addr) == gStList.end() &&
                                    find(gBsList.begin(), gBsList.end(),
                                         insn.ops[0].addr) == gBsList.end() &&
                                    find(gRtList.begin(), gRtList.end(),
                                         insn.ops[0].addr) == gRtList.end()) {
                                    char hexAddr[21] = {};
                                    snprintf(hexAddr, 21, "%llX",
                                             static_cast<uint64_t>(
                                                 insn.ops[0].addr));
                                    set_cmt(ea, "EFI_SYSTEM_TABLE *gST", true);
                                    string name =
                                        "gST_" + static_cast<string>(hexAddr);
                                    setPtrTypeAndName(insn.ops[0].addr, name,
                                                      "EFI_SYSTEM_TABLE");
                                    gStList.push_back(insn.ops[0].addr);
                                }
                                stFound = true;
                            }
                        }
                        if (bsFound && stFound) {
                            break;
                        }
                        if (bsFound && !stFound) {
                            /* check 8 instructions above baseInsnAddr */
                            ea_t addr = prev_head(baseInsnAddr, startAddress);
                            for (auto i = 0; i < 8; i++) {
                                decode_insn(&insn, addr);
                                if (insn.itype == NN_mov &&
                                    insn.ops[1].type == o_reg &&
                                    insn.ops[1].reg == stRegister &&
                                    insn.ops[0].type == o_mem) {
                                    DEBUG_MSG(
                                        "[%s] found SystemTable at 0x%016X, "
                                        "address = "
                                        "0x%016X\n",
                                        plugin_name, addr, insn.ops[0].addr);
                                    if (find(gStList.begin(), gStList.end(),
                                             insn.ops[0].addr) ==
                                            gStList.end() &&
                                        find(gBsList.begin(), gBsList.end(),
                                             insn.ops[0].addr) ==
                                            gBsList.end() &&
                                        find(gRtList.begin(), gRtList.end(),
                                             insn.ops[0].addr) ==
                                            gRtList.end()) {
                                        char hexAddr[21] = {};
                                        snprintf(hexAddr, 21, "%llX",
                                                 static_cast<uint64_t>(
                                                     insn.ops[0].addr));
                                        set_cmt(addr, "EFI_SYSTEM_TABLE *gST",
                                                true);
                                        string name =
                                            "gST_" +
                                            static_cast<string>(hexAddr);
                                        setPtrTypeAndName(insn.ops[0].addr,
                                                          name,
                                                          "EFI_SYSTEM_TABLE");
                                        gStList.push_back(insn.ops[0].addr);
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
bool efiAnalysis::efiAnalyzer::findRuntimeServicesTables(uint8_t arch) {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    /* init architecture-specific constants */
    auto RT_OFFSET = RT_OFFSET_X64;
    auto REG_SP = REG_RSP;
    if (arch == X86) {
        RT_OFFSET = RT_OFFSET_X86;
        REG_SP = REG_ESP;
    }
    insn_t insn;
    for (vector<segment_t *>::iterator seg = textSegments.begin();
         seg != textSegments.end(); ++seg) {
        segment_t *s = *seg;
        DEBUG_MSG(
            "[%s] RuntimeServices tables finding from 0x%016X to 0x%016X\n",
            plugin_name, s->start_ea, s->end_ea);
        ea_t ea = s->start_ea;
        uint16_t rtRegister = 0;
        uint16_t stRegister = 0;
        while (ea <= s->end_ea) {
            decode_insn(&insn, ea);
            if (insn.itype == NN_mov && insn.ops[1].type == o_displ &&
                insn.ops[1].phrase != REG_SP) {
                if (insn.ops[0].type == o_reg &&
                    insn.ops[1].addr == RT_OFFSET) {
                    rtRegister = insn.ops[0].reg;
                    stRegister = insn.ops[1].phrase;
                    auto rtFound = false;
                    auto stFound = false;
                    ea_t baseInsnAddr;
                    /* found RT_OFFSET, need to check 10 instructions below */
                    for (auto i = 0; i < 10; i++) {
                        decode_insn(&insn, ea);
                        if (insn.itype == NN_mov && insn.ops[1].type == o_reg &&
                            insn.ops[0].type == o_mem) {
                            if (insn.ops[1].reg == rtRegister && !rtFound) {
                                DEBUG_MSG("[%s] found RuntimeServices table at "
                                          "0x%016X, address "
                                          "= 0x%016X\n",
                                          plugin_name, ea, insn.ops[0].addr);
                                baseInsnAddr = ea;
                                if (find(gRtList.begin(), gRtList.end(),
                                         insn.ops[0].addr) == gRtList.end()) {
                                    char hexAddr[21] = {};
                                    snprintf(hexAddr, 21, "%llX",
                                             static_cast<uint64_t>(
                                                 insn.ops[0].addr));
                                    set_cmt(ea, "EFI_RUNTIME_SERVICES *gRT",
                                            true);
                                    string name =
                                        "gRT_" + static_cast<string>(hexAddr);
                                    setPtrTypeAndName(insn.ops[0].addr, name,
                                                      "EFI_RUNTIME_SERVICES");
                                    gRtList.push_back(insn.ops[0].addr);
                                }
                                rtFound = true;
                            }
                            /* here you can also find gST */
                            if (insn.ops[1].reg == stRegister && !stFound &&
                                stRegister != rtRegister) {
                                DEBUG_MSG("[%s] found SystemTable at 0x%016X, "
                                          "address = "
                                          "0x%016X\n",
                                          plugin_name, ea, insn.ops[0].addr);
                                if (find(gStList.begin(), gStList.end(),
                                         insn.ops[0].addr) == gStList.end() &&
                                    find(gBsList.begin(), gBsList.end(),
                                         insn.ops[0].addr) == gBsList.end() &&
                                    find(gRtList.begin(), gRtList.end(),
                                         insn.ops[0].addr) == gRtList.end()) {
                                    char hexAddr[21] = {};
                                    snprintf(hexAddr, 21, "%llX",
                                             static_cast<uint64_t>(
                                                 insn.ops[0].addr));
                                    set_cmt(ea, "EFI_SYSTEM_TABLE *gST", true);
                                    string name =
                                        "gST_" + static_cast<string>(hexAddr);
                                    setPtrTypeAndName(insn.ops[0].addr, name,
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
                            /* check 8 instructions above baseInsnAddr */
                            ea_t addr = prev_head(baseInsnAddr, startAddress);
                            for (auto i = 0; i < 8; i++) {
                                decode_insn(&insn, addr);
                                if (insn.itype == NN_mov &&
                                    insn.ops[1].type == o_reg &&
                                    insn.ops[1].reg == stRegister &&
                                    insn.ops[0].type == o_mem) {
                                    DEBUG_MSG(
                                        "[%s] found SystemTable at 0x%016X, "
                                        "address = "
                                        "0x%016X\n",
                                        plugin_name, addr, insn.ops[0].addr);
                                    if (find(gStList.begin(), gStList.end(),
                                             insn.ops[0].addr) ==
                                            gStList.end() &&
                                        find(gBsList.begin(), gBsList.end(),
                                             insn.ops[0].addr) ==
                                            gBsList.end() &&
                                        find(gRtList.begin(), gRtList.end(),
                                             insn.ops[0].addr) ==
                                            gRtList.end()) {
                                        char hexAddr[21] = {};
                                        snprintf(hexAddr, 21, "%llX",
                                                 static_cast<uint64_t>(
                                                     insn.ops[0].addr));
                                        set_cmt(addr, "EFI_SYSTEM_TABLE *gST",
                                                true);
                                        string name =
                                            "gST_" +
                                            static_cast<string>(hexAddr);
                                        setPtrTypeAndName(insn.ops[0].addr,
                                                          name,
                                                          "EFI_SYSTEM_TABLE");
                                        gStList.push_back(insn.ops[0].addr);
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
void efiAnalysis::efiAnalyzer::getAllBootServices(uint8_t arch) {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    if (!gBsList.size()) {
        return;
    }
    /* init architecture-specific constants */
    auto REG_AX = REG_RAX;
    if (arch == X86) {
        REG_AX = REG_EAX;
    }
    insn_t insn;
    auto found = false;
    ft_table_t *table = ft_create_table();
    ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
    ft_write_ln(table, " Address ", " Service ");
    for (vector<segment_t *>::iterator seg = textSegments.begin();
         seg != textSegments.end(); ++seg) {
        segment_t *s = *seg;
        DEBUG_MSG("[%s] BootServices finding from 0x%016X to 0x%016X (all)\n",
                  plugin_name, s->start_ea, s->end_ea);
        ea_t ea = s->start_ea;
        while (ea <= s->end_ea) {
            decode_insn(&insn, ea);
            for (vector<ea_t>::iterator bs = gBsList.begin();
                 bs != gBsList.end(); ++bs) {
                if (insn.itype == NN_mov && insn.ops[0].reg == REG_AX &&
                    insn.ops[1].type == o_mem && insn.ops[1].addr == *bs) {
                    ea_t addr = next_head(ea, BADADDR);
                    /* 16 instructions below */
                    for (auto i = 0; i < 16; i++) {
                        decode_insn(&insn, addr);
                        if (insn.itype == NN_callni &&
                            insn.ops[0].reg == REG_AX) {
                            for (int j = 0; j < bootServicesTableAllLength;
                                 j++) {
                                /* architecture-specific variables */
                                auto offset = bootServicesTableAll[j].offset64;
                                if (arch == X86) {
                                    offset = bootServicesTableAll[j].offset86;
                                }
                                if (insn.ops[0].addr ==
                                    static_cast<ea_t>(offset)) {
                                    found = true;
                                    string cmt = getBsComment(
                                        static_cast<ea_t>(offset), arch);
                                    set_cmt(addr, cmt.c_str(), true);
                                    /* op_stroff */
                                    opStroff(addr, "EFI_BOOT_SERVICES");
                                    /* add line to table */
                                    ft_printf_ln(
                                        table, " 0x%016X | %s ",
                                        static_cast<unsigned int>(addr),
                                        static_cast<char *>(
                                            bootServicesTableAll[j]
                                                .service_name));
                                    DEBUG_MSG("[%s] 0x%016X : %s\n",
                                              plugin_name, addr,
                                              static_cast<char *>(
                                                  bootServicesTableAll[j]
                                                      .service_name));
                                    bootServicesAll[static_cast<string>(
                                                        bootServicesTableAll[j]
                                                            .service_name)]
                                        .push_back(addr);
                                    /* add item to allBootServices vector */
                                    json bsItem;
                                    bsItem["address"] = addr;
                                    bsItem["service_name"] =
                                        static_cast<string>(
                                            bootServicesTableAll[j]
                                                .service_name);
                                    bsItem["table_name"] = static_cast<string>(
                                        "EFI_BOOT_SERVICES");
                                    bsItem["offset"] = offset;
                                    if (find(allServices.begin(),
                                             allServices.end(),
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
    if (found) {
        msg("[%s] Boot services (all):\n", plugin_name);
        msg(ft_to_string(table));
    }
    ft_destroy_table(table);
}

//--------------------------------------------------------------------------
// Get all runtime services for X86/X64 modules
void efiAnalysis::efiAnalyzer::getAllRuntimeServices(uint8_t arch) {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    if (!gRtList.size()) {
        return;
    }
    insn_t insn;
    auto found = false;
    ft_table_t *table = ft_create_table();
    ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
    ft_write_ln(table, " Address ", " Service ");
    for (vector<segment_t *>::iterator seg = textSegments.begin();
         seg != textSegments.end(); ++seg) {
        segment_t *s = *seg;
        DEBUG_MSG("[%s] RuntimeServices finding from 0x%016X to 0x%016X\n",
                  plugin_name, s->start_ea, s->end_ea);
        ea_t ea = s->start_ea;
        while (ea <= s->end_ea) {
            decode_insn(&insn, ea);
            for (vector<ea_t>::iterator rt = gRtList.begin();
                 rt != gRtList.end(); ++rt) {
                if (insn.itype == NN_mov && insn.ops[0].reg == REG_RAX &&
                    insn.ops[1].type == o_mem && insn.ops[1].addr == *rt) {
                    ea_t addr = next_head(ea, BADADDR);
                    /* 16 instructions below */
                    for (int i = 0; i < 16; i++) {
                        decode_insn(&insn, addr);
                        if (insn.itype == NN_callni &&
                            insn.ops[0].reg == REG_RAX) {
                            for (int j = 0; j < runtimeServicesTableAllLength;
                                 j++) {
                                /* architecture-specific variables */
                                auto offset =
                                    runtimeServicesTableAll[j].offset64;
                                if (arch == X86) {
                                    offset =
                                        runtimeServicesTableAll[j].offset86;
                                }
                                if (insn.ops[0].addr ==
                                    static_cast<ea_t>(offset)) {
                                    found = true;
                                    string cmt = getRtComment(
                                        static_cast<ea_t>(offset), arch);
                                    set_cmt(addr, cmt.c_str(), true);
                                    /* op_stroff */
                                    opStroff(addr, "EFI_RUNTIME_SERVICES");
                                    /* add line to table */
                                    ft_printf_ln(
                                        table, " 0x%016X | %s ",
                                        static_cast<unsigned int>(addr),
                                        static_cast<char *>(
                                            runtimeServicesTableAll[j]
                                                .service_name));
                                    DEBUG_MSG("[%s] 0x%016X : %s\n",
                                              plugin_name, addr,
                                              static_cast<char *>(
                                                  runtimeServicesTableAll[j]
                                                      .service_name));
                                    runtimeServicesAll
                                        [static_cast<string>(
                                             runtimeServicesTableAll[j]
                                                 .service_name)]
                                            .push_back(addr);
                                    /* add item to allRuntimeServices vector */
                                    json rtItem;
                                    rtItem["address"] = addr;
                                    rtItem["service_name"] =
                                        static_cast<string>(
                                            runtimeServicesTableAll[j]
                                                .service_name);
                                    rtItem["table_name"] = static_cast<string>(
                                        "EFI_RUNTIME_SERVICES");
                                    rtItem["offset"] = offset;
                                    if (find(allServices.begin(),
                                             allServices.end(),
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
    if (found) {
        msg("[%s] Runtime services (all):\n", plugin_name);
        msg(ft_to_string(table));
    }
    ft_destroy_table(table);
}

//--------------------------------------------------------------------------
// Get all smm services for X64 modules
void efiAnalysis::efiAnalyzer::getAllSmmServicesX64() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] SmmServices finding (all)\n", plugin_name);
    if (!gSmstList.size()) {
        return;
    }
    insn_t insn;
    auto found = false;
    ft_table_t *table = ft_create_table();
    ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
    ft_write_ln(table, " Address ", " Service ");
    for (vector<segment_t *>::iterator seg = textSegments.begin();
         seg != textSegments.end(); ++seg) {
        segment_t *s = *seg;
        DEBUG_MSG("[%s] SmmServices finding from 0x%016X to 0x%016X\n",
                  plugin_name, s->start_ea, s->end_ea);
        ea_t ea = s->start_ea;
        while (ea <= s->end_ea) {
            decode_insn(&insn, ea);
            for (vector<ea_t>::iterator smms = gSmstList.begin();
                 smms != gSmstList.end(); ++smms) {
                if (insn.itype == NN_mov && insn.ops[0].reg == REG_RAX &&
                    insn.ops[1].type == o_mem && insn.ops[1].addr == *smms) {
                    ea_t addr = ea;
                    /* 10 instructions below */
                    for (auto i = 0; i < 10; i++) {
                        decode_insn(&insn, addr);
                        if (insn.itype == NN_callni &&
                            insn.ops[0].reg == REG_RAX) {
                            for (int j = 0; j < smmServicesTableAllLength;
                                 j++) {
                                if (insn.ops[0].addr ==
                                    static_cast<ea_t>(
                                        smmServicesTableAll[j].offset64)) {
                                    found = true;
                                    string cmt =
                                        "gSmst->" + static_cast<string>(
                                                        smmServicesTableAll[j]
                                                            .service_name);
                                    set_cmt(addr, cmt.c_str(), true);
                                    /* op_stroff */
                                    opStroff(addr, "_EFI_SMM_SYSTEM_TABLE2");
                                    /* add line to table */
                                    ft_printf_ln(
                                        table, " 0x%016X | %s ",
                                        static_cast<unsigned int>(addr),
                                        static_cast<char *>(
                                            smmServicesTableAll[j]
                                                .service_name));
                                    DEBUG_MSG("[%s] 0x%016X : %s\n",
                                              plugin_name, addr,
                                              static_cast<char *>(
                                                  smmServicesTableAll[j]
                                                      .service_name));
                                    /* add address to smmServices[...] vector */
                                    if (find(protSmmNames.begin(),
                                             protSmmNames.end(),
                                             smmServicesTableAll[j]
                                                 .service_name) !=
                                        protSmmNames.end()) {
                                        smmServices[smmServicesTableAll[j]
                                                        .service_name]
                                            .push_back(addr);
                                    }
                                    smmServicesAll[static_cast<string>(
                                                       smmServicesTableAll[j]
                                                           .service_name)]
                                        .push_back(addr);
                                    /* add item to allSmmServices vector */
                                    json smmsItem;
                                    smmsItem["address"] = addr;
                                    smmsItem["service_name"] =
                                        static_cast<string>(
                                            smmServicesTableAll[j]
                                                .service_name);
                                    smmsItem["table_name"] =
                                        static_cast<string>(
                                            "_EFI_SMM_SYSTEM_TABLE2");
                                    smmsItem["offset"] =
                                        smmServicesTableAll[j].offset64;
                                    if (find(allServices.begin(),
                                             allServices.end(),
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
    if (found) {
        msg("[%s] SMM services (all):\n", plugin_name);
        msg(ft_to_string(table));
    }
    ft_destroy_table(table);
}

//--------------------------------------------------------------------------
// Get all Pei services for X86 modules
// Currently should cover all PeiServices except EFI_PEI_COPY_MEM,
// EFI_PEI_SET_MEM, EFI_PEI_RESET2_SYSTEM, and "Future Installed Services"
// (EFI_PEI_FFS_FIND_BY_NAME, etc.)
void efiAnalysis::efiAnalyzer::getAllPeiServicesX86() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] PeiServices finding from 0x%016X to 0x%016X (all)\n",
              plugin_name, startAddress, endAddress);
    ea_t ea = startAddress;
    insn_t insn;
    ft_table_t *table = ft_create_table();
    ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
    ft_write_ln(table, " Address ", " Service ");
    auto found = false;
    while (ea <= endAddress) {
        decode_insn(&insn, ea);
        if (insn.itype == NN_callni &&
            (insn.ops[0].reg == REG_EAX || insn.ops[0].reg == REG_ECX ||
             insn.ops[0].reg == REG_EDX)) {
            for (int j = 0; j < pei_services_table_size; j++) {
                if (insn.ops[0].addr ==
                    static_cast<ea_t>(pei_services_table[j].offset)) {
                    bool found_src_reg = false;
                    ea_t address = ea;
                    insn_t aboveInst;
                    uint16_t src_reg = 0xffff;
                    /* 15 instructions above */
                    for (auto j = 0; j < 15; j++) {
                        address = prev_head(address, startAddress);
                        decode_insn(&aboveInst, address);
                        if (aboveInst.itype == NN_mov &&
                            aboveInst.ops[0].type == o_reg &&
                            aboveInst.ops[0].reg == insn.ops[0].reg &&
                            aboveInst.ops[1].type == o_phrase) {
                            found_src_reg = true;
                            src_reg = aboveInst.ops[1].reg;
                        }
                    }

                    bool found_push = false;
                    /* 15 instructions above */
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
                        string cmt = getPeiSvcComment(
                            static_cast<ea_t>(pei_services_table[j].offset));
                        set_cmt(ea, cmt.c_str(), true);
                        /* op_stroff */
                        opStroff(ea, "EFI_PEI_SERVICES");
                        /* add line to table */
                        ft_printf_ln(
                            table, " 0x%016X | %s",
                            static_cast<unsigned int>(ea),
                            static_cast<char *>(pei_services_table[j].name));
                        DEBUG_MSG(
                            "[%s] 0x%016X : %s\n", plugin_name, ea,
                            static_cast<char *>(pei_services_table[j].name));
                        peiServicesAll[static_cast<string>(
                                           pei_services_table[j].name)]
                            .push_back(ea);
                        json psItem;
                        psItem["address"] = ea;
                        psItem["service_name"] =
                            static_cast<string>(pei_services_table[j].name);
                        psItem["table_name"] =
                            static_cast<string>("EFI_PEI_SERVICES");
                        psItem["offset"] = pei_services_table[j].offset;
                        if (find(allServices.begin(), allServices.end(),
                                 psItem) == allServices.end()) {
                            allServices.push_back(psItem);
                        }
                    }
                    break;
                }
            }
        }
        ea = next_head(ea, BADADDR);
    }
    if (found) {
        msg("[%s] Pei services (all):\n", plugin_name);
        msg(ft_to_string(table));
    }
    ft_destroy_table(table);
}

//--------------------------------------------------------------------------
// Get all EFI_PEI_READ_ONLY_VARIABLE2_PPI (GetVariable, NextVariableName)
void efiAnalysis::efiAnalyzer::getAllVariablePPICallsX86() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] Variable PPI calls finding from 0x%016X to 0x%016X (all)\n",
              plugin_name, startAddress, endAddress);
    ea_t ea = startAddress;
    insn_t insn;
    ft_table_t *table = ft_create_table();
    ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
    ft_write_ln(table, " Address ", " Service ");
    auto found = false;
    while (ea <= endAddress) {
        decode_insn(&insn, ea);
        if (insn.itype == NN_callni && insn.ops[0].type == o_phrase) {
            for (int j = 0; j < variable_ppi_table_size; j++) {
                if (insn.ops[0].addr ==
                    static_cast<ea_t>(variable_ppi_table[j].offset)) {
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
                        string cmt = getPPICallComment(
                            static_cast<ea_t>(variable_ppi_table[j].offset),
                            static_cast<string>(variable_ppi_name));
                        set_cmt(ea, cmt.c_str(), true);
                        /* op_stroff */
                        opStroff(ea, "EFI_PEI_READ_ONLY_VARIABLE2_PPI");
                        /* add line to table */
                        ft_printf_ln(
                            table, " 0x%016X | %s",
                            static_cast<unsigned int>(ea),
                            static_cast<char *>(variable_ppi_table[j].name));
                        DEBUG_MSG(
                            "[%s] 0x%016X : %s\n", plugin_name, ea,
                            static_cast<char *>(variable_ppi_table[j].name));
                        string ppi_call =
                            static_cast<string>(variable_ppi_name) + "." +
                            static_cast<string>(variable_ppi_table[j].name);
                        ppiCallsAll[ppi_call].push_back(ea);

                        // Injecting PPI call as service
                        json ppiItem;
                        ppiItem["address"] = ea;
                        ppiItem["service_name"] = ppi_call;
                        ppiItem["table_name"] = static_cast<string>(
                            "EFI_PEI_READ_ONLY_VARIABLE2_PPI");
                        ppiItem["offset"] = variable_ppi_table[j].offset;
                        if (find(allServices.begin(), allServices.end(),
                                 ppiItem) == allServices.end()) {
                            allServices.push_back(ppiItem);
                        }
                    }
                    break;
                }
            }
        }
        ea = next_head(ea, BADADDR);
    }
    if (found) {
        msg("[%s] Variable PPI calls (all):\n", plugin_name);
        msg(ft_to_string(table));
    }
    ft_destroy_table(table);
}

//--------------------------------------------------------------------------
// Get PPI names for X86 PEI modules
void efiAnalysis::efiAnalyzer::getPpiNamesX86() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] PPI finding (PEI services)\n", plugin_name);
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
        vector<ea_t> addrs = peiServicesAll[pei_services_table[i].name];
        vector<ea_t>::iterator ea;
        /* for each pei service */
        for (ea = addrs.begin(); ea != addrs.end(); ++ea) {
            ea_t address = *ea;

            insn_t insn;
            ea_t guidCodeAddress = 0;
            ea_t guidDataAddress = 0;
            auto found = false;
            uint16_t pushNumber = pei_services_table[i].ppi_guid_push_number;
            /* 10 instructions above */
            uint16_t pushCounter = 0;
            DEBUG_MSG("[%s] looking for PPIs in the 0x%016X area \n",
                      plugin_name, address, pushNumber);
            for (auto j = 0; j < 10; j++) {
                address = prev_head(address, startAddress);
                decode_insn(&insn, address);
                if (insn.itype == NN_push) {
                    pushCounter += 1;
                    if (pushCounter > pushNumber) {
                        break;
                    }
                    if (pushCounter == pushNumber) {
                        ea_t g_offset = pei_services_table[i].guid_offset;
                        if (g_offset == GUID_OFFSET_NONE) {
                            guidCodeAddress = address;
                            guidDataAddress = truncImmToDtype(
                                insn.ops[0].value, insn.ops[0].dtype);
                        } else {
                            guidCodeAddress = address;
                            ea_t guidDataAddressXref = truncImmToDtype(
                                insn.ops[0].value, insn.ops[0].dtype);
                            guidDataAddress =
                                get_wide_dword(guidDataAddressXref + g_offset);
                        }
                        if (guidDataAddress >= start &&
                            guidDataAddress != BADADDR) {
                            found = true;
                            break;
                        }
                    }
                }
            }
            if (found) {
                DEBUG_MSG("[%s] found PPI GUID parameter at 0x%016X\n",
                          plugin_name, guidCodeAddress);
                /* get guid */
                auto guid = json::array({get_wide_dword(guidDataAddress),
                                         get_wide_word(guidDataAddress + 4),
                                         get_wide_word(guidDataAddress + 6),
                                         get_wide_byte(guidDataAddress + 8),
                                         get_wide_byte(guidDataAddress + 9),
                                         get_wide_byte(guidDataAddress + 10),
                                         get_wide_byte(guidDataAddress + 11),
                                         get_wide_byte(guidDataAddress + 12),
                                         get_wide_byte(guidDataAddress + 13),
                                         get_wide_byte(guidDataAddress + 14),
                                         get_wide_byte(guidDataAddress + 15)});
                /* check guid */
                if ((static_cast<uint32_t>(guid[0]) == 0x00000000 &&
                     (uint16_t)guid[1] == 0x0000) ||
                    (static_cast<uint32_t>(guid[0]) == 0xffffffff &&
                     (uint16_t)guid[1] == 0xffff)) {
                    DEBUG_MSG("[%s] Incorrect GUID at 0x%016X\n", plugin_name,
                              guidCodeAddress);
                    continue;
                }
                /* get PPI item */
                json ppiItem;
                ppiItem["address"] = guidDataAddress;
                ppiItem["xref"] = guidCodeAddress;
                ppiItem["service"] = pei_services_table[i].name;
                ppiItem["guid"] = guid;
                /* find guid name */
                json::iterator dbItem;
                for (dbItem = dbProtocols.begin(); dbItem != dbProtocols.end();
                     ++dbItem) {
                    if (guid == dbItem.value()) {
                        ppiItem["ppi_name"] = dbItem.key();
                        /* check if item already exists */
                        vector<json>::iterator it;
                        it = find(allPPIs.begin(), allPPIs.end(), ppiItem);
                        if (it == allPPIs.end()) {
                            allPPIs.push_back(ppiItem);
                        }
                        break;
                    }
                }
                /* proprietary Ppi */
                if (ppiItem["ppi_name"].is_null()) {
                    ppiItem["ppi_name"] = "ProprietaryPpi";
                    /* check if item already exists */
                    vector<json>::iterator it;
                    it = find(allPPIs.begin(), allPPIs.end(), ppiItem);
                    if (it == allPPIs.end()) {
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
void efiAnalysis::efiAnalyzer::getProtBootServicesX64() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    insn_t insn;
    ft_table_t *table = ft_create_table();
    ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
    ft_write_ln(table, " Address ", " Service ");
    for (vector<segment_t *>::iterator seg = textSegments.begin();
         seg != textSegments.end(); ++seg) {
        segment_t *s = *seg;
        DEBUG_MSG(
            "[%s] BootServices finding from 0x%016X to 0x%016X (protocols)\n",
            plugin_name, s->start_ea, s->end_ea);
        ea_t ea = s->start_ea;
        uint16_t bsRegister = 0;
        while (ea <= s->end_ea) {
            decode_insn(&insn, ea);
            if (insn.itype == NN_callni && insn.ops[0].reg == REG_RAX) {
                for (auto i = 0; i < bootServicesTableX64Length; i++) {
                    if (insn.ops[0].addr ==
                        static_cast<ea_t>(bootServicesTableX64[i].offset)) {
                        /* set comment */
                        string cmt = getBsComment(
                            static_cast<ea_t>(bootServicesTableX64[i].offset),
                            X64);
                        set_cmt(ea, cmt.c_str(), true);
                        /* op_stroff */
                        opStroff(ea, "EFI_BOOT_SERVICES");
                        /* add line to table */
                        ft_printf_ln(table, " 0x%016X | %s ",
                                     static_cast<unsigned int>(ea),
                                     static_cast<char *>(
                                         bootServicesTableX64[i].service_name));
                        DEBUG_MSG("[%s] 0x%016X : %s\n", plugin_name, ea,
                                  static_cast<char *>(
                                      bootServicesTableX64[i].service_name));
                        bootServices[static_cast<string>(
                                         bootServicesTableX64[i].service_name)]
                            .push_back(ea);
                        /* add item to allBootServices vector */
                        json bsItem;
                        bsItem["address"] = ea;
                        bsItem["service_name"] = static_cast<string>(
                            bootServicesTableX64[i].service_name);
                        bsItem["table_name"] =
                            static_cast<string>("EFI_BOOT_SERVICES");
                        bsItem["offset"] = bootServicesTableX64[i].offset;
                        if (find(allServices.begin(), allServices.end(),
                                 bsItem) == allServices.end()) {
                            allServices.push_back(bsItem);
                        }
                        break;
                    }
                }
            }
            ea = next_head(ea, endAddress);
        }
    }
    msg("[%s] Boot services (protocols):\n", plugin_name);
    msg(ft_to_string(table));
    ft_destroy_table(table);
}

//--------------------------------------------------------------------------
// Get boot services by protocols for X86 modules
void efiAnalysis::efiAnalyzer::getProtBootServicesX86() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] BootServices finding from 0x%016X to 0x%016X (protocols)\n",
              plugin_name, startAddress, endAddress);
    ea_t ea = startAddress;
    insn_t insn;
    uint16_t bsRegister = 0;
    ft_table_t *table = ft_create_table();
    ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
    ft_write_ln(table, " Address ", " Service ");
    while (ea <= endAddress) {
        decode_insn(&insn, ea);
        if (insn.itype == NN_callni && insn.ops[0].reg == REG_EAX) {
            for (auto i = 0; i < bootServicesTableX86Length; i++) {
                if (insn.ops[0].addr ==
                    static_cast<ea_t>(bootServicesTableX86[i].offset)) {
                    /* set comment */
                    string cmt = getBsComment(
                        static_cast<ea_t>(bootServicesTableX86[i].offset), X86);
                    set_cmt(ea, cmt.c_str(), true);
                    /* op_stroff */
                    opStroff(ea, "EFI_BOOT_SERVICES");
                    /* add line to table */
                    ft_printf_ln(table, " 0x%016X | %s ",
                                 static_cast<unsigned int>(ea),
                                 static_cast<char *>(
                                     bootServicesTableX86[i].service_name));
                    DEBUG_MSG("[%s] 0x%016X : %s\n", plugin_name, ea,
                              static_cast<char *>(
                                  bootServicesTableX86[i].service_name));
                    bootServices[static_cast<string>(
                                     bootServicesTableX86[i].service_name)]
                        .push_back(ea);
                    /* add item to allBootServices vector */
                    json bsItem;
                    bsItem["address"] = ea;
                    bsItem["service_name"] = static_cast<string>(
                        bootServicesTableX86[i].service_name);
                    bsItem["table_name"] =
                        static_cast<string>("EFI_BOOT_SERVICES");
                    bsItem["offset"] = bootServicesTableX86[i].offset;
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
    msg("[%s] Boot services (protocols):\n", plugin_name);
    msg(ft_to_string(table));
    ft_destroy_table(table);
}

//--------------------------------------------------------------------------
// find other addresses of global gBS vars for X64 modules
void efiAnalysis::efiAnalyzer::findOtherBsTablesX64() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] finding of other addresses of global gBS variables\n",
              plugin_name);
    for (vector<json>::iterator s = allServices.begin(); s != allServices.end();
         ++s) {
        json jService = *s;
        string table_name = jService["table_name"];
        if (table_name.compare(static_cast<string>("EFI_BOOT_SERVICES"))) {
            continue;
        }
        size_t offset = static_cast<size_t>(jService["offset"]);
        if (offset < 0xf0) {
            continue;
        }
        ea_t addr = static_cast<ea_t>(jService["address"]);
        DEBUG_MSG("[%s] current service: 0x%016X\n", plugin_name, addr);
        ea_t addrBs = findUnknownBsVarX64(addr);
        if (!addrBs ||
            !(find(gBsList.begin(), gBsList.end(), addrBs) == gBsList.end())) {
            continue;
        }
        DEBUG_MSG("[%s] found BootServices table at 0x%016X, address = "
                  "0x%016X\n",
                  plugin_name, addr, addrBs);
        char hexAddr[21] = {};
        snprintf(hexAddr, 21, "%llX", static_cast<uint64_t>(addrBs));
        string name = "gBS_" + static_cast<string>(hexAddr);
        setPtrTypeAndName(addrBs, name, "EFI_BOOT_SERVICES");
        if (find(gRtList.begin(), gRtList.end(), addrBs) == gRtList.end()) {
            gBsList.push_back(addrBs);
        }
    }
}

//--------------------------------------------------------------------------
// Get boot services protocols names for X64 modules
void efiAnalysis::efiAnalyzer::getBsProtNamesX64() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    if (!textSegments.size()) {
        return;
    }
    segment_t *s = textSegments.at(0);
    ea_t start = s->start_ea;
    DEBUG_MSG(
        "[%s] protocols finding (boot services, start address = 0x%016X)\n",
        plugin_name, start);
    for (int i = 0; i < bootServicesTableX64Length; i++) {
        vector<ea_t> addrs = bootServices[bootServicesTableX64[i].service_name];
        vector<ea_t>::iterator ea;
        /* for each boot service */
        for (ea = addrs.begin(); ea != addrs.end(); ++ea) {
            ea_t address = *ea;
            DEBUG_MSG("[%s] looking for protocols in the 0x%016X area\n",
                      plugin_name, address);
            insn_t insn;
            ea_t guidCodeAddress = 0;
            ea_t guidDataAddress = 0;
            auto found = false;
            /* 10 instructions above */
            for (auto j = 0; j < 10; j++) {
                address = prev_head(address, startAddress);
                decode_insn(&insn, address);
                if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
                    insn.ops[0].reg == bootServicesTableX64[i].reg) {
                    guidCodeAddress = address;
                    guidDataAddress = insn.ops[1].addr;
                    if (insn.ops[1].addr > start &&
                        insn.ops[1].addr != BADADDR) {
                        found = true;
                        break;
                    }
                }
            }
            if (found) {
                DEBUG_MSG("[%s] found protocol GUID parameter at 0x%016X\n",
                          plugin_name, guidCodeAddress);
                /* get guid */
                auto guid = json::array({get_wide_dword(guidDataAddress),
                                         get_wide_word(guidDataAddress + 4),
                                         get_wide_word(guidDataAddress + 6),
                                         get_wide_byte(guidDataAddress + 8),
                                         get_wide_byte(guidDataAddress + 9),
                                         get_wide_byte(guidDataAddress + 10),
                                         get_wide_byte(guidDataAddress + 11),
                                         get_wide_byte(guidDataAddress + 12),
                                         get_wide_byte(guidDataAddress + 13),
                                         get_wide_byte(guidDataAddress + 14),
                                         get_wide_byte(guidDataAddress + 15)});
                /* check guid */
                if ((static_cast<uint32_t>(guid[0]) == 0x00000000 &&
                     (uint16_t)guid[1] == 0x0000) ||
                    (static_cast<uint32_t>(guid[0]) == 0xffffffff &&
                     (uint16_t)guid[1] == 0xffff)) {
                    DEBUG_MSG("[%s] Incorrect GUID at 0x%016X\n", plugin_name,
                              guidCodeAddress);
                    continue;
                }
                /* get protocol item */
                json protocolItem;
                protocolItem["address"] = guidDataAddress;
                protocolItem["xref"] = guidCodeAddress;
                protocolItem["service"] = bootServicesTableX64[i].service_name;
                protocolItem["guid"] = guid;
                /* find guid name */
                json::iterator dbItem;
                for (dbItem = dbProtocols.begin(); dbItem != dbProtocols.end();
                     ++dbItem) {
                    if (guid == dbItem.value()) {
                        protocolItem["prot_name"] = dbItem.key();
                        /* check if item already exist */
                        vector<json>::iterator it;
                        it = find(allProtocols.begin(), allProtocols.end(),
                                  protocolItem);
                        if (it == allProtocols.end()) {
                            allProtocols.push_back(protocolItem);
                        }
                        break;
                    }
                }
                /* proprietary protocol */
                if (protocolItem["prot_name"].is_null()) {
                    protocolItem["prot_name"] = "ProprietaryProtocol";
                    /* check if item already exist */
                    vector<json>::iterator it;
                    it = find(allProtocols.begin(), allProtocols.end(),
                              protocolItem);
                    if (it == allProtocols.end()) {
                        allProtocols.push_back(protocolItem);
                    }
                    continue;
                }
            }
        }
    }
}

//--------------------------------------------------------------------------
// Get boot services protocols names for X86 modules
void efiAnalysis::efiAnalyzer::getBsProtNamesX86() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] protocols finding (boot services)\n", plugin_name);
    ea_t start = startAddress;
    segment_t *seg_info = get_segm_by_name(".text");
    if (seg_info != nullptr) {
        start = seg_info->start_ea;
    }
    for (int i = 0; i < bootServicesTableX86Length; i++) {
        vector<ea_t> addrs = bootServices[bootServicesTableX86[i].service_name];
        vector<ea_t>::iterator ea;
        /* for each boot service */
        for (ea = addrs.begin(); ea != addrs.end(); ++ea) {
            ea_t address = *ea;
            DEBUG_MSG("[%s] looking for protocols in the 0x%016X area\n",
                      plugin_name, address);
            insn_t insn;
            ea_t guidCodeAddress = 0;
            ea_t guidDataAddress = 0;
            auto found = false;
            uint16_t pushNumber = bootServicesTableX86[i].push_number;
            /* if service is not currently being processed */
            if (pushNumber == PUSH_NONE) {
                break;
            }
            /* 10 instructions above */
            uint16_t pushCounter = 0;
            for (auto j = 0; j < 10; j++) {
                address = prev_head(address, startAddress);
                decode_insn(&insn, address);
                if (insn.itype == NN_push) {
                    pushCounter += 1;
                    if (pushCounter > pushNumber) {
                        break;
                    }
                    if (pushCounter == pushNumber) {
                        guidCodeAddress = address;
                        guidDataAddress = insn.ops[0].value;
                        if (insn.ops[0].value > start &&
                            insn.ops[0].value != BADADDR) {
                            found = true;
                            break;
                        }
                    }
                }
            }
            if (found) {
                DEBUG_MSG("[%s] found protocol GUID parameter at 0x%016X\n",
                          plugin_name, guidCodeAddress);
                /* get guid */
                auto guid = json::array({get_wide_dword(guidDataAddress),
                                         get_wide_word(guidDataAddress + 4),
                                         get_wide_word(guidDataAddress + 6),
                                         get_wide_byte(guidDataAddress + 8),
                                         get_wide_byte(guidDataAddress + 9),
                                         get_wide_byte(guidDataAddress + 10),
                                         get_wide_byte(guidDataAddress + 11),
                                         get_wide_byte(guidDataAddress + 12),
                                         get_wide_byte(guidDataAddress + 13),
                                         get_wide_byte(guidDataAddress + 14),
                                         get_wide_byte(guidDataAddress + 15)});
                /* check guid */
                if ((static_cast<uint32_t>(guid[0]) == 0x00000000 &&
                     (uint16_t)guid[1] == 0x0000) ||
                    (static_cast<uint32_t>(guid[0]) == 0xffffffff &&
                     (uint16_t)guid[1] == 0xffff)) {
                    DEBUG_MSG("[%s] Incorrect GUID at 0x%016X\n", plugin_name,
                              guidCodeAddress);
                    continue;
                }
                /* get protocol item */
                json protocolItem;
                protocolItem["address"] = guidDataAddress;
                protocolItem["xref"] = guidCodeAddress;
                protocolItem["service"] = bootServicesTableX86[i].service_name;
                protocolItem["guid"] = guid;
                /* find guid name */
                json::iterator dbItem;
                for (dbItem = dbProtocols.begin(); dbItem != dbProtocols.end();
                     ++dbItem) {
                    if (guid == dbItem.value()) {
                        protocolItem["prot_name"] = dbItem.key();
                        /* check if item already exist */
                        vector<json>::iterator it;
                        it = find(allProtocols.begin(), allProtocols.end(),
                                  protocolItem);
                        if (it == allProtocols.end()) {
                            allProtocols.push_back(protocolItem);
                        }
                        break;
                    }
                }
                /* proprietary protocol */
                if (protocolItem["prot_name"].is_null()) {
                    protocolItem["prot_name"] = "ProprietaryProtocol";
                    /* check if item already exist */
                    vector<json>::iterator it;
                    it = find(allProtocols.begin(), allProtocols.end(),
                              protocolItem);
                    if (it == allProtocols.end()) {
                        allProtocols.push_back(protocolItem);
                    }
                    continue;
                }
            }
        }
    }
}

//--------------------------------------------------------------------------
// Get smm services protocols names for X64 modules
void efiAnalysis::efiAnalyzer::getSmmProtNamesX64() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    if (!textSegments.size()) {
        return;
    }
    segment_t *s = textSegments.at(0);
    ea_t start = s->start_ea;
    DEBUG_MSG(
        "[%s] protocols finding (smm services, start address = 0x%016X)\n",
        plugin_name, start);
    for (int i = 0; i < smmServicesProtX64Length; i++) {
        vector<ea_t> addrs = smmServices[smmServicesProtX64[i].service_name];
        vector<ea_t>::iterator ea;
        /* for each smm service */
        for (ea = addrs.begin(); ea != addrs.end(); ++ea) {
            ea_t address = *ea;
            DEBUG_MSG("[%s] looking for protocols in the 0x%016X area\n",
                      plugin_name, address);
            insn_t insn;
            ea_t guidCodeAddress = 0;
            ea_t guidDataAddress = 0;
            auto found = false;
            /* 10 instructions above */
            for (auto j = 0; j < 10; j++) {
                address = prev_head(address, startAddress);
                decode_insn(&insn, address);
                if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
                    insn.ops[0].reg == smmServicesProtX64[i].reg) {
                    guidCodeAddress = address;
                    guidDataAddress = insn.ops[1].addr;
                    if (insn.ops[1].addr > start &&
                        insn.ops[1].addr != BADADDR) {
                        found = true;
                        break;
                    }
                }
            }
            if (found) {
                DEBUG_MSG("[%s] found protocol GUID parameter at 0x%016X\n",
                          plugin_name, guidCodeAddress);
                /* get guid */
                auto guid = json::array({get_wide_dword(guidDataAddress),
                                         get_wide_word(guidDataAddress + 4),
                                         get_wide_word(guidDataAddress + 6),
                                         get_wide_byte(guidDataAddress + 8),
                                         get_wide_byte(guidDataAddress + 9),
                                         get_wide_byte(guidDataAddress + 10),
                                         get_wide_byte(guidDataAddress + 11),
                                         get_wide_byte(guidDataAddress + 12),
                                         get_wide_byte(guidDataAddress + 13),
                                         get_wide_byte(guidDataAddress + 14),
                                         get_wide_byte(guidDataAddress + 15)});
                /* check guid */
                if ((static_cast<uint32_t>(guid[0]) == 0x00000000 &&
                     (uint16_t)guid[1] == 0x0000) ||
                    (static_cast<uint32_t>(guid[0]) == 0xffffffff &&
                     (uint16_t)guid[1] == 0xffff)) {
                    DEBUG_MSG("[%s] Incorrect GUID at 0x%016X\n", plugin_name,
                              guidCodeAddress);
                    continue;
                }
                /* get protocol item */
                json protocolItem;
                protocolItem["address"] = guidDataAddress;
                protocolItem["xref"] = guidCodeAddress;
                protocolItem["service"] = smmServicesProtX64[i].service_name;
                protocolItem["guid"] = guid;
                /* find guid name */
                json::iterator dbItem;
                for (dbItem = dbProtocols.begin(); dbItem != dbProtocols.end();
                     ++dbItem) {
                    if (guid == dbItem.value()) {
                        protocolItem["prot_name"] = dbItem.key();
                        /* check if item already exist */
                        vector<json>::iterator it;
                        it = find(allProtocols.begin(), allProtocols.end(),
                                  protocolItem);
                        if (it == allProtocols.end()) {
                            allProtocols.push_back(protocolItem);
                        }
                        break;
                    }
                }
                /* proprietary protocol */
                if (protocolItem["prot_name"].is_null()) {
                    protocolItem["prot_name"] = "ProprietaryProtocol";
                    /* check if item already exist */
                    vector<json>::iterator it;
                    it = find(allProtocols.begin(), allProtocols.end(),
                              protocolItem);
                    if (it == allProtocols.end()) {
                        allProtocols.push_back(protocolItem);
                    }
                    continue;
                }
            }
        }
    }
}

//--------------------------------------------------------------------------
// Print protocols / PPIs
void efiAnalysis::efiAnalyzer::printInterfaces() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] %s printing\n", plugin_name, if_pl);
    if (!if_tbl->size()) {
        printf("[%s] %s list is empty\n", plugin_name, if_pl);
        return;
    }
    ft_table_t *table = ft_create_table();
    ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
    ft_write_ln(table, " GUID ", if_name, " Address ", " Service ");
    for (vector<json>::iterator ifItemIt = if_tbl->begin();
         ifItemIt != if_tbl->end(); ++ifItemIt) {
        json ifItem = *ifItemIt;
        auto guid = ifItem["guid"];
        string svcName = ifItem[if_key];
        ea_t address = static_cast<ea_t>(ifItem["address"]);
        string service = ifItem["service"];
        ft_printf_ln(
            table,
            " %08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X | %s | "
            "0x%016X | %s ",
            static_cast<uint32_t>(guid[0]), static_cast<uint16_t>(guid[1]),
            static_cast<uint16_t>(guid[2]), static_cast<uint8_t>(guid[3]),
            static_cast<uint8_t>(guid[4]), static_cast<uint8_t>(guid[5]),
            static_cast<uint8_t>(guid[6]), static_cast<uint8_t>(guid[7]),
            static_cast<uint8_t>(guid[8]), static_cast<uint8_t>(guid[9]),
            static_cast<uint8_t>(guid[10]), svcName.c_str(),
            static_cast<unsigned int>(address), service.c_str());
    }
    msg("[%s] %s:\n", plugin_name, if_pl);
    msg(ft_to_string(table));
    ft_destroy_table(table);
}

//--------------------------------------------------------------------------
// Mark protocols
void efiAnalysis::efiAnalyzer::markInterfaces() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] %s marking\n", plugin_name, if_pl);
    for (vector<json>::iterator ifItemIt = if_tbl->begin();
         ifItemIt != if_tbl->end(); ++ifItemIt) {
        json ifItem = *ifItemIt;
        ea_t address = static_cast<ea_t>(ifItem["address"]);
        /* check if guid on this address already marked */
        bool marked = false;
        for (vector<ea_t>::iterator markedAddress = markedInterfaces.begin();
             markedAddress != markedInterfaces.end(); ++markedAddress) {
            if (*markedAddress == address) {
                marked = true;
                break;
            }
        }
        if (marked) {
            continue;
        }
        char hexAddr[21] = {};
        snprintf(hexAddr, 21, "%llX", static_cast<uint64_t>(address));
        string svcName = static_cast<string>(ifItem[if_key]);
        string name = svcName + "_" + static_cast<string>(hexAddr);
        set_name(address, name.c_str(), SN_CHECK);
        setGuidType(address);
        /* comment line */
        string comment = "EFI_GUID " + svcName;
        /* save address */
        markedInterfaces.push_back(address);
        DEBUG_MSG("[%s] address: 0x%016X, comment: %s\n", plugin_name, address,
                  comment.c_str());
    }
}

//--------------------------------------------------------------------------
// Mark GUIDs found in the .data segment
void efiAnalysis::efiAnalyzer::markDataGuids() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    for (vector<segment_t *>::iterator seg = dataSegments.begin();
         seg != dataSegments.end(); ++seg) {
        segment_t *s = *seg;
        DEBUG_MSG("[%s] marking .data GUIDs from 0x%016X to 0x%016X\n",
                  plugin_name, s->start_ea, s->end_ea);
        ea_t ea = s->start_ea;
        while (ea != BADADDR && ea <= s->end_ea - 15) {
            if (get_wide_dword(ea) == 0x00000000 ||
                get_wide_dword(ea) == 0xffffffff) {
                ea += 1;
                continue;
            }
            /* get guid */
            auto guid =
                json::array({get_wide_dword(ea), get_wide_word(ea + 4),
                             get_wide_word(ea + 6), get_wide_byte(ea + 8),
                             get_wide_byte(ea + 9), get_wide_byte(ea + 10),
                             get_wide_byte(ea + 11), get_wide_byte(ea + 12),
                             get_wide_byte(ea + 13), get_wide_byte(ea + 14),
                             get_wide_byte(ea + 15)});
            /* find guid name */
            json::iterator dbItem;
            for (dbItem = dbProtocols.begin(); dbItem != dbProtocols.end();
                 ++dbItem) {
                if (guid == dbItem.value()) {
                    /* mark .data guid */
                    char hexAddr[21] = {};
                    snprintf(hexAddr, 21, "%llX", static_cast<uint64_t>(ea));
                    string name =
                        dbItem.key() + "_" + static_cast<string>(hexAddr);
                    set_name(ea, name.c_str(), SN_CHECK);
                    setGuidType(ea);
                    /* comment line */
                    string comment = "EFI_GUID " + dbItem.key();
                    DEBUG_MSG("[%s] address: 0x%016X, comment: %s\n",
                              plugin_name, ea, comment.c_str());
                    json guidItem;
                    guidItem["address"] = ea;
                    guidItem["name"] = dbItem.key();
                    char guidValue[37] = {0};
                    snprintf(guidValue, 37,
                             "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                             static_cast<uint32_t>(guid[0]),
                             static_cast<uint16_t>(guid[1]),
                             static_cast<uint16_t>(guid[2]),
                             static_cast<uint8_t>(guid[3]),
                             static_cast<uint8_t>(guid[4]),
                             static_cast<uint8_t>(guid[5]),
                             static_cast<uint8_t>(guid[6]),
                             static_cast<uint8_t>(guid[7]),
                             static_cast<uint8_t>(guid[8]),
                             static_cast<uint8_t>(guid[9]),
                             static_cast<uint8_t>(guid[10]));
                    guidItem["guid"] = guidValue;
                    allGuids.push_back(guidItem);
                    dataGuids.push_back(guidItem);
                    break;
                }
            }
            ea += 1;
        }
    }
}

//--------------------------------------------------------------------------
// Mark GUIDs found in local variables for X64 modules
void efiAnalysis::efiAnalyzer::markLocalGuidsX64() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    for (vector<segment_t *>::iterator seg = textSegments.begin();
         seg != textSegments.end(); ++seg) {
        segment_t *s = *seg;
        ea_t ea = s->start_ea;
        insn_t insn;
        insn_t insnNext;
        DEBUG_MSG("[%s] local GUIDs finding from 0x%016X to 0x%016X\n",
                  plugin_name, s->start_ea, s->end_ea);
        while (ea <= s->end_ea) {
            decode_insn(&insn, ea);
            /* check if insn like 'mov dword ptr [...], gData1' */
            if (insn.itype == NN_mov && insn.ops[0].type == o_displ &&
                insn.ops[1].type == o_imm) {
                /* get guid->data1 value */
                uint32_t gData1 = static_cast<uint32_t>(insn.ops[1].value);
                if (gData1 == 0x00000000 || gData1 == 0xffffffff) {
                    ea = next_head(ea, BADADDR);
                    continue;
                }
                ea_t eaNext = next_head(ea, BADADDR);
                decode_insn(&insnNext, eaNext);
                /* check if insn like 'mov dword ptr [...], gData2' */
                if (insnNext.itype == NN_mov &&
                    insnNext.ops[0].type == o_displ &&
                    insnNext.ops[1].type == o_imm) {
                    /* get guid->data2 value */
                    uint16_t gData2 =
                        static_cast<uint16_t>(insnNext.ops[1].value);
                    if (gData2 == 0x0000 || gData2 == 0xffff) {
                        ea = next_head(ea, BADADDR);
                        continue;
                    }
                    /* found guid->data1 and guid->data2 values, try to get guid
                     * name */
                    json::iterator dbItem;
                    for (dbItem = dbProtocols.begin();
                         dbItem != dbProtocols.end(); ++dbItem) {
                        auto guid = dbItem.value();
                        if (gData1 == static_cast<uint32_t>(guid[0]) &&
                            gData2 == static_cast<uint16_t>(guid[1])) {
                            /* mark local guid */

                            char hexAddr[21] = {};
                            snprintf(hexAddr, 21, "%llX",
                                     static_cast<uint64_t>(ea));
                            string name = dbItem.key() + "_" +
                                          static_cast<string>(hexAddr);
                            /* comment line */
                            string comment = "EFI_GUID " + dbItem.key();
                            DEBUG_MSG("[%s] address: 0x%016X, comment: %s\n",
                                      plugin_name, ea, comment.c_str());
                            /* set comment */
                            set_cmt(ea, comment.c_str(), true);
                            json guidItem;
                            guidItem["address"] = ea;
                            guidItem["name"] = dbItem.key();
                            char guidValue[37] = {0};
                            snprintf(guidValue, 37,
                                     "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%"
                                     "02X%02X",
                                     static_cast<uint32_t>(guid[0]),
                                     static_cast<uint16_t>(guid[1]),
                                     static_cast<uint16_t>(guid[2]),
                                     static_cast<uint8_t>(guid[3]),
                                     static_cast<uint8_t>(guid[4]),
                                     static_cast<uint8_t>(guid[5]),
                                     static_cast<uint8_t>(guid[6]),
                                     static_cast<uint8_t>(guid[7]),
                                     static_cast<uint8_t>(guid[8]),
                                     static_cast<uint8_t>(guid[9]),
                                     static_cast<uint8_t>(guid[10]));
                            guidItem["guid"] = guidValue;
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
    for (ea_t ea = func->start_ea; ea < func->end_ea;
         ea = next_head(ea, BADADDR)) {
        decode_insn(&insn, ea);
        if (insn.itype == NN_call) {
            ea_t nextFuncAddr = insn.ops[0].addr;
            func_t *nextFunc = get_func(nextFuncAddr);
            if (nextFunc) {
                auto it = std::find(excFunctions.begin(), excFunctions.end(),
                                    nextFunc);
                if (it == excFunctions.end()) {
                    excFunctions.push_back(nextFunc);
                    findCalloutRec(nextFunc);
                }
            }
        }
        /* find callouts with gBS */
        for (vector<ea_t>::iterator bs = gBsList.begin(); bs != gBsList.end();
             ++bs) {
            /* check if insn is 'mov rax, cs:gBS' */
            if (insn.itype == NN_mov && insn.ops[0].reg == REG_RAX &&
                insn.ops[1].type == o_mem && insn.ops[1].addr == *bs) {
                DEBUG_MSG("[%s] SMM callout found: 0x%016X\n", plugin_name, ea);
                calloutAddrs.push_back(ea);
            }
        }
        /* find callouts with gRT */
        for (vector<ea_t>::iterator rt = gRtList.begin(); rt != gRtList.end();
             ++rt) {
            /* check if insn is 'mov rax, cs:gRT' */
            if (insn.itype == NN_mov && insn.ops[0].reg == REG_RAX &&
                insn.ops[1].type == o_mem && insn.ops[1].addr == *rt) {
                DEBUG_MSG("[%s] SMM callout found: 0x%016X\n", plugin_name, ea);
                calloutAddrs.push_back(ea);
            }
        }
    }
}

//--------------------------------------------------------------------------
// Find SwSmiHandler function inside SMM drivers
void efiAnalysis::efiAnalyzer::findSwSmiHandlers() {
    smiHandlers = findSmiHandlersSmmSwDispatch(dataSegments, stackGuids);
}

//--------------------------------------------------------------------------
// Find callouts inside SwSmiHandler function:
//  * find SwSmiHandler function
//  * find gBS->service_name and gRT->service_name inside SmiHandler
//  function
bool efiAnalysis::efiAnalyzer::findSmmCallout() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] Looking for SMM callout\n", plugin_name);
    if (!gBsList.size() && !gRtList.size()) {
        return false;
    }
    if (!smiHandlers.size()) {
        DEBUG_MSG("[%s] can't find a SwSmiHandler functions\n", plugin_name);
        return false;
    }
    for (vector<func_t *>::iterator f = smiHandlers.begin();
         f != smiHandlers.end(); ++f) {
        func_t *func = *f;
        findCalloutRec(func);
    }
    return true;
}

bool efiAnalysis::efiAnalyzer::findPPIGetVariableStackOveflow() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] Looking for ppi getvariable stack overflow, "
              "allServices.size() = %d \n",
              plugin_name, allServices.size());
    vector<ea_t> getVariableServicesCalls;
    string getVariableStr("VariablePPI.GetVariable");
    for (vector<json>::iterator j_service = allServices.begin();
         j_service != allServices.end(); ++j_service) {
        json service = *j_service;
        string service_name = static_cast<string>(service["service_name"]);
        string table_name = static_cast<string>(service["table_name"]);
        ea_t addr = static_cast<ea_t>(service["address"]);
        if (service_name.compare(getVariableStr) == 0) {
            getVariableServicesCalls.push_back(addr);
        }
    }
    DEBUG_MSG("[%s] Finished iterating over allServices, "
              "getVariableServicesCalls.size() = %d \n",
              plugin_name, getVariableServicesCalls.size());
    sort(getVariableServicesCalls.begin(), getVariableServicesCalls.end());
    if (getVariableServicesCalls.size() < 2) {
        DEBUG_MSG("[%s] less than 2 VariablePPI.GetVariable calls found\n",
                  plugin_name);
        return false;
    }
    ea_t prev_addr = getVariableServicesCalls.at(0);
    for (auto i = 1; i < getVariableServicesCalls.size(); ++i) {
        ea_t curr_addr = getVariableServicesCalls.at(i);
        DEBUG_MSG("[%s] VariablePPI.GetVariable_1: 0x%016x, "
                  "VariablePPI.GetVariable_2: 0x%016x\n",
                  plugin_name, prev_addr, curr_addr);
        /* check code from GetVariable_1 to GetVariable_2 */
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
                        if (insn.ops[0].type = o_reg) {
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
                getVariableStackOverflow.push_back(curr_addr);
                DEBUG_MSG("[%s] overflow can occur here: 0x%016llX\n",
                          plugin_name, curr_addr);
                continue;
            }

            for (auto j = 0; j < 15; j++) {
                address = prev_head(address, startAddress);
                decode_insn(&insn, address);
                if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
                    insn.ops[0].reg == arg5_reg &&
                    insn.ops[1].type == o_displ) {
                    curr_datasize_addr = insn.ops[1].addr;
                    datasize_addr_found = true;
                    break;
                }
            }

            DEBUG_MSG("[%s] curr_datasize_addr = 0x%016x, datasize_addr_found "
                      "= %d \n",
                      plugin_name, curr_datasize_addr, datasize_addr_found);

            if (!datasize_addr_found) {
                // if datasize wasn't found, just let the pattern
                // trigger - for manual review
                getVariableStackOverflow.push_back(curr_addr);
                DEBUG_MSG("[%s] overflow can occur here: 0x%016llX\n",
                          plugin_name, curr_addr);
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
                        if (insn.ops[0].type = o_reg) {
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
                getVariableStackOverflow.push_back(curr_addr);
                DEBUG_MSG("[%s] overflow can occur here: 0x%016llX\n",
                          plugin_name, curr_addr);
                continue;
            }

            for (auto j = 0; j < 15; j++) {
                address = prev_head(address, startAddress);
                decode_insn(&insn, address);
                if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
                    insn.ops[0].reg == arg5_reg &&
                    insn.ops[1].type == o_displ) {
                    prev_datasize_addr = insn.ops[1].addr;
                    datasize_addr_found = true;
                    break;
                }
            }

            DEBUG_MSG(
                "[%s] prev_datasize_addr = 0x%016x, datasize_addr_found = %d, "
                "(prev_datasize_addr == curr_datasize_addr) = %d \n",
                plugin_name, prev_datasize_addr, datasize_addr_found,
                (prev_datasize_addr == curr_datasize_addr));

            if (!datasize_addr_found) {
                getVariableStackOverflow.push_back(curr_addr);
                DEBUG_MSG("[%s] overflow can occur here: 0x%016llX\n",
                          plugin_name, curr_addr);
            } else if (prev_datasize_addr == curr_datasize_addr) {
                getVariableStackOverflow.push_back(curr_addr);
                DEBUG_MSG("[%s] overflow can occur here: 0x%016llX "
                          "(prev_datasize_addr == curr_datasize_addr) \n",
                          plugin_name, curr_addr);
            }
        }
        prev_addr = curr_addr;
    }
    return (getVariableStackOverflow.size() > 0);
}

//--------------------------------------------------------------------------
// Find potential stack/heap overflow with double GetVariable calls
bool efiAnalysis::efiAnalyzer::findGetVariableOveflow(
    vector<json> allServices) {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] Looking for GetVariable stack/heap overflow\n",
              plugin_name);
    vector<ea_t> getVariableServicesCalls;
    string getVariableStr("GetVariable");
    for (vector<json>::iterator j_service = allServices.begin();
         j_service != allServices.end(); ++j_service) {
        json service = *j_service;
        string service_name = static_cast<string>(service["service_name"]);
        ea_t addr = static_cast<ea_t>(service["address"]);
        if (service_name.compare(getVariableStr) == 0) {
            getVariableServicesCalls.push_back(addr);
        }
    }
    sort(getVariableServicesCalls.begin(), getVariableServicesCalls.end());
    if (getVariableServicesCalls.size() < 2) {
        DEBUG_MSG("[%s] less than 2 GetVariable calls found\n", plugin_name);
        return false;
    }
    ea_t prev_addr = getVariableServicesCalls.at(0);
    ea_t ea;
    insn_t insn;
    for (auto i = 1; i < getVariableServicesCalls.size(); ++i) {
        ea_t curr_addr = getVariableServicesCalls.at(i);
        DEBUG_MSG("[%s] GetVariable_1: 0x%016x, GetVariable_2: 0x%016x\n",
                  plugin_name, prev_addr, curr_addr);
        /* get dataSizeStackAddr */
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
        /* check code from GetVariable_1 to GetVariable_2 */
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
            /* check for wrong GetVariable detection */
            bool wrong_detection = false;
            ea = prev_head(static_cast<ea_t>(curr_addr), 0);
            for (auto i = 0; i < 8; ++i) {
                decode_insn(&insn, ea);
                if (insn.itype == NN_mov && insn.ops[0].type == o_reg &&
                    insn.ops[1].type == o_mem) {
                    ea_t mem_addr = static_cast<ea_t>(insn.ops[1].addr);
                    if (find(gBsList.begin(), gBsList.end(), mem_addr) !=
                        gBsList.end()) {
                        wrong_detection = true;
                        break;
                    }
                }
                ea = prev_head(ea, 0);
            }
            /* check DataSize initialization */
            bool init_ok = false;
            decode_insn(&insn, prev_head(curr_addr, 0));
            if (!wrong_detection &&
                !(insn.itype == NN_mov && insn.ops[0].type == o_displ &&
                  (insn.ops[0].phrase == REG_RSP ||
                   insn.ops[0].phrase == REG_RBP))) {
                init_ok = true;
            }
            /* check that the DataSize argument variable is the same for two
             * calls */
            if (init_ok) {
                ea = prev_head(static_cast<ea_t>(prev_addr), 0);
                for (auto i = 0; i < 10; ++i) {
                    decode_insn(&insn, ea);
                    if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
                        insn.ops[0].reg == REG_R9) {
                        if (dataSizeStackAddr == insn.ops[1].addr) {
                            getVariableOverflow.push_back(curr_addr);
                            DEBUG_MSG(
                                "[%s] \toverflow can occur here: 0x%016llX\n",
                                plugin_name, curr_addr);
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
bool efiAnalysis::efiAnalyzer::findSmmGetVariableOveflow() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] Looking for SmmGetVariable stack/heap overflow\n",
              plugin_name);
    vector<ea_t> smmGetVariableCalls =
        findSmmGetVariableCalls(dataSegments, &allServices);
    sort(smmGetVariableCalls.begin(), smmGetVariableCalls.end());
    if (smmGetVariableCalls.size() < 2) {
        DEBUG_MSG("[%s] less than 2 GetVariable calls found\n", plugin_name);
        return false;
    }
    ea_t prev_addr = smmGetVariableCalls.at(0);
    ea_t ea;
    insn_t insn;
    for (auto i = 1; i < smmGetVariableCalls.size(); ++i) {
        ea_t curr_addr = smmGetVariableCalls.at(i);
        DEBUG_MSG("[%s] SmmGetVariable_1: 0x%016x, SmmGetVariable_2: 0x%016x\n",
                  plugin_name, prev_addr, curr_addr);
        /* get dataSizeStackAddr */
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
        /* check code from SmmGetVariable_1 to SmmGetVariable_2 */
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
        /* if ok */
        if (ok) {
            /* check DataSize initialization */
            bool init_ok = false;
            decode_insn(&insn, prev_head(curr_addr, 0));
            if (!(insn.itype == NN_mov && insn.ops[0].type == o_displ &&
                  (insn.ops[0].phrase == REG_RSP ||
                   insn.ops[0].phrase == REG_RBP))) {
                init_ok = true;
            }
            /* check that the DataSize argument variable is the same for two
             * calls */
            if (init_ok) {
                ea = prev_head(static_cast<ea_t>(prev_addr), 0);
                for (auto i = 0; i < 10; ++i) {
                    decode_insn(&insn, ea);
                    if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
                        insn.ops[0].reg == REG_R9) {
                        if (dataSizeStackAddr == insn.ops[1].addr) {
                            smmGetVariableOverflow.push_back(curr_addr);
                            DEBUG_MSG(
                                "[%s] \toverflow can occur here: 0x%016llX\n",
                                plugin_name, curr_addr);
                            break;
                        }
                        DEBUG_MSG(
                            "[%s] \tDataSize argument variable is not the "
                            "same: 0x%016x\n",
                            plugin_name, curr_addr);
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
bool efiAnalysis::efiAnalyzer::efiSmmCpuProtocolResolver() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    readSaveStateCalls =
        resolveEfiSmmCpuProtocol(stackGuids, dataGuids, &allServices);
    return true;
}

//--------------------------------------------------------------------------
// Dump all info to JSON file
void efiAnalysis::efiAnalyzer::dumpInfo() {
    json info;
    info["gST"] = gStList;
    info["gBS"] = gBsList;
    info["gRT"] = gRtList;
    info["gSmst"] = gSmstList;
    info["gImageHandle"] = gImageHandleList;
    info["bs_all"] = bootServicesAll;
    info["rt_all"] = runtimeServicesAll;
    info["smm_all"] = smmServicesAll;
    info["bs_protocols"] = bootServices;
    info["smm_protocols"] = smmServices;
    info["protocols"] = allProtocols;
    if (readSaveStateCalls.size()) {
        info["ReadSaveState"] = readSaveStateCalls;
    }
    if (calloutAddrs.size()) {
        info["vulns"]["smm_callout"] = calloutAddrs;
    }
    if (getVariableStackOverflow.size()) {
        info["vulns"]["pei_get_variable_stack_over"] = getVariableStackOverflow;
    }
    if (getVariableOverflow.size()) {
        info["vulns"]["get_variable_over"] = getVariableOverflow;
    }
    if (smmGetVariableOverflow.size()) {
        info["vulns"]["smm_get_variable_over"] = smmGetVariableOverflow;
    }
    info["pei_all"] = peiServicesAll;

    vector<json> smiHandlersAddrs;
    if (smiHandlers.size() > 0) {
        for (vector<func_t *>::iterator f = smiHandlers.begin();
             f != smiHandlers.end(); ++f) {
            func_t *func = *f;
            smiHandlersAddrs.push_back(func->start_ea);
        }
    }
    info["smi_handlers"] = smiHandlersAddrs;

    string idbPath;
    idbPath = get_path(PATH_TYPE_IDB);
    path logFile;
    logFile /= idbPath;
    logFile.replace_extension(".json");
    std::ofstream out(logFile);
    out << std::setw(4) << info << std::endl;
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] the log is saved in a JSON file\n", plugin_name);
}

//--------------------------------------------------------------------------
// Show all non-empty choosers windows
void showAllChoosers(efiAnalysis::efiAnalyzer analyzer) {
    qstring title;
    /* open window with all services */
    if (analyzer.allServices.size()) {
        title = "efiXplorer: services";
        services_show(analyzer.allServices, title);
    }
    /* open window with protocols */
    if (analyzer.fileType == FTYPE_PEI) {
        if (analyzer.allPPIs.size()) {
            title = "efiXplorer: PPIs";
            ppis_show(analyzer.allPPIs, title);
        }
    } else { /* FTYPE_DXE_AND_THE_LIKE */
        if (analyzer.allProtocols.size()) {
            title = "efiXplorer: protocols";
            protocols_show(analyzer.allProtocols, title);
        }
    }
    /* open window with data guids */
    if (analyzer.allGuids.size()) {
        qstring title = "efiXplorer: guids";
        guids_show(analyzer.allGuids, title);
    }
}

//--------------------------------------------------------------------------
// Main function for X64 modules
bool efiAnalysis::efiAnalyzerMainX64() {
    efiAnalysis::efiAnalyzer analyzer;

    while (!auto_is_ok()) {
        auto_wait();
    };

    /* find .text and .data segments */
    analyzer.getSegments();

    /* mark GUIDs */
    analyzer.markDataGuids();
    analyzer.markLocalGuidsX64();

    analyzer.fileType = getFileType(&analyzer.allGuids);

    analyzer.setStrings();

    /* find global vars for gImageHandle, gST, gBS, gRT, gSmst */
    if (analyzer.fileType == FTYPE_DXE_AND_THE_LIKE) {
        analyzer.findImageHandleX64();
        analyzer.findSystemTableX64();
        analyzer.findBootServicesTables(X64);
        analyzer.findRuntimeServicesTables(X64);
        analyzer.findSmstX64();

        /* find boot services and runtime services */
        analyzer.getProtBootServicesX64();
        analyzer.findOtherBsTablesX64();
        analyzer.getAllBootServices(X64);
        analyzer.getAllRuntimeServices(X64);

        /* find smm services */
        analyzer.getAllSmmServicesX64();

        /* print and mark protocols */
        analyzer.getBsProtNamesX64();
        analyzer.getSmmProtNamesX64();
        analyzer.printInterfaces();
        analyzer.markInterfaces();

        /* find potential smm callouts */
        analyzer.findSwSmiHandlers();
        analyzer.findSmmCallout();

        /* find potential vuln in GetVariable function */
        analyzer.findGetVariableOveflow(analyzer.allServices);

        /* find potential vuln in SmmGetVariable function */
        analyzer.findSmmGetVariableOveflow();

        analyzer.efiSmmCpuProtocolResolver();
    } else {
        DEBUG_MSG("[%s] Parsing of 64-bit PEI files is not supported yet\n",
                  plugin_name);
    }

    /* dump info to JSON file */
    analyzer.dumpInfo();

    /* show all choosers windows */
    showAllChoosers(analyzer);

    return true;
}

//--------------------------------------------------------------------------
// Main function for X86 modules
bool efiAnalysis::efiAnalyzerMainX86() {
    efiAnalysis::efiAnalyzer analyzer;

    while (!auto_is_ok()) {
        auto_wait();
    };

    /* find .text and .data segments */
    analyzer.getSegments();

    /* mark GUIDs */
    analyzer.markDataGuids();

    analyzer.fileType = getFileType(&analyzer.allGuids);

    analyzer.setStrings();

    if (analyzer.fileType == FTYPE_DXE_AND_THE_LIKE) {
        /* find global vars for gST, gBS, gRT */
        analyzer.findBootServicesTables(X86);
        analyzer.findRuntimeServicesTables(X86);

        /* find boot services and runtime services */
        analyzer.getAllRuntimeServices(X86);
        analyzer.getProtBootServicesX86();
        analyzer.getAllBootServices(X86);

        /* print and mark protocols */
        analyzer.getBsProtNamesX86();
        analyzer.printInterfaces();
        analyzer.markInterfaces();
    } else if (analyzer.fileType == FTYPE_PEI) {
        setEntryArgToPeiSvc();
        analyzer.getAllPeiServicesX86();
        analyzer.getPpiNamesX86();
        analyzer.getAllVariablePPICallsX86();
        analyzer.printInterfaces();
        analyzer.markInterfaces();

        analyzer.findPPIGetVariableStackOveflow();
    }

    /* dump info to JSON file */
    analyzer.dumpInfo();

    /* show all choosers windows */
    showAllChoosers(analyzer);

    return true;
}
