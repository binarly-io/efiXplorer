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

efiAnalysis::efiAnalyzer::efiAnalyzer() {
    /* get guids.json path */
    guidsJsonPath /= idadir("plugins");
    guidsJsonPath /= "guids";
    guidsJsonPath /= "guids.json";

    /* get base address */
    base = get_imagebase();

    func_t *start_func = nullptr;
    func_t *end_func = nullptr;

    this->fileType = getFileType();

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
}

efiAnalysis::efiAnalyzer::~efiAnalyzer() {}

//--------------------------------------------------------------------------
// Find gImageHandle address for X64 modules
bool efiAnalysis::efiAnalyzer::findImageHandleX64() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] ImageHandle finding\n", plugin_name);
    insn_t insn;
    for (auto idx = 0; idx < get_entry_qty(); idx++) {
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
                /* with this name type will applied automatically */
                set_name(insn.ops[0].addr, "gImageHandle", SN_CHECK);
                set_cmt(ea, "EFI_HANDLE gImageHandle", true);
                gImageHandleList.push_back(insn.ops[0].addr);
                return true;
            }
            ea = next_head(ea, endAddress);
        }
    }
    return false;
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
                /* with this name type will applied automatically */
                set_name(insn.ops[0].addr, "gST", SN_CHECK);
                set_cmt(ea, "EFI_SYSTEM_TABLE *gST", true);
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
    gSmstList = findSmstSmmBase(gBsList);
    if (!gSmstList.size()) {
        gSmstList = findSmstSwDispatch(gBsList);
        if (!gSmstList.size()) {
            return false;
        }
    }
    return true;
}

//--------------------------------------------------------------------------
// Find gBS addresses for X86/X64 modules
bool efiAnalysis::efiAnalyzer::findBootServicesTables(uint8_t arch) {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] BootServices table finding from 0x%016X to 0x%016X\n",
              plugin_name, startAddress, endAddress);
    /* init architecture-specific constants */
    auto BS_OFFSET = BS_OFFSET_X64;
    auto REG_SP = REG_RSP;
    if (arch == X86) {
        BS_OFFSET = BS_OFFSET_X86;
        REG_SP = REG_ESP;
    }
    ea_t ea = startAddress;
    insn_t insn;
    uint16_t bsRegister = 0;
    uint16_t stRegister = 0;
    while (ea <= endAddress) {
        decode_insn(&insn, ea);
        if (insn.itype == NN_mov && insn.ops[1].type == o_displ &&
            insn.ops[1].phrase != REG_SP) {
            if (insn.ops[0].type == o_reg && insn.ops[1].addr == BS_OFFSET) {
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
                                snprintf(
                                    hexAddr, 21, "%llX",
                                    static_cast<uint64_t>(insn.ops[0].addr));
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
                                snprintf(
                                    hexAddr, 21, "%llX",
                                    static_cast<uint64_t>(insn.ops[0].addr));
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
                                DEBUG_MSG("[%s] found SystemTable at 0x%016X, "
                                          "address = "
                                          "0x%016X\n",
                                          plugin_name, addr, insn.ops[0].addr);
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
                                    set_cmt(addr, "EFI_SYSTEM_TABLE *gST",
                                            true);
                                    string name =
                                        "gST_" + static_cast<string>(hexAddr);
                                    setPtrTypeAndName(insn.ops[0].addr, name,
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
    return (gBsList.size() != 0);
}

//--------------------------------------------------------------------------
// Find gRT addresses for X86/X64 modules
bool efiAnalysis::efiAnalyzer::findRuntimeServicesTables(uint8_t arch) {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] RuntimeServices table finding from 0x%016X to 0x%016X\n",
              plugin_name, startAddress, endAddress);
    /* init architecture-specific constants */
    auto RT_OFFSET = RT_OFFSET_X64;
    auto REG_SP = REG_RSP;
    if (arch == X86) {
        RT_OFFSET = RT_OFFSET_X86;
        REG_SP = REG_ESP;
    }
    ea_t ea = startAddress;
    insn_t insn;
    uint16_t rtRegister = 0;
    uint16_t stRegister = 0;
    while (ea <= endAddress) {
        decode_insn(&insn, ea);
        if (insn.itype == NN_mov && insn.ops[1].type == o_displ &&
            insn.ops[1].phrase != REG_SP) {
            if (insn.ops[0].type == o_reg && insn.ops[1].addr == RT_OFFSET) {
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
                                snprintf(
                                    hexAddr, 21, "%llX",
                                    static_cast<uint64_t>(insn.ops[0].addr));
                                set_cmt(ea, "EFI_RUNTIME_SERVICES *gRT", true);
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
                                     insn.ops[0].addr) == gStList.end()) {
                                char hexAddr[21] = {};
                                snprintf(
                                    hexAddr, 21, "%llX",
                                    static_cast<uint64_t>(insn.ops[0].addr));
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
                                DEBUG_MSG("[%s] found SystemTable at 0x%016X, "
                                          "address = "
                                          "0x%016X\n",
                                          plugin_name, addr, insn.ops[0].addr);
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
                                    set_cmt(addr, "EFI_SYSTEM_TABLE *gST",
                                            true);
                                    string name =
                                        "gST_" + static_cast<string>(hexAddr);
                                    setPtrTypeAndName(insn.ops[0].addr, name,
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
    return (gRtList.size() != 0);
}

//--------------------------------------------------------------------------
// Get all boot services for X86/X64 modules
void efiAnalysis::efiAnalyzer::getAllBootServices(uint8_t arch) {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] BootServices finding from 0x%016X to 0x%016X (all)\n",
              plugin_name, startAddress, endAddress);
    if (!gBsList.size()) {
        return;
    }
    /* init architecture-specific constants */
    auto REG_AX = REG_RAX;
    if (arch == X86) {
        REG_AX = REG_EAX;
    }
    ea_t ea = startAddress;
    insn_t insn;
    ft_table_t *table = ft_create_table();
    ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
    ft_write_ln(table, " Address ", " Service ");
    auto found = false;
    while (ea <= endAddress) {
        decode_insn(&insn, ea);
        for (vector<ea_t>::iterator bs = gBsList.begin(); bs != gBsList.end();
             ++bs) {
            if (insn.itype == NN_mov && insn.ops[0].reg == REG_AX &&
                insn.ops[1].type == o_mem && insn.ops[1].addr == *bs) {
                ea_t addr = next_head(ea, BADADDR);
                /* 16 instructions below */
                for (auto i = 0; i < 16; i++) {
                    decode_insn(&insn, addr);
                    if (insn.itype == NN_callni && insn.ops[0].reg == REG_AX) {
                        for (int j = 0; j < bootServicesTableAllLength; j++) {
                            /* architecture-specific variables */
                            auto offset = bootServicesTableAll[j].offset64;
                            if (arch == X86) {
                                offset = bootServicesTableAll[j].offset86;
                            }
                            if (insn.ops[0].addr == static_cast<ea_t>(offset)) {
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
                                        bootServicesTableAll[j].service_name));
                                DEBUG_MSG(
                                    "[%s] 0x%016X : %s\n", plugin_name, addr,
                                    static_cast<char *>(
                                        bootServicesTableAll[j].service_name));
                                bootServicesAll[static_cast<string>(
                                                    bootServicesTableAll[j]
                                                        .service_name)]
                                    .push_back(addr);
                                /* add item to allBootServices vector */
                                json bsItem;
                                bsItem["address"] = addr;
                                bsItem["service_name"] = static_cast<string>(
                                    bootServicesTableAll[j].service_name);
                                bsItem["table_name"] =
                                    static_cast<string>("EFI_BOOT_SERVICES");
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
    DEBUG_MSG("[%s] RuntimeServices finding from 0x%016X to 0x%016X (all)\n",
              plugin_name, startAddress, endAddress);
    if (!gRtList.size()) {
        return;
    }
    ea_t ea = startAddress;
    insn_t insn;
    ft_table_t *table = ft_create_table();
    ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
    ft_write_ln(table, " Address ", " Service ");
    auto found = false;
    while (ea <= endAddress) {
        decode_insn(&insn, ea);
        for (vector<ea_t>::iterator rt = gRtList.begin(); rt != gRtList.end();
             ++rt) {
            if (insn.itype == NN_mov && insn.ops[0].reg == REG_RAX &&
                insn.ops[1].type == o_mem && insn.ops[1].addr == *rt) {
                ea_t addr = next_head(ea, BADADDR);
                /* 16 instructions below */
                for (int i = 0; i < 16; i++) {
                    decode_insn(&insn, addr);
                    if (insn.itype == NN_callni && insn.ops[0].reg == REG_RAX) {
                        for (int j = 0; j < runtimeServicesTableAllLength;
                             j++) {
                            /* architecture-specific variables */
                            auto offset = runtimeServicesTableAll[j].offset64;
                            if (arch == X86) {
                                offset = runtimeServicesTableAll[j].offset86;
                            }
                            if (insn.ops[0].addr == static_cast<ea_t>(offset)) {
                                found = true;
                                string cmt = getRtComment(
                                    static_cast<ea_t>(offset), arch);
                                set_cmt(addr, cmt.c_str(), true);
                                /* op_stroff */
                                opStroff(addr, "EFI_RUNTIME_SERVICES");
                                /* add line to table */
                                ft_printf_ln(table, " 0x%016X | %s ",
                                             static_cast<unsigned int>(addr),
                                             static_cast<char *>(
                                                 runtimeServicesTableAll[j]
                                                     .service_name));
                                DEBUG_MSG("[%s] 0x%016X : %s\n", plugin_name,
                                          addr,
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
                                rtItem["service_name"] = static_cast<string>(
                                    runtimeServicesTableAll[j].service_name);
                                rtItem["table_name"] =
                                    static_cast<string>("EFI_RUNTIME_SERVICES");
                                rtItem["offset"] = offset;
                                if (find(allServices.begin(), allServices.end(),
                                         rtItem) == allServices.end()) {
                                    allServices.push_back(rtItem);
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
    DEBUG_MSG("[%s] SmmServices finding from 0x%016X to 0x%016X (all)\n",
              plugin_name, startAddress, endAddress);
    if (!gSmstList.size()) {
        return;
    }
    ea_t ea = startAddress;
    insn_t insn;
    ft_table_t *table = ft_create_table();
    ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
    ft_write_ln(table, " Address ", " Service ");
    auto found = false;
    while (ea <= endAddress) {
        decode_insn(&insn, ea);
        for (vector<ea_t>::iterator smms = gSmstList.begin();
             smms != gSmstList.end(); ++smms) {
            if (insn.itype == NN_mov && insn.ops[0].reg == REG_RAX &&
                insn.ops[1].type == o_mem && insn.ops[1].addr == *smms) {
                ea_t addr = ea;
                /* 10 instructions below */
                for (auto i = 0; i < 10; i++) {
                    decode_insn(&insn, addr);
                    if (insn.itype == NN_callni && insn.ops[0].reg == REG_RAX) {
                        for (int j = 0; j < smmServicesTableAllLength; j++) {
                            if (insn.ops[0].addr ==
                                static_cast<ea_t>(
                                    smmServicesTableAll[j].offset64)) {
                                found = true;
                                string cmt =
                                    "gSmst->" +
                                    static_cast<string>(
                                        smmServicesTableAll[j].service_name);
                                set_cmt(addr, cmt.c_str(), true);
                                /* op_stroff */
                                opStroff(addr, "_EFI_SMM_SYSTEM_TABLE2");
                                /* add line to table */
                                ft_printf_ln(
                                    table, " 0x%016X | %s ",
                                    static_cast<unsigned int>(addr),
                                    static_cast<char *>(
                                        smmServicesTableAll[j].service_name));
                                DEBUG_MSG(
                                    "[%s] 0x%016X : %s\n", plugin_name, addr,
                                    static_cast<char *>(
                                        smmServicesTableAll[j].service_name));
                                /* add address to smmServices[...] vector */
                                if (find(protSmmNames.begin(),
                                         protSmmNames.end(),
                                         smmServicesTableAll[j].service_name) !=
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
                                smmsItem["service_name"] = static_cast<string>(
                                    smmServicesTableAll[j].service_name);
                                smmsItem["table_name"] = static_cast<string>(
                                    "_EFI_SMM_SYSTEM_TABLE2");
                                smmsItem["offset"] =
                                    smmServicesTableAll[j].offset64;
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
                            "[%s] 0x%016X : %s\n",
                            plugin_name, ea,
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
// Get boot services by protocols for X64 modules
void efiAnalysis::efiAnalyzer::getProtBootServicesX64() {
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
        if (insn.itype == NN_callni && insn.ops[0].reg == REG_RAX) {
            for (auto i = 0; i < bootServicesTableX64Length; i++) {
                if (insn.ops[0].addr ==
                    static_cast<ea_t>(bootServicesTableX64[i].offset)) {
                    /* set comment */
                    string cmt = getBsComment(
                        static_cast<ea_t>(bootServicesTableX64[i].offset), X64);
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
        gBsList.push_back(addrBs);
    }
}

//--------------------------------------------------------------------------
// Get boot services protocols names for X64 modules
void efiAnalysis::efiAnalyzer::getBsProtNamesX64() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] protocols finding (boot services)\n", plugin_name);
    ea_t start = startAddress;
    segment_t *seg_info = get_segm_by_name(".text");
    if (seg_info != nullptr) {
        start = seg_info->start_ea;
    }
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
                    if (insn.ops[1].addr > start and
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
                if ((static_cast<uint32_t>(guid[0]) == 0x00000000 and
                     (uint16_t) guid[1] == 0x0000) or
                    (static_cast<uint32_t>(guid[0]) == 0xffffffff and
                     (uint16_t) guid[1] == 0xffff)) {
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
                        if (insn.ops[0].value > start and
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
                if ((static_cast<uint32_t>(guid[0]) == 0x00000000 and
                     (uint16_t) guid[1] == 0x0000) or
                    (static_cast<uint32_t>(guid[0]) == 0xffffffff and
                     (uint16_t) guid[1] == 0xffff)) {
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
    DEBUG_MSG("[%s] protocols finding (smm services)\n", plugin_name);
    ea_t start = startAddress;
    segment_t *seg_info = get_segm_by_name(".text");
    if (seg_info != nullptr) {
        start = seg_info->start_ea;
    }
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
                    if (insn.ops[1].addr > start and
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
                if ((static_cast<uint32_t>(guid[0]) == 0x00000000 and
                     (uint16_t) guid[1] == 0x0000) or
                    (static_cast<uint32_t>(guid[0]) == 0xffffffff and
                     (uint16_t) guid[1] == 0xffff)) {
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
// Print protocols
void efiAnalysis::efiAnalyzer::printProtocols() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] protocols printing\n", plugin_name);
    if (!allProtocols.size()) {
        printf("[%s] protocols list is empty\n", plugin_name);
        return;
    }
    ft_table_t *table = ft_create_table();
    ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
    ft_write_ln(table, " GUID ", " Protocol name ", " Address ", " Service ");
    for (vector<json>::iterator protocolItem = allProtocols.begin();
         protocolItem != allProtocols.end(); ++protocolItem) {
        json protItem = *protocolItem;
        auto guid = protItem["guid"];
        string protName = protItem["prot_name"];
        ea_t address = static_cast<ea_t>(protItem["address"]);
        string service = protItem["service"];
        ft_printf_ln(
            table,
            " %08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X | %s | "
            "0x%016X | %s ",
            static_cast<uint32_t>(guid[0]), static_cast<uint16_t>(guid[1]),
            static_cast<uint16_t>(guid[2]), static_cast<uint8_t>(guid[3]),
            static_cast<uint8_t>(guid[4]), static_cast<uint8_t>(guid[5]),
            static_cast<uint8_t>(guid[6]), static_cast<uint8_t>(guid[7]),
            static_cast<uint8_t>(guid[8]), static_cast<uint8_t>(guid[9]),
            static_cast<uint8_t>(guid[10]), protName.c_str(),
            static_cast<unsigned int>(address), service.c_str());
    }
    msg("[%s] Protocols:\n", plugin_name);
    msg(ft_to_string(table));
    ft_destroy_table(table);
}

//--------------------------------------------------------------------------
// Mark protocols
void efiAnalysis::efiAnalyzer::markProtocols() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] protocols marking\n", plugin_name);
    for (vector<json>::iterator protocolItem = allProtocols.begin();
         protocolItem != allProtocols.end(); ++protocolItem) {
        json protItem = *protocolItem;
        ea_t address = static_cast<ea_t>(protItem["address"]);
        /* check if guid on this address already marked */
        bool marked = false;
        for (vector<ea_t>::iterator markedAddress = markedProtocols.begin();
             markedAddress != markedProtocols.end(); ++markedAddress) {
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
        string protName = static_cast<string>(protItem["prot_name"]);
        string name = protName + "_" + static_cast<string>(hexAddr);
        set_name(address, name.c_str(), SN_CHECK);
        setGuidType(address);
        /* comment line */
        string comment = "EFI_GUID " + protName;
        /* save address */
        markedProtocols.push_back(address);
        DEBUG_MSG("[%s] address: 0x%016X, comment: %s\n", plugin_name, address,
                  comment.c_str());
    }
}

//--------------------------------------------------------------------------
// Mark GUIDs found in the .data segment
void efiAnalysis::efiAnalyzer::markDataGuids() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    vector<string> segments = {".data"};
    for (vector<string>::iterator seg = segments.begin(); seg != segments.end();
         ++seg) {
        string segName = *seg;
        DEBUG_MSG("[%s] marking GUIDs from %s segment\n", plugin_name,
                  segName.c_str());
        segment_t *seg_info = get_segm_by_name(segName.c_str());
        if (seg_info == NULL) {
            DEBUG_MSG("[%s] can't find a %s segment\n", plugin_name,
                      segName.c_str());
            continue;
        }
        DEBUG_MSG("[%s] start = 0x%016X, end = 0x%016X\n", plugin_name,
                  seg_info->start_ea, seg_info->end_ea);
        ea_t ea = seg_info->start_ea;
        while (ea != BADADDR && ea <= seg_info->end_ea - 15) {
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
    DEBUG_MSG("[%s] local GUIDs finding from 0x%016X to 0x%016X\n", plugin_name,
              startAddress, endAddress);
    ea_t ea = startAddress;
    insn_t insn;
    insn_t insnNext;
    while (ea <= endAddress) {
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
            if (insnNext.itype == NN_mov && insnNext.ops[0].type == o_displ &&
                insnNext.ops[1].type == o_imm) {
                /* get guid->data2 value */
                uint16_t gData2 = static_cast<uint16_t>(insnNext.ops[1].value);
                if (gData2 == 0x0000 || gData2 == 0xffff) {
                    ea = next_head(ea, BADADDR);
                    continue;
                }
                /* found guid->data1 and guid->data2 values, try to get guid
                 * name */
                json::iterator dbItem;
                for (dbItem = dbProtocols.begin(); dbItem != dbProtocols.end();
                     ++dbItem) {
                    auto guid = dbItem.value();
                    if (gData1 == static_cast<uint32_t>(guid[0]) &&
                        gData2 == static_cast<uint16_t>(guid[1])) {
                        /* mark local guid */
                        char hexAddr[21] = {};
                        snprintf(hexAddr, 21, "%llX",
                                 static_cast<uint64_t>(ea));
                        string name =
                            dbItem.key() + "_" + static_cast<string>(hexAddr);
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
                        dataGuids.push_back(guidItem);
                        break;
                    }
                }
            }
        }
        ea = next_head(ea, BADADDR);
    }
}

//--------------------------------------------------------------------------
// Find SwSmiHandler function inside SMM drivers
func_t *efiAnalysis::efiAnalyzer::findSwSmiHandler() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    return findSmiHandlerSmmSwDispatch();
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
    if (analyzer.allProtocols.size()) {
        title = "efiXplorer: protocols";
        protocols_show(analyzer.allProtocols, title);
    }
    /* open window with data guids */
    if (analyzer.dataGuids.size()) {
        qstring title = "efiXplorer: guids";
        guids_show(analyzer.dataGuids, title);
    }
}

//--------------------------------------------------------------------------
// Main function for X64 modules
bool efiAnalysis::efiAnalyzerMainX64() {
    efiAnalysis::efiAnalyzer analyzer;

    while (!auto_is_ok()) {
        auto_wait();
    };

    /* find global vars for gImageHandle, gST, gBS, gRT, gSmst */
    if (analyzer.fileType == FTYPE_DXE_AND_THE_LIKE) {
        analyzer.findImageHandleX64();
        analyzer.findSystemTableX64();
        analyzer.findBootServicesTables(X64);
        analyzer.findRuntimeServicesTables(X64);
        analyzer.findSmstX64();

        /* find boot services and runtime services */
        analyzer.getAllRuntimeServices(X64);
        analyzer.getProtBootServicesX64();

        /* other addresses of global gBS values finding */
        analyzer.findOtherBsTablesX64();
        analyzer.getAllBootServices(X64);

        /* find smm services */
        analyzer.getAllSmmServicesX64();

        /* print and mark protocols */
        analyzer.getBsProtNamesX64();
        analyzer.getSmmProtNamesX64();
        analyzer.printProtocols();
        analyzer.markProtocols();

        /* mark GUIDs */
        analyzer.markDataGuids();
        analyzer.markLocalGuidsX64();

        /* find SwSmiHandler function */
        analyzer.findSwSmiHandler();
    }

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
        analyzer.printProtocols();
        analyzer.markProtocols();
    } else if (analyzer.fileType == FTYPE_PEI) {
        setEntryArgToPeiSvc();
        analyzer.getAllPeiServicesX86();
    }

    /* mark GUIDs */
    analyzer.markDataGuids();

    /* show all choosers windows */
    showAllChoosers(analyzer);

    return true;
}
