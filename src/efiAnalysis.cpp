/* efiAnalysis.cpp
 * This file is part of efiXplorer
 */

#include "efiAnalysis.h"
#include "efiUi.h"
#include "tables/efi_services.h"
#include "thirdparty/libfort/fort.h"

using namespace efiAnalysis;

static const char plugin_name[] = "efiXplorer";

ea_t gBS = 0;
ea_t gRT = 0;

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

    /* set boot services that work with protocols */
    vector<ea_t> addrs;
    bootServices["InstallProtocolInterface"] = addrs;
    bootServices["ReinstallProtocolInterface"] = addrs;
    bootServices["UninstallProtocolInterface"] = addrs;
    bootServices["HandleProtocol"] = addrs;
    bootServices["RegisterProtocolNotify"] = addrs;
    bootServices["OpenProtocol"] = addrs;
    bootServices["CloseProtocol"] = addrs;
    bootServices["OpenProtocolInformation"] = addrs;
    bootServices["ProtocolsPerHandle"] = addrs;
    bootServices["LocateHandleBuffer"] = addrs;
    bootServices["LocateProtocol"] = addrs;
    bootServices["InstallMultipleProtocolInterfaces"] = addrs;
    bootServices["UninstallMultipleProtocolInterfaces"] = addrs;

    /* load protocols from guids/guids.json file */
    ifstream in(guidsJsonPath);
    in >> dbProtocols;
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
                set_name(insn.ops[0].addr, "gImageHandle", SN_CHECK);
                set_cmt(ea, "EFI_HANDLE gImageHandle", true);
                apply_named_type(ea, "EFI_HANDLE");
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
                set_name(insn.ops[0].addr, "gST", SN_CHECK);
                set_cmt(ea, "EFI_SYSTEM_TABLE *gST", true);
                apply_named_type(ea, "EFI_SYSTEM_TABLE *");
                return true;
            }
            ea = next_head(ea, endAddress);
        }
    }
    return false;
}

//--------------------------------------------------------------------------
// Find gBS address for X64 modules
ea_t efiAnalysis::efiAnalyzer::findBootServicesTableX64() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] BootServices table finding from 0x%016X to 0x%016X\n",
              plugin_name, startAddress, endAddress);
    ea_t ea = startAddress;
    auto foundBs = false;
    insn_t insn;
    uint16_t bsRegister = 0;
    while (ea <= endAddress) {
        decode_insn(&insn, ea);
        if (insn.itype == NN_mov && insn.ops[1].type == o_displ &&
            insn.ops[1].phrase == REG_EDX) {
            if (insn.ops[0].type == o_reg && insn.ops[1].addr == BS_OFFSET) {
                bsRegister = insn.ops[0].reg;
                foundBs = true;
            }
        }
        /* if we found BS_OFFSET */
        if (foundBs) {
            if (insn.itype == NN_mov && insn.ops[1].type == o_reg &&
                insn.ops[1].reg == bsRegister && insn.ops[0].type == o_mem) {
                DEBUG_MSG("[%s] found BootServices table at 0x%016X, address = "
                          "0x%016X\n",
                          plugin_name, ea, insn.ops[0].addr);
                set_name(insn.ops[0].addr, "gBS", SN_CHECK);
                set_cmt(ea, "EFI_BOOT_SERVICES *gBS", true);
                apply_named_type(ea, "EFI_BOOT_SERVICES *");
                return insn.ops[0].addr;
            }
        }
        ea = next_head(ea, endAddress);
    }
    return 0;
}

//--------------------------------------------------------------------------
// Find gRT address for X64 modules
ea_t efiAnalysis::efiAnalyzer::findRuntimeServicesTableX64() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] RuntimeServices table finding from 0x%016X to 0x%016X\n",
              plugin_name, startAddress, endAddress);
    ea_t ea = startAddress;
    auto foundRs = false;
    insn_t insn;
    uint16_t rsRegister = 0;
    while (ea <= endAddress) {
        decode_insn(&insn, ea);
        if (insn.itype == NN_mov && insn.ops[1].type == o_displ &&
            insn.ops[1].phrase == REG_EDX) {
            if (insn.ops[0].type == o_reg && insn.ops[1].addr == RS_OFFSET) {
                rsRegister = insn.ops[0].reg;
                foundRs = true;
            }
        }
        /* if we found RS_OFFSET */
        if (foundRs) {
            if (insn.itype == NN_mov && insn.ops[1].type == o_reg &&
                insn.ops[1].reg == rsRegister && insn.ops[0].type == o_mem) {
                DEBUG_MSG(
                    "[%s] found RuntimeServices table at 0x%016X, address "
                    "= 0x%016X\n",
                    plugin_name, ea, insn.ops[0].addr);
                set_name(insn.ops[0].addr, "gRT", SN_CHECK);
                set_cmt(ea, "EFI_RUNTIME_SERVICES *gRT", true);
                apply_named_type(ea, "EFI_RUNTIME_SERVICES *");
                return insn.ops[0].addr;
            }
        }
        ea = next_head(ea, endAddress);
    }
    return 0;
}

//--------------------------------------------------------------------------
// Get all boot services for X64 modules
void efiAnalysis::efiAnalyzer::getAllBootServicesX64() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] BootServices finding from 0x%016X to 0x%016X (all)\n",
              plugin_name, startAddress, endAddress);
    if (!gBS) {
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
        if (insn.itype == NN_mov && insn.ops[0].reg == REG_RAX &&
            insn.ops[1].type == o_mem && insn.ops[1].addr == gBS) {
            ea_t addr = ea;
            /* 10 instructions below */
            for (auto i = 0; i < 10; i++) {
                decode_insn(&insn, addr);
                if (insn.itype == NN_callni && insn.ops[0].reg == REG_RAX) {
                    for (int j = 0; j < bootServicesX64AllLength; j++) {
                        if (insn.ops[0].addr ==
                            static_cast<ea_t>(bootServicesX64All[j].offset)) {
                            found = true;
                            string cmt = getBsComment(
                                static_cast<ea_t>(bootServicesX64All[j].offset),
                                X64);
                            set_cmt(addr, cmt.c_str(), true);
                            /* add line to table */
                            ft_printf_ln(
                                table, " 0x%016X | %s ", addr,
                                static_cast<char *>(
                                    bootServicesX64All[j].service_name));
                            DEBUG_MSG("[%s] 0x%016X : %s\n", plugin_name, addr,
                                      static_cast<char *>(
                                          bootServicesX64All[j].service_name));
                            bootServicesAll[static_cast<string>(
                                                bootServicesX64All[j]
                                                    .service_name)]
                                .push_back(addr);
                            /* add item to allBootServices vector */
                            json bsItem;
                            bsItem["address"] = addr;
                            bsItem["service_name"] = static_cast<string>(
                                bootServicesX64All[j].service_name);
                            if (find(allBootServices.begin(),
                                     allBootServices.end(),
                                     bsItem) == allBootServices.end()) {
                                allBootServices.push_back(bsItem);
                            }
                            break;
                        }
                    }
                }
                addr = next_head(addr, BADADDR);
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
// Get all runtime services for X64 modules
void efiAnalysis::efiAnalyzer::getAllRuntimeServicesX64() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] RuntimeServices finding from 0x%016X to 0x%016X (all)\n",
              plugin_name, startAddress, endAddress);
    if (!gRT) {
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
        if (insn.itype == NN_mov && insn.ops[0].reg == REG_RAX &&
            insn.ops[1].type == o_mem && insn.ops[1].addr == gRT) {
            ea_t addr = ea;
            /* 10 instructions below */
            for (int i = 0; i < 10; i++) {
                decode_insn(&insn, addr);
                if (insn.itype == NN_callni && insn.ops[0].reg == REG_RAX) {
                    for (int j = 0; j < runtimeServicesX64AllLength; j++) {
                        if (insn.ops[0].addr ==
                            static_cast<ea_t>(
                                runtimeServicesX64All[j].offset)) {
                            found = true;
                            string cmt = getRtComment(
                                static_cast<ea_t>(
                                    runtimeServicesX64All[j].offset),
                                X64);
                            set_cmt(addr, cmt.c_str(), true);
                            /* add line to table */
                            ft_printf_ln(
                                table, " 0x%016X | %s ", addr,
                                static_cast<char *>(
                                    runtimeServicesX64All[j].service_name));
                            DEBUG_MSG(
                                "[%s] 0x%016X : %s\n", plugin_name, addr,
                                static_cast<char *>(
                                    runtimeServicesX64All[j].service_name));
                            runtimeServicesAll[static_cast<string>(
                                                   runtimeServicesX64All[j]
                                                       .service_name)]
                                .push_back(addr);
                            /* add item to allRuntimeServices vector */
                            json rtItem;
                            rtItem["address"] = addr;
                            rtItem["service_name"] = static_cast<string>(
                                runtimeServicesX64All[j].service_name);
                            if (find(allRuntimeServices.begin(),
                                     allRuntimeServices.end(),
                                     rtItem) == allRuntimeServices.end()) {
                                allRuntimeServices.push_back(rtItem);
                            }
                            break;
                        }
                    }
                }
                addr = next_head(addr, BADADDR);
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
                    /* add line to table */
                    ft_printf_ln(table, " 0x%016X | %s ", ea,
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
                    if (find(allBootServices.begin(), allBootServices.end(),
                             bsItem) == allBootServices.end()) {
                        allBootServices.push_back(bsItem);
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
                    /* add line to table */
                    ft_printf_ln(table, " 0x%016X | %s ", ea,
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
                    if (find(allBootServices.begin(), allBootServices.end(),
                             bsItem) == allBootServices.end()) {
                        allBootServices.push_back(bsItem);
                    }
                    break;
                }
            }
        }
        ea = next_head(ea, endAddress);
    }
    msg("[%s] Boot services:\n", plugin_name);
    msg(ft_to_string(table));
    ft_destroy_table(table);
}

//--------------------------------------------------------------------------
// Get protocols names for X64 modules
void efiAnalysis::efiAnalyzer::getProtNamesX64() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] protocols finding\n", plugin_name);
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
            uint16_t argReg = bootServicesTableX64[i].reg;
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
                protocolItem["service"] = bootServicesTableX64[i].service_name;
                /* if guid looks ok */
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
// Get protocols names for X86 modules
void efiAnalysis::efiAnalyzer::getProtNamesX86() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] protocols finding\n", plugin_name);
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
                protocolItem["service"] = bootServicesTableX86[i].service_name;
                /* if guid looks ok */
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
            static_cast<uint8_t>(guid[10]), protName.c_str(), address,
            service.c_str());
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
        char hexAddr[16] = {};
        sprintf(hexAddr, "%llx", address);
        string protName = static_cast<string>(protItem["prot_name"]);
        string name = protName + "_" + static_cast<string>(hexAddr);
        set_name(address, name.c_str(), SN_CHECK);
        setGuidStructure(address);
        /* comment line */
        string comment = "EFI_GUID *" + protName;
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
                    char hexAddr[16] = {};
                    sprintf(hexAddr, "%llx", ea);
                    string name =
                        dbItem.key() + "_" + static_cast<string>(hexAddr);
                    set_name(ea, name.c_str(), SN_CHECK);
                    setGuidStructure(ea);
                    /* comment line */
                    string comment = "EFI_GUID *" + dbItem.key();
                    DEBUG_MSG("[%s] address: 0x%016X, comment: %s\n",
                              plugin_name, ea, comment.c_str());
                    json guidItem;
                    guidItem["address"] = ea;
                    guidItem["name"] = dbItem.key();
                    char guidValue[37] = {0};
                    snprintf(guidValue, 36,
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
// Dump all info to JSON file
void efiAnalysis::efiAnalyzer::dumpInfo() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    json info;
    info["bs_all"] = bootServicesAll;
    info["rt_all"] = runtimeServicesAll;
    info["bs_protocols"] = bootServices;
    info["protocols"] = allProtocols;
    string idbPath = get_path(PATH_TYPE_IDB);
    path log_file;
    log_file /= idbPath;
    log_file.replace_extension(".json");
    std::ofstream out(log_file);
    out << std::setw(4) << info << std::endl;
    DEBUG_MSG("[%s] the log is saved in a JSON file\n", plugin_name);
}

//--------------------------------------------------------------------------
// Show all non-empty choosers windows
void showAllChoosers(efiAnalysis::efiAnalyzer analyzer) {
    qstring title;
    /* open window with boot services */
    if (analyzer.allBootServices.size()) {
        title = "efiXplorer: boot services";
        services_show(analyzer.allBootServices, title);
    }
    /* open window with runtime services */
    if (analyzer.allRuntimeServices.size()) {
        title = "efiXplorer: runtime services";
        services_show(analyzer.allRuntimeServices, title);
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

    analyzer.findImageHandleX64();
    analyzer.findSystemTableX64();
    gBS = analyzer.findBootServicesTableX64();
    gRT = analyzer.findRuntimeServicesTableX64();
    analyzer.getAllBootServicesX64();
    analyzer.getAllRuntimeServicesX64();
    analyzer.getProtBootServicesX64();
    analyzer.getProtNamesX64();

    analyzer.printProtocols();
    analyzer.markProtocols();
    analyzer.markDataGuids();

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

    analyzer.getProtBootServicesX86();
    analyzer.getProtNamesX86();

    analyzer.printProtocols();
    analyzer.markProtocols();
    analyzer.markDataGuids();
    analyzer.dumpInfo();

    /* show all choosers windows */
    showAllChoosers(analyzer);

    return true;
}
