#include "efiAnalysis.h"
#include "tables/efi_services.h"

using namespace efiAnalysis;

static const char plugin_name[] = "efiXplorer";

ea_t gBS = 0;
ea_t gRT = 0;

/* for smm callouts finding */
vector<ea_t> calloutAddrs;
vector<func_t *> excFunctions;

efiAnalysis::efiAnalyzer::efiAnalyzer() {
    /* get guids.json path */
    guidsJsonPath /= idadir("plugins");
    guidsJsonPath /= "guids";
    guidsJsonPath /= "guids.json";

    /* get base address */
    base = get_imagebase();

    func_t *startFunc = NULL;
    func_t *endFunc = NULL;
    /* get start address for scan */
    startFunc = getn_func(0);
    startAddress = startFunc->start_ea;
    /* get end address for scan */
    endFunc = getn_func(get_func_qty() - 1);
    endAddress = endFunc->end_ea;

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

efiAnalysis::efiAnalyzer::~efiAnalyzer() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] analyzer destruction\n", plugin_name);
}

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
        for (int i = 0; i < 8; i++) {
            decode_insn(&insn, ea);
            if (insn.itype == NN_mov && insn.ops[1].type == o_reg &&
                insn.ops[1].reg == REG_RCX && insn.ops[0].type == o_mem) {
                DEBUG_MSG("[%s] found ImageHandle at 0x%llx, address = "
                          "0x%llx\n",
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
                DEBUG_MSG("[%s] found SystemTable at 0x%llx, address = "
                          "0x%llx\n",
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

ea_t efiAnalysis::efiAnalyzer::findBootServicesTableX64() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] BootServices table finding from 0x%llx to 0x%llx\n",
              plugin_name, startAddress, endAddress);
    ea_t ea = startAddress;
    bool foundBs = false;
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
                DEBUG_MSG("[%s] found BootServices table at 0x%llx, address = "
                          "0x%llx\n",
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

ea_t efiAnalysis::efiAnalyzer::findRuntimeServicesTableX64() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] RuntimeServices table finding from 0x%llx to 0x%llx\n",
              plugin_name, startAddress, endAddress);
    ea_t ea = startAddress;
    bool foundRs = false;
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
                DEBUG_MSG("[%s] found RuntimeServices table at 0x%llx, address "
                          "= 0x%llx\n",
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

void efiAnalysis::efiAnalyzer::getAllBootServicesX64() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] BootServices finding from 0x%llx to 0x%llx (all)\n",
              plugin_name, startAddress, endAddress);
    if (!gBS) {
        return;
    }
    ea_t ea = startAddress;
    insn_t insn;
    ft_table_t *table = ft_create_table();
    ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
    ft_write_ln(table, " Address ", " Service ");
    bool found = false;
    while (ea <= endAddress) {
        decode_insn(&insn, ea);
        if (insn.itype == NN_mov && insn.ops[0].reg == REG_RAX &&
            insn.ops[1].type == o_mem && insn.ops[1].addr == gBS) {
            ea_t addr = ea;
            /* 10 instructions below */
            for (int i = 0; i < 10; i++) {
                decode_insn(&insn, addr);
                if (insn.itype == NN_callni && insn.ops[0].reg == REG_RAX) {
                    for (int j = 0; j < bootServicesX64AllLength; j++) {
                        if (insn.ops[0].addr ==
                            (ea_t)bootServicesX64All[j].offset) {
                            found = true;
                            string cmt = getBsComment(
                                (ea_t)bootServicesX64All[j].offset, X64);
                            set_cmt(addr, cmt.c_str(), true);
                            /* add line to table */
                            ft_printf_ln(
                                table, " 0x%llx | %s ", ea,
                                (char *)bootServicesX64All[j].service_name);
                            DEBUG_MSG(
                                "[%s] 0x%llx : %s\n", plugin_name, addr,
                                (char *)bootServicesX64All[j].service_name);
                            bootServicesAll[(string)bootServicesX64All[j]
                                                .service_name]
                                .push_back(addr);
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

void efiAnalysis::efiAnalyzer::getAllRuntimeServicesX64() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] RuntimeServices finding from 0x%llx to 0x%llx (all)\n",
              plugin_name, startAddress, endAddress);
    if (!gRT) {
        return;
    }
    ea_t ea = startAddress;
    insn_t insn;
    ft_table_t *table = ft_create_table();
    ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
    ft_write_ln(table, " Address ", " Service ");
    bool found = false;
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
                            (ea_t)runtimeServicesX64All[j].offset) {
                            found = true;
                            string cmt = getRtComment(
                                (ea_t)runtimeServicesX64All[j].offset, X64);
                            set_cmt(addr, cmt.c_str(), true);
                            /* add line to table */
                            ft_printf_ln(
                                table, " 0x%llx | %s ", ea,
                                (char *)runtimeServicesX64All[j].service_name);
                            DEBUG_MSG(
                                "[%s] 0x%llx : %s\n", plugin_name, addr,
                                (char *)runtimeServicesX64All[j].service_name);
                            runtimeServicesAll[(string)runtimeServicesX64All[j]
                                                   .service_name]
                                .push_back(addr);
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

void efiAnalysis::efiAnalyzer::getProtBootServicesX64() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] BootServices finding from 0x%llx to 0x%llx (protocols)\n",
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
            for (int i = 0; i < bootServicesTableX64Length; i++) {
                if (insn.ops[0].addr == (ea_t)bootServicesTableX64[i].offset) {
                    /* set comment */
                    string cmt =
                        getBsComment((ea_t)bootServicesTableX64[i].offset, X64);
                    set_cmt(ea, cmt.c_str(), true);
                    /* add line to table */
                    ft_printf_ln(table, " 0x%llx | %s ", ea,
                                 (char *)bootServicesTableX64[i].service_name);
                    DEBUG_MSG("[%s] 0x%llx : %s\n", plugin_name, ea,
                              (char *)bootServicesTableX64[i].service_name);
                    bootServices[(string)bootServicesTableX64[i].service_name]
                        .push_back(ea);
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

void efiAnalysis::efiAnalyzer::getProtBootServicesX86() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] BootServices finding from 0x%llx to 0x%llx\n (protocols)",
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
            for (int i = 0; i < bootServicesTableX86Length; i++) {
                if (insn.ops[0].addr == (ea_t)bootServicesTableX86[i].offset) {
                    /* does not work currently */
                    long strid = get_struc_id("EFI_BOOT_SERVICES");
                    op_stroff(insn, 0, (const tid_t *)strid, 0, 0);
                    /* set comment */
                    string cmt =
                        getBsComment((ea_t)bootServicesTableX86[i].offset, X86);
                    set_cmt(ea, cmt.c_str(), true);
                    /* add line to table */
                    ft_printf_ln(table, " 0x%llx | %s ", ea,
                                 (char *)bootServicesTableX86[i].service_name);
                    DEBUG_MSG("[%s] 0x%llx : %s\n", plugin_name, ea,
                              (char *)bootServicesTableX86[i].service_name);
                    bootServices[(string)bootServicesTableX86[i].service_name]
                        .push_back(ea);
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

void efiAnalysis::efiAnalyzer::getProtNamesX64() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] protocols finding\n", plugin_name);
    ea_t start = startAddress;
    segment_t *seg_info = get_segm_by_name(".text");
    if (seg_info != NULL) {
        start = seg_info->start_ea;
    }
    for (int i = 0; i < bootServicesTableX64Length; i++) {
        vector<ea_t> addrs = bootServices[bootServicesTableX64[i].service_name];
        vector<ea_t>::iterator ea;
        /* for each boot service */
        for (ea = addrs.begin(); ea != addrs.end(); ++ea) {
            ea_t address = *ea;
            DEBUG_MSG("[%s] looking for protocols in the 0x%llx area\n",
                      plugin_name, address);
            insn_t insn;
            ea_t guidCodeAddress = 0;
            ea_t guidDataAddress = 0;
            bool found = false;
            uint16_t argReg = bootServicesTableX64[i].reg;
            /* 10 instructions above */
            for (int j = 0; j < 10; j++) {
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
                DEBUG_MSG("[%s] found protocol GUID parameter at 0x%llx\n",
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
                if (((uint32_t)guid[0] == 0x00000000 and
                     (uint16_t) guid[1] == 0x0000) or
                    ((uint32_t)guid[0] == 0xffffffff and
                     (uint16_t) guid[1] == 0xffff)) {
                    DEBUG_MSG("[%s] Incorrect GUID at 0x%llx\n", plugin_name,
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

void efiAnalysis::efiAnalyzer::getProtNamesX86() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] protocols finding\n", plugin_name);
    ea_t start = startAddress;
    segment_t *seg_info = get_segm_by_name(".text");
    if (seg_info != NULL) {
        start = seg_info->start_ea;
    }
    for (int i = 0; i < bootServicesTableX86Length; i++) {
        vector<ea_t> addrs = bootServices[bootServicesTableX86[i].service_name];
        vector<ea_t>::iterator ea;
        /* for each boot service */
        for (ea = addrs.begin(); ea != addrs.end(); ++ea) {
            ea_t address = *ea;
            DEBUG_MSG("[%s] looking for protocols in the 0x%llx area\n",
                      plugin_name, address);
            insn_t insn;
            ea_t guidCodeAddress = 0;
            ea_t guidDataAddress = 0;
            bool found = false;
            uint16_t pushNumber = bootServicesTableX86[i].push_number;
            /* if service is not currently being processed */
            if (pushNumber == PUSH_NONE) {
                break;
            }
            /* 10 instructions above */
            uint16_t pushCounter = 0;
            for (int j = 0; j < 10; j++) {
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
                DEBUG_MSG("[%s] found protocol GUID parameter at 0x%llx\n",
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
                if (((uint32_t)guid[0] == 0x00000000 and
                     (uint16_t) guid[1] == 0x0000) or
                    ((uint32_t)guid[0] == 0xffffffff and
                     (uint16_t) guid[1] == 0xffff)) {
                    DEBUG_MSG("[%s] Incorrect GUID at 0x%llx\n", plugin_name,
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
        ea_t address = (ea_t)protItem["address"];
        string service = protItem["service"];
        ft_printf_ln(table,
                     " %08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X | %s | "
                     "0x%llx | %s ",
                     (uint32_t)guid[0], (uint16_t)guid[1], (uint16_t)guid[2],
                     (uint8_t)guid[3], (uint8_t)guid[4], (uint8_t)guid[5],
                     (uint8_t)guid[6], (uint8_t)guid[7], (uint8_t)guid[8],
                     (uint8_t)guid[9], (uint8_t)guid[10], protName.c_str(),
                     address, service.c_str());
    }
    msg("[%s] Protocols:\n", plugin_name);
    msg(ft_to_string(table));
    ft_destroy_table(table);
}

void efiAnalysis::efiAnalyzer::markProtocols() {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] protocols marking\n", plugin_name);
    for (vector<json>::iterator protocolItem = allProtocols.begin();
         protocolItem != allProtocols.end(); ++protocolItem) {
        json protItem = *protocolItem;
        ea_t address = (ea_t)protItem["address"];
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
        string protName = (string)protItem["prot_name"];
        string name = protName + "_" + (string)hexAddr;
        set_name(address, name.c_str(), SN_CHECK);
        setGuidStructure(address);
        /* comment line */
        string comment = "EFI_GUID *" + protName;
        /* save address */
        markedProtocols.push_back(address);
        DEBUG_MSG("[%s] address: 0x%llx, comment: %s\n", plugin_name, address,
                  comment.c_str());
    }
}

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
        DEBUG_MSG("[%s] start = 0x%llx, end = 0x%llx\n", plugin_name,
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
                    string name = dbItem.key() + "_" + (string)hexAddr;
                    set_name(ea, name.c_str(), SN_CHECK);
                    setGuidStructure(ea);
                    /* comment line */
                    string comment = "EFI_GUID *" + dbItem.key();
                    DEBUG_MSG("[%s] address: 0x%llx, comment: %s\n",
                              plugin_name, ea, comment.c_str());
                    break;
                }
            }
            ea += 1;
        }
    }
}

void findCalloutRec(func_t *func) {
    DEBUG_MSG("[%s] current function address: 0x%llx\n", plugin_name,
              func->start_ea);
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
        /* check if insn is 'mov rax, cs:gBS' or 'mov rax, cs:gRT' */
        if (insn.itype == NN_mov && insn.ops[0].reg == REG_RAX &&
            insn.ops[1].type == o_mem &&
            ((gBS && insn.ops[1].addr == gBS) ||
             (gRT && insn.ops[1].addr == gRT))) {
            DEBUG_MSG("[%s] SMM callout finded: 0x%llx\n", plugin_name, ea);
            calloutAddrs.push_back(ea);
        }
    }
}

bool efiAnalysis::efiAnalyzer::findSmmCallout() {
    /*
        +----------------------------------------------------------------+
        | Find SMI handler inside SMM drivers:                           |
        -----------------------------------------------------------------+
        | 1. find 'SmiHandler' function                                  |
        | 2. find 'gBS->...' and 'gRT->...' inside 'SmiHandler' function |
        +----------------------------------------------------------------+
    */
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name)
    DEBUG_MSG("[%s] SMM callouts finding (gBS = 0x%llx, gRT = 0x%llx)\n",
              plugin_name, gBS, gRT);
    if (!gBS and !gRT) {
        DEBUG_MSG("[%s] can't find a gBS and gRT tables\n", plugin_name);
        return false;
    }
    func_t *smiHandler = findSmiHandlerSmmSwDispatch();
    if (smiHandler) {
        DEBUG_MSG("[%s] SmiHandler function address: 0x%llx\n", plugin_name,
                  smiHandler->start_ea);
        findCalloutRec(smiHandler);
        return true;
    }
    return false;
}

void efiAnalysis::efiAnalyzer::dumpInfo() {
    json info;
    info["bs_all"] = bootServicesAll;
    info["rt_all"] = runtimeServicesAll;
    info["bs_protocols"] = bootServices;
    info["protocols"] = allProtocols;
    if (calloutAddrs.size()) {
        info["vulns"]["smm_callout"] = calloutAddrs;
    }
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

    analyzer.findSmmCallout();

    analyzer.dumpInfo();

    return true;
}

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

    return true;
}
