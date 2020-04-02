#include "efiAnalysis.h"

using namespace efiAnalysis;

static const char plugin_name[] = "efiXplorer";

struct bootService {
    char service_name[64];
    size_t offset;
    size_t reg;
};

size_t bootServicesTableX64Length = 12;
/* REG_NONE means that the service is not currently being processed */
struct bootService bootServicesTableX64[] = {
    {"InstallProtocolInterface", x64InstallProtocolInterfaceOffset, REG_RDX},
    {"ReinstallProtocolInterface", x64RenstallProtocolInterfaceOffset, REG_RDX},
    {"UninstallProtocolInterface", x64UninstallProtocolInterfaceOffset,
     REG_RDX},
    {"HandleProtocol", x64HandleProtocolOffset, REG_RDX},
    {"RegisterProtocolNotify", x64RegisterProtocolNotifyOffset, REG_RCX},
    {"OpenProtocol", x64OpenProtocolOffset, REG_RDX},
    {"CloseProtocol", x64CloseProtocolOffset, REG_RDX},
    {"OpenProtocolInformation", x64OpenProtocolInformationOffset, REG_RDX},
    {"LocateHandleBuffer", x64LocateHandleBufferOffset, REG_RDX},
    {"LocateProtocol", x64LocateProtocolOffset, REG_RCX},
    {"InstallMultipleProtocolInterfaces",
     x64InstallMultipleProtocolInterfacesOffset, REG_RDX},
    {"UninstallMultipleProtocolInterfaces",
     x64UninstallMultipleProtocolInterfacesOffset, REG_RDX}};

size_t bootServicesTableX86Length = 12;
/* REG_NONE means that the service is not currently being processed */
struct bootService bootServicesTableX86[] = {
    {"InstallProtocolInterface", x86InstallProtocolInterfaceOffset,
     REG_NONE_32},
    {"ReinstallProtocolInterface", x86RenstallProtocolInterfaceOffset,
     REG_NONE_32},
    {"UninstallProtocolInterface", x86UninstallProtocolInterfaceOffset,
     REG_NONE_32},
    {"HandleProtocol", x86HandleProtocolOffset, REG_NONE_32},
    {"RegisterProtocolNotify", x86RegisterProtocolNotifyOffset, REG_NONE_32},
    {"OpenProtocol", x86OpenProtocolOffset, REG_NONE_32},
    {"CloseProtocol", x86CloseProtocolOffset, REG_NONE_32},
    {"OpenProtocolInformation", x86OpenProtocolInformationOffset, REG_NONE_32},
    {"LocateHandleBuffer", x86LocateHandleBufferOffset, REG_NONE_32},
    {"LocateProtocol", x86LocateProtocolOffset, REG_NONE_32},
    {"InstallMultipleProtocolInterfaces",
     x86InstallMultipleProtocolInterfacesOffset, REG_NONE_32},
    {"UninstallMultipleProtocolInterfaces",
     x86UninstallMultipleProtocolInterfacesOffset, REG_NONE_32}};

efiAnalysis::efiAnalyzer::efiAnalyzer() {
    /* check if file is valid EFI module */
    valid = true;
    /* get arch, X86 or X64 */
    arch = X64;

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
    DEBUG_MSG("[%s] analyzer destruction\n", plugin_name);
}

bool efiAnalysis::efiAnalyzer::findImageHandle() {
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

bool efiAnalysis::efiAnalyzer::findSystemTable() {
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

bool efiAnalysis::efiAnalyzer::findBootServicesTable() {
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
                break;
            }
        }
        ea = next_head(ea, endAddress);
    }
    return foundBs;
}

bool efiAnalysis::efiAnalyzer::findRuntimeServicesTable() {
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
                break;
            }
        }
        ea = next_head(ea, endAddress);
    }
    return foundRs;
}

void efiAnalysis::efiAnalyzer::getBootServices() {
    DEBUG_MSG("[%s] BootServices finding from 0x%llx to 0x%llx\n", plugin_name,
              startAddress, endAddress);
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
                    /* does not work currently */
                    long strid = get_struc_id("EFI_BOOT_SERVICES");
                    op_stroff(insn, 0, (const tid_t *)strid, 0, 0);
                    /* set comment */
                    string cmt = "gBs->";
                    cmt += (string)bootServicesTableX64[i].service_name;
                    set_cmt(ea, cmt.c_str(), true);
                    /* add line to table */
                    ft_printf_ln(table, " 0x%llx | %s ", ea,
                                 (char *)bootServicesTableX64[i].service_name);
                    DEBUG_MSG("[%s] 0x%llx : %s\n", plugin_name, ea,
                              (char *)bootServicesTableX64[i].service_name);
                    bootServices[(string)bootServicesTableX64[i].service_name]
                        .push_back(ea);
                }
            }
        }
        ea = next_head(ea, endAddress);
    }
    msg("Boot services:\n");
    msg(ft_to_string(table));
    ft_destroy_table(table);
}

void efiAnalysis::efiAnalyzer::getProtNames() {
    DEBUG_MSG("[%s] protocols finding\n", plugin_name);
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
            /* if service is not currently being processed */
            if (argReg == REG_NONE_64) {
                break;
            }
            /* 10 instructions above */
            for (int j = 0; j < 10; j++) {
                address = prev_head(address, startAddress);
                decode_insn(&insn, address);
                if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
                    insn.ops[0].reg == bootServicesTableX64[i].reg) {
                    guidCodeAddress = address;
                    guidDataAddress = insn.ops[1].addr;
                    found = true;
                    break;
                }
            }

            if (found) {
                DEBUG_MSG("[%s] found protocol GUID parameter at 0x%llx\n",
                          plugin_name, guidCodeAddress);
                /* get protocol item */
                json protocolItem;
                protocolItem["address"] = guidDataAddress;
                protocolItem["service"] = bootServicesTableX64[i].service_name;
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
                if (guid == json::array({0x00000000, 0x0000, 0x0000, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00})) {
                    DEBUG_MSG("[%s] NULL GUID at 0x%llx\n", plugin_name,
                              guidCodeAddress);
                    continue;
                }
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
    DEBUG_MSG("[%s] protocols names finding\n", plugin_name);
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
    msg("Protocols:\n");
    msg(ft_to_string(table));
    ft_destroy_table(table);
}

void efiAnalysis::efiAnalyzer::markProtocols() {
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
        string name = protName + "_0x" + (string)hexAddr;
        set_name(address, name.c_str(), SN_CHECK);
        setGuidStructure(address);
        /* comment line */
        string comment = "EFI_GUID *" + protName;
        add_extra_line(address, 2, comment.c_str());
        /* save address */
        markedProtocols.push_back(address);
        DEBUG_MSG("[%s] address: 0x%llx, comment: %s\n", plugin_name, address,
                  comment.c_str());
    }
}

void efiAnalysis::efiAnalyzer::markDataGuids() {
    DEBUG_MSG("[%s] .data GUIDs marking\n", plugin_name);
    vector<string> segments = {".data"};
    for (vector<string>::iterator seg = segments.begin(); seg != segments.end();
         ++seg) {
        string segName = *seg;
        segment_t *seg_info = get_segm_by_name(segName.c_str());
        if (seg_info == NULL) {
            DEBUG_MSG("[%s] can't find a %s segment\n", plugin_name,
                      segName.c_str());
        }
        ea_t ea = seg_info->start_ea;
        while (ea != BADADDR && ea <= seg_info->end_ea - 15) {
            /* check if guid on this address already marked */
            bool marked = false;
            for (vector<ea_t>::iterator address = markedProtocols.begin();
                 address != markedProtocols.end(); ++address) {
                if (*address == ea) {
                    marked = true;
                    break;
                }
            }
            if (marked) {
                ea = next_head(ea, seg_info->end_ea);
                continue;
            }
            if (get_wide_dword(ea) == 0x00000000 ||
                get_wide_dword(ea) == 0xffffffff) {
                ea = next_head(ea, seg_info->end_ea);
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
                    string name = dbItem.key() + "_0x" + (string)hexAddr;
                    set_name(ea, name.c_str(), SN_CHECK);
                    setGuidStructure(ea);
                    /* comment line */
                    string comment = "EFI_GUID *" + dbItem.key();
                    add_extra_line(ea, 2, comment.c_str());
                    DEBUG_MSG("[%s] address: 0x%llx, comment: %s\n",
                              plugin_name, ea, comment.c_str());
                    break;
                }
            }
            ea = next_head(ea, seg_info->end_ea);
        }
    }
}

void efiAnalysis::efiAnalyzer::dumpInfo() {
    json info;
    info["boot_services"] = bootServices;
    info["protocols"] = allProtocols;
    string idbPath;
    idbPath = get_path(PATH_TYPE_IDB);
    path logFile;
    logFile /= idbPath;
    logFile.replace_extension(".json");
    std::ofstream out(logFile);
    out << std::setw(4) << info << std::endl;
    DEBUG_MSG("[%s] log file: %s\n", plugin_name, logFile.c_str());
}

bool efiAnalysis::efiAnalyzerMain() {
    efiAnalysis::efiAnalyzer analyzer;

    auto_wait();

    analyzer.findImageHandle();
    analyzer.findSystemTable();
    analyzer.findBootServicesTable();
    analyzer.findRuntimeServicesTable();
    analyzer.getBootServices();
    analyzer.getProtNames();
    analyzer.printProtocols();
    analyzer.markProtocols();
    analyzer.markDataGuids();
    analyzer.dumpInfo();

    return true;
}
