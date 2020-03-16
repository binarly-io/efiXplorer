#include "efiAnalysis.h"

using namespace efiAnalysis;

static const char plugin_name[] = "efiXplorer";

struct bootService {
    char service_name[64];
    size_t offset;
};

size_t bootServicesTableX64Length = 13;
struct bootService bootServicesTableX64[] = {
    {"InstallProtocolInterface", 0x80},
    {"ReinstallProtocolInterface", 0x88},
    {"UninstallProtocolInterface", 0x90},
    {"HandleProtocol", 0x98},
    {"RegisterProtocolNotify", 0xa8},
    {"OpenProtocol", 0x118},
    {"CloseProtocol", 0x120},
    {"OpenProtocolInformation", 0x128},
    {"ProtocolsPerHandle", 0x130},
    {"LocateHandleBuffer", 0x138},
    {"LocateProtocol", 0x140},
    {"InstallMultipleProtocolInterfaces", 0x148},
    {"UninstallMultipleProtocolInterfaces", 0x150}};

size_t bootServicesTableX86Length = 13;
struct bootService bootServicesTableX86[] = {
    {"InstallProtocolInterface", 0x4c},
    {"ReinstallProtocolInterface", 0x50},
    {"UninstallProtocolInterface", 0x54},
    {"HandleProtocol", 0x58},
    {"RegisterProtocolNotify", 0x60},
    {"OpenProtocol", 0x98},
    {"CloseProtocol", 0x9c},
    {"OpenProtocolInformation", 0xa0},
    {"ProtocolsPerHandle", 0xa4},
    {"LocateHandleBuffer", 0xa8},
    {"LocateProtocol", 0xaC},
    {"InstallMultipleProtocolInterfaces", 0xb0},
    {"UninstallMultipleProtocolInterfaces", 0xb4}};

efiAnalysis::efiAnalyzer::efiAnalyzer() {
    // check if file is valid EFI module
    valid = true;
    // get arch, X86 or X64
    arch = X64;

    // get guids.json path
    guidsJsonPath /= idadir("plugins");
    guidsJsonPath /= "guids";
    guidsJsonPath /= "guids.json";

    // get base address
    base = get_imagebase();

    func_t *startFunc = NULL;
    func_t *endFunc = NULL;
    // get start address for scan
    startFunc = getn_func(0);
    startAddress = startFunc->start_ea;
    // get end address for scan
    endFunc = getn_func(get_func_qty() - 1);
    endAddress = endFunc->end_ea;

    // set boot services that work with protocols
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

    // load protocols from guids/guids.json file
    ifstream in(guidsJsonPath);
    in >> dbProtocols;

    // all finded protocols (data + code analysis)
    allProtocols = json::array();
    // protocols from data
    dataProtocols = json::array();
    // proprietary protocols
    propProtocols = json::array();
}

efiAnalysis::efiAnalyzer::~efiAnalyzer() {
    DEBUG_MSG("[%s] analyzer destruction\n", plugin_name);
}

bool efiAnalysis::efiAnalyzer::findImageHandle() {
    insn_t insn;
    for (int idx = 0; idx < get_entry_qty(); idx++) {
        // get address of entry point
        uval_t ord = get_entry_ordinal(idx);
        ea_t ea = get_entry(ord);
        // ImageHandle finding, first 8 instructions checking
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
            ea = next_head(ea, MAX_ADDR);
        }
    }
    return false;
}

bool efiAnalysis::efiAnalyzer::findSystemTable() {
    insn_t insn;
    for (int idx = 0; idx < get_entry_qty(); idx++) {
        // get address of entry point
        uval_t ord = get_entry_ordinal(idx);
        ea_t ea = get_entry(ord);
        // SystemTable finding, first 16 instructions checking
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
            ea = next_head(ea, MAX_ADDR);
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
        // if we found BS_OFFSET
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
        ea = next_head(ea, MAX_ADDR);
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
        // if we found RS_OFFSET
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
        ea = next_head(ea, MAX_ADDR);
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
        ea = next_head(ea, MAX_ADDR);
    }
    msg("Boot services:\n");
    msg(ft_to_string(table));
    ft_destroy_table(table);
}

void efiAnalysis::efiAnalyzer::getProtocols() {
    DEBUG_MSG("[%s] protocols finding\n", plugin_name);
}

void efiAnalysis::efiAnalyzer::getProtNames() {
    DEBUG_MSG("[%s] protocols names finding\n", plugin_name);
}

bool efiAnalysis::efiAnalyzerMain() {
    efiAnalysis::efiAnalyzer analyzer;

    auto_wait();

    analyzer.findImageHandle();
    analyzer.findSystemTable();
    analyzer.findBootServicesTable();
    analyzer.findRuntimeServicesTable();
    analyzer.getBootServices();
    analyzer.getProtocols();

    return true;
}
