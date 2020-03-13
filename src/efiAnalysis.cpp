#include "efiAnalysis.h"

using namespace efiAnalysis;

static const char plugin_name[] = "efiXplorer";

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

    // ------------
    // import types
    // ------------

    // import_type(-1, "EFI_GUID");
    // import_type(-1, "EFI_SYSTEM_TABLE");
    // import_type(-1, "EFI_RUNTIME_SERVICES");
    // import_type(-1, "EFI_BOOT_SERVICES");

    // set boot services that work with protocols
    bootServices["InstallProtocolInterface"] = json::array();
    bootServices["ReinstallProtocolInterface"] = json::array();
    bootServices["UninstallProtocolInterface"] = json::array();
    bootServices["HandleProtocol"] = json::array();
    bootServices["RegisterProtocolNotify"] = json::array();
    bootServices["OpenProtocol"] = json::array();
    bootServices["CloseProtocol"] = json::array();
    bootServices["OpenProtocolInformation"] = json::array();
    bootServices["ProtocolsPerHandle"] = json::array();
    bootServices["LocateHandleBuffer"] = json::array();
    bootServices["LocateProtocol"] = json::array();
    bootServices["InstallMultipleProtocolInterfaces"] = json::array();
    bootServices["UninstallMultipleProtocolInterfaces"] = json::array();

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
                set_name(insn.ops[0].addr, "gSt", SN_CHECK);
                return true;
            }
            ea = next_head(ea, MAX_ADDR);
        }
    }
    return false;
}

bool efiAnalysis::efiAnalyzer::findBootServicesTable() {
    DEBUG_MSG("[%s] BootServices finding from 0x%llx to 0x%llx\n", plugin_name,
              startAddress, endAddress);
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
                set_name(insn.ops[0].addr, "gBs", SN_CHECK);
                break;
            }
        }
        ea = next_head(ea, MAX_ADDR);
    }
    return foundBs;
}

bool efiAnalysis::efiAnalyzer::findRuntimeServicesTable() {
    DEBUG_MSG("[%s] RuntimeServices finding from 0x%llx to 0x%llx\n",
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
                set_name(insn.ops[0].addr, "gRs", SN_CHECK);
                break;
            }
        }
        ea = next_head(ea, MAX_ADDR);
    }
    return foundRs;
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

    analyzer.findSystemTable();
    analyzer.findBootServicesTable();
    analyzer.findRuntimeServicesTable();

    return true;
}
