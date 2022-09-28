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
 * efiAnalyzerArm.cpp
 * contains ARM specific analysis routines
 *
 */

#include "efiAnalyzer.h"
#include "efiUi.h"

using namespace EfiAnalysis;

std::vector<ea_t> gImageHandleListArm;
std::vector<ea_t> gStListArm;
std::vector<ea_t> gBsListArm;
std::vector<ea_t> gRtListArm;

void EfiAnalysis::EfiAnalyzerArm::fixOffsets() {
    insn_t insn;
    for (auto func_addr : funcs) {
        func_t *f = get_func(func_addr);
        if (f == nullptr) {
            continue;
        }
        ea_t ea = f->start_ea;
        while (ea < f->end_ea) {
            ea = next_head(ea, BADADDR);
            decode_insn(&insn, ea);
            if (insn.itype == ARM_str) {
                continue;
            }
            if (insn.ops[0].type == o_displ) {
                op_num(ea, 0);
            }
            if (insn.ops[1].type == o_displ) {
                op_num(ea, 1);
            }
        }
    }
}

void EfiAnalysis::EfiAnalyzerArm::initialAnalysis() {
    fixOffsets();
    for (auto idx = 0; idx < get_entry_qty(); idx++) {
        uval_t ord = get_entry_ordinal(idx);
        ea_t ep = get_entry(ord);
        set_name(ep, "_ModuleEntryPoint", SN_FORCE);
        // TrackEntryParams(get_func(ep), 0);
    }
}

ea_t getTable(ea_t code_addr, uint64_t offset) {
    ea_t table = BADADDR;
    insn_t insn;
    decode_insn(&insn, code_addr);
    if (insn.itype != ARM_ldr || insn.ops[0].type != o_reg ||
        insn.ops[1].type != o_displ || insn.ops[1].addr != offset ||
        insn.ops[1].reg == REG_XSP) {
        return table;
    }
    uint8_t table_reg = insn.ops[0].reg;
    uint8_t st_reg = insn.ops[1].reg;

    // handle following code patterns
    // ADR    REG1, gBS
    // LDR    REG2, [REG3,#0x60] <- we are here
    // STR    REG2, [REG4]
    ea_t ea = code_addr;
    uint8_t adr_reg = 0xff;
    while (true) {
        ea = next_head(ea, BADADDR);
        decode_insn(&insn, ea);
        if (insn.itype == ARM_str && insn.ops[0].type == o_reg &&
            insn.ops[1].type == o_displ && insn.ops[1].addr == 0x0) {
            adr_reg = insn.ops[1].reg;
        }
        if (is_basic_block_end(insn, false)) {
            break;
        }
    }
    if (adr_reg != 0xff) {
        ea = code_addr;
        while (true) {
            ea = prev_head(ea, 0);
            decode_insn(&insn, ea);
            if (insn.itype == ARM_adr && insn.ops[0].type == o_reg &&
                insn.ops[0].reg == adr_reg && insn.ops[1].type == o_imm) {
                return insn.ops[1].value; // gBS/gRT
            }
            if (is_basic_block_end(insn, false)) {
                break;
            }
        }
    }

    ea = code_addr;
    while (true) {
        ea = next_head(ea, BADADDR);
        decode_insn(&insn, ea);
        if (insn.itype == ARM_adrp && insn.ops[0].type == o_reg &&
            insn.ops[1].type == o_imm) {
            uint64_t base = insn.ops[1].value;
            uint8_t reg = insn.ops[0].reg;
            decode_insn(&insn, next_head(ea, BADADDR));
            if (insn.itype == ARM_str && insn.ops[0].type == o_reg &&
                insn.ops[0].reg == table_reg && insn.ops[1].type == o_displ &&
                insn.ops[1].reg == reg) {
                return static_cast<ea_t>(base + insn.ops[1].addr);
            }
        }
        if (is_basic_block_end(insn, false)) {
            break;
        }
    }
    return table;
}

json getService(ea_t addr, uint8_t table_id) {
    json s;
    insn_t insn;
    decode_insn(&insn, addr);
    if (insn.itype == ARM_ldr && insn.ops[0].type == o_reg &&
        insn.ops[1].type == o_displ) {
        ea_t ea = addr;
        uint8_t blr_reg = 0xff;
        uint8_t table_reg = insn.ops[0].reg;
        uint64_t service_offset = BADADDR;
        while (true) {
            ea = next_head(ea, BADADDR);
            decode_insn(&insn, ea);
            if (insn.itype == ARM_ldr && insn.ops[0].type == o_reg &&
                insn.ops[1].type == o_displ && insn.ops[1].reg == table_reg) {
                service_offset = insn.ops[1].addr;
                blr_reg = insn.ops[0].reg;
            }
            if (blr_reg != 0xff && service_offset != BADADDR && insn.itype == ARM_blr &&
                insn.ops[0].type == o_reg && insn.ops[0].reg == blr_reg) {
                s["address"] = ea;
                if (table_id == 1) {
                    s["service_name"] = lookupBootServiceName(service_offset);
                    s["table_name"] = std::string("EFI_BOOT_SERVICES");
                } else if (table_id == 2) {
                    s["service_name"] = lookupRuntimeServiceName(service_offset);
                    s["table_name"] = std::string("EFI_RUNTIME_SERVICES");
                } else {
                    s["table_name"] = std::string("OTHER");
                }
                return s;
            }
            if (is_basic_block_end(insn, false)) {
                break;
            }
        }
    }

    // handle following code patterns
    // ADR    REG1, gBS
    // ...
    // LDR    REG2, [REG1]
    // ...
    // LDR    REG3, [REG2,#0x28]
    if (insn.itype == ARM_adr && insn.ops[0].type == o_reg && insn.ops[1].type == o_imm) {
        uint8_t reg1 = insn.ops[0].reg;
        uint8_t reg2 = 0xff;
        ea_t ea = addr;
        while (true) {
            ea = next_head(ea, BADADDR);
            decode_insn(&insn, ea);
            if (insn.itype == ARM_ldr && insn.ops[0].type == o_reg &&
                insn.ops[1].type == o_displ && insn.ops[1].reg == reg1 &&
                insn.ops[1].addr == 0) {
                reg2 = insn.ops[0].reg;
            }
            if (reg2 != 0xff && insn.itype == ARM_ldr && insn.ops[0].type == o_reg &&
                insn.ops[1].type == o_displ && insn.ops[1].reg == reg2) {
                s["address"] = ea;
                if (table_id == 1) {
                    s["service_name"] = lookupBootServiceName(insn.ops[1].addr);
                    s["table_name"] = std::string("EFI_BOOT_SERVICES");
                } else if (table_id == 2) {
                    s["service_name"] = lookupRuntimeServiceName(insn.ops[1].addr);
                    s["table_name"] = std::string("EFI_RUNTIME_SERVICES");
                } else {
                    s["table_name"] = std::string("OTHER");
                }
                return s;
            }
        }
    }

    return s;
}

void EfiAnalysis::EfiAnalyzerArm::initialGlobalVarsDetection() {
    // analyze entry point with Hex-Rays
    for (auto idx = 0; idx < get_entry_qty(); idx++) {
        uval_t ord = get_entry_ordinal(idx);
        ea_t ep = get_entry(ord);
        json res = DetectVars(get_func(ep));
        if (res.contains("gImageHandleList")) {
            for (auto addr : res["gImageHandleList"]) {
                if (!addrInVec(gImageHandleListArm, addr)) {
                    gImageHandleListArm.push_back(addr);
                }
            }
        }
        if (res.contains("gStList")) {
            for (auto addr : res["gStList"]) {
                if (!addrInVec(gStListArm, addr)) {
                    gStListArm.push_back(addr);
                }
            }
        }
        if (res.contains("gBsList")) {
            for (auto addr : res["gBsList"]) {
                if (!addrInVec(gBsListArm, addr)) {
                    gBsListArm.push_back(addr);
                }
            }
        }
        if (res.contains("gRtList")) {
            for (auto addr : res["gRtList"]) {
                if (!addrInVec(gRtListArm, addr)) {
                    gRtListArm.push_back(addr);
                }
            }
        }
    }

    // analysis of all functions and search for additional table initializations
    for (auto func_addr : funcs) {
        func_t *f = get_func(func_addr);
        if (f == nullptr) {
            continue;
        }
        auto ea = f->start_ea;
        while (ea < f->end_ea) {
            ea = next_head(ea, BADADDR);
            ea_t bs = getTable(ea, 0x60);
            if (bs != BADADDR) {
                msg("[efiXplorer] gBS = 0x%016llX\n", u64_addr(ea));
                setPtrTypeAndName(bs, "gBS", "EFI_BOOT_SERVICES");
                if (!addrInVec(gBsListArm, bs)) {
                    gBsListArm.push_back(bs);
                }
                continue;
            }
            ea_t rt = getTable(ea, 0x58);
            if (rt != BADADDR) {
                msg("[efiXplorer] gRT = 0x%016llX\n", u64_addr(ea));
                setPtrTypeAndName(rt, "gRT", "EFI_RUNTIME_SERVICES");
                if (!addrInVec(gRtListArm, rt)) {
                    gRtListArm.push_back(rt);
                }
                continue;
            }
        }
    }
}

void EfiAnalysis::EfiAnalyzerArm::servicesDetection() {

    for (auto func_addr : funcs) {
        std::vector<json> services = DetectServices(get_func(func_addr));
        for (auto service : services) {
            allServices.push_back(service);
        }
    }

    // analyze xrefs to gBS, gRT
    for (auto bs : gBsListArm) {
        auto xrefs = getXrefs(bs);
        for (auto ea : xrefs) {
            auto s = getService(ea, 1);
            if (!s.contains("address")) {
                continue;
            }
            std::string name = s["service_name"];
            if (name == std::string("Unknown")) {
                continue;
            }
            if (!jsonInVec(allServices, s)) {
                msg("[efiXplorer] gBS xref address: 0x%016llX, found new service\n", ea);
                allServices.push_back(s);
            }
        }
    }
    for (auto rt : gRtListArm) {
        auto xrefs = getXrefs(rt);
        for (auto ea : xrefs) {
            auto s = getService(ea, 2);
            if (!s.contains("address")) {
                continue;
            }
            std::string name = s["service_name"];
            if (name == std::string("Unknown")) {
                continue;
            }
            if (!jsonInVec(allServices, s)) {
                msg("[efiXplorer] gRT xref address: 0x%016llX, found new service\n", ea);
                allServices.push_back(s);
            }
        }
    }
}

bool EfiAnalysis::EfiAnalyzerArm::getProtocol(ea_t address, uint32_t p_reg,
                                              std::string service_name) {
    ea_t ea = address;
    insn_t insn;
    ea_t offset = BADADDR;
    ea_t guid_addr = BADADDR;
    ea_t code_addr = BADADDR;
    while (true) {
        ea = prev_head(ea, 0);
        decode_insn(&insn, ea);
        if (insn.itype == ARM_adrl && insn.ops[0].type == o_reg &&
            insn.ops[0].reg == p_reg && insn.ops[1].type == o_imm) {
            guid_addr = insn.ops[1].value;
            code_addr = ea;
            break;
        }
        if (insn.itype == ARM_add && insn.ops[0].type == o_reg &&
            insn.ops[0].reg == p_reg && insn.ops[1].type == o_reg &&
            insn.ops[1].reg == p_reg && insn.ops[2].type == o_imm) {
            offset = insn.ops[2].value;
        }
        if (insn.itype == ARM_adrp && insn.ops[0].type == o_reg &&
            insn.ops[0].reg == p_reg && insn.ops[1].type == o_imm) {
            guid_addr = insn.ops[1].value + offset;
            code_addr = ea;
            break;
        }
        if (is_basic_block_end(insn, false)) {
            break;
        }
    }
    if (guid_addr == BADADDR || code_addr == BADADDR) {
        return false;
    }
    msg("[efiXplorer] address: 0x%016llX, found new protocol\n", u64_addr(code_addr));
    return AddProtocol(service_name, guid_addr, code_addr, address);
}

void EfiAnalysis::EfiAnalyzerArm::protocolsDetection() {
    for (auto s : allServices) {
        std::string service_name = s["service_name"];
        for (auto i = 0; i < 13; i++) {
            std::string current_name =
                static_cast<std::string>(bs_table_aarch64[i].service_name);
            if (current_name != service_name) {
                continue;
            }
            getProtocol(s["address"], bs_table_aarch64[i].reg, service_name);
            break;
        }
    }
}

//--------------------------------------------------------------------------
// Show all non-empty choosers windows
void showAllChoosers(EfiAnalysis::EfiAnalyzerArm analyzer) {
    qstring title;

    // open window with all services
    if (analyzer.allServices.size()) {
        title = "efiXplorer: services";
        services_show(analyzer.allServices, title);
    }

    // open window with data guids
    if (analyzer.allGuids.size()) {
        qstring title = "efiXplorer: GUIDs";
        guids_show(analyzer.allGuids, title);
    }

    // open window with protocols
    if (analyzer.allProtocols.size()) {
        title = "efiXplorer: protocols";
        protocols_show(analyzer.allProtocols, title);
    }
}

//--------------------------------------------------------------------------
// Main function for AARCH64 modules
bool EfiAnalysis::efiAnalyzerMainArm() {
    EfiAnalysis::EfiAnalyzerArm analyzer;

    while (!auto_is_ok()) {
        auto_wait();
    };

    // find .text and .data segments
    analyzer.getSegments();

    // mark GUIDs
    analyzer.markDataGuids();

    // set the correct name for the entry point and automatically fix the prototype
    analyzer.initialAnalysis();
    analyzer.initialGlobalVarsDetection();

    // detect services
    analyzer.servicesDetection();

    // detect protocols
    analyzer.protocolsDetection();

    applyAllTypesForInterfacesBootServices(analyzer.allProtocols);
    showAllChoosers(analyzer);

    return true;
}
