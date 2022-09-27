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
 * efiAnalyzer.cpp
 * contains ARM specific analysis routines
 *
 */

#include "efiAnalyzer.h"
#include "efiUi.h"

using namespace EfiAnalysis;

void EfiAnalysis::EfiAnalyzerArm::renameEntryPoints() {
    for (auto idx = 0; idx < get_entry_qty(); idx++) {
        uval_t ord = get_entry_ordinal(idx);
        ea_t ep = get_entry(ord);
        set_name(ep, "_ModuleEntryPoint", SN_FORCE);
        // does not works on tested ARM binaries
        // func_data.size() always returns 0
        TrackEntryParams(get_func(ep), 0);
    }
}

ea_t getTable(ea_t code_addr, uint64_t offset) {
    ea_t bs = BADADDR;
    insn_t insn;
    decode_insn(&insn, code_addr);
    if (insn.itype != ARM_ldr || insn.ops[0].type != o_reg ||
        insn.ops[1].type != o_displ || insn.ops[1].addr != offset ||
        insn.ops[1].reg == REG_XSP) {
        return bs;
    }
    uint8_t bs_reg = insn.ops[0].reg;
    uint8_t st_reg = insn.ops[1].reg;

    // msg("[efiXplorer] address: 0x%016llX, reg = %d\n", u64_addr(code_addr), bs_reg);

    ea_t ea = code_addr;
    while (true) {
        ea = next_head(ea, BADADDR);
        decode_insn(&insn, ea);
        if (insn.itype == ARM_adrp && insn.ops[0].type == o_reg &&
            insn.ops[1].type == o_imm) {
            uint64_t base = insn.ops[1].value;
            uint8_t reg = insn.ops[0].reg;
            decode_insn(&insn, next_head(ea, BADADDR));
            if (insn.itype == ARM_str && insn.ops[0].type == o_reg &&
                insn.ops[0].reg == bs_reg && insn.ops[1].type == o_displ &&
                insn.ops[1].reg == reg) {
                bs = static_cast<ea_t>(base + insn.ops[1].addr);
                return bs;
            }
        }
        // Exit loop if end of previous basic block found
        if (is_basic_block_end(insn, false)) {
            break;
        }
    }
    return bs;
}

void EfiAnalysis::EfiAnalyzerArm::initialGlobalVarsDetection() {
    // analyze entry point with Hex-Rays
    for (auto idx = 0; idx < get_entry_qty(); idx++) {
        uval_t ord = get_entry_ordinal(idx);
        ea_t ep = get_entry(ord);
        DetectVars(get_func(ep));
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
                continue;
            }
            ea_t rt = getTable(ea, 0x58);
            if (rt != BADADDR) {
                msg("[efiXplorer] gRT = 0x%016llX\n", u64_addr(ea));
                setPtrTypeAndName(bs, "gRT", "EFI_RUNTIME_SERVICES");
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
    analyzer.renameEntryPoints();

    analyzer.initialGlobalVarsDetection();
    analyzer.servicesDetection();

    showAllChoosers(analyzer);

    return true;
}
