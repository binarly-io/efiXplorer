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

#ifdef HEX_RAYS
#include "efiHexRays.h"
#endif

using namespace EfiAnalysis;

void EfiAnalysis::EfiAnalyzerArm::renameEntryPoints() {
    for (auto idx = 0; idx < get_entry_qty(); idx++) {
        uval_t ord = get_entry_ordinal(idx);
        ea_t ep = get_entry(ord);
        set_name(ep, "_ModuleEntryPoint", SN_FORCE);
    }
}

//--------------------------------------------------------------------------
// Main function for AARCH64 modules
bool EfiAnalysis::efiAnalyzerMainArm() {
    EfiAnalysis::EfiAnalyzerArm analyzer;

    while (!auto_is_ok()) {
        auto_wait();
    };

    // set the correct name for the entry point and automatically fix the prototype
    analyzer.renameEntryPoints();

    // find .text and .data segments
    analyzer.getSegments();

    // mark GUIDs
    analyzer.markDataGuids();

    return true;
}
