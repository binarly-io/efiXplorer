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
 * efiSmmUtils.cpp
 *
 */

#include "efiSmmUtils.h"

static const char plugin_name[] = "efiXplorer";

//--------------------------------------------------------------------------
// Find and mark gSmst global variable via EFI_SMM_SW_DISPATCH(2)_PROTOCOL_GUID
std::vector<ea_t> findSmstSwDispatch(std::vector<ea_t> gBsList) {
    std::vector<ea_t> smst_addrs;
    EfiGuid guid2 = {0x18a3c6dc,
                     0x5eea,
                     0x48c8,
                     {0xa1, 0xc1, 0xb5, 0x33, 0x89, 0xf9, 0x89,
                      0x99}}; // EFI_SMM_SW_DISPATCH2_PROTOCOL_GUID
    EfiGuid guid = {0xe541b773,
                    0xdd11,
                    0x420c,
                    {0xb0, 0x26, 0xdf, 0x99, 0x36, 0x53, 0xf8,
                     0xbf}}; // EFI_SMM_SW_DISPATCH_PROTOCOL_GUID
    std::vector<ea_t> data_addrs = findData(0, BADADDR, guid.uchar_data().data(), 16);
    std::vector<ea_t> data2_addrs = findData(0, BADADDR, guid2.uchar_data().data(), 16);
    data_addrs.insert(data_addrs.end(), data2_addrs.begin(), data2_addrs.end());
    for (auto data_addr : data_addrs) {
        msg("[%s] EFI_SMM_SW_DISPATCH(2)_PROTOCOL_GUID: 0x%016llX\n", plugin_name,
            static_cast<uint64_t>(data_addr));
        std::vector<ea_t> xrefs = getXrefs(data_addr);
        insn_t insn;
        for (auto xref : xrefs) {
            ea_t res_addr = BADADDR;
            ea_t cur_addr = xref;
            // Check 4 instructions below
            for (auto i = 0; i < 4; i++) {
                cur_addr = prev_head(cur_addr, 0);
                decode_insn(&insn, cur_addr);
                if (insn.itype == NN_mov && insn.ops[0].type == o_reg &&
                    insn.ops[0].reg == REG_RAX && insn.ops[1].type == o_mem) {
                    msg("[%s] found gSmst at 0x%016llX, address = 0x%016llX\n",
                        plugin_name, static_cast<uint64_t>(cur_addr),
                        static_cast<uint64_t>(insn.ops[1].addr));
                    res_addr = insn.ops[1].addr;
                    if (find(gBsList.begin(), gBsList.end(), res_addr) != gBsList.end()) {
                        continue;
                    }
                    set_cmt(cur_addr, "_EFI_SMM_SYSTEM_TABLE2 *gSmst;", true);
                    setPtrTypeAndName(res_addr, "gSmst", "_EFI_SMM_SYSTEM_TABLE2");
                    smst_addrs.push_back(res_addr);
                    break;
                }
            }
        }
    }
    return smst_addrs;
}

//--------------------------------------------------------------------------
// Find and mark gSmst global variable via EFI_SMM_BASE2_PROTOCOL_GUID
std::vector<ea_t> findSmstSmmBase(std::vector<ea_t> gBsList) {
    std::vector<ea_t> smst_addrs;
    EfiGuid guid = {
        0xf4ccbfb7,
        0xf6e0,
        0x47fd,
        {0x9d, 0xd4, 0x10, 0xa8, 0xf1, 0x50, 0xc1, 0x91}}; // EFI_SMM_BASE2_PROTOCOL_GUID
    std::vector<ea_t> data_addrs = findData(0, BADADDR, guid.uchar_data().data(), 16);
    for (auto data_addr : data_addrs) {
        msg("[%s] EFI_SMM_BASE2_PROTOCOL_GUID: 0x%016llX\n", plugin_name,
            static_cast<uint64_t>(data_addr));
        std::vector<ea_t> data_xrefs = getXrefs(data_addr);
        insn_t insn;
        for (auto xref : data_xrefs) {
            ea_t res_addr = BADADDR;
            ea_t cur_addr = xref;
            // Check 16 instructions below
            for (auto i = 0; i < 16; i++) {
                cur_addr = next_head(cur_addr, BADADDR);
                decode_insn(&insn, cur_addr);
                if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
                    insn.ops[0].reg == REG_RDX && insn.ops[1].type == o_mem) {
                    msg("[%s] found gSmst at 0x%016llX, address = 0x%016llX\n",
                        plugin_name, static_cast<uint64_t>(cur_addr),
                        static_cast<uint64_t>(insn.ops[1].addr));
                    res_addr = insn.ops[1].addr;
                    if (find(gBsList.begin(), gBsList.end(), res_addr) != gBsList.end()) {
                        continue;
                    }
                    set_cmt(cur_addr, "_EFI_SMM_SYSTEM_TABLE2 *gSmst;", true);
                    setPtrTypeAndName(res_addr, "gSmst", "_EFI_SMM_SYSTEM_TABLE2");
                    smst_addrs.push_back(res_addr);
                    break;
                }
            }
        }
    }
    return smst_addrs;
}

//--------------------------------------------------------------------------
// Find SmiHandler in RegSwSmi function
std::vector<func_t *> findSmiHandlers(ea_t address) {
    std::vector<func_t *> smiHandlers;

    // Get RegSwSmi function
    func_t *regSmi = get_func(address);
    ea_t start = 0;
    ea_t ea = 0;
    insn_t insn;

    if (regSmi == nullptr) {
        msg("[%s] can't get RegSwSmi function, will try to create it\n", plugin_name);

        // Try to create function
        ea = address;
        for (int i = 0; i < 100; i++) {
            ea = prev_head(ea, 0);
            decode_insn(&insn, ea);
            if (insn.itype == NN_retn) {
                start = next_head(ea, BADADDR);
                break;
            }
        }

        // Create function
        add_func(start);
        regSmi = get_func(address);
        if (regSmi == nullptr) {
            return smiHandlers;
        }
    }

    // Find (SwDispath->Register)(SwDispath, SwSmiHandler, &SwSmiNum, Data)
    for (ea_t ea = regSmi->start_ea; ea <= regSmi->end_ea; ea = next_head(ea, BADADDR)) {
        decode_insn(&insn, ea);
        if (insn.itype == NN_callni) {
            // Find `lea r9`
            bool success = false;
            ea_t addr = prev_head(ea, 0);
            for (int i = 0; i < 12; i++) {
                decode_insn(&insn, addr);
                if (insn.itype == NN_lea && insn.ops[0].reg == REG_R9 &&
                    insn.ops[1].type == o_displ) {
                    success = true;
                    break;
                }
                addr = prev_head(addr, 0);
            }

            if (!success)
                continue;

            // Find `lea r8`
            success = false;
            addr = prev_head(ea, 0);
            for (int i = 0; i < 12; i++) {
                decode_insn(&insn, addr);
                if (insn.itype == NN_lea && insn.ops[0].reg == REG_R8 &&
                    insn.ops[1].type == o_displ) {
                    success = true;
                    break;
                }
                addr = prev_head(addr, 0);
            }

            if (!success)
                continue;

            // Find `lea rdx`
            success = false;
            addr = prev_head(ea, 0);
            for (int i = 0; i < 12; i++) {
                decode_insn(&insn, addr);
                if (insn.itype == NN_lea && insn.ops[0].reg == REG_RDX &&
                    insn.ops[1].type == o_mem) {
                    success = true;
                    break;
                }
                addr = prev_head(addr, 0);
            }

            if (!success)
                continue;

            ea_t smiHandlerAddr = insn.ops[1].addr;
            func_t *smiHandler = get_func(smiHandlerAddr);
            if (smiHandler == nullptr) {
                msg("[%s] can't get SwSmiHandler function, will try to create it\n",
                    plugin_name);

                // Create function
                add_func(smiHandlerAddr);
                smiHandler = get_func(smiHandlerAddr);
            }

            if (smiHandler == nullptr) {
                continue;
            }

            // Make name for SwSmiHandler function
            set_name(smiHandler->start_ea, "SwSmiHandler", SN_FORCE);

            smiHandlers.push_back(smiHandler);
            msg("[%s] found SmiHandler: 0x%016llX\n", plugin_name,
                static_cast<uint64_t>(smiHandler->start_ea));
        }
    }
    return smiHandlers;
}

//--------------------------------------------------------------------------
// Find SwSmiHandler function inside SMM drivers
//  * find EFI_SMM_SW_DISPATCH(2)_PROTOCOL_GUID
//  * get EFI_SMM_SW_DISPATCH(2)_PROTOCOL_GUID xref address
//  * this address will be inside RegSwSmi function
//  * find SmiHandler by pattern (instructions may be out of order)
//        lea     r9, ...
//        lea     r8, ...
//        lea     rdx, <func>
//        call    qword ptr [...]
std::vector<func_t *> findSmiHandlersSmmSwDispatch(std::vector<segment_t *> dataSegments,
                                                   std::vector<json> stackGuids) {
    std::vector<func_t *> smiHandlers;
    EfiGuid guid2 = {0x18a3c6dc,
                     0x5eea,
                     0x48c8,
                     {0xa1, 0xc1, 0xb5, 0x33, 0x89, 0xf9, 0x89,
                      0x99}}; // EFI_SMM_SW_DISPATCH2_PROTOCOL_GUID
    EfiGuid guid = {0xe541b773,
                    0xdd11,
                    0x420c,
                    {0xb0, 0x26, 0xdf, 0x99, 0x36, 0x53, 0xf8,
                     0xbf}}; // EFI_SMM_SW_DISPATCH_PROTOCOL_GUID
    std::vector<ea_t> data_addrs = findData(0, BADADDR, guid.uchar_data().data(), 16);
    std::vector<ea_t> data2_addrs = findData(0, BADADDR, guid2.uchar_data().data(), 16);
    data_addrs.insert(data_addrs.end(), data2_addrs.begin(), data2_addrs.end());
    msg("[%s] SwSmiHandler function finding (using "
        "EFI_SMM_SW_DISPATCH(2)_PROTOCOL_GUID)\n",
        plugin_name);
    for (auto data_addr : data_addrs) {
        std::vector<ea_t> xrefs = getXrefs(data_addr);

        for (auto xref : xrefs) {
            std::vector<func_t *> smiHandlersCur = findSmiHandlers(xref);
            smiHandlers.insert(smiHandlers.end(), smiHandlersCur.begin(),
                               smiHandlersCur.end());
        }
    }

    // Append stackSmiHandlers to result
    std::vector<func_t *> stackSmiHandlers =
        findSmiHandlersSmmSwDispatchStack(stackGuids);
    smiHandlers.insert(smiHandlers.end(), stackSmiHandlers.begin(),
                       stackSmiHandlers.end());
    return smiHandlers;
}

//--------------------------------------------------------------------------
// Find SwSmiHandler function inside SMM drivers in case where
// EFI_SMM_SW_DISPATCH(2)_PROTOCOL_GUID is a local variable
std::vector<func_t *> findSmiHandlersSmmSwDispatchStack(std::vector<json> stackGuids) {
    std::vector<func_t *> smiHandlers;

    for (auto guid : stackGuids) {
        std::string name = static_cast<std::string>(guid["name"]);

        if (name != "EFI_SMM_SW_DISPATCH2_PROTOCOL_GUID" &&
            name != "EFI_SMM_SW_DISPATCH_PROTOCOL_GUID") {
            continue;
        }

        ea_t address = static_cast<ea_t>(guid["address"]);
        msg("[%s] found EFI_SMM_SW_DISPATCH(2)_PROTOCOL_GUID on stack: "
            "0x%016llX\n",
            plugin_name, static_cast<uint64_t>(address));
        std::vector<func_t *> smiHandlersCur = findSmiHandlers(address);
        smiHandlers.insert(smiHandlers.end(), smiHandlersCur.begin(),
                           smiHandlersCur.end());
    }

    return smiHandlers;
}

//--------------------------------------------------------------------------
// Find gSmmVar->SmmGetVariable calls via EFI_SMM_VARIABLE_PROTOCOL_GUID
std::vector<ea_t> findSmmGetVariableCalls(std::vector<segment_t *> dataSegments,
                                          std::vector<json> *allServices) {
    msg("[%s] gSmmVar->SmmGetVariable calls finding via EFI_SMM_VARIABLE_PROTOCOL_GUID\n",
        plugin_name);
    std::vector<ea_t> smmGetVariableCalls;
    EfiGuid guid = {0xed32d533,
                    0x99e6,
                    0x4209,
                    {0x9c, 0xc0, 0x2d, 0x72, 0xcd, 0xd9, 0x98,
                     0xa7}}; // EFI_SMM_VARIABLE_PROTOCOL_GUID

    // Find all EFI_GUID EFI_SMM_VARIABLE_PROTOCOL_GUID addresses
    std::vector<ea_t> data_addrs = findData(0, BADADDR, guid.uchar_data().data(), 16);
    std::vector<ea_t> gSmmVarAddrs; // Find all gSmmVar variables
    for (auto data_addr : data_addrs) {
        msg("Here\n");
        std::vector<ea_t> xrefs = getXrefs(data_addr);

        for (auto xref : xrefs) {
            segment_t *seg = getseg(static_cast<ea_t>(xref));
            qstring seg_name;
            get_segm_name(&seg_name, seg);
            msg("[%s] EFI_SMM_VARIABLE_PROTOCOL_GUID xref address: 0x%016llX, "
                "segment: %s\n",
                plugin_name, static_cast<uint64_t>(xref), seg_name.c_str());

            size_t index = seg_name.find(".text");
            if (index == std::string::npos) {
                continue;
            }

            insn_t insn;
            ea_t ea = xref;
            for (auto i = 0; i < 8; i++) {
                // Find `lea r8, <gSmmVar_addr>` instruction
                ea = prev_head(ea, 0);
                decode_insn(&insn, ea);
                if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
                    insn.ops[0].reg == REG_R8 && insn.ops[1].type == o_mem) {
                    msg("[%s] gSmmVar address: 0x%016llX\n", plugin_name,
                        static_cast<uint64_t>(insn.ops[1].addr));
                    set_cmt(ea, "EFI_SMM_VARIABLE_PROTOCOL *gSmmVar", true);
                    setPtrTypeAndName(insn.ops[1].addr, "gSmmVar",
                                      "EFI_SMM_VARIABLE_PROTOCOL");
                    gSmmVarAddrs.push_back(insn.ops[1].addr);
                    break;
                }
            }
        }
    }

    if (!gSmmVarAddrs.size()) {
        msg("[%s] can't find gSmmVar addresses\n", plugin_name);
        return smmGetVariableCalls;
    }

    for (auto smmVarAddr : gSmmVarAddrs) {
        std::vector<ea_t> smmVarXrefs = getXrefs(static_cast<ea_t>(smmVarAddr));
        for (auto smmVarXref : smmVarXrefs) {
            segment_t *seg = getseg(static_cast<ea_t>(smmVarXref));
            qstring seg_name;
            get_segm_name(&seg_name, seg);
            msg("[%s] gSmmVar xref address: 0x%016llX, segment: %s\n", plugin_name,
                static_cast<uint64_t>(smmVarXref), seg_name.c_str());

            size_t index = seg_name.find(".text");
            if (index == std::string::npos) {
                continue;
            }

            uint16 gSmmVarReg = 0xffff;
            insn_t insn;
            ea_t ea = static_cast<ea_t>(smmVarXref);
            decode_insn(&insn, ea);

            if (insn.itype == NN_mov && insn.ops[0].type == o_reg &&
                insn.ops[1].type == o_mem) {
                gSmmVarReg = insn.ops[0].reg;
                for (auto i = 0; i < 16; i++) {
                    ea = next_head(ea, BADADDR);
                    decode_insn(&insn, ea);

                    if (insn.itype == NN_callni && gSmmVarReg == insn.ops[0].reg &&
                        insn.ops[0].addr == 0) {
                        msg("[%s] gSmmVar->SmmGetVariable found: 0x%016llX\n",
                            plugin_name, static_cast<uint64_t>(ea));

                        if (find(smmGetVariableCalls.begin(), smmGetVariableCalls.end(),
                                 ea) == smmGetVariableCalls.end()) {
                            smmGetVariableCalls.push_back(ea);
                        }

                        // Temporarily add a "virtual" smm service call
                        // for easier annotations and UI

                        std::string cmt = getSmmVarComment();
                        set_cmt(ea, cmt.c_str(), true);
                        opStroff(ea, "EFI_SMM_VARIABLE_PROTOCOL");
                        msg("[%s] 0x%016llX : %s\n", plugin_name,
                            static_cast<uint64_t>(ea), "SmmGetVariable");
                        std::string smm_call = "gSmmVar->SmmGetVariable";
                        json smm_item;
                        smm_item["address"] = ea;
                        smm_item["service_name"] = smm_call;
                        smm_item["table_name"] =
                            static_cast<std::string>("EFI_SMM_VARIABLE_PROTOCOL");
                        smm_item["offset"] = 0;

                        if (find(allServices->begin(), allServices->end(), smm_item) ==
                            allServices->end()) {
                            allServices->push_back(smm_item);
                        }

                        break;
                    }
                }
            }
        }
    }
    return smmGetVariableCalls;
}

std::vector<ea_t> resolveEfiSmmCpuProtocol(std::vector<json> stackGuids,
                                           std::vector<json> dataGuids,
                                           std::vector<json> *allServices) {
    std::vector<ea_t> readSaveStateCalls;
    msg("[%s] Looking for EFI_SMM_CPU_PROTOCOL\n", plugin_name);
    std::vector<ea_t> codeAddrs;
    std::vector<ea_t> gSmmCpuAddrs;
    for (auto guid : stackGuids) {
        std::string name = static_cast<std::string>(guid["name"]);
        if (name != "EFI_SMM_CPU_PROTOCOL_GUID")
            continue;
        ea_t address = static_cast<ea_t>(guid["address"]);
        msg("[%s] found EFI_SMM_CPU_PROTOCOL on stack: 0x%016llX\n", plugin_name,
            static_cast<uint64_t>(address));
        codeAddrs.push_back(address);
    }

    for (auto guid : dataGuids) {
        std::string name = static_cast<std::string>(guid["name"]);
        if (name != "EFI_SMM_CPU_PROTOCOL_GUID")
            continue;

        ea_t address = static_cast<ea_t>(guid["address"]);
        msg("[%s] found EFI_SMM_CPU_PROTOCOL: 0x%016llX\n", plugin_name,
            static_cast<uint64_t>(address));
        std::vector<ea_t> guidXrefs = getXrefs(address);

        for (auto guidXref : guidXrefs) {
            segment_t *seg = getseg(static_cast<ea_t>(guidXref));
            qstring seg_name;
            get_segm_name(&seg_name, seg);
            size_t index = seg_name.find(".text");
            if (index == std::string::npos) {
                continue;
            }
            codeAddrs.push_back(static_cast<ea_t>(guidXref));
        }
    }

    for (auto addr : codeAddrs) {
        msg("[%s] current address: 0x%016llX\n", plugin_name,
            static_cast<uint64_t>(addr));
        insn_t insn;
        ea_t ea = prev_head(addr, 0);

        for (auto i = 0; i < 8; i++) {
            // Find 'lea r8, <gSmmCpu_addr>' instruction
            decode_insn(&insn, ea);
            if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
                insn.ops[0].reg == REG_R8 && insn.ops[1].type == o_mem) {
                msg("[%s] gSmmCpu address: 0x%016llX\n", plugin_name,
                    static_cast<uint64_t>(insn.ops[1].addr));
                set_cmt(ea, "EFI_SMM_CPU_PROTOCOL *gSmmCpu", true);
                setPtrTypeAndName(insn.ops[1].addr, "gSmmCpu", "EFI_SMM_CPU_PROTOCOL");
                gSmmCpuAddrs.push_back(insn.ops[1].addr);
                break;
            }
            ea = prev_head(ea, 0);
        }
    }

    if (!gSmmCpuAddrs.size()) {
        msg("[%s] can't find gSmmCpu addresses\n", plugin_name);
        return readSaveStateCalls;
    }

    for (auto smmCpu : gSmmCpuAddrs) {
        std::vector<ea_t> smmCpuXrefs = getXrefs(static_cast<ea_t>(smmCpu));

        for (auto smmCpuXref : smmCpuXrefs) {
            segment_t *seg = getseg(static_cast<ea_t>(smmCpuXref));
            qstring seg_name;
            get_segm_name(&seg_name, seg);
            size_t index = seg_name.find(".text");

            if (index == std::string::npos) {
                continue;
            }

            uint16_t gSmmCpuReg = 0xffff;
            insn_t insn;
            ea_t ea = static_cast<ea_t>(smmCpuXref);
            decode_insn(&insn, ea);

            if (insn.itype == NN_mov && insn.ops[0].type == o_reg &&
                insn.ops[1].type == o_mem) {
                gSmmCpuReg = insn.ops[0].reg;

                for (auto i = 0; i < 16; i++) {
                    ea = next_head(ea, BADADDR);
                    decode_insn(&insn, ea);

                    if (insn.itype == NN_callni && gSmmCpuReg == insn.ops[0].reg &&
                        insn.ops[0].addr == 0) {
                        if (find(readSaveStateCalls.begin(), readSaveStateCalls.end(),
                                 ea) == readSaveStateCalls.end()) {
                            readSaveStateCalls.push_back(ea);
                        }

                        opStroff(ea, "EFI_SMM_CPU_PROTOCOL");
                        msg("[%s] 0x%016llX : %s\n", plugin_name,
                            static_cast<uint64_t>(ea), "gSmmCpu->ReadSaveState");
                        std::string smm_call = "gSmmCpu->ReadSaveState";
                        json smm_item;
                        smm_item["address"] = ea;
                        smm_item["service_name"] = smm_call;
                        smm_item["table_name"] =
                            static_cast<std::string>("EFI_SMM_CPU_PROTOCOL");
                        smm_item["offset"] = 0;

                        if (find(allServices->begin(), allServices->end(), smm_item) ==
                            allServices->end()) {
                            allServices->push_back(smm_item);
                        }

                        break;
                    }
                }
            }
        }
    }
    return readSaveStateCalls;
}

ea_t markSmiHandler(ea_t ea) {
    insn_t insn;
    auto addr = prev_head(ea, 0);
    decode_insn(&insn, addr);
    while (!is_basic_block_end(insn, false)) {
        // for next iteration
        decode_insn(&insn, addr);
        addr = prev_head(addr, 0);

        // check current instruction
        if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
            insn.ops[0].reg == REG_RCX) {
            if (insn.ops[1].type != o_mem) {
                continue;
            }
            set_name(insn.ops[1].addr, "SmiHandler", SN_FORCE);
            return insn.ops[1].addr;
        }
    }
    return BADADDR;
}
