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
 * Copyright (C) 2020-2021  Binarly
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
 * efiSmmUtils.cpp
 *
 */

#define _CRT_SECURE_NO_WARNINGS

#include "efiSmmUtils.h"

static const char plugin_name[] = "efiXplorer";

//--------------------------------------------------------------------------
// Find and mark gSmst global variable via EFI_SMM_SW_DISPATCH(2)_PROTOCOL_GUID
vector<ea_t> findSmstSwDispatch(vector<ea_t> gBsList,
                                vector<segment_t *> dataSegments) {
    vector<ea_t> resAddrs;
    efiGuid efiSmmSwDispatch2ProtocolGuid = {
        0x18a3c6dc,
        0x5eea,
        0x48c8,
        {0xa1, 0xc1, 0xb5, 0x33, 0x89, 0xf9, 0x89, 0x99}};
    efiGuid efiSmmSwDispatchProtocolGuid = {
        0xe541b773,
        0xdd11,
        0x420c,
        {0xb0, 0x26, 0xdf, 0x99, 0x36, 0x53, 0xf8, 0xbf}};
    ea_t efiSmmSwDispatchProtocolGuidAddr = 0;
    for (vector<segment_t *>::iterator seg = dataSegments.begin();
         seg != dataSegments.end(); ++seg) {
        segment_t *seg_info = *seg;
        if (seg_info == nullptr) {
            return resAddrs;
        }
        DEBUG_MSG("[%s] gSmst finding from 0x%016X to 0x%016X (via "
                  "EFI_SMM_SW_DISPATCH(2)_PROTOCOL_GUID)\n",
                  plugin_name, seg_info->start_ea, seg_info->end_ea);
        ea_t ea = seg_info->start_ea;
        while (ea != BADADDR && ea <= seg_info->end_ea - 15) {
            if (get_wide_dword(ea) == efiSmmSwDispatchProtocolGuid.data1) {
                efiSmmSwDispatchProtocolGuidAddr = ea;
                break;
            }
            ea += 1;
        }
        if (!efiSmmSwDispatchProtocolGuidAddr) {
            continue;
        }
        vector<ea_t> efiSmmSwDispatchProtocolGuidXrefs =
            getXrefs(efiSmmSwDispatchProtocolGuidAddr);
        for (vector<ea_t>::iterator guidXref =
                 efiSmmSwDispatchProtocolGuidXrefs.begin();
             guidXref != efiSmmSwDispatchProtocolGuidXrefs.end(); ++guidXref) {
            ea_t resAddr = 0;
            ea_t curAddr = prev_head(*guidXref, 0);
            insn_t insn;
            /* 4 instructions below */
            for (auto i = 0; i < 4; i++) {
                decode_insn(&insn, curAddr);
                /* check if insn like 'mov rax, cs:<gSmst>' */
                if (insn.itype == NN_mov && insn.ops[0].type == o_reg &&
                    insn.ops[0].reg == REG_RAX && insn.ops[1].type == o_mem) {
                    DEBUG_MSG(
                        "[%s] found gSmst at 0x%016X, address = 0x%016X\n",
                        plugin_name, curAddr, insn.ops[1].addr);
                    resAddr = insn.ops[1].addr;
                    if (find(gBsList.begin(), gBsList.end(), resAddr) !=
                        gBsList.end()) {
                        continue;
                    }
                    char hexAddr[21] = {};
                    snprintf(hexAddr, 21, "%llX",
                             static_cast<uint64_t>(resAddr));
                    set_cmt(curAddr, "_EFI_SMM_SYSTEM_TABLE2 *gSmst;", true);
                    string name = "gSmst_" + static_cast<string>(hexAddr);
                    setPtrTypeAndName(resAddr, name, "_EFI_SMM_SYSTEM_TABLE2");
                    resAddrs.push_back(resAddr);
                    break;
                }
                curAddr = prev_head(curAddr, 0);
            }
        }
    }
    return resAddrs;
}

//--------------------------------------------------------------------------
// Find and mark gSmst global variable via EFI_SMM_BASE2_PROTOCOL_GUID
vector<ea_t> findSmstSmmBase(vector<ea_t> gBsList,
                             vector<segment_t *> dataSegments) {
    vector<ea_t> resAddrs;
    efiGuid efiSmmBase2ProtocolGuid = {
        0xf4ccbfb7,
        0xf6e0,
        0x47fd,
        {0x9d, 0xd4, 0x10, 0xa8, 0xf1, 0x50, 0xc1, 0x91}};
    ea_t efiSmmBase2ProtocolGuidAddr = 0;
    for (vector<segment_t *>::iterator seg = dataSegments.begin();
         seg != dataSegments.end(); ++seg) {
        segment_t *seg_info = *seg;
        if (seg_info == nullptr) {
            return resAddrs;
        }
        DEBUG_MSG("[%s] gSmst finding from 0x%016X to 0x%016X (via "
                  "EFI_SMM_BASE2_PROTOCOL_GUID)\n",
                  plugin_name, seg_info->start_ea, seg_info->end_ea);
        ea_t ea = seg_info->start_ea;
        while (ea != BADADDR && ea <= seg_info->end_ea - 15) {
            if (get_wide_dword(ea) == efiSmmBase2ProtocolGuid.data1) {
                efiSmmBase2ProtocolGuidAddr = ea;
                break;
            }
            ea += 1;
        }
        if (!efiSmmBase2ProtocolGuidAddr) {
            continue;
        }
        vector<ea_t> efiSmmBase2ProtocolGuidXrefs =
            getXrefs(efiSmmBase2ProtocolGuidAddr);
        for (vector<ea_t>::iterator guidXref =
                 efiSmmBase2ProtocolGuidXrefs.begin();
             guidXref != efiSmmBase2ProtocolGuidXrefs.end(); ++guidXref) {
            ea_t resAddr = 0;
            ea_t curAddr = next_head(*guidXref, BADADDR);
            insn_t insn;
            /* 16 instructions below */
            for (auto i = 0; i < 16; i++) {
                decode_insn(&insn, curAddr);
                /* check if insn like 'lea rdx, <gSmst>' */
                if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
                    insn.ops[0].reg == REG_RDX && insn.ops[1].type == o_mem) {
                    DEBUG_MSG(
                        "[%s] found gSmst at 0x%016X, address = 0x%016X\n",
                        plugin_name, curAddr, insn.ops[1].addr);
                    resAddr = insn.ops[1].addr;
                    if (find(gBsList.begin(), gBsList.end(), resAddr) !=
                        gBsList.end()) {
                        continue;
                    }
                    char hexAddr[21] = {};
                    snprintf(hexAddr, 21, "%llX",
                             static_cast<uint64_t>(resAddr));
                    set_cmt(curAddr, "_EFI_SMM_SYSTEM_TABLE2 *gSmst;", true);
                    string name = "gSmst_" + static_cast<string>(hexAddr);
                    setPtrTypeAndName(resAddr, name, "_EFI_SMM_SYSTEM_TABLE2");
                    resAddrs.push_back(resAddr);
                    break;
                }
                curAddr = next_head(curAddr, BADADDR);
            }
        }
    }
    return resAddrs;
}

//--------------------------------------------------------------------------
// Find SmiHandler in RegSwSmi function
vector<func_t *> findSmiHandlers(ea_t address) {
    vector<func_t *> smiHandlers;
    /* get RegSwSmi function */
    func_t *regSmi = get_func(address);
    ea_t start = 0;
    ea_t ea = 0;
    insn_t insn;
    if (regSmi == nullptr) {
        DEBUG_MSG("[%s] can't get RegSwSmi function, will try to create it\n",
                  plugin_name)
        /* try to create function */
        ea = address;
        /* find function start */
        for (int i = 0; i < 100; i++) {
            /* find 'retn' insn */
            ea = prev_head(ea, 0);
            decode_insn(&insn, ea);
            if (insn.itype == NN_retn) {
                start = next_head(ea, BADADDR);
                break;
            }
        }
        /* create function */
        add_func(start);
        regSmi = get_func(address);
        if (regSmi == nullptr) {
            return smiHandlers;
        }
    }
    /* find (SwDispath->Register)(SwDispath, SwSmiHandler, &SwSmiNum,
     * Data)
     */
    for (ea_t ea = regSmi->start_ea; ea <= regSmi->end_ea;
         ea = next_head(ea, BADADDR)) {
        decode_insn(&insn, ea);
        if (insn.itype == NN_callni) {
            /* find 'lea r9' */
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
            /* find 'lea r8' */
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
            /* find 'lea rdx' */
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
                DEBUG_MSG("[%s] can't get SwSmiHandler function, will try to "
                          "create it\n",
                          plugin_name);
                /* create function */
                add_func(smiHandlerAddr);
                smiHandler = get_func(smiHandlerAddr);
            }
            if (smiHandler == nullptr) {
                continue;
            }
            /* make name for SwSmiHandler function */
            char hexAddr[21] = {0};
            snprintf(hexAddr, 21, "%llX",
                     static_cast<uint64_t>(smiHandler->start_ea));
            string name = "SwSmiHandler_" + static_cast<string>(hexAddr);
            set_name(smiHandler->start_ea, name.c_str(), SN_CHECK);
            smiHandlers.push_back(smiHandler);
            DEBUG_MSG("[%s] found SmiHandler: 0x%016X\n", plugin_name,
                      smiHandler->start_ea);
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
vector<func_t *> findSmiHandlersSmmSwDispatch(vector<segment_t *> dataSegments,
                                              vector<json> stackGuids) {
    DEBUG_MSG("[%s] SwSmiHandler function finding (using "
              "EFI_SMM_SW_DISPATCH(2)_PROTOCOL_GUID)\n",
              plugin_name);
    efiGuid efiSmmSwDispatch2ProtocolGuid = {
        0x18a3c6dc,
        0x5eea,
        0x48c8,
        {0xa1, 0xc1, 0xb5, 0x33, 0x89, 0xf9, 0x89, 0x99}};
    efiGuid efiSmmSwDispatchProtocolGuid = {
        0xe541b773,
        0xdd11,
        0x420c,
        {0xb0, 0x26, 0xdf, 0x99, 0x36, 0x53, 0xf8, 0xbf}};
    vector<func_t *> smiHandlers;
    for (vector<segment_t *>::iterator seg = dataSegments.begin();
         seg != dataSegments.end(); ++seg) {
        segment_t *seg_info = *seg;
        DEBUG_MSG(
            "[%s] SwSmiHandler function finding from 0x%016X to 0x%016X\n",
            plugin_name, seg_info->start_ea, seg_info->end_ea);
        ea_t efiSmmSwDispatchProtocolGuidAddr = 0;
        ea_t ea = seg_info->start_ea;
        while (ea != BADADDR && ea <= seg_info->end_ea - 15) {
            if (get_wide_dword(ea) == efiSmmSwDispatchProtocolGuid.data1 ||
                get_wide_dword(ea) == efiSmmSwDispatch2ProtocolGuid.data1) {
                efiSmmSwDispatchProtocolGuidAddr = ea;
                break;
            }
            ea += 1;
        }
        if (!efiSmmSwDispatchProtocolGuidAddr) {
            DEBUG_MSG(
                "[%s] can't find a EFI_SMM_SW_DISPATCH(2)_PROTOCOL_GUID guid\n",
                plugin_name);
            continue;
        }
        DEBUG_MSG(
            "[%s] EFI_SMM_SW_DISPATCH(2)_PROTOCOL_GUID address: 0x%016X\n",
            plugin_name, efiSmmSwDispatchProtocolGuidAddr);
        vector<ea_t> efiSmmSwDispatchProtocolGuidXrefs =
            getXrefs(efiSmmSwDispatchProtocolGuidAddr);
        for (vector<ea_t>::iterator guidXref =
                 efiSmmSwDispatchProtocolGuidXrefs.begin();
             guidXref != efiSmmSwDispatchProtocolGuidXrefs.end(); ++guidXref) {
            DEBUG_MSG("[%s] EFI_SMM_SW_DISPATCH(2)_PROTOCOL_GUID xref address: "
                      "0x%016X\n",
                      plugin_name, *guidXref);
            vector<func_t *> smiHandlersCur = findSmiHandlers(*guidXref);
            smiHandlers.insert(smiHandlers.end(), smiHandlersCur.begin(),
                               smiHandlersCur.end());
        }
    }
    /* append stackSmiHandlers to result */
    vector<func_t *> stackSmiHandlers =
        findSmiHandlersSmmSwDispatchStack(stackGuids);
    smiHandlers.insert(smiHandlers.end(), stackSmiHandlers.begin(),
                       stackSmiHandlers.end());
    return smiHandlers;
}

//--------------------------------------------------------------------------
// Find SwSmiHandler function inside SMM drivers in case where
// EFI_SMM_SW_DISPATCH(2)_PROTOCOL_GUID is a local variable
vector<func_t *> findSmiHandlersSmmSwDispatchStack(vector<json> stackGuids) {
    vector<func_t *> smiHandlers;
    for (vector<json>::iterator g = stackGuids.begin(); g != stackGuids.end();
         ++g) {
        json guid = *g;
        string name = static_cast<string>(guid["name"]);
        if (name != "EFI_SMM_SW_DISPATCH2_PROTOCOL_GUID" &&
            name != "EFI_SMM_SW_DISPATCH_PROTOCOL_GUID") {
            continue;
        }
        ea_t address = static_cast<ea_t>(guid["address"]);
        DEBUG_MSG("[%s] found EFI_SMM_SW_DISPATCH(2)_PROTOCOL_GUID on stack: "
                  "0x%016X\n",
                  plugin_name, address);
        vector<func_t *> smiHandlersCur = findSmiHandlers(address);
        smiHandlers.insert(smiHandlers.end(), smiHandlersCur.begin(),
                           smiHandlersCur.end());
    }
    return smiHandlers;
}

//--------------------------------------------------------------------------
// Find gSmmVar->SmmGetVariable calls via EFI_SMM_VARIABLE_PROTOCOL_GUID
vector<ea_t> findSmmGetVariableCalls(vector<segment_t *> dataSegments,
                                     vector<json> *allServices) {
    DEBUG_MSG("[%s] gSmmVar->SmmGetVariable calls finding via "
              "EFI_SMM_VARIABLE_PROTOCOL_GUID\n",
              plugin_name);
    efiGuid efiSmmVariableProtocolGuid = {
        0xed32d533,
        0xc5a6,
        0x40a2,
        {0xbd, 0xe2, 0x52, 0x55, 0x8d, 0x33, 0xcc, 0xa1}};
    vector<ea_t> smmGetVariableCalls;
    /* find all EFI_GUID EFI_SMM_VARIABLE_PROTOCOL_GUID addresses */
    vector<ea_t> efiSmmVariableProtocolGuidAddrs;
    for (vector<segment_t *>::iterator seg = dataSegments.begin();
         seg != dataSegments.end(); ++seg) {
        segment_t *seg_info = *seg;
        DEBUG_MSG("[%s] gSmmVar->SmmGetVariable function finding from 0x%016X "
                  "to 0x%016X\n",
                  plugin_name, seg_info->start_ea, seg_info->end_ea);
        ea_t ea = seg_info->start_ea;
        while (ea != BADADDR && ea <= seg_info->end_ea - 15) {
            if (get_wide_dword(ea) == efiSmmVariableProtocolGuid.data1) {
                efiSmmVariableProtocolGuidAddrs.push_back(ea);
                DEBUG_MSG(
                    "[%s] EFI_SMM_VARIABLE_PROTOCOL_GUID address: 0x%016X\n",
                    plugin_name, ea);
            }
            ea += 1;
        }
        if (!efiSmmVariableProtocolGuidAddrs.size()) {
            DEBUG_MSG("[%s] can't find a EFI_SMM_VARIABLE_PROTOCOL_GUID guid\n",
                      plugin_name);
            return smmGetVariableCalls;
        }
    }
    /* find all gSmmVar variables */
    vector<ea_t> gSmmVarAddrs;
    for (vector<ea_t>::iterator guid_addr =
             efiSmmVariableProtocolGuidAddrs.begin();
         guid_addr != efiSmmVariableProtocolGuidAddrs.end(); ++guid_addr) {
        vector<ea_t> efiSmmVariableProtocolGuidXrefs = getXrefs(*guid_addr);
        for (vector<ea_t>::iterator guidXref =
                 efiSmmVariableProtocolGuidXrefs.begin();
             guidXref != efiSmmVariableProtocolGuidXrefs.end(); ++guidXref) {
            segment_t *seg = getseg(*guidXref);
            qstring seg_name;
            get_segm_name(&seg_name, seg);
            DEBUG_MSG("[%s] EFI_SMM_VARIABLE_PROTOCOL_GUID xref address: "
                      "0x%016X, segment: %s\n",
                      plugin_name, *guidXref, seg_name.c_str());
            size_t index = seg_name.find(".text");
            if (index == string::npos) {
                /* wrong segment */
                continue;
            }
            /* if .text segment */
            insn_t insn;
            ea_t ea = prev_head(*guidXref, 0);
            for (auto i = 0; i < 8; i++) {
                /* find 'lea r8, <gSmmVar_addr>' insn */
                decode_insn(&insn, ea);
                if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
                    insn.ops[0].reg == REG_R8 && insn.ops[1].type == o_mem) {
                    DEBUG_MSG("[%s] gSmmVar address: 0x%016X\n", plugin_name,
                              insn.ops[1].addr);
                    /* set name and type */
                    char hexAddr[21] = {};
                    snprintf(hexAddr, 21, "%llX",
                             static_cast<uint64_t>(insn.ops[1].addr));
                    set_cmt(ea, "EFI_SMM_VARIABLE_PROTOCOL *gSmmVar", true);
                    string name = "gSmmVar_" + static_cast<string>(hexAddr);
                    setPtrTypeAndName(insn.ops[1].addr, name,
                                      "EFI_SMM_VARIABLE_PROTOCOL");
                    gSmmVarAddrs.push_back(insn.ops[1].addr);
                    break;
                }
                ea = prev_head(ea, 0);
            }
        }
    }
    if (!gSmmVarAddrs.size()) {
        DEBUG_MSG("[%s] can't find gSmmVar addresses\n", plugin_name);
        return smmGetVariableCalls;
    }
    for (vector<ea_t>::iterator smmVarAddr = gSmmVarAddrs.begin();
         smmVarAddr != gSmmVarAddrs.end(); ++smmVarAddr) {
        vector<ea_t> smmVarXrefs = getXrefs(*smmVarAddr);
        for (vector<ea_t>::iterator smmVarXref = smmVarXrefs.begin();
             smmVarXref != smmVarXrefs.end(); ++smmVarXref) {
            segment_t *seg = getseg(*smmVarXref);
            qstring seg_name;
            get_segm_name(&seg_name, seg);
            DEBUG_MSG("[%s] gSmmVar xref address: 0x%016X, segment: %s\n",
                      plugin_name, *smmVarXref, seg_name.c_str());
            size_t index = seg_name.find(".text");
            if (index == string::npos) {
                /* wrong segment */
                continue;
            }
            /* if .text segment */
            uint16_t gSmmVarReg = 0xffff;
            insn_t insn;
            ea_t ea = *smmVarXref;
            decode_insn(&insn, ea);
            if (insn.itype == NN_mov && insn.ops[0].type == o_reg &&
                insn.ops[1].type == o_mem) {
                gSmmVarReg = insn.ops[0].reg;
                for (auto i = 0; i < 16; i++) {
                    ea = next_head(ea, BADADDR);
                    decode_insn(&insn, ea);
                    if (insn.itype == NN_callni &&
                        gSmmVarReg == insn.ops[0].reg &&
                        insn.ops[0].addr == 0) {
                        DEBUG_MSG(
                            "[%s] gSmmVar->SmmGetVariable found: 0x%016X\n",
                            plugin_name, ea);
                        if (find(smmGetVariableCalls.begin(),
                                 smmGetVariableCalls.end(),
                                 ea) == smmGetVariableCalls.end()) {
                            smmGetVariableCalls.push_back(ea);
                        }

                        // Temporarily add a "virtual" smm service call
                        // for easier annotations and UI

                        string cmt = getSmmVarComment();
                        set_cmt(ea, cmt.c_str(), true);
                        /* op_stroff */
                        opStroff(ea, "EFI_SMM_VARIABLE_PROTOCOL");
                        DEBUG_MSG("[%s] 0x%016X : %s\n", plugin_name, ea,
                                  "SmmGetVariable");
                        string smm_call = "gSmmVar->SmmGetVariable";
                        json smmItem;
                        smmItem["address"] = ea;
                        smmItem["service_name"] = smm_call;
                        smmItem["table_name"] =
                            static_cast<string>("EFI_SMM_VARIABLE_PROTOCOL");
                        smmItem["offset"] = 0;
                        if (find(allServices->begin(), allServices->end(),
                                 smmItem) == allServices->end()) {
                            allServices->push_back(smmItem);
                        }

                        break;
                    }
                }
            }
        }
    }
    return smmGetVariableCalls;
}

vector<ea_t> resolveEfiSmmCpuProtocol(vector<json> stackGuids,
                                      vector<json> dataGuids,
                                      vector<json> *allServices) {
    vector<ea_t> readSaveStateCalls;
    DEBUG_MSG("[%s] Looking for EFI_SMM_CPU_PROTOCOL\n", plugin_name);
    vector<ea_t> codeAddrs;
    vector<ea_t> gSmmCpuAddrs;
    for (vector<json>::iterator g = stackGuids.begin(); g != stackGuids.end();
         ++g) {
        json guid = *g;
        string name = static_cast<string>(guid["name"]);
        if (name != "EFI_SMM_CPU_PROTOCOL_GUID")
            continue;
        ea_t address = static_cast<ea_t>(guid["address"]);
        DEBUG_MSG("[%s] found EFI_SMM_CPU_PROTOCOL on stack: "
                  "0x%016X\n",
                  plugin_name, address);
        codeAddrs.push_back(address);
    }
    for (vector<json>::iterator g = dataGuids.begin(); g != dataGuids.end();
         ++g) {
        json guid = *g;
        string name = static_cast<string>(guid["name"]);
        if (name != "EFI_SMM_CPU_PROTOCOL_GUID")
            continue;
        ea_t address = static_cast<ea_t>(guid["address"]);
        DEBUG_MSG("[%s] found EFI_SMM_CPU_PROTOCOL: "
                  "0x%016X\n",
                  plugin_name, address);
        vector<ea_t> guidXrefs = getXrefs(address);
        for (vector<ea_t>::iterator guidXref = guidXrefs.begin();
             guidXref != guidXrefs.end(); ++guidXref) {
            segment_t *seg = getseg(*guidXref);
            qstring seg_name;
            get_segm_name(&seg_name, seg);
            size_t index = seg_name.find(".text");
            if (index == string::npos) {
                /* wrong segment */
                continue;
            }
            codeAddrs.push_back(*guidXref);
        }
    }
    for (vector<ea_t>::iterator addr = codeAddrs.begin();
         addr != codeAddrs.end(); ++addr) {
        DEBUG_MSG("[%s] current address: 0x%016X\n", plugin_name, *addr)
        insn_t insn;
        ea_t ea = prev_head(*addr, 0);
        for (auto i = 0; i < 8; i++) {
            /* find 'lea r8, <gSmmCpu_addr>' insn */
            decode_insn(&insn, ea);
            if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
                insn.ops[0].reg == REG_R8 && insn.ops[1].type == o_mem) {
                DEBUG_MSG("[%s] gSmmCpu address: 0x%016X\n", plugin_name,
                          insn.ops[1].addr);
                /* set name and type */
                char hexAddr[21] = {};
                snprintf(hexAddr, 21, "%llX",
                         static_cast<uint64_t>(insn.ops[1].addr));
                set_cmt(ea, "EFI_SMM_CPU_PROTOCOL *gSmmCpu", true);
                string name = "gSmmCpu_" + static_cast<string>(hexAddr);
                setPtrTypeAndName(insn.ops[1].addr, name,
                                  "EFI_SMM_CPU_PROTOCOL");
                gSmmCpuAddrs.push_back(insn.ops[1].addr);
                break;
            }
            ea = prev_head(ea, 0);
        }
    }
    if (!gSmmCpuAddrs.size()) {
        DEBUG_MSG("[%s] can't find gSmmCpu addresses\n", plugin_name);
        return readSaveStateCalls;
    }
    for (vector<ea_t>::iterator smmCpu = gSmmCpuAddrs.begin();
         smmCpu != gSmmCpuAddrs.end(); ++smmCpu) {
        vector<ea_t> smmCpuXrefs = getXrefs(*smmCpu);
        for (vector<ea_t>::iterator smmCpuXref = smmCpuXrefs.begin();
             smmCpuXref != smmCpuXrefs.end(); ++smmCpuXref) {
            segment_t *seg = getseg(*smmCpuXref);
            qstring seg_name;
            get_segm_name(&seg_name, seg);
            size_t index = seg_name.find(".text");
            if (index == string::npos) {
                /* wrong segment */
                continue;
            }
            /* if .text segment */
            uint16_t gSmmCpuReg = 0xffff;
            insn_t insn;
            ea_t ea = *smmCpuXref;
            decode_insn(&insn, ea);
            if (insn.itype == NN_mov && insn.ops[0].type == o_reg &&
                insn.ops[1].type == o_mem) {
                gSmmCpuReg = insn.ops[0].reg;
                for (auto i = 0; i < 16; i++) {
                    ea = next_head(ea, BADADDR);
                    decode_insn(&insn, ea);
                    if (insn.itype == NN_callni &&
                        gSmmCpuReg == insn.ops[0].reg &&
                        insn.ops[0].addr == 0) {
                        if (find(readSaveStateCalls.begin(),
                                 readSaveStateCalls.end(),
                                 ea) == readSaveStateCalls.end()) {
                            readSaveStateCalls.push_back(ea);
                        }
                        opStroff(ea, "EFI_SMM_CPU_PROTOCOL");
                        DEBUG_MSG("[%s] 0x%016X : %s\n", plugin_name, ea,
                                  "gSmmCpu->ReadSaveState");
                        string smm_call = "gSmmCpu->ReadSaveState";
                        json smmItem;
                        smmItem["address"] = ea;
                        smmItem["service_name"] = smm_call;
                        smmItem["table_name"] =
                            static_cast<string>("EFI_SMM_CPU_PROTOCOL");
                        smmItem["offset"] = 0;
                        if (find(allServices->begin(), allServices->end(),
                                 smmItem) == allServices->end()) {
                            allServices->push_back(smmItem);
                        }
                        break;
                    }
                }
            }
        }
    }
    return readSaveStateCalls;
}
