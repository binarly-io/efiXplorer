#include "efiSmmUtils.h"

static const char plugin_name[] = "efiXplorer";

/* experimental */
func_t *findSmiHandlerCpuProtocol() {
    /*
        +------------------------------------------------------------------+
        | Find SW SMI handler inside SMM drivers:                          |
        -------------------------------------------------------------------+
        | 1. find EFI_SMM_CPU_PROTOCOL_GUID                                |
        | 2. find gEfiSmmCpuProtocol interface address                     |
        | 3. find address for 'mov rax, cs:gEfiSmmCpuProtocol' instruction |
        | 4. this address will be inside 'SmiHandler' function             |
        +------------------------------------------------------------------+
    */
    DEBUG_MSG("[%s] SW SMI handler finding (using EFI_SMM_CPU_PROTOCOL_GUID)\n",
              plugin_name);
    efiGuid efiSmmCpuProtocolGuid = {
        0xeb346b97,
        0x975f,
        0x4a9f,
        {0x8b, 0x22, 0xf8, 0xe9, 0x2b, 0xb3, 0xd5, 0x69}};
    ea_t efiSmmCpuProtocolGuidAddr = 0;
    ea_t gEfiSmmCpuProtocolAddr = 0;
    string segName = ".data";
    segment_t *seg_info = get_segm_by_name(segName.c_str());
    if (seg_info == NULL) {
        DEBUG_MSG("[%s] can't find a %s segment\n", plugin_name,
                  segName.c_str());
        return NULL;
    }
    ea_t ea = seg_info->start_ea;
    while (ea != BADADDR && ea <= seg_info->end_ea - 15) {
        if (get_wide_dword(ea) == efiSmmCpuProtocolGuid.data1) {
            efiSmmCpuProtocolGuidAddr = ea;
            break;
        }
        ea += 1;
    }
    if (!efiSmmCpuProtocolGuidAddr) {
        DEBUG_MSG("[%s] can't find a EFI_SMM_CPU_PROTOCOL_GUID guid\n",
                  plugin_name);
        return NULL;
    }
    DEBUG_MSG("[%s] EFI_SMM_CPU_PROTOCOL_GUID address: 0x%llx\n", plugin_name,
              efiSmmCpuProtocolGuidAddr);
    vector<ea_t> efiSmmCpuProtocolGuidXrefs =
        getXrefs(efiSmmCpuProtocolGuidAddr);
    for (vector<ea_t>::iterator guidXref = efiSmmCpuProtocolGuidXrefs.begin();
         guidXref != efiSmmCpuProtocolGuidXrefs.end(); ++guidXref) {
        DEBUG_MSG("[%s] EFI_SMM_CPU_PROTOCOL_GUID xref address: 0x%llx\n",
                  plugin_name, *guidXref);
        /* find gEfiSmmCpuProtocol interface address */
        ea_t ea = prev_head(*guidXref, 0);
        insn_t insn;
        bool success = false;
        for (int i = 0; i < 8; i++) {
            decode_insn(&insn, ea);
            if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
                insn.ops[1].type == o_mem) {
                DEBUG_MSG("[%s] gEfiSmmCpuProtocol interface address: 0x%llx\n",
                          plugin_name, insn.ops[1].addr);
                success = true;
                break;
            }
            ea = prev_head(ea, 0);
        }
        if (!success) {
            continue;
        }
        /* get address from SmiHandler function */
        ea_t addrFromSmiHandler = get_first_dref_to(insn.ops[1].addr);
        if (addrFromSmiHandler == BADADDR) {
            continue;
        }
        DEBUG_MSG("[%s] address from SmiHandler function: 0x%llx\n",
                  plugin_name, addrFromSmiHandler);
        func_t *smiHandler = get_func(addrFromSmiHandler);
        ea_t start = 0;
        if (smiHandler == NULL) {
            DEBUG_MSG(
                "[%s] can't get SmiHandler function, will try to create it\n",
                plugin_name)
            /* try to create function */
            ea = addrFromSmiHandler;
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
            smiHandler = get_func(addrFromSmiHandler);
        }
        /* make name for SmiHandler function */
        char hexAddr[16] = {};
        sprintf(hexAddr, "%llx", smiHandler->start_ea);
        string name = "SmiHandler_" + (string)hexAddr;
        set_name(smiHandler->start_ea, name.c_str(), SN_CHECK);
        return smiHandler;
    }
    return NULL;
}

func_t *findSmiHandlerSmmSwDispatch() {
    /*
        +------------------------------------------------------------------+
        | Find SW SMI handler inside SMM drivers                           |
        -------------------------------------------------------------------+
        | 1. find EFI_SMM_SW_DISPATCH(2)_PROTOCOL_GUID                     |
        | 2. get EFI_SMM_SW_DISPATCH(2)_PROTOCOL_GUID xref address         |
        | 3. this address will be inside 'RegSwSmi' function               |
        | 4. find SmiHandler by pattern (instructions may be out of order) |
        |     lea     r9, ...                                              |
        |     lea     r8, ...                                              |
        |     lea     rdx, <func>                                          |
        |     call    qword ptr [...]                                      |
        +------------------------------------------------------------------+
    */
    DEBUG_MSG("[%s] SW SMI handler finding (using "
              "EFI_SMM_SW_DISPATCH_PROTOCOL_GUID)\n",
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
    ea_t efiSmmSwDispatchProtocolGuidAddr = 0;
    string segName = ".data";
    segment_t *seg_info = get_segm_by_name(segName.c_str());
    if (seg_info == NULL) {
        DEBUG_MSG("[%s] can't find a %s segment\n", plugin_name,
                  segName.c_str());
        return NULL;
    }
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
        return NULL;
    }
    DEBUG_MSG("[%s] EFI_SMM_SW_DISPATCH(2)_PROTOCOL_GUID address: 0x%llx\n",
              plugin_name, efiSmmSwDispatchProtocolGuidAddr);
    vector<ea_t> efiSmmSwDispatchProtocolGuidXrefs =
        getXrefs(efiSmmSwDispatchProtocolGuidAddr);
    for (vector<ea_t>::iterator guidXref =
             efiSmmSwDispatchProtocolGuidXrefs.begin();
         guidXref != efiSmmSwDispatchProtocolGuidXrefs.end(); ++guidXref) {
        DEBUG_MSG(
            "[%s] EFI_SMM_SW_DISPATCH2_PROTOCOL_GUID xref address: 0x%llx\n",
            plugin_name, *guidXref);
        /* get 'RegSwSmi' function */
        func_t *regSmi = get_func(*guidXref);
        ea_t start = 0;
        insn_t insn;
        if (regSmi == NULL) {
            DEBUG_MSG(
                "[%s] can't get RegSwSmi function, will try to create it\n",
                plugin_name)
            /* try to create function */
            ea = *guidXref;
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
            regSmi = get_func(*guidXref);
            if (regSmi == NULL) {
                continue;
            }
        }
        /* find (SwDispath->Register)(SwDispath, SmiHandler, &SwSmiNum, Data) */
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
                if (smiHandler == NULL) {
                    DEBUG_MSG("[%s] can't get smiHandler function, will try to "
                              "create it\n",
                              plugin_name);
                    /* create function */
                    add_func(smiHandlerAddr);
                    smiHandler = get_func(smiHandlerAddr);
                }
                if (smiHandler == NULL) {
                    continue;
                }
                /* make name for SmiHandler function */
                char hexAddr[16] = {};
                sprintf(hexAddr, "%llx", smiHandler->start_ea);
                string name = "SmiHandler_" + (string)hexAddr;
                set_name(smiHandler->start_ea, name.c_str(), SN_CHECK);
                return smiHandler;
            }
        }
    }
    return NULL;
}
