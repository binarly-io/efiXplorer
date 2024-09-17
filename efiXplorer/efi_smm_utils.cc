/*
 * efiXplorer
 * Copyright (C) 2020-2024 Binarly
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
 */

#include "efi_smm_utils.h"

#include "efi_global.h"
#include <algorithm>

//--------------------------------------------------------------------------
// Find and mark gSmst global variable via EFI_SMM_SW_DISPATCH(2)_PROTOCOL_GUID
ea_list_t findSmstSwDispatch(ea_list_t bs_list) {
  ea_list_t smst_addrs;
  efi_guid_t guid2 = {0x18a3c6dc,
                      0x5eea,
                      0x48c8,
                      {0xa1, 0xc1, 0xb5, 0x33, 0x89, 0xf9, 0x89,
                       0x99}}; // EFI_SMM_SW_DISPATCH2_PROTOCOL_GUID
  efi_guid_t guid = {0xe541b773,
                     0xdd11,
                     0x420c,
                     {0xb0, 0x26, 0xdf, 0x99, 0x36, 0x53, 0xf8,
                      0xbf}}; // EFI_SMM_SW_DISPATCH_PROTOCOL_GUID
  ea_list_t data_addrs =
      efi_utils::find_data(0, BADADDR, guid.uchar_data().data(), 16);
  ea_list_t data2_addrs =
      efi_utils::find_data(0, BADADDR, guid2.uchar_data().data(), 16);
  data_addrs.insert(data_addrs.end(), data2_addrs.begin(), data2_addrs.end());
  for (auto data_addr : data_addrs) {
    msg("[%s] EFI_SMM_SW_DISPATCH(2)_PROTOCOL_GUID: 0x%016llX\n", g_plugin_name,
        u64_addr(data_addr));
    ea_list_t xrefs = efi_utils::get_xrefs(data_addr);
    insn_t insn;
    for (auto xref : xrefs) {
      uint16_t smst_reg = 0xffff; // Smst register
      ea_t cur_addr = xref;
      while (true) {
        cur_addr = next_head(cur_addr, BADADDR);
        decode_insn(&insn, cur_addr);
        // check for SmmLocateProtocol function call
        if (insn.itype == NN_callni && insn.ops[0].type == o_displ &&
            insn.ops[0].addr == 0xd0) {
          smst_reg = insn.ops[0].reg;
          break;
        }
        if (is_basic_block_end(insn, false)) {
          break;
        }
      }

      if (smst_reg == 0xffff) {
        continue; // smst_reg not found
      }

      ea_t res_addr = BADADDR;
      cur_addr = xref;
      while (true) {
        cur_addr = prev_head(cur_addr, 0);
        decode_insn(&insn, cur_addr);
        if (insn.itype == NN_mov && insn.ops[0].type == o_reg &&
            insn.ops[0].reg == smst_reg && insn.ops[1].type == o_mem) {
          msg("[%s] found gSmst at 0x%016llX, address = 0x%016llX\n",
              g_plugin_name, u64_addr(cur_addr), u64_addr(insn.ops[1].addr));
          res_addr = insn.ops[1].addr;
          if (efi_utils::addr_in_vec(bs_list, res_addr)) {
            continue;
          }
          efi_utils::set_ptr_type_and_name(res_addr, "gSmst",
                                           "_EFI_SMM_SYSTEM_TABLE2");
          smst_addrs.push_back(res_addr);
          break;
        }
        if (is_basic_block_end(insn, false)) {
          break;
        }
      }
    }
  }

  return smst_addrs;
}

//--------------------------------------------------------------------------
// Find and mark gSmst global variable via EFI_SMM_BASE2_PROTOCOL_GUID
ea_list_t findSmstSmmBase(ea_list_t bs_list) {
  ea_list_t smst_addrs;
  efi_guid_t guid = {0xf4ccbfb7,
                     0xf6e0,
                     0x47fd,
                     {0x9d, 0xd4, 0x10, 0xa8, 0xf1, 0x50, 0xc1,
                      0x91}}; // EFI_SMM_BASE2_PROTOCOL_GUID
  ea_list_t data_addrs =
      efi_utils::find_data(0, BADADDR, guid.uchar_data().data(), 16);
  for (auto data_addr : data_addrs) {
    msg("[%s] EFI_SMM_BASE2_PROTOCOL_GUID: 0x%016llX\n", g_plugin_name,
        u64_addr(data_addr));
    ea_list_t data_xrefs = efi_utils::get_xrefs(data_addr);
    insn_t insn;
    for (auto xref : data_xrefs) {
      ea_t res_addr = BADADDR;
      ea_t cur_addr = xref;
      bool in_smram = false;
      // Check 16 instructions below
      for (auto i = 0; i < 16; i++) {
        cur_addr = next_head(cur_addr, BADADDR);
        decode_insn(&insn, cur_addr);
        if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
            insn.ops[0].reg == R_RDX && insn.ops[1].type == o_mem) {
          res_addr = insn.ops[1].addr;
          msg("[%s] found gSmst/gInSmram at 0x%016llX, address = 0x%016llX\n",
              g_plugin_name, u64_addr(cur_addr), u64_addr(res_addr));
        }
        if (res_addr != BADADDR && insn.itype == NN_callni &&
            insn.ops[0].type == o_phrase && !insn.ops[0].addr) {
          // gEfiSmmBase2Protocol->InSmm(gEfiSmmBase2Protocol, &gInSmram)
          in_smram = true;
        }
      }
      if (!in_smram) {
        // we found gSmst
        if (efi_utils::addr_in_vec(bs_list, res_addr)) {
          continue;
        }
        efi_utils::set_ptr_type_and_name(res_addr, "gSmst",
                                         "_EFI_SMM_SYSTEM_TABLE2");
        smst_addrs.push_back(res_addr);
      } else {
        // we found gInSmram
        efi_utils::set_type_and_name(res_addr, "gInSmram", "BOOLEAN");
      }
    }
  }

  return smst_addrs;
}

//--------------------------------------------------------------------------
// Find SmiHandler in reg_smi_func function (prefix: Sw, TrapIo, Sx, Gpi, Usb,
// StandbyButton, PeriodicTimer, PowerButton)
func_list_t findSmiHandlers(ea_t address, std::string prefix) {
  msg("[%s] Analyse xref to gEfiSmm%sDispatch(2)Protocol: 0x%016llX\n",
      g_plugin_name, prefix.c_str(), u64_addr(address));

  func_list_t m_smi_handlers;
  insn_t insn;

  // Find Dispatch interface address (via gSmst->SmmLocateProtocol call)

  // Check instruction
  decode_insn(&insn, address);
  if (!(insn.ops[0].type == o_reg && insn.ops[0].reg == R_RCX)) {
    msg("[%s] %sSmiHandler: wrong xref to dispatch(2) protocol\n",
        g_plugin_name, prefix.c_str());
    return m_smi_handlers;
  }

  // Analyse current basic block
  auto ea = address;

  // Search for SmmLocateProtocol
  bool found = false;
  uint64_t dispatch_interface = BADADDR;
  while (!is_basic_block_end(insn, false)) {
    ea = next_head(ea, BADADDR);
    decode_insn(&insn, ea);
    if (insn.itype == NN_callni && insn.ops[0].type == o_displ &&
        insn.ops[0].addr == 0xd0) {
      found = true;
      msg("[%s] %sSmiHandler: found = true\n", g_plugin_name, prefix.c_str());
      break;
    }
    // Interface in stack
    if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
        insn.ops[0].reg == R_R8 && insn.ops[1].type == o_displ &&
        (insn.ops[1].reg == R_RBP || insn.ops[1].reg == R_RSP)) {
      if (dispatch_interface == BADADDR) {
        dispatch_interface = insn.ops[1].addr;
      }
    }
    // Interface in data
    if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
        insn.ops[0].reg == R_R8 && insn.ops[1].type == o_mem) {
      if (dispatch_interface == BADADDR) {
        dispatch_interface = insn.ops[1].addr;
      }
    }
  }

  if (!found) {
    return m_smi_handlers;
  }

  if (dispatch_interface == BADADDR) {
    ea = address;
    while (!is_basic_block_end(insn, false)) {
      ea = prev_head(ea, 0);
      decode_insn(&insn, ea);
      // Interface in stack
      if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
          insn.ops[0].reg == R_R8 && insn.ops[1].type == o_displ &&
          (insn.ops[1].reg == R_RBP || insn.ops[1].reg == R_RSP)) {
        dispatch_interface = insn.ops[1].addr;
        break;
      }
      // Interface in data
      if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
          insn.ops[0].reg == R_R8 && insn.ops[1].type == o_mem) {
        dispatch_interface = insn.ops[1].addr;
        break;
      }
    }
  }

  if (dispatch_interface == BADADDR) {
    return m_smi_handlers;
  }

  msg("[%s] Found EfiSmm%sDispatch(2)Protocol interface: 0x%016llX\n",
      g_plugin_name, prefix.c_str(), dispatch_interface);

  // TODO(yeggor): handle xrefs for globals
  // (fw71.bin.out/SmmHddSecurity-316b1230-0500-4592-8c09-eaba0fb6b07f.smm)

  // Track interface stack variable
  ea = address;
  uint16_t reg = NONE_REG;
  uint64_t dispatch_func = BADADDR;
  for (auto i = 0; i < 100; i++) {
    ea = next_head(ea, BADADDR);
    decode_insn(&insn, ea);
    // get Interface base register
    if (insn.itype == NN_mov && insn.ops[0].type == o_reg &&
        (insn.ops[1].type == o_displ || insn.ops[1].type == o_mem)) {
      if (insn.ops[1].addr == dispatch_interface) {
        reg = insn.ops[0].reg;
      } else {
        reg = NONE_REG; // resetting
      }
      continue;
    }

    // resetting (register overwrite or call)
    if (reg != NONE_REG && insn.ops[0].type == o_reg &&
        insn.ops[0].reg == reg) {
      reg = NONE_REG;
      continue;
    }

    // resetting (call)
    if (insn.itype == NN_call) {
      reg = NONE_REG;
      continue;
    }

    // get DispatchFunction address
    if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
        insn.ops[0].reg == R_RDX && insn.ops[1].type == o_mem) {
      dispatch_func = insn.ops[1].addr;
      continue;
    }
    if (insn.itype == NN_callni && insn.ops[0].type == o_phrase &&
        insn.ops[0].reg == reg) {
      msg("[%s] Found EfiSmm%sDispatch2Protocol->Register call (0x%016llX)\n",
          g_plugin_name, prefix.c_str(), u64_addr(ea));
      msg("[%s]  %sSmiHandler: 0x%016llX\n", g_plugin_name, prefix.c_str(),
          dispatch_func);
      auto handler_func = get_func(dispatch_func);
      if (handler_func == nullptr) {
        add_func(dispatch_func);                // create function
        handler_func = get_func(dispatch_func); // retry
      }
      if (handler_func != nullptr) {
        m_smi_handlers.push_back(handler_func); // add in result
      }
      reg = NONE_REG; // resetting

      // op_stroff + set_name
      std::string name = prefix + "SmiHandler";
      set_name(dispatch_func, name.c_str(), SN_FORCE);
      std::string prefix_upper;
      std::transform(prefix.begin(), prefix.end(), prefix_upper.begin(),
                     ::toupper);
      std::string type = "EFI_SMM_" + prefix_upper + "_DISPATCH2_PROTOCOL";
      efi_utils::op_stroff(ea, type);
    }

    if (insn.itype == NN_retn || insn.itype == NN_int3) {
      break;
    }
  }

  return m_smi_handlers;
}

//--------------------------------------------------------------------------
// Find {Prefix}SmiHandler function inside SMM drivers
//  * find GUID
//  * get xrefs to GUID
//  * xref will be inside RegSwSmi function
//  * find SmiHandler by pattern (instructions may be out of order)
//        lea     r9, ...
//        lea     r8, ...
//        lea     rdx, <func>
//        call    qword ptr [...]
func_list_t findSmiHandlersSmmDispatch(efi_guid_t guid, std::string prefix) {
  func_list_t m_smi_handlers;
  ea_list_t data_addrs =
      efi_utils::find_data(0, BADADDR, guid.uchar_data().data(), 16);
  msg("[%s] %sSmiHandler function finding\n", g_plugin_name, prefix.c_str());
  for (auto data_addr : data_addrs) {
    ea_list_t xrefs = efi_utils::get_xrefs(data_addr);

    for (auto xref : xrefs) {
      msg("[%s] findSmiHandlers: 0x%016llX\n", g_plugin_name, u64_addr(xref));
      auto res = findSmiHandlers(xref, prefix);
      m_smi_handlers.insert(m_smi_handlers.end(), res.begin(), res.end());
    }
  }

  return m_smi_handlers;
}

//--------------------------------------------------------------------------
// Find SwSmiHandler function inside SMM drivers in case where
// EFI_SMM_SW_DISPATCH(2)_PROTOCOL_GUID is a local variable
func_list_t findSmiHandlersSmmDispatchStack(json_list_t stackGuids,
                                            std::string prefix) {
  func_list_t m_smi_handlers;

  for (auto guid : stackGuids) {
    std::string name = static_cast<std::string>(guid["name"]);

    if (name != "EFI_SMM_SW_DISPATCH2_PROTOCOL_GUID" &&
        name != "EFI_SMM_SW_DISPATCH_PROTOCOL_GUID") {
      continue;
    }

    ea_t address = static_cast<ea_t>(guid["address"]);
    msg("[%s] found EFI_SMM_SW_DISPATCH(2)_PROTOCOL_GUID on stack: "
        "0x%016llX\n",
        g_plugin_name, u64_addr(address));
    auto res = findSmiHandlers(address, prefix);
    m_smi_handlers.insert(m_smi_handlers.end(), res.begin(), res.end());
  }

  return m_smi_handlers;
}

//--------------------------------------------------------------------------
// Find gSmmVariable->SmmGetVariable calls via EFI_SMM_VARIABLE_PROTOCOL_GUID
ea_list_t findSmmGetVariableCalls(segment_list_t dataSegments,
                                  json_list_t *m_all_services) {
  msg("[%s] gSmmVariable->SmmGetVariable calls finding via "
      "EFI_SMM_VARIABLE_PROTOCOL_GUID\n",
      g_plugin_name);
  ea_list_t smmGetVariableCalls;
  efi_guid_t guid = {0xed32d533,
                     0x99e6,
                     0x4209,
                     {0x9c, 0xc0, 0x2d, 0x72, 0xcd, 0xd9, 0x98,
                      0xa7}}; // EFI_SMM_VARIABLE_PROTOCOL_GUID

  // Find all EFI_GUID EFI_SMM_VARIABLE_PROTOCOL_GUID addresses
  ea_list_t data_addrs =
      efi_utils::find_data(0, BADADDR, guid.uchar_data().data(), 16);
  ea_list_t gSmmVariableAddrs; // Find all gSmmVariable variables
  for (auto data_addr : data_addrs) {
    ea_list_t xrefs = efi_utils::get_xrefs(data_addr);

    for (auto xref : xrefs) {
      segment_t *seg = getseg(static_cast<ea_t>(xref));
      qstring seg_name;
      get_segm_name(&seg_name, seg);
      msg("[%s] EFI_SMM_VARIABLE_PROTOCOL_GUID xref address: 0x%016llX, "
          "segment: %s\n",
          g_plugin_name, u64_addr(xref), seg_name.c_str());

      size_t index = seg_name.find(".text");
      if (index == std::string::npos) {
        continue;
      }

      insn_t insn;
      ea_t ea = xref;
      for (auto i = 0; i < 8; i++) {
        // Find `lea r8, <gSmmVariable_addr>` instruction
        ea = prev_head(ea, 0);
        decode_insn(&insn, ea);
        if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
            insn.ops[0].reg == R_R8 && insn.ops[1].type == o_mem) {
          msg("[%s] gSmmVariable address: 0x%016llX\n", g_plugin_name,
              u64_addr(insn.ops[1].addr));
          efi_utils::set_ptr_type_and_name(insn.ops[1].addr, "gSmmVariable",
                                           "EFI_SMM_VARIABLE_PROTOCOL");
          gSmmVariableAddrs.push_back(insn.ops[1].addr);
          break;
        }
      }
    }
  }

  if (!gSmmVariableAddrs.size()) {
    msg("[%s] can't find gSmmVariable addresses\n", g_plugin_name);
    return smmGetVariableCalls;
  }

  for (auto smmVarAddr : gSmmVariableAddrs) {
    ea_list_t smmVarXrefs = efi_utils::get_xrefs(static_cast<ea_t>(smmVarAddr));
    for (auto smmVarXref : smmVarXrefs) {
      segment_t *seg = getseg(static_cast<ea_t>(smmVarXref));
      qstring seg_name;
      get_segm_name(&seg_name, seg);
      msg("[%s] gSmmVariable xref address: 0x%016llX, segment: %s\n",
          g_plugin_name, u64_addr(smmVarXref), seg_name.c_str());

      size_t index = seg_name.find(".text");
      if (index == std::string::npos) {
        continue;
      }

      uint16 gSmmVariableReg = 0xffff;
      insn_t insn;
      ea_t ea = static_cast<ea_t>(smmVarXref);
      decode_insn(&insn, ea);

      if (insn.itype == NN_mov && insn.ops[0].type == o_reg &&
          insn.ops[1].type == o_mem) {
        gSmmVariableReg = insn.ops[0].reg;
        for (auto i = 0; i < 16; i++) {
          ea = next_head(ea, BADADDR);
          decode_insn(&insn, ea);

          if (insn.itype == NN_callni && gSmmVariableReg == insn.ops[0].reg &&
              insn.ops[0].addr == 0) {
            msg("[%s] gSmmVariable->SmmGetVariable found: 0x%016llX\n",
                g_plugin_name, u64_addr(ea));

            if (find(smmGetVariableCalls.begin(), smmGetVariableCalls.end(),
                     ea) == smmGetVariableCalls.end()) {
              smmGetVariableCalls.push_back(ea);
            }

            // Temporarily add a "virtual" smm service call
            // for easier annotations and UI

            efi_utils::op_stroff(ea, "EFI_SMM_VARIABLE_PROTOCOL");
            msg("[%s] 0x%016llX : %s\n", g_plugin_name, u64_addr(ea),
                "SmmGetVariable");
            std::string smm_call = "gSmmVariable->SmmGetVariable";
            json smm_item;
            smm_item["address"] = ea;
            smm_item["service_name"] = smm_call;
            smm_item["table_name"] =
                static_cast<std::string>("EFI_SMM_VARIABLE_PROTOCOL");
            smm_item["offset"] = 0;

            if (find(m_all_services->begin(), m_all_services->end(),
                     smm_item) == m_all_services->end()) {
              m_all_services->push_back(smm_item);
            }

            break;
          }
        }
      }
    }
  }
  return smmGetVariableCalls;
}

ea_list_t resolveEfiSmmCpuProtocol(json_list_t stackGuids,
                                   json_list_t dataGuids,
                                   json_list_t *m_all_services) {
  ea_list_t readSaveStateCalls;
  msg("[%s] Looking for EFI_SMM_CPU_PROTOCOL\n", g_plugin_name);
  ea_list_t code_addrs;
  ea_list_t gSmmCpuAddrs;
  for (auto guid : stackGuids) {
    std::string name = static_cast<std::string>(guid["name"]);
    if (name != "EFI_SMM_CPU_PROTOCOL_GUID")
      continue;
    ea_t address = static_cast<ea_t>(guid["address"]);
    msg("[%s] found EFI_SMM_CPU_PROTOCOL on stack: 0x%016llX\n", g_plugin_name,
        u64_addr(address));
    code_addrs.push_back(address);
  }

  for (auto guid : dataGuids) {
    std::string name = static_cast<std::string>(guid["name"]);
    if (name != "EFI_SMM_CPU_PROTOCOL_GUID")
      continue;

    ea_t address = static_cast<ea_t>(guid["address"]);
    msg("[%s] found EFI_SMM_CPU_PROTOCOL: 0x%016llX\n", g_plugin_name,
        u64_addr(address));
    ea_list_t guidXrefs = efi_utils::get_xrefs(address);

    for (auto guidXref : guidXrefs) {
      segment_t *seg = getseg(static_cast<ea_t>(guidXref));
      qstring seg_name;
      get_segm_name(&seg_name, seg);
      size_t index = seg_name.find(".text");
      if (index == std::string::npos) {
        continue;
      }
      code_addrs.push_back(static_cast<ea_t>(guidXref));
    }
  }

  for (auto addr : code_addrs) {
    msg("[%s] current address: 0x%016llX\n", g_plugin_name, u64_addr(addr));
    insn_t insn;
    ea_t ea = prev_head(addr, 0);

    for (auto i = 0; i < 8; i++) {
      // Find 'lea r8, <gSmmCpu_addr>' instruction
      decode_insn(&insn, ea);
      if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
          insn.ops[0].reg == R_R8 && insn.ops[1].type == o_mem) {
        msg("[%s] gSmmCpu address: 0x%016llX\n", g_plugin_name,
            u64_addr(insn.ops[1].addr));
        efi_utils::set_ptr_type_and_name(insn.ops[1].addr, "gSmmCpu",
                                         "EFI_SMM_CPU_PROTOCOL");
        gSmmCpuAddrs.push_back(insn.ops[1].addr);
        break;
      }
      ea = prev_head(ea, 0);
    }
  }

  if (!gSmmCpuAddrs.size()) {
    msg("[%s] can't find gSmmCpu addresses\n", g_plugin_name);
    return readSaveStateCalls;
  }

  for (auto smmCpu : gSmmCpuAddrs) {
    ea_list_t smmCpuXrefs = efi_utils::get_xrefs(static_cast<ea_t>(smmCpu));

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

            efi_utils::op_stroff(ea, "EFI_SMM_CPU_PROTOCOL");
            msg("[%s] 0x%016llX : %s\n", g_plugin_name, u64_addr(ea),
                "gSmmCpu->ReadSaveState");
            std::string smm_call = "gSmmCpu->ReadSaveState";
            json smm_item;
            smm_item["address"] = ea;
            smm_item["service_name"] = smm_call;
            smm_item["table_name"] =
                static_cast<std::string>("EFI_SMM_CPU_PROTOCOL");
            smm_item["offset"] = 0;

            if (find(m_all_services->begin(), m_all_services->end(),
                     smm_item) == m_all_services->end()) {
              m_all_services->push_back(smm_item);
            }

            break;
          }
        }
      }
    }
  }
  return readSaveStateCalls;
}

ea_t markChildSwSmiHandler(ea_t ea) {
  insn_t insn;
  auto addr = prev_head(ea, 0);
  decode_insn(&insn, addr);
  while (!is_basic_block_end(insn, false)) {
    // for next iteration
    decode_insn(&insn, addr);
    addr = prev_head(addr, 0);

    // check current instruction
    if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
        insn.ops[0].reg == R_RCX) {
      if (insn.ops[1].type != o_mem) {
        continue;
      }
      set_name(insn.ops[1].addr, "ChildSwSmiHandler", SN_FORCE);
      return insn.ops[1].addr;
    }
  }
  return BADADDR;
}
