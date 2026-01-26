// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2020-2026 Binarly

#include "efi_smm_utils.h"

#include "efi_global.h"
#include <algorithm>
#include <string>

//--------------------------------------------------------------------------
// find and mark gSmst global variable via
// EFI_SMM_SW_DISPATCH_PROTOCOL_GUID/EFI_SMM_SW_DISPATCH2_PROTOCOL_GUID
ea_set_t efi_smm_utils::find_smst_sw_dispatch(const ea_set_t &bs_addrs) {
  ea_set_t smst_addrs;
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

  ea_set_t data_addrs =
      efi_utils::find_data(0, BADADDR, guid.uchar_data().data(), 16);
  ea_set_t data2_addrs =
      efi_utils::find_data(0, BADADDR, guid2.uchar_data().data(), 16);
  data_addrs.insert(data2_addrs.begin(), data2_addrs.end());

  for (auto data_addr : data_addrs) {
    efi_utils::log("SMM dispatch protocol GUID: 0x%" PRIx64 "\n",
                   u64_addr(data_addr));
    ea_set_t xrefs = efi_utils::get_xrefs(data_addr);
    insn_t insn;
    for (auto xref : xrefs) {
      // smst register
      uint16_t smst_reg = NONE_REG;
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

      if (smst_reg == NONE_REG) {
        // smst register not found
        continue;
      }

      ea_t res_addr = BADADDR;
      cur_addr = xref;
      while (true) {
        cur_addr = prev_head(cur_addr, 0);
        decode_insn(&insn, cur_addr);
        if (insn.itype == NN_mov && insn.ops[0].type == o_reg &&
            insn.ops[0].reg == smst_reg && insn.ops[1].type == o_mem) {
          efi_utils::log("found gSmst at 0x%" PRIx64 ", address = 0x%" PRIx64
                         "\n",
                         u64_addr(cur_addr), u64_addr(insn.ops[1].addr));
          res_addr = insn.ops[1].addr;
          if (bs_addrs.contains(res_addr)) {
            continue;
          }
          efi_utils::set_ptr_type_and_name(res_addr, "gSmst",
                                           "_EFI_SMM_SYSTEM_TABLE2");
          smst_addrs.insert(res_addr);
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
// find and mark gSmst global variable via EFI_SMM_BASE2_PROTOCOL_GUID
ea_set_t efi_smm_utils::find_smst_smm_base(const ea_set_t &bs_addrs) {
  ea_set_t smst_addrs;
  efi_guid_t guid = {0xf4ccbfb7,
                     0xf6e0,
                     0x47fd,
                     {0x9d, 0xd4, 0x10, 0xa8, 0xf1, 0x50, 0xc1,
                      0x91}}; // EFI_SMM_BASE2_PROTOCOL_GUID
  ea_set_t data_addrs =
      efi_utils::find_data(0, BADADDR, guid.uchar_data().data(), 16);
  for (auto data_addr : data_addrs) {
    efi_utils::log("SMM base protocol GUID: 0x%" PRIx64 "\n",
                   u64_addr(data_addr));
    ea_set_t data_xrefs = efi_utils::get_xrefs(data_addr);
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
          efi_utils::log("found gSmst/InSmram at 0x%" PRIx64
                         ", address = 0x%" PRIx64 "\n",
                         u64_addr(cur_addr), u64_addr(res_addr));
        }
        if (res_addr != BADADDR && insn.itype == NN_callni &&
            insn.ops[0].type == o_phrase && !insn.ops[0].addr) {
          // gEfiSmmBase2Protocol->InSmm(gEfiSmmBase2Protocol, &gInSmram)
          in_smram = true;
        }
      }
      if (!in_smram) {
        // found gSmst
        if (bs_addrs.contains(res_addr)) {
          continue;
        }
        efi_utils::set_ptr_type_and_name(res_addr, "gSmst",
                                         "_EFI_SMM_SYSTEM_TABLE2");
        smst_addrs.insert(res_addr);
      } else {
        // found gInSmram
        efi_utils::set_type_and_name(res_addr, "gInSmram", "BOOLEAN");
      }
    }
  }

  return smst_addrs;
}

//--------------------------------------------------------------------------
// find SmiHandler in reg_smi_func function,
// prefix: Sw, TrapIo, Sx, Gpi, Usb, StandbyButton, PeriodicTimer, ...
func_list_t efi_smm_utils::find_smi_handlers(ea_t address, std::string prefix) {
  efi_utils::log("analyse xref to SMM %sDispatch protocol: 0x%" PRIx64 "\n",
                 prefix.c_str(), u64_addr(address));

  func_list_t smi_handlers;
  insn_t insn;

  // find Dispatch interface address (via gSmst->SmmLocateProtocol call)

  // check instruction
  decode_insn(&insn, address);
  if (!(insn.ops[0].type == o_reg && insn.ops[0].reg == R_RCX)) {
    return smi_handlers;
  }

  // analyse current basic block
  auto ea = address;

  // search for SmmLocateProtocol
  bool found = false;
  uint64_t dispatch_interface = BADADDR;
  while (!is_basic_block_end(insn, false)) {
    ea = next_head(ea, BADADDR);
    decode_insn(&insn, ea);
    if (insn.itype == NN_callni && insn.ops[0].type == o_displ &&
        insn.ops[0].addr == 0xd0) {
      found = true;
      efi_utils::log("found %sSmiHandler\n", prefix.c_str());
      break;
    }
    // interface is a local variable
    if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
        insn.ops[0].reg == R_R8 && insn.ops[1].type == o_displ &&
        (insn.ops[1].reg == R_RBP || insn.ops[1].reg == R_RSP)) {
      if (dispatch_interface == BADADDR) {
        dispatch_interface = insn.ops[1].addr;
      }
    }
    // interface is a global variable
    if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
        insn.ops[0].reg == R_R8 && insn.ops[1].type == o_mem) {
      if (dispatch_interface == BADADDR) {
        dispatch_interface = insn.ops[1].addr;
      }
    }
  }

  if (!found) {
    return smi_handlers;
  }

  if (dispatch_interface == BADADDR) {
    ea = address;
    while (!is_basic_block_end(insn, false)) {
      ea = prev_head(ea, 0);
      decode_insn(&insn, ea);
      // interface is local variable
      if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
          insn.ops[0].reg == R_R8 && insn.ops[1].type == o_displ &&
          (insn.ops[1].reg == R_RBP || insn.ops[1].reg == R_RSP)) {
        dispatch_interface = insn.ops[1].addr;
        break;
      }
      // interface is global variable
      if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
          insn.ops[0].reg == R_R8 && insn.ops[1].type == o_mem) {
        dispatch_interface = insn.ops[1].addr;
        break;
      }
    }
  }

  if (dispatch_interface == BADADDR) {
    return smi_handlers;
  }

  efi_utils::log("found SMM %sDispatch protocol interface at: 0x%" PRIx64 "\n",
                 prefix.c_str(), dispatch_interface);

  // TODO(yeggor): handle xrefs for globals
  // (fw71.bin.out/SmmHddSecurity-316b1230-0500-4592-8c09-eaba0fb6b07f.smm)

  // track interface stack variable
  ea = address;
  uint16_t reg = NONE_REG;
  uint64_t dispatch_func = BADADDR;
  for (auto i = 0; i < 100; i++) {
    ea = next_head(ea, BADADDR);
    decode_insn(&insn, ea);
    // get interface base register
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
      efi_utils::log("Register(): 0x%" PRIx64 ", %sSmiHandler: 0x%" PRIx64 "\n",
                     u64_addr(ea), prefix.c_str(), dispatch_func);
      auto handler_func = get_func(dispatch_func);
      if (handler_func == nullptr) {
        add_func(dispatch_func);                // create function
        handler_func = get_func(dispatch_func); // retry
      }
      if (handler_func != nullptr) {
        smi_handlers.push_back(handler_func); // add in result
      }
      reg = NONE_REG; // resetting

      // op_stroff + set_name
      auto name = prefix + "SmiHandler";
      efi_utils::set_type_and_name(dispatch_func, name.c_str(),
                                   "EFI_SMM_HANDLER_ENTRY_POINT2");

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

  return smi_handlers;
}

//--------------------------------------------------------------------------
// find {Prefix}SmiHandler function inside SMM drivers
//  - find GUID
//  - get xrefs to GUID
//  - xref will be inside RegSwSmi function
//  - find SmiHandler by pattern (instructions may be out of order)
//      lea     r9, ...
//      lea     r8, ...
//      lea     rdx, <func>
//      call    qword ptr [...]
func_list_t efi_smm_utils::find_smi_handlers_dispatch(efi_guid_t guid,
                                                      std::string prefix) {
  func_list_t smi_handlers;
  ea_set_t data_addrs =
      efi_utils::find_data(0, BADADDR, guid.uchar_data().data(), 16);
  for (const auto &data_addr : data_addrs) {
    ea_set_t xrefs = efi_utils::get_xrefs(data_addr);

    for (const auto &xref : xrefs) {
      auto res = efi_smm_utils::find_smi_handlers(xref, prefix);
      smi_handlers.insert(smi_handlers.end(), res.begin(), res.end());
    }
  }

  return smi_handlers;
}

//--------------------------------------------------------------------------
// find SwSmiHandler function inside SMM drivers in case where
// EFI_SMM_SW_DISPATCH{2}_PROTOCOL_GUID is a local variable
func_list_t
efi_smm_utils::find_smi_handlers_dispatch_stack(json_list_t stack_guids,
                                                std::string prefix) {
  func_list_t smi_handlers;

  for (auto guid : stack_guids) {
    std::string name = guid["name"];

    if (name != "EFI_SMM_SW_DISPATCH2_PROTOCOL_GUID" &&
        name != "EFI_SMM_SW_DISPATCH_PROTOCOL_GUID") {
      continue;
    }

    ea_t address = guid["address"];
    efi_utils::log(
        "found EFI_SMM_SW_DISPATCH{2}_PROTOCOL_GUID on stack: 0x%" PRIx64 "\n",
        u64_addr(address));
    auto res = efi_smm_utils::find_smi_handlers(address, prefix);
    smi_handlers.insert(smi_handlers.end(), res.begin(), res.end());
  }

  return smi_handlers;
}

//--------------------------------------------------------------------------
// Find gEfiSmmVariableProtocol->SmmGetVariable calls via
// EFI_SMM_VARIABLE_PROTOCOL_GUID
ea_set_t efi_smm_utils::find_smm_get_variable_calls(segment_list_t data_segs,
                                                    json_list_t *all_services) {
  ea_set_t smm_get_variable_calls;
  efi_guid_t guid = {0xed32d533,
                     0x99e6,
                     0x4209,
                     {0x9c, 0xc0, 0x2d, 0x72, 0xcd, 0xd9, 0x98,
                      0xa7}}; // EFI_SMM_VARIABLE_PROTOCOL_GUID

  // find all EFI_SMM_VARIABLE_PROTOCOL_GUID addresses
  ea_set_t data_addrs =
      efi_utils::find_data(0, BADADDR, guid.uchar_data().data(), 16);

  // find all gEfiSmmVariableProtocol variables
  ea_set_t smm_variable_addrs;
  for (auto data_addr : data_addrs) {
    ea_set_t xrefs = efi_utils::get_xrefs(data_addr);

    for (auto xref : xrefs) {
      segment_t *seg = getseg(xref);
      qstring seg_name;
      get_segm_name(&seg_name, seg);
      efi_utils::log("found EFI_SMM_VARIABLE_PROTOCOL_GUID xref at 0x%" PRIx64
                     "\n",
                     u64_addr(xref));

      size_t index = seg_name.find(".text");
      if (index == std::string::npos) {
        continue;
      }

      insn_t insn;
      ea_t ea = xref;
      for (auto i = 0; i < 8; i++) {
        // search for `lea r8, {gEfiSmmVariableProtocol}` instruction
        ea = prev_head(ea, 0);
        decode_insn(&insn, ea);
        if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
            insn.ops[0].reg == R_R8 && insn.ops[1].type == o_mem) {
          efi_utils::log("gEfiSmmVariableProtocol: 0x%" PRIx64 "\n",
                         u64_addr(insn.ops[1].addr));
          efi_utils::set_ptr_type_and_name(insn.ops[1].addr,
                                           "gEfiSmmVariableProtocol",
                                           "EFI_SMM_VARIABLE_PROTOCOL");
          smm_variable_addrs.insert(insn.ops[1].addr);
          break;
        }
      }
    }
  }

  if (!smm_variable_addrs.size()) {
    return smm_get_variable_calls;
  }

  for (auto smm_variable_addr : smm_variable_addrs) {
    ea_set_t smm_variable_xrefs = efi_utils::get_xrefs(smm_variable_addr);
    for (auto smm_variable_xref : smm_variable_xrefs) {
      segment_t *seg = getseg(smm_variable_xref);
      qstring seg_name;
      get_segm_name(&seg_name, seg);
      efi_utils::log("found gEfiSmmVariableProtocol xref at 0x%" PRIx64 "\n",
                     u64_addr(smm_variable_xref));

      size_t index = seg_name.find(".text");
      if (index == std::string::npos) {
        continue;
      }

      uint16 smm_variable_reg = NONE_REG;
      insn_t insn;
      ea_t ea = smm_variable_xref;
      decode_insn(&insn, ea);

      if (insn.itype == NN_mov && insn.ops[0].type == o_reg &&
          insn.ops[1].type == o_mem) {
        smm_variable_reg = insn.ops[0].reg;
        for (auto i = 0; i < 16; i++) {
          ea = next_head(ea, BADADDR);
          decode_insn(&insn, ea);

          if (insn.itype == NN_callni && smm_variable_reg == insn.ops[0].reg &&
              insn.ops[0].addr == 0) {
            if (find(smm_get_variable_calls.begin(),
                     smm_get_variable_calls.end(),
                     ea) == smm_get_variable_calls.end()) {
              smm_get_variable_calls.insert(ea);
            }

            efi_utils::op_stroff(ea, "EFI_SMM_VARIABLE_PROTOCOL");
            efi_utils::log("found SmmGetVariable call at 0x%" PRIx64 "\n",
                           u64_addr(ea));

            json s;
            s["address"] = ea;
            s["service_name"] = "gEfiSmmVariableProtocol->SmmGetVariable";
            s["table_name"] = "EFI_SMM_VARIABLE_PROTOCOL";
            s["offset"] = 0;

            if (!efi_utils::json_in_vec(*all_services, s)) {
              all_services->push_back(s);
            }

            break;
          }
        }
      }
    }
  }
  return smm_get_variable_calls;
}

ea_set_t
efi_smm_utils::resolve_efi_smm_cpu_protocol(json_list_t stack_guids,
                                            json_list_t data_guids,
                                            json_list_t *all_services) {
  ea_set_t read_save_state_calls;
  ea_set_t code_addrs;
  ea_set_t smm_cpu_addrs;
  for (auto guid : stack_guids) {
    if (guid["name"] != "EFI_SMM_CPU_PROTOCOL_GUID")
      continue;
    ea_t address = guid["address"];
    efi_utils::log("found EFI_SMM_CPU_PROTOCOL on stack at 0x%" PRIx64 "\n",
                   u64_addr(address));
    code_addrs.insert(address);
  }

  for (auto guid : data_guids) {
    if (guid["name"] != "EFI_SMM_CPU_PROTOCOL_GUID")
      continue;

    ea_t address = guid["address"];
    efi_utils::log("found EFI_SMM_CPU_PROTOCOL at 0x%" PRIx64 "\n",
                   u64_addr(address));
    ea_set_t guid_xrefs = efi_utils::get_xrefs(address);

    for (auto guid_xref : guid_xrefs) {
      segment_t *seg = getseg(guid_xref);
      qstring seg_name;
      get_segm_name(&seg_name, seg);
      size_t index = seg_name.find(".text");
      if (index == std::string::npos) {
        continue;
      }
      code_addrs.insert(guid_xref);
    }
  }

  for (auto addr : code_addrs) {
    insn_t insn;
    ea_t ea = prev_head(addr, 0);

    for (auto i = 0; i < 8; i++) {
      // find 'lea r8, {gEfiSmmCpuProtocol}' instruction
      decode_insn(&insn, ea);
      if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
          insn.ops[0].reg == R_R8 && insn.ops[1].type == o_mem) {
        efi_utils::log("gEfiSmmCpuProtocol: 0x%" PRIx64 "\n",
                       u64_addr(insn.ops[1].addr));
        efi_utils::set_ptr_type_and_name(insn.ops[1].addr, "gEfiSmmCpuProtocol",
                                         "EFI_SMM_CPU_PROTOCOL");
        smm_cpu_addrs.insert(insn.ops[1].addr);
        break;
      }
      ea = prev_head(ea, 0);
    }
  }

  if (smm_cpu_addrs.empty()) {
    return read_save_state_calls;
  }

  for (auto smm_cpu_addr : smm_cpu_addrs) {
    ea_set_t smm_cpu_xrefs = efi_utils::get_xrefs(smm_cpu_addr);

    for (auto smm_cpu_xref : smm_cpu_xrefs) {
      segment_t *seg = getseg(smm_cpu_xref);
      qstring seg_name;
      get_segm_name(&seg_name, seg);
      size_t index = seg_name.find(".text");

      if (index == std::string::npos) {
        continue;
      }

      uint16_t smm_cpu_reg = NONE_REG;
      insn_t insn;
      ea_t ea = smm_cpu_xref;
      decode_insn(&insn, ea);

      if (insn.itype == NN_mov && insn.ops[0].type == o_reg &&
          insn.ops[1].type == o_mem) {
        smm_cpu_reg = insn.ops[0].reg;

        for (auto i = 0; i < 16; i++) {
          ea = next_head(ea, BADADDR);
          decode_insn(&insn, ea);

          if (insn.itype == NN_callni && smm_cpu_reg == insn.ops[0].reg &&
              insn.ops[0].addr == 0) {
            if (find(read_save_state_calls.begin(), read_save_state_calls.end(),
                     ea) == read_save_state_calls.end()) {
              read_save_state_calls.insert(ea);
            }

            efi_utils::op_stroff(ea, "EFI_SMM_CPU_PROTOCOL");
            efi_utils::log("gEfiSmmCpuProtocol->ReadSaveState: 0x%" PRIx64 "\n",
                           u64_addr(ea));

            json s;
            s["address"] = ea;
            s["service_name"] = "gEfiSmmCpuProtocol->ReadSaveState";
            s["table_name"] = "EFI_SMM_CPU_PROTOCOL";
            s["offset"] = 0;

            if (!efi_utils::json_in_vec(*all_services, s)) {
              all_services->push_back(s);
            }

            break;
          }
        }
      }
    }
  }
  return read_save_state_calls;
}

ea_t efi_smm_utils::mark_child_sw_smi_handlers(ea_t ea) {
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
      efi_utils::set_type_and_name(insn.ops[1].addr, "ChildSwSmiHandler",
                                   "EFI_SMM_HANDLER_ENTRY_POINT2");
      return insn.ops[1].addr;
    }
  }
  return BADADDR;
}
