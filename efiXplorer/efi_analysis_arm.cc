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

#include "efi_analysis.h"
#include "efi_global.h"
#include "efi_ui.h"
#include "efi_utils.h"

ea_list_t image_handle_list_arm;
ea_list_t st_list_arm;
ea_list_t bs_list_arm;
ea_list_t rt_list_arm;

void efi_analysis::efi_analyser_arm_t::fix_offsets() {
  insn_t insn;
  for (auto faddr : m_funcs) {
    func_t *f = get_func(faddr);
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

void efi_analysis::efi_analyser_arm_t::initial_analysis() {
  fix_offsets();
  for (auto idx = 0; idx < get_entry_qty(); idx++) {
    uval_t ord = get_entry_ordinal(idx);
    ea_t ep = get_entry(ord);
    set_name(ep, "_ModuleEntryPoint", SN_FORCE);
#ifdef HEX_RAYS
    efi_hexrays::track_entry_params(get_func(ep), 0);
#endif /* HEX_RAYS */
  }
  if (m_ftype == ffs_file_type_t::pei) {
    // efi_utils::set_entry_arg_to_pei_svc();
  }
}

ea_t get_table_addr(ea_t code_addr, uint64_t offset) {
  ea_t table = BADADDR;
  insn_t insn;
  decode_insn(&insn, code_addr);
  if (insn.itype != ARM_ldr || insn.ops[0].type != o_reg ||
      insn.ops[1].type != o_displ || insn.ops[1].addr != offset ||
      insn.ops[1].reg == R_XSP) {
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
    ea_t base = BADADDR;
    uint8_t reg = 0xff;
    if (insn.itype == ARM_adrp && insn.ops[0].type == o_reg &&
        insn.ops[1].type == o_imm) {
      // Example:
      // LDR   X8, [X1,#0x58]
      // ADRP  X9, #gRT@PAGE <- we are here
      // ...
      // STR   X8, [X9,#gRT@PAGEOFF]

      base = insn.ops[1].value;
      reg = insn.ops[0].reg;
      ea_t current_addr = ea;
      while (true) {
        current_addr = next_head(current_addr, BADADDR);
        decode_insn(&insn, current_addr);
        if (insn.itype == ARM_str && insn.ops[0].type == o_reg &&
            insn.ops[0].reg == table_reg && insn.ops[1].type == o_displ &&
            insn.ops[1].reg == reg) {
          return base + insn.ops[1].addr;
        }
        if (is_basic_block_end(insn, false)) {
          break;
        }
      }
    }
    if (is_basic_block_end(insn, false)) {
      break;
    }
  }
  return table;
}

json get_service(ea_t addr, uint8_t table_id) {
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
      if (blr_reg != 0xff && service_offset != BADADDR &&
          insn.itype == ARM_blr && insn.ops[0].type == o_reg &&
          insn.ops[0].reg == blr_reg) {
        s["address"] = ea;
        if (table_id == 1) {
          s["service_name"] =
              efi_utils::lookup_boot_service_name(service_offset);
          s["table_name"] = "EFI_BOOT_SERVICES";
        } else if (table_id == 2) {
          s["service_name"] =
              efi_utils::lookup_runtime_service_name(service_offset);
          s["table_name"] = "EFI_RUNTIME_SERVICES";
        } else {
          s["table_name"] = "Unknown";
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
  if (insn.itype == ARM_adr && insn.ops[0].type == o_reg &&
      insn.ops[1].type == o_imm) {
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
          s["service_name"] =
              efi_utils::lookup_boot_service_name(insn.ops[1].addr);
          s["table_name"] = "EFI_BOOT_SERVICES";
        } else if (table_id == 2) {
          s["service_name"] =
              efi_utils::lookup_runtime_service_name(insn.ops[1].addr);
          s["table_name"] = "EFI_RUNTIME_SERVICES";
        } else {
          s["table_name"] = "Unknown";
        }
        return s;
      }
    }
  }

  return s;
}

void efi_analysis::efi_analyser_arm_t::initial_gvars_detection() {
#ifdef HEX_RAYS
  // analyse entry point with Hex-Rays
  for (auto func_addr : m_funcs) {
    json res = efi_hexrays::detect_vars(get_func(func_addr));
    if (res.contains("image_handle_list")) {
      for (auto addr : res["image_handle_list"]) {
        if (!efi_utils::addr_in_vec(image_handle_list_arm, addr)) {
          image_handle_list_arm.push_back(addr);
        }
      }
    }
    if (res.contains("st_list")) {
      for (auto addr : res["st_list"]) {
        if (!efi_utils::addr_in_vec(st_list_arm, addr)) {
          st_list_arm.push_back(addr);
        }
      }
    }
    if (res.contains("bs_list")) {
      for (auto addr : res["bs_list"]) {
        if (!efi_utils::addr_in_vec(bs_list_arm, addr)) {
          bs_list_arm.push_back(addr);
        }
      }
    }
    if (res.contains("rt_list")) {
      for (auto addr : res["rt_list"]) {
        if (!efi_utils::addr_in_vec(rt_list_arm, addr)) {
          rt_list_arm.push_back(addr);
        }
      }
    }
  }
#endif /* HEX_RAYS */

  // analysis of all functions and search for additional table initialisations
  for (auto func_addr : m_funcs) {
    func_t *f = get_func(func_addr);
    if (f == nullptr) {
      continue;
    }
    auto ea = f->start_ea;
    while (ea < f->end_ea) {
      ea = next_head(ea, BADADDR);
      ea_t bs = get_table_addr(ea, 0x60);
      if (bs != BADADDR) {
        efi_utils::log("gBS: 0x%" PRIx64 "\n", u64_addr(ea));
        efi_utils::set_ptr_type_and_name(bs, "gBS", "EFI_BOOT_SERVICES");
        if (!efi_utils::addr_in_vec(bs_list_arm, bs)) {
          bs_list_arm.push_back(bs);
        }
        continue;
      }
      ea_t rt = get_table_addr(ea, 0x58);
      if (rt != BADADDR) {
        efi_utils::log("gRT: 0x%" PRIx64 "\n", u64_addr(ea));
        efi_utils::set_ptr_type_and_name(rt, "gRT", "EFI_RUNTIME_SERVICES");
        if (!efi_utils::addr_in_vec(rt_list_arm, rt)) {
          rt_list_arm.push_back(rt);
        }
        continue;
      }
    }
  }
}

void efi_analysis::efi_analyser_arm_t::detect_services_all() {
#ifdef HEX_RAYS
  for (auto func_addr : m_funcs) {
    json_list_t services = efi_hexrays::detect_services(get_func(func_addr));
    for (auto service : services) {
      m_all_services.push_back(service);
    }
  }
#endif /* HEX_RAYS */

  // analyse xrefs to gBS, gRT
  for (auto bs : bs_list_arm) {
    auto xrefs = efi_utils::get_xrefs(bs);
    for (auto ea : xrefs) {
      auto s = get_service(ea, 1);
      if (!s.contains("address")) {
        continue;
      }
      std::string name = s["service_name"];
      if (name == "Unknown") {
        continue;
      }
      if (!efi_utils::json_in_vec(m_all_services, s)) {
        efi_utils::log("found new boot service at 0x%" PRIx64 "\n",
                       u64_addr(ea));
        m_all_services.push_back(s);
      }
    }
  }
  for (auto rt : rt_list_arm) {
    auto xrefs = efi_utils::get_xrefs(rt);
    for (auto ea : xrefs) {
      auto s = get_service(ea, 2);
      if (!s.contains("address")) {
        continue;
      }
      std::string name = s["service_name"];
      if (name == "Unknown") {
        continue;
      }
      if (!efi_utils::json_in_vec(m_all_services, s)) {
        efi_utils::log("found new runtime service at 0x%" PRIx64 "\n",
                       u64_addr(ea));
        m_all_services.push_back(s);
      }
    }
  }
}

bool efi_analysis::efi_analyser_arm_t::get_protocol(ea_t address,
                                                    uint32_t p_reg,
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
  efi_utils::log("found new protocol at 0x%" PRIx64 "\n", u64_addr(code_addr));
  return add_protocol(service_name, guid_addr, code_addr, address);
}

void efi_analysis::efi_analyser_arm_t::detect_protocols_all() {
  for (auto s : m_all_services) {
    std::string service_name = s["service_name"];
    for (auto i = 0; i < g_boot_services_table_aarch64_count; i++) {
      std::string current_name =
          static_cast<std::string>(g_boot_services_table_aarch64[i].name);
      if (current_name != service_name) {
        continue;
      }
      get_protocol(s["address"], g_boot_services_table_aarch64[i].reg,
                   service_name);
      break;
    }
  }
}

void efi_analysis::efi_analyser_arm_t::find_pei_services_function() {
  insn_t insn;
  for (auto start_ea : m_funcs) {
    decode_insn(&insn, start_ea);
    if (!(insn.itype == ARM_mrs && insn.ops[0].type == o_reg &&
          insn.ops[0].reg == R_X0 && insn.ops[1].type == o_imm &&
          insn.ops[1].value == 0x3 && insn.ops[2].type == o_idpspec3 &&
          insn.ops[2].reg == R_C13 && insn.ops[3].type == o_idpspec3 &&
          insn.ops[3].reg == R_C0 && insn.ops[4].type == o_imm &&
          insn.ops[4].value == 0x2)) {
      continue;
    }
    auto end_ea = next_head(start_ea, BADADDR);
    if (end_ea == BADADDR) {
      continue;
    }
    decode_insn(&insn, end_ea);
    if (insn.itype == ARM_ret) {
      efi_utils::log("found GetPeiServices() function at 0x%" PRIx64 "\n",
                     u64_addr(start_ea));
      set_name(start_ea, "GetPeiServices", SN_FORCE);
      efi_utils::set_ret_to_pei_svc(start_ea);
    }
  }
}

//--------------------------------------------------------------------------
// show all non-empty choosers windows (services, protocols, etc)
void efi_analysis::efi_analyser_arm_t::show_all_choosers() {
  qstring title;

  // open window with all services
  if (m_all_services.size()) {
    title = "efiXplorer: services";
    show_services(m_all_services, title);
  }

  // open window with data guids
  if (m_all_guids.size()) {
    qstring title = "efiXplorer: GUIDs";
    show_guids(m_all_guids, title);
  }

  // open window with protocols
  if (m_all_protocols.size()) {
    title = "efiXplorer: protocols";
    show_protocols(m_all_protocols, title);
  }
}

//--------------------------------------------------------------------------
// main function for AARCH64 modules
bool efi_analysis::efi_analyse_main_aarch64() {
  show_wait_box("HIDECANCEL\nAnalysing module(s) with efiXplorer...");

  efi_analysis::efi_analyser_arm_t analyser;

  while (!auto_is_ok()) {
    auto_wait();
  }

  // find .text and .data segments
  analyser.get_segments();

  // mark GUIDs
  analyser.annotate_data_guids();

  if (g_args.disable_ui) {
    analyser.m_ftype = g_args.module_type == module_type_t::pei
                           ? analyser.m_ftype = ffs_file_type_t::pei
                           : analyser.m_ftype = ffs_file_type_t::dxe_smm;
  } else {
    analyser.m_ftype = efi_utils::ask_file_type(&analyser.m_all_guids);
  }

  if (analyser.m_ftype == ffs_file_type_t::pei) {
    efi_utils::log("input file is PEI module\n");
  }

  // set the correct name for the entry point and automatically fix the
  // prototype
  analyser.initial_analysis();

  if (analyser.m_ftype == ffs_file_type_t::dxe_smm) {
    analyser.initial_gvars_detection();

    // detect services
    analyser.detect_services_all();

    // detect protocols
    analyser.detect_protocols_all();
  } else if (analyser.m_ftype == ffs_file_type_t::pei) {
    analyser.find_pei_services_function();
  }

#ifdef HEX_RAYS
  for (auto addr : analyser.m_funcs) {
    json_list_t services = efi_hexrays::detect_pei_services_arm(get_func(addr));
    for (auto service : services) {
      analyser.m_all_services.push_back(service);
    }
  }
  efi_hexrays::apply_all_types_for_interfaces(analyser.m_all_protocols);
#endif /* HEX_RAYS */

  analyser.show_all_choosers();
  analyser.dump_json();

  hide_wait_box();

  return true;
}
