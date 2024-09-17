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

#include "efi_analyser.h"
#include "efi_global.h"
#include "efi_ui.h"
#include "efi_utils.h"

#ifdef HEX_RAYS
#include "efi_hexrays.h"
#endif

using efi_analysis::efi_analyser_t;
using efi_analysis::efi_analyser_x86_t;

extern ea_list_t g_get_smst_location_calls;
extern ea_list_t g_smm_get_variable_calls;
extern ea_list_t g_smm_set_variable_calls;

ea_list_t st_list;               // gST list (system table addresses)
ea_list_t ps_list;               // gPS list (PEI services addresses)
ea_list_t bs_list;               // gBS list (boot services addresses)
ea_list_t rt_list;               // gRT list (runtime services addresses)
ea_list_t smst_list;             // gSmst list (SMM system table addresses)
ea_list_t image_handle_list;     // gImageHandle list (image handle addresses)
ea_list_t runtime_services_list; // runtime services list

json_list_t stackGuids;
json_list_t dataGuids;

// all .text and .data segments for compatibility with the efiLoader
segment_list_t textSegments;
segment_list_t dataSegments;

// for smm callouts finding
ea_list_t calloutAddrs;
func_list_t excFunctions;
func_list_t childSmiHandlers;
ea_list_t readSaveStateCalls;

// for GetVariable stack overflow finding
ea_list_t peiGetVariableOverflow;
ea_list_t getVariableOverflow;
ea_list_t smmGetVariableOverflow;

efi_analysis::efi_analyser_t::efi_analyser_t() {
  // 32-bit, 64-bit, ARM or UEFI (in loader instance)
  m_arch = input_file_type();

  // get guids.json path
  m_guids_json_path /= get_guids_json_file();

  func_t *start_func = nullptr;
  func_t *end_func = nullptr;

  // get start address for scan
  start_func = getn_func(0);
  if (start_func) {
    m_start_addr = start_func->start_ea;
  }

  // get end address for scan
  end_func = getn_func(get_func_qty() - 1);
  if (end_func) {
    m_end_addr = end_func->end_ea;
  }

  // save all m_funcs
  for (auto i = 0; i < get_func_qty(); i++) {
    auto func = getn_func(i);
    m_funcs.push_back(func->start_ea);
  }

  ea_list_t addrs;
  for (auto service : m_prot_bs_names) {
    m_boot_services[service] = addrs;
  }

  for (auto service : m_prot_smms_names) {
    m_smm_services[service] = addrs;
  }

  try {
    // load protocols from guids.json file
    std::ifstream in(m_guids_json_path);
    in >> m_guiddb;
  } catch (std::exception &e) {
    m_guiddb.clear();
    std::string msg_text = "guids.json file is invalid, check its contents";
    msg("[%s] %s\n", g_plugin_name, msg_text.c_str());
    warning("%s: %s\n", g_plugin_name, msg_text.c_str());
  }

  // get reverse dictionary
  for (auto g = m_guiddb.begin(); g != m_guiddb.end(); ++g) {
    m_guiddb_map[static_cast<json>(g.value())] =
        static_cast<std::string>(g.key());
  }
}

efi_analysis::efi_analyser_t::~efi_analyser_t() {
  m_funcs.clear();

  st_list.clear();
  ps_list.clear();
  bs_list.clear();
  rt_list.clear();
  smst_list.clear();
  image_handle_list.clear();
  runtime_services_list.clear();

  stackGuids.clear();
  dataGuids.clear();

  textSegments.clear();
  dataSegments.clear();

  calloutAddrs.clear();
  excFunctions.clear();
  readSaveStateCalls.clear();
  m_smi_handlers.clear();
  childSmiHandlers.clear();

  peiGetVariableOverflow.clear();
  getVariableOverflow.clear();
  smmGetVariableOverflow.clear();

  g_get_smst_location_calls.clear();
  g_smm_get_variable_calls.clear();
  g_smm_set_variable_calls.clear();

#ifdef HEX_RAYS
  clear_cached_cfuncs();
#endif
}

void efi_analysis::efi_analyser_t::set_pvalues() {
  if (m_ftype == ffs_file_type_t::dxe_smm) {
    m_pname = "protocols";
    m_pkey = "prot_name";
    m_ptable = &m_all_protocols;
  } else if (m_ftype == ffs_file_type_t::pei) {
    m_pname = "ppis";
    m_pkey = "ppi_name";
    m_ptable = &m_all_ppis;
  }
}

//--------------------------------------------------------------------------
// Get all .text and .data segments
void efi_analysis::efi_analyser_t::get_segments() {
  for (segment_t *s = get_first_seg(); s != nullptr;
       s = get_next_seg(s->start_ea)) {
    qstring seg_name;
    get_segm_name(&seg_name, s);

    string_list_t codeSegNames{".text",
                               ".code"}; // for compatibility with ida-efitools2
    for (auto name : codeSegNames) {
      auto index = seg_name.find(name.c_str());
      if (index != std::string::npos) {
        // fix permissions and class for code segment
        // in order for decompilation to work properly
        s->perm = (SEGPERM_READ | SEGPERM_WRITE | SEGPERM_EXEC);
        set_segm_class(s, "DATA");
        textSegments.push_back(s);
        continue;
      }
    }

    auto index = seg_name.find(".data");
    if (index != std::string::npos) {
      dataSegments.push_back(s);
      continue;
    }
  }

  // print all .text and .code segments addresses
  for (auto seg : textSegments) {
    segment_t *s = seg;
    msg("[%s] code segment: 0x%016llX\n", g_plugin_name, u64_addr(s->start_ea));
  }

  // print all .data segments addresses
  for (auto seg : dataSegments) {
    segment_t *s = seg;
    msg("[%s] data segment: 0x%016llX\n", g_plugin_name, u64_addr(s->start_ea));
  }
}

//--------------------------------------------------------------------------
// Find gImageHandle address for X64 modules
bool efi_analysis::efi_analyser_x86_t::find_image_handle64() {
  msg("[%s] gImageHandle finding\n", g_plugin_name);
  insn_t insn;
  for (int idx = 0; idx < get_entry_qty(); idx++) {
    // get address of entry point
    uval_t ord = get_entry_ordinal(idx);
    ea_t ea = get_entry(ord);

    // EFI_IMAGE_HANDLE finding, first 8 instructions checking
    for (auto i = 0; i < 8; i++) {
      decode_insn(&insn, ea);
      if (insn.itype == NN_mov && insn.ops[1].type == o_reg &&
          insn.ops[1].reg == REG_RCX && insn.ops[0].type == o_mem) {
        msg("[%s] found ImageHandle at 0x%016llX, address = 0x%016llX\n",
            g_plugin_name, u64_addr(ea), u64_addr(insn.ops[0].addr));

        // set type and name
        set_type_and_name(insn.ops[0].addr, "gImageHandle", "EFI_IMAGE_HANDLE");
        image_handle_list.push_back(insn.ops[0].addr);
        break;
      }
      ea = next_head(ea, m_end_addr);
    }
  }
  return true;
}

//--------------------------------------------------------------------------
// Find gST address for X64 modules
bool efi_analysis::efi_analyser_x86_t::find_system_table64() {
  msg("[%s] gEfiSystemTable finding\n", g_plugin_name);
  insn_t insn;
  for (int idx = 0; idx < get_entry_qty(); idx++) {
    // get address of entry point
    uval_t ord = get_entry_ordinal(idx);
    ea_t ea = get_entry(ord);

    // EFI_SYSTEM_TABLE finding, first 16 instructions checking
    for (int i = 0; i < 16; i++) {
      decode_insn(&insn, ea);
      if (insn.itype == NN_mov && insn.ops[1].type == o_reg &&
          insn.ops[1].reg == REG_RDX && insn.ops[0].type == o_mem) {
        set_ptr_type_and_name(insn.ops[0].addr, "gST", "EFI_SYSTEM_TABLE");
        st_list.push_back(insn.ops[0].addr);
        return true;
      }
      ea = next_head(ea, BADADDR);
    }
  }
  return false;
}

//--------------------------------------------------------------------------
// Find and mark gSmst global variable address for X64 module
bool efi_analysis::efi_analyser_x86_t::find_smst64() {
  msg("[%s] gSmst finding\n", g_plugin_name);
  ea_list_t smst_listSmmBase = findSmstSmmBase(bs_list);
  ea_list_t smst_listSwDispatch = findSmstSwDispatch(bs_list);
  smst_list.insert(smst_list.end(), smst_listSwDispatch.begin(),
                   smst_listSwDispatch.end());
  smst_list.insert(smst_list.end(), smst_listSmmBase.begin(),
                   smst_listSmmBase.end());

  // Deduplicate
  auto last = std::unique(smst_list.begin(), smst_list.end());
  smst_list.erase(last, smst_list.end());

  for (auto smst : smst_list) {
    msg("[%s] 0x%016llX: gSmst\n", g_plugin_name, u64_addr(smst));
  }
  return smst_list.size();
}

//--------------------------------------------------------------------------
// Find and mark gSmst global and local variable address for X64 module
// after Hex-Rays based analysis
bool efi_analysis::efi_analyser_x86_t::find_smst_postproc64() {
  for (auto ea : g_get_smst_location_calls) {
    msg("[%s] EfiSmmBase2Protocol->GetSmstLocation call: 0x%016llX\n",
        g_plugin_name, u64_addr(ea));
    insn_t insn;
    auto addr = ea;
    ea_t smst_addr = BADADDR;
    json smst_stack;
    while (true) {
      addr = prev_head(addr, 0);
      decode_insn(&insn, addr);

      if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
          insn.ops[0].reg == REG_RDX) {
        switch (insn.ops[1].type) {
        case o_displ:
          if (insn.ops[1].reg == REG_RSP || insn.ops[1].reg == REG_RBP) {
            smst_addr = insn.ops[1].addr;
            smst_stack["addr"] = smst_addr;
            smst_stack["reg"] = insn.ops[1].reg;
            smst_stack["start"] = next_head(ea, BADADDR);
            // get bounds
            func_t *f = get_func(addr);
            if (f == nullptr) {
              smst_stack["end"] = BADADDR;
            } else {
              smst_stack["end"] = f->end_ea;
            }
          }
          break;
        case o_mem:
          smst_addr = insn.ops[1].addr;
          break;
        }
      }

      // Exit loop if end of previous basic block found
      if (is_basic_block_end(insn, false)) {
        break;
      }
    }

    if (smst_stack.is_null() && smst_addr != BADADDR) {
      msg("[%s]   gSmst: 0x%016llX\n", g_plugin_name, u64_addr(smst_addr));
      if (!addr_in_vec(smst_list, smst_addr)) {
        set_ptr_type_and_name(smst_addr, "gSmst", "_EFI_SMM_SYSTEM_TABLE2");
        smst_list.push_back(smst_addr);
      }
    }

    if (!smst_stack.is_null()) {
      auto reg = smst_stack["reg"] == REG_RSP ? "RSP" : "RBP";
      msg("[%s]   Smst: 0x%016llX, reg = %s\n", g_plugin_name,
          u64_addr(smst_addr), reg);

      // try to extract ChildSwSmiHandler
      auto counter = 0;
      ea_t ea = static_cast<ea_t>(smst_stack["start"]);
      uint16_t smst_reg = BADREG;
      uint64_t rcx_last = BADADDR;
      while (ea < static_cast<ea_t>(smst_stack["end"])) {
        counter += 1;
        if (counter > 500) {
          break; // just in case
        }

        ea = next_head(ea, BADADDR);
        decode_insn(&insn, ea);

        if (insn.itype == NN_mov && insn.ops[0].type == o_reg &&
            insn.ops[1].type == o_displ &&
            smst_stack["addr"] == insn.ops[1].addr) {
          switch (insn.ops[1].reg) {
          case REG_RSP:
            if (smst_stack["reg"] == REG_RSP) {
              smst_reg = insn.ops[0].reg;
            }
            break;
          case REG_RBP:
            if (smst_stack["reg"] == REG_RBP) {
              smst_reg = insn.ops[0].reg;
            }
          default:
            break;
          }
        }

        // Save potencial ChildSwSmiHandler address
        if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
            insn.ops[0].reg == REG_RCX && insn.ops[1].type == o_mem) {
          rcx_last = insn.ops[1].addr;
        }

        if (rcx_last == BADADDR || smst_reg == BADREG) {
          continue;
        }

        if (insn.itype == NN_callni && insn.ops[0].type == o_displ &&
            insn.ops[0].reg == smst_reg &&
            insn.ops[0].addr == SmiHandlerRegisterOffset64) {
          op_stroff_util(ea, "_EFI_SMM_SYSTEM_TABLE2");
          // save child SW SMI handler
          func_t *handler_func = get_func(rcx_last);
          if (handler_func != nullptr) {
            childSmiHandlers.push_back(handler_func);
            set_name(rcx_last, "ChildSwSmiHandler", SN_FORCE);
            break;
          }
        }
      }
    }
  }

  return true;
}

//--------------------------------------------------------------------------
// Find gBS addresses for 32-bit/64-bit modules
bool efi_analysis::efi_analyser_x86_t::find_boot_services_tables() {
  // init architecture-specific constants
  auto BS_OFFSET = BS_OFFSET_64;
  uint16_t REG_SP = static_cast<uint16_t>(REG_RSP);

  if (m_arch == arch_file_type_t::x86_32) {
    BS_OFFSET = BS_OFFSET_32;
    REG_SP = static_cast<uint16_t>(REG_ESP);
  }

  insn_t insn;
  for (auto seg : textSegments) {
    segment_t *s = seg;
    msg("[%s] gEfiBootServices finding from 0x%016llX to 0x%016llX\n",
        g_plugin_name, u64_addr(s->start_ea), u64_addr(s->end_ea));
    ea_t ea = s->start_ea;
    uint16_t bsRegister = 0;
    uint16_t stRegister = 0;
    ea_t var_addr = BADADDR; // current global variable address
    while (ea <= s->end_ea) {
      ea = next_head(ea, m_end_addr);
      decode_insn(&insn, ea);
      if (insn.itype == NN_mov && insn.ops[1].type == o_displ &&
          insn.ops[1].phrase != REG_SP) {
        if (insn.ops[0].type == o_reg && insn.ops[1].addr == BS_OFFSET) {
          auto bsFound = false;
          auto stFound = false;
          ea_t baseInsnAddr = BADADDR;
          bsRegister = insn.ops[0].reg;
          stRegister = insn.ops[1].phrase;

          // found BS_OFFSET, need to check 10 instructions below
          for (auto i = 0; i < 10; i++) {
            ea = next_head(ea, m_end_addr);
            decode_insn(&insn, ea);
            if (insn.itype == NN_mov && insn.ops[0].type == o_reg &&
                insn.ops[1].type == o_imm) {
              var_addr = insn.ops[1].value;
              auto phrase_reg = insn.ops[0].phrase;
              auto next_ea = next_head(ea, BADADDR);
              insn_t next_insn;
              decode_insn(&next_insn, next_ea);
              if (next_insn.itype == NN_mov &&
                  next_insn.ops[0].type == o_phrase &&
                  next_insn.ops[0].phrase == phrase_reg &&
                  next_insn.ops[1].type == o_reg &&
                  next_insn.ops[1].reg == bsRegister) {
                baseInsnAddr = ea;
                if (!addr_in_vec(bs_list, var_addr)) {
                  set_ptr_type_and_name(var_addr, "gBS", "EFI_BOOT_SERVICES");
                  bs_list.push_back(var_addr);
                }
                bsFound = true;
              }
            }

            if (insn.itype == NN_mov && insn.ops[1].type == o_reg &&
                insn.ops[0].type == o_mem) {
              if (insn.ops[1].reg == bsRegister && !bsFound) {
                baseInsnAddr = ea;
                var_addr = insn.ops[0].addr;
                if (!addr_in_vec(bs_list, var_addr)) {
                  set_ptr_type_and_name(var_addr, "gBS", "EFI_BOOT_SERVICES");
                  bs_list.push_back(var_addr);
                }
                bsFound = true;
              }

              // here you can also find gST
              if (insn.ops[1].reg == stRegister && !stFound &&
                  stRegister != bsRegister) {
                var_addr = insn.ops[0].addr;
                if (!addr_in_tables(st_list, bs_list, rt_list, var_addr)) {
                  set_ptr_type_and_name(var_addr, "gST", "EFI_SYSTEM_TABLE");
                  st_list.push_back(var_addr);
                }
                stFound = true;
              }
            }

            if (bsFound && stFound) {
              break;
            }

            if (bsFound && !stFound) {
              // check 8 instructions above baseInsnAddr
              auto addr = baseInsnAddr;
              for (auto i = 0; i < 8; i++) {
                addr = prev_head(addr, m_start_addr);
                decode_insn(&insn, addr);
                if (insn.itype == NN_mov && insn.ops[1].type == o_reg &&
                    insn.ops[1].reg == stRegister &&
                    insn.ops[0].type == o_mem) {
                  var_addr = insn.ops[0].addr;
                  if (!addr_in_tables(st_list, bs_list, rt_list, var_addr)) {
                    set_ptr_type_and_name(var_addr, "gST", "EFI_SYSTEM_TABLE");
                    st_list.push_back(var_addr);
                  }
                  stFound = true;
                  break;
                }
              }
            }
          }
        }
      }
    }
  }
  return (bs_list.size() != 0);
}

//--------------------------------------------------------------------------
// Find gRT addresses for X86/X64 modules
bool efi_analysis::efi_analyser_x86_t::find_runtime_services_tables() {
  // init architecture-specific constants
  auto RT_OFFSET = RT_OFFSET_64;
  uint16_t REG_SP = static_cast<uint16_t>(REG_RSP);

  if (m_arch == arch_file_type_t::x86_32) {
    RT_OFFSET = RT_OFFSET_32;
    REG_SP = static_cast<uint16_t>(REG_ESP);
  }

  insn_t insn;
  for (auto seg : textSegments) {
    segment_t *s = seg;
    msg("[%s] gEfiRuntimeServices finding from 0x%016llX to 0x%016llX\n",
        g_plugin_name, u64_addr(s->start_ea), u64_addr(s->end_ea));
    ea_t ea = s->start_ea;
    uint16_t rtRegister = 0;
    uint16_t stRegister = 0;
    ea_t var_addr = BADADDR; // current global variable address
    while (ea <= s->end_ea) {
      ea = next_head(ea, m_end_addr);
      decode_insn(&insn, ea);
      if (insn.itype == NN_mov && insn.ops[1].type == o_displ &&
          insn.ops[1].phrase != REG_SP) {
        if (insn.ops[0].type == o_reg && insn.ops[1].addr == RT_OFFSET) {
          rtRegister = insn.ops[0].reg;
          stRegister = insn.ops[1].phrase;
          auto rtFound = false;
          auto stFound = false;
          ea_t baseInsnAddr;

          // found RT_OFFSET, need to check 10 instructions below
          for (auto i = 0; i < 10; i++) {
            ea = next_head(ea, m_end_addr);
            decode_insn(&insn, ea);
            if (insn.itype == NN_mov && insn.ops[0].type == o_reg &&
                insn.ops[1].type == o_imm) {
              var_addr = insn.ops[1].value;
              auto phrase_reg = insn.ops[0].phrase;
              auto next_ea = next_head(ea, BADADDR);
              insn_t next_insn;
              decode_insn(&next_insn, next_ea);
              if (next_insn.itype == NN_mov &&
                  next_insn.ops[0].type == o_phrase &&
                  next_insn.ops[0].phrase == phrase_reg &&
                  next_insn.ops[1].type == o_reg &&
                  next_insn.ops[1].reg == rtRegister) {
                baseInsnAddr = ea;
                if (!addr_in_vec(rt_list, var_addr)) {
                  set_ptr_type_and_name(var_addr, "gRT",
                                        "EFI_RUNTIME_SERVICES");
                  rt_list.push_back(var_addr);
                }
                rtFound = true;
              }
            }

            if (insn.itype == NN_mov && insn.ops[1].type == o_reg &&
                insn.ops[0].type == o_mem) {
              if (insn.ops[1].reg == rtRegister && !rtFound) {
                baseInsnAddr = ea;
                var_addr = insn.ops[0].addr;
                if (!addr_in_vec(rt_list, var_addr)) {
                  set_ptr_type_and_name(var_addr, "gRT",
                                        "EFI_RUNTIME_SERVICES");
                  rt_list.push_back(var_addr);
                }
                rtFound = true;
              }

              // here you can also find gST
              if (insn.ops[1].reg == stRegister && !stFound &&
                  stRegister != rtRegister) {
                var_addr = insn.ops[0].addr;
                if (!addr_in_tables(st_list, bs_list, rt_list, var_addr)) {
                  set_ptr_type_and_name(insn.ops[0].addr, "gST",
                                        "EFI_SYSTEM_TABLE");
                  st_list.push_back(insn.ops[0].addr);
                }
                stFound = true;
              }
            }

            if (rtFound && stFound) {
              break;
            }

            if (rtFound && !stFound) {
              // check 8 instructions above baseInsnAddr
              auto addr = baseInsnAddr;
              for (auto i = 0; i < 8; i++) {
                addr = prev_head(addr, m_start_addr);
                decode_insn(&insn, addr);
                if (insn.itype == NN_mov && insn.ops[1].type == o_reg &&
                    insn.ops[1].reg == stRegister &&
                    insn.ops[0].type == o_mem) {
                  if (!addr_in_tables(st_list, bs_list, rt_list, var_addr)) {
                    set_ptr_type_and_name(var_addr, "gST", "EFI_SYSTEM_TABLE");
                    st_list.push_back(var_addr);
                  }
                  stFound = true;
                  break;
                }
              }
            }
          }
        }
      }
    }
  }
  return (rt_list.size() != 0);
}

//--------------------------------------------------------------------------
// Get all boot services by xrefs for X86/X64 modules
void efi_analysis::efi_analyser_x86_t::get_boot_services_all() {
  msg("[%s] BootServices finding (xrefs)\n", g_plugin_name);

  if (!bs_list.size()) {
    return;
  }

  insn_t insn;
  for (auto bs : bs_list) {
    msg("[%s] BootServices finding by xrefs to gBS (0x%016llX)\n",
        g_plugin_name, u64_addr(bs));

    auto xrefs = get_xrefs_util(bs);
    for (auto ea : xrefs) {
      bool found = false;
      decode_insn(&insn, ea);

      if (!(insn.itype == NN_mov &&
            (insn.ops[1].addr == bs || insn.ops[1].value == bs))) {
        continue;
      }

      auto bs_reg = insn.ops[0].reg;

      // 16 instructions below
      auto addr = ea;
      ea_t service_offset = BADADDR;
      for (auto i = 0; i < 16; i++) {
        addr = next_head(addr, BADADDR);
        decode_insn(&insn, addr);

        if (insn.itype == NN_mov && insn.ops[1].type == o_displ &&
            insn.ops[1].reg == bs_reg && insn.ops[1].addr) {
          service_offset = insn.ops[1].addr;
        }

        if (insn.itype == NN_callni && insn.ops[0].reg == bs_reg) {
          if (insn.ops[0].addr) {
            service_offset = insn.ops[0].addr;
          }

          for (int j = 0; j < g_boot_services_table_all_count; j++) {
            // architecture-specific variables
            auto offset = g_boot_services_table_all[j].offset64;
            if (m_arch == arch_file_type_t::x86_32) {
              offset = g_boot_services_table_all[j].offset32;
            }

            if (service_offset == u32_addr(offset)) {
              // additional check for gBS->RegisterProtocolNotify
              // (can be confused with
              // gSmst->SmmInstallProtocolInterface)
              if (u32_addr(offset) == RegisterProtocolNotifyOffset64) {
                if (!check_boot_service_protocol(addr)) {
                  break;
                }
              }

              op_stroff_util(addr, "EFI_BOOT_SERVICES");

              msg("[%s] 0x%016llX : %s\n", g_plugin_name, u64_addr(addr),
                  static_cast<char *>(g_boot_services_table_all[j].name));
              m_boot_services[static_cast<std::string>(
                                  g_boot_services_table_all[j].name)]
                  .push_back(addr);

              // add item to allBootServices
              json bsItem;
              bsItem["address"] = addr;
              bsItem["service_name"] =
                  static_cast<std::string>(g_boot_services_table_all[j].name);
              bsItem["table_name"] =
                  static_cast<std::string>("EFI_BOOT_SERVICES");
              bsItem["offset"] = offset;

              // add code addresses for arguments
              eavec_t args;
              get_arg_addrs(&args, addr);
              bsItem["args"] = args;

              if (!json_in_vec(m_all_services, bsItem)) {
                m_all_services.push_back(bsItem);
              }

              found = true;
              break;
            }
          }
        }
        if (found) {
          break;
        }
      }
    }
  }
}

//--------------------------------------------------------------------------
// Get all runtime services for X86/X64 modules by xrefs
void efi_analysis::efi_analyser_x86_t::get_runtime_services_all() {
  msg("[%s] RuntimeServices finding (xrefs)\n", g_plugin_name);

  if (!rt_list.size()) {
    return;
  }

  insn_t insn;
  for (auto rt : rt_list) {
    auto xrefs = get_xrefs_util(rt);

    msg("[%s] RuntimeServices finding by xrefs to gRT (0x%016llX)\n",
        g_plugin_name, u64_addr(rt));

    for (auto ea : xrefs) {
      decode_insn(&insn, ea);

      if (!(insn.itype == NN_mov &&
            (insn.ops[1].addr == rt || insn.ops[1].value == rt))) {
        continue;
      }

      auto rt_reg = insn.ops[0].reg;

      // 16 instructions below
      ea_t addr = ea;
      ea_t service_offset = BADADDR;
      for (int i = 0; i < 16; i++) {
        addr = next_head(addr, BADADDR);
        decode_insn(&insn, addr);

        if (insn.itype == NN_mov && insn.ops[1].type == o_displ &&
            insn.ops[1].reg == rt_reg && insn.ops[1].addr) {
          service_offset = insn.ops[1].addr;
        }

        if (insn.itype == NN_callni && insn.ops[0].reg == rt_reg) {
          if (insn.ops[0].addr) {
            service_offset = insn.ops[0].addr;
          }

          for (int j = 0; j < g_runtime_services_table_all_count; j++) {
            // architecture-specific variables
            auto offset = g_runtime_services_table_all[j].offset64;
            if (m_arch == arch_file_type_t::x86_32) {
              offset = g_runtime_services_table_all[j].offset32;
            }
            if (service_offset == u32_addr(offset)) {
              op_stroff_util(addr, "EFI_RUNTIME_SERVICES");
              msg("[%s] 0x%016llX : %s\n", g_plugin_name, u64_addr(addr),
                  static_cast<char *>(g_runtime_services_table_all[j].name));
              m_runtime_services_all[static_cast<std::string>(
                                         g_runtime_services_table_all[j].name)]
                  .push_back(addr);

              // add item to allRuntimeServices
              json rtItem;
              rtItem["address"] = addr;
              rtItem["service_name"] = static_cast<std::string>(
                  g_runtime_services_table_all[j].name);
              rtItem["table_name"] =
                  static_cast<std::string>("EFI_RUNTIME_SERVICES");
              rtItem["offset"] = offset;

              // add code addresses for arguments
              eavec_t args;
              get_arg_addrs(&args, addr);
              rtItem["args"] = args;

              if (!json_in_vec(m_all_services, rtItem)) {
                m_all_services.push_back(rtItem);
              }
              runtime_services_list.push_back(addr);
              break;
            }
          }
        }
      }
    }
  }
}

//--------------------------------------------------------------------------
// Get all smm services for X64 modules
void efi_analysis::efi_analyser_x86_t::get_smm_services_all64() {
  msg("[%s] SmmServices finding (xrefs)\n", g_plugin_name);

  if (!smst_list.size()) {
    return;
  }

  insn_t insn;
  for (auto smms : smst_list) {
    auto xrefs = get_xrefs_util(smms);

    msg("[%s] SmmServices finding by xref to gSmst (0x%016llX)\n",
        g_plugin_name, u64_addr(smms));

    for (auto ea : xrefs) {
      decode_insn(&insn, ea);

      if (!(insn.itype == NN_mov && insn.ops[1].type == o_mem &&
            insn.ops[1].addr == smms)) {
        continue;
      }

      auto smst_reg = insn.ops[0].reg;

      // 10 instructions below
      auto addr = ea;
      for (auto i = 0; i < 10; i++) {
        addr = next_head(addr, BADADDR);
        decode_insn(&insn, addr);
        // Add NN_jmpni insn type to handle such cases
        // jmp qword ptr [r9+0D0h]
        if ((insn.itype == NN_callni || insn.itype == NN_jmpni) &&
            insn.ops[0].reg == smst_reg) {
          for (int j = 0; j < g_smm_services_table_all_count; j++) {
            if (insn.ops[0].addr ==
                u32_addr(g_smm_services_table_all[j].offset64)) {
              if (u32_addr(g_smm_services_table_all[j].offset64) ==
                  SmiHandlerRegisterOffset64) {
                // set name for Handler argument
                auto smiHandlerAddr = markChildSwSmiHandler(addr);
                // save SMI handler
                func_t *childSmiHandler = get_func(smiHandlerAddr);
                if (childSmiHandler != nullptr) {
                  childSmiHandlers.push_back(childSmiHandler);
                }
              }

              op_stroff_util(addr, "_EFI_SMM_SYSTEM_TABLE2");
              msg("[%s] 0x%016llX : %s\n", g_plugin_name, u64_addr(addr),
                  static_cast<char *>(g_smm_services_table_all[j].name));

              // add address to m_smm_services[...]
              if (find(m_prot_smms_names.begin(), m_prot_smms_names.end(),
                       g_smm_services_table_all[j].name) !=
                  m_prot_smms_names.end()) {
                m_smm_services[g_smm_services_table_all[j].name].push_back(
                    addr);
              }
              m_smm_services_all[static_cast<std::string>(
                                     g_smm_services_table_all[j].name)]
                  .push_back(addr);

              // add item to allSmmServices
              json smmsItem;
              smmsItem["address"] = addr;
              smmsItem["service_name"] =
                  static_cast<std::string>(g_smm_services_table_all[j].name);
              smmsItem["table_name"] =
                  static_cast<std::string>("_EFI_SMM_SYSTEM_TABLE2");
              smmsItem["offset"] = g_smm_services_table_all[j].offset64;

              // add code addresses for arguments
              eavec_t args;
              get_arg_addrs(&args, addr);
              smmsItem["args"] = args;

              if (!json_in_vec(m_all_services, smmsItem)) {
                m_all_services.push_back(smmsItem);
              }
              break;
            }
          }
        }
      }
    }
  }
}

//--------------------------------------------------------------------------
// Get all Pei services for X86 modules
// Currently should cover all PeiServices except EFI_PEI_COPY_MEM,
// EFI_PEI_SET_MEM, EFI_PEI_RESET2_SYSTEM, and "Future Installed Services"
// (EFI_PEI_FFS_FIND_BY_NAME, etc.)
void efi_analysis::efi_analyser_x86_t::get_pei_services_all32() {
  msg("[%s] PeiServices finding from 0x%016llX to 0x%016llX (all)\n",
      g_plugin_name, u64_addr(m_start_addr), u64_addr(m_end_addr));
  ea_t ea = m_start_addr;
  insn_t insn;
  auto found = false;
  while (ea <= m_end_addr) {
    ea = next_head(ea, BADADDR);
    decode_insn(&insn, ea);
    if (insn.itype == NN_callni &&
        (insn.ops[0].reg == REG_EAX || insn.ops[0].reg == REG_ECX ||
         insn.ops[0].reg == REG_EDX)) {
      for (int j = 0; j < g_pei_services_table32_count; j++) {
        if (insn.ops[0].addr == u32_addr(g_pei_services_table32[j].offset)) {
          bool found_src_reg = false;
          ea_t address = ea;
          insn_t aboveInst;
          uint16_t src_reg = 0xffff;

          // 15 instructions above
          for (auto j = 0; j < 15; j++) {
            address = prev_head(address, m_start_addr);
            decode_insn(&aboveInst, address);
            if (aboveInst.itype == NN_mov && aboveInst.ops[0].type == o_reg &&
                aboveInst.ops[0].reg == insn.ops[0].reg &&
                aboveInst.ops[1].type == o_phrase) {
              found_src_reg = true;
              src_reg = aboveInst.ops[1].reg;
            }
          }

          bool found_push = false;

          // 15 instructions above
          address = ea;
          for (auto j = 0; j < 15; j++) {
            address = prev_head(address, m_start_addr);
            decode_insn(&aboveInst, address);
            if (aboveInst.itype == NN_push) {
              if (aboveInst.ops[0].type == o_reg &&
                  aboveInst.ops[0].reg == src_reg) {
                found_push = true;
              }
              break;
            }
          }

          if (found_src_reg && found_push) {
            eavec_t args;
            get_arg_addrs(&args, ea);
            if (!args.size()) {
              // looks like a FP
              break;
            }
            op_stroff_util(ea, "EFI_PEI_SERVICES");
            msg("[%s] 0x%016llX : %s\n", g_plugin_name, u64_addr(ea),
                static_cast<char *>(g_pei_services_table32[j].name));
            m_pei_services_all[static_cast<std::string>(
                                   g_pei_services_table32[j].name)]
                .push_back(ea);
            json psItem;
            psItem["address"] = ea;
            psItem["service_name"] =
                static_cast<std::string>(g_pei_services_table32[j].name);
            psItem["table_name"] = static_cast<std::string>("EFI_PEI_SERVICES");
            psItem["offset"] = g_pei_services_table32[j].offset;

            // add code addresses for arguments
            psItem["args"] = args;

            if (!json_in_vec(m_all_services, psItem)) {
              m_all_services.push_back(psItem);
            }
          }
          break;
        }
      }
    }
  }
}

//--------------------------------------------------------------------------
// Get all EFI_PEI_READ_ONLY_VARIABLE2_PPI (GetVariable, NextVariableName)
void efi_analysis::efi_analyser_x86_t::get_variable_ppi_calls_all32() {
  msg("[%s] Variable PPI calls finding from 0x%016llX to 0x%016llX (all)\n",
      g_plugin_name, u64_addr(m_start_addr), u64_addr(m_end_addr));
  ea_t ea = m_start_addr;
  insn_t insn;
  auto found = false;
  while (ea <= m_end_addr) {
    ea = next_head(ea, BADADDR);
    decode_insn(&insn, ea);
    if (insn.itype == NN_callni && insn.ops[0].type == o_phrase) {
      for (int j = 0; j < g_variable_ppi_table_all_count; j++) {
        if (insn.ops[0].addr ==
            u32_addr(g_variable_ppi_table_all[j].offset32)) {
          uint16_t ppi_reg = insn.ops[0].reg;
          insn_t aboveInst;
          ea_t address = ea;
          bool found_push = false;

          for (auto j = 0; j < 15; j++) {
            address = prev_head(address, m_start_addr);
            decode_insn(&aboveInst, address);
            if (aboveInst.itype == NN_push) {
              if (aboveInst.ops[0].type == o_reg &&
                  aboveInst.ops[0].reg == ppi_reg) {
                found_push = true;
              }
              break;
            }
          }

          if (found_push) {
            op_stroff_util(ea, "EFI_PEI_READ_ONLY_VARIABLE2_PPI");
            msg("[%s] 0x%016llX : %s\n", g_plugin_name, u64_addr(ea),
                static_cast<char *>(g_variable_ppi_table_all[j].name));
            std::string ppi_call =
                "VariablePPI." +
                static_cast<std::string>(g_variable_ppi_table_all[j].name);
            m_ppi_calls_all[ppi_call].push_back(ea);

            // Injecting PPI call as service
            json ppiItem;
            ppiItem["address"] = ea;
            ppiItem["service_name"] = ppi_call;
            ppiItem["table_name"] =
                static_cast<std::string>("EFI_PEI_READ_ONLY_VARIABLE2_PPI");
            ppiItem["offset"] = g_variable_ppi_table_all[j].offset32;

            // add code addresses for arguments
            eavec_t args;
            get_arg_addrs(&args, ea);
            ppiItem["args"] = args;

            if (!json_in_vec(m_all_services, ppiItem)) {
              m_all_services.push_back(ppiItem);
            }
          }
          break;
        }
      }
    }
  }
}

//--------------------------------------------------------------------------
// Get PPI names for X86 PEI modules
void efi_analysis::efi_analyser_x86_t::get_ppi_names32() {
  msg("[%s] PPI finding (PEI services)\n", g_plugin_name);
  ea_t start = m_start_addr;
  segment_t *seg_info = get_segm_by_name(".text");
  if (seg_info != nullptr) {
    start = seg_info->start_ea;
  }
  for (int i = 0; i < g_pei_services_table32_count; i++) {
    if (g_pei_services_table32[i].push_number == PUSH_NONE ||
        !m_pei_services_all.contains(g_pei_services_table_all[i].name)) {
      continue;
    }

    ea_list_t addrs = m_pei_services_all[g_pei_services_table32[i].name];

    // for each PEI service
    for (auto ea : addrs) {
      ea_t address = ea;

      insn_t insn;
      ea_t guidCodeAddress = 0;
      ea_t guidDataAddress = 0;
      auto found = false;

      uint16_t pushCounter = 0;
      msg("[%s] looking for PPIs in the 0x%016llX area (push number: %d)\n",
          g_plugin_name, u64_addr(address),
          g_pei_services_table32[i].push_number);

      // Check current basic block
      while (true) {
        address = prev_head(address, m_start_addr);
        decode_insn(&insn, address);

        if (insn.itype == NN_push) {
          pushCounter += 1;
        }

        if (pushCounter == g_pei_services_table32[i].push_number &&
            insn.ops[0].type == o_imm &&
            (insn.ops[0].value & 0xffffffff) >= start &&
            insn.ops[0].value != BADADDR) { // found "push gGuid" insn
          guidCodeAddress = address;
          guidDataAddress = insn.ops[0].value & 0xffffffff;
          found = true;
          break;
        }

        // Exit loop if end of previous basic block found
        if (is_basic_block_end(insn, false)) {
          break;
        }
      }

      msg("[%s] GUID address: 0x%016llX\n", g_plugin_name,
          u64_addr(guidDataAddress));

      if (found) {
        msg("[%s] found PPI GUID parameter at 0x%016llX\n", g_plugin_name,
            u64_addr(guidCodeAddress));
        auto guid = get_guid_by_address(guidDataAddress);
        if (!valid_guid(guid)) {
          msg("[%s] Incorrect GUID at 0x%016llX\n", g_plugin_name,
              u64_addr(guidCodeAddress));
          continue;
        }

        // get PPI item
        json ppiItem;
        ppiItem["address"] = guidDataAddress;
        ppiItem["xref"] = guidCodeAddress;
        ppiItem["service"] = g_pei_services_table_all[i].name;
        ppiItem["guid"] = guid_to_string(guid);
        ppiItem["module"] = "Current";

        // find GUID name
        auto it = m_guiddb_map.find(guid);
        if (it != m_guiddb_map.end()) {
          std::string name = it->second;
          ppiItem["ppi_name"] = name;

          // check if item already exists
          if (!json_in_vec(m_all_ppis, ppiItem)) {
            m_all_ppis.push_back(ppiItem);
          }
          continue;
        }

        // proprietary PPI
        if (ppiItem["ppi_name"].is_null()) {
          ppiItem["ppi_name"] = "ProprietaryPpi";

          // check if item already exists
          if (!json_in_vec(m_all_ppis, ppiItem)) {
            m_all_ppis.push_back(ppiItem);
          }
          continue;
        }
      }
    }
  }
}

//--------------------------------------------------------------------------
// Get boot services by protocols for X64 modules
void efi_analysis::efi_analyser_x86_t::get_prot_boot_services64() {
  insn_t insn;
  for (auto s : textSegments) {
    msg("[%s] BootServices finding from 0x%016llX to 0x%016llX (protocols)\n",
        g_plugin_name, u64_addr(s->start_ea), u64_addr(s->end_ea));
    ea_t ea = s->start_ea;
    uint16_t bsRegister = 0;
    while (ea <= s->end_ea) {
      ea = next_head(ea, m_end_addr);
      decode_insn(&insn, ea);
      if (insn.itype != NN_callni || insn.ops[0].reg != REG_RAX) {
        continue;
      }
      for (auto i = 0; i < g_boot_services_table64_count; i++) {
        if (insn.ops[0].addr != u32_addr(g_boot_services_table64[i].offset)) {
          continue;
        }

        // additional check for gBS->RegisterProtocolNotify
        // (can be confused with gSmst->SmmInstallProtocolInterface)
        if (u32_addr(g_boot_services_table64[i].offset) ==
            RegisterProtocolNotifyOffset64) {
          if (!check_boot_service_protocol(ea)) {
            break;
          }
        }

        // check that address does not belong to the protocol interface
        // (gBS != gInterface)
        auto bs_addr = find_unknown_bs_var_64(ea);
        if (addr_in_vec(rt_list, bs_addr) ||
            !check_boot_service_protocol_xrefs(bs_addr)) {
          break;
        }

        op_stroff_util(ea, "EFI_BOOT_SERVICES");
        msg("[%s] 0x%016llX : %s\n", g_plugin_name, u64_addr(ea),
            static_cast<char *>(g_boot_services_table64[i].name));
        m_boot_services[static_cast<std::string>(
                            g_boot_services_table64[i].name)]
            .push_back(ea);

        // add item to allBootServices
        json bsItem;
        bsItem["address"] = ea;
        bsItem["service_name"] =
            static_cast<std::string>(g_boot_services_table64[i].name);
        bsItem["table_name"] = static_cast<std::string>("EFI_BOOT_SERVICES");
        bsItem["offset"] = g_boot_services_table64[i].offset;

        // add code addresses for arguments
        eavec_t args;
        get_arg_addrs(&args, ea);
        bsItem["args"] = args;

        if (!json_in_vec(m_all_services, bsItem)) {
          m_all_services.push_back(bsItem);
        }
        break;
      }
    }
  }
}

//--------------------------------------------------------------------------
// Get boot services by protocols for X86 modules
void efi_analysis::efi_analyser_x86_t::get_prot_boot_services32() {
  msg("[%s] BootServices finding from 0x%016llX to 0x%016llX (protocols)\n",
      g_plugin_name, u64_addr(m_start_addr), u64_addr(m_end_addr));
  ea_t ea = m_start_addr;
  insn_t insn;
  uint16_t bsRegister = 0;
  while (ea <= m_end_addr) {
    ea = next_head(ea, m_end_addr);
    decode_insn(&insn, ea);
    if (insn.itype == NN_callni && insn.ops[0].reg == REG_EAX) {
      for (auto i = 0; i < g_boot_services_table32_count; i++) {
        if (insn.ops[0].addr == u32_addr(g_boot_services_table32[i].offset)) {
          op_stroff_util(ea, "EFI_BOOT_SERVICES");
          msg("[%s] 0x%016llX : %s\n", g_plugin_name, u64_addr(ea),
              static_cast<char *>(g_boot_services_table32[i].name));
          m_boot_services[static_cast<std::string>(
                              g_boot_services_table32[i].name)]
              .push_back(ea);

          // add item to allBootServices
          json bsItem;
          bsItem["address"] = ea;
          bsItem["service_name"] =
              static_cast<std::string>(g_boot_services_table32[i].name);
          bsItem["table_name"] = static_cast<std::string>("EFI_BOOT_SERVICES");
          bsItem["offset"] = g_boot_services_table32[i].offset;

          // add code addresses for arguments
          eavec_t args;
          get_arg_addrs(&args, ea);
          bsItem["args"] = args;

          if (!json_in_vec(m_all_services, bsItem)) {
            m_all_services.push_back(bsItem);
          }
          break;
        }
      }
    }
  }
}

//--------------------------------------------------------------------------
// find other addresses of gBS variables for X86-64 modules
void efi_analysis::efi_analyser_x86_t::find_other_boot_services_tables64() {
  msg("[%s] find other addresses of gBS variables\n", g_plugin_name);
  for (auto s : m_all_services) {
    std::string table_name = s["table_name"];
    if (table_name.compare("EFI_BOOT_SERVICES")) {
      continue;
    }

    auto offset = u32_addr(s["offset"]);
    if (offset < 0xf0) {
      continue;
    }

    ea_t addr = static_cast<ea_t>(s["address"]);
    msg("[%s] current service: 0x%016llX\n", g_plugin_name, u64_addr(addr));
    ea_t addr_bs = find_unknown_bs_var_64(addr);

    if (addr_bs == BADADDR || addr_in_tables(bs_list, rt_list, addr_bs)) {
      continue;
    }

    msg("[%s] found BootServices table at 0x%016llX, address = 0x%016llX\n",
        g_plugin_name, u64_addr(addr), u64_addr(addr_bs));
    set_ptr_type_and_name(addr_bs, "gBS", "EFI_BOOT_SERVICES");
    bs_list.push_back(addr_bs);
  }
}

bool efi_analysis::efi_analyser_t::add_protocol(std::string service_name,
                                                ea_t guid_addr, ea_t xref_addr,
                                                ea_t call_addr) {
  if (m_arch != arch_file_type_t::uefi && guid_addr >= m_start_addr &&
      guid_addr <= m_end_addr) {
    msg("[%s] wrong service call detection: 0x%016llX\n", g_plugin_name,
        u64_addr(call_addr));
    return false; // filter FP
  }

  json protocol;
  auto guid = get_guid_by_address(guid_addr);
  protocol["address"] = guid_addr;
  protocol["xref"] = xref_addr;
  protocol["service"] = service_name;
  protocol["guid"] = guid_to_string(guid);
  protocol["ea"] = call_addr;

  qstring moduleName("Current");
  if (input_file_type() == arch_file_type_t::uefi) {
    moduleName = get_module_name_loader(call_addr);
  }
  protocol["module"] = static_cast<std::string>(moduleName.c_str());

  // find GUID name
  auto it = m_guiddb_map.find(guid);
  if (it != m_guiddb_map.end()) {
    std::string name = it->second;
    protocol["prot_name"] = name;
  } else {
    protocol["prot_name"] = "UNKNOWN_PROTOCOL_GUID";
    set_type_and_name(guid_addr, "UNKNOWN_PROTOCOL_GUID", "EFI_GUID");
  }
  if (!json_in_vec(m_all_protocols, protocol)) {
    m_all_protocols.push_back(protocol);
  }
  return true;
}

//--------------------------------------------------------------------------
// Extract protocols from InstallMultipleProtocolInterfaces service call
bool efi_analysis::efi_analyser_x86_t::
    install_multiple_prot_interfaces_analyser() {
  ea_list_t addrs = m_boot_services["InstallMultipleProtocolInterfaces"];
  std::map<ea_t, ea_t> stack_params;
  insn_t insn;

  for (auto ea : addrs) {
    ea_t address = ea;
    bool found = false;
    bool check_stack = true;
    ea_t handle_arg = BADADDR;
    stack_params.clear();

    // Check current basic block
    while (true) {
      address = prev_head(address, m_start_addr);
      decode_insn(&insn, address);

      if (!check_stack && found) {
        break; // installed only one protocol
      }

      // Exit loop if end of previous basic block found
      if (is_basic_block_end(insn, false)) {
        break;
      }

      // Get handle stack/data parameter
      if (handle_arg == BADADDR && insn.itype == NN_lea &&
          insn.ops[0].reg == REG_RCX) {
        switch (insn.ops[1].type) {
        case o_displ:
          if (insn.ops[1].reg == REG_RSP || insn.ops[1].reg == REG_RBP) {
            handle_arg = insn.ops[1].addr;
          }
          break;
        case o_mem:
          handle_arg = insn.ops[1].addr;
          break;
        }
      }

      // Exit from loop if found last argument
      if (insn.itype == NN_xor && insn.ops[0].reg == REG_R9 &&
          insn.ops[1].reg == REG_R9) {
        check_stack = false;
      }

      if (insn.itype == NN_and && insn.ops[0].type == o_displ &&
          (insn.ops[0].reg == REG_RSP || insn.ops[0].reg == REG_RBP) &&
          insn.ops[0].addr != handle_arg && insn.ops[1].type == o_imm &&
          insn.ops[1].value == 0) {
        check_stack = false;
        break;
      }

      if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
          insn.ops[1].type == o_mem) {
        switch (insn.ops[0].reg) {
        case REG_RDX:
        case REG_R9:
          add_protocol("InstallMultipleProtocolInterfaces", insn.ops[1].addr,
                       address, ea);
          found = true;
          break;
        case REG_RAX:
          stack_params.insert(std::make_pair(address, insn.ops[1].addr));
          break;
        }
      }
    }

    // Enumerate all stack params
    auto index = 0;
    for (auto const &param : stack_params) {
      if (index++ % 2) {
        add_protocol("InstallMultipleProtocolInterfaces", param.second,
                     param.first, ea);
      }
    }
  }

  return true;
}

//--------------------------------------------------------------------------
// Get boot services protocols names for X64 modules
void efi_analysis::efi_analyser_x86_t::get_bs_prot_names64() {
  if (!textSegments.size()) {
    return;
  }
  segment_t *s = textSegments.at(0);
  ea_t start = s->start_ea;
  msg("[%s] protocols finding (boot services, start address = 0x%016llX)\n",
      g_plugin_name, u64_addr(start));

  install_multiple_prot_interfaces_analyser();
  for (int i = 0; i < g_boot_services_table64_count; i++) {
    if (g_boot_services_table64[i].offset ==
        InstallMultipleProtocolInterfacesOffset64) {
      // Handle InstallMultipleProtocolInterfaces separately
      continue;
    }

    ea_list_t addrs = m_boot_services[g_boot_services_table64[i].name];
    for (auto ea : addrs) {
      ea_t address = ea;
      msg("[%s] looking for protocols in the 0x%016llX area\n", g_plugin_name,
          u64_addr(address));
      insn_t insn;
      ea_t guidCodeAddress = 0;
      ea_t guidDataAddress = 0;
      auto found = false;

      // check current basic block
      while (true) {
        address = prev_head(address, m_start_addr);
        decode_insn(&insn, address);

        // exit from loop if end of previous basic block found
        if (is_basic_block_end(insn, false)) {
          break;
        }

        if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
            insn.ops[0].reg == g_boot_services_table64[i].reg &&
            insn.ops[1].type == o_mem) {
          guidCodeAddress = address;
          guidDataAddress = insn.ops[1].addr;
          if (insn.ops[1].addr > start && insn.ops[1].addr != BADADDR) {
            found = true;
            break;
          }
        }

        if (insn.itype == NN_mov && insn.ops[0].type == o_reg &&
            insn.ops[0].reg == g_boot_services_table64[i].reg &&
            insn.ops[1].type == o_imm) {
          guidCodeAddress = address;
          guidDataAddress = insn.ops[1].value;
          if (insn.ops[1].value > start && insn.ops[1].value != BADADDR) {
            found = true;
            break;
          }
        }
      }

      if (found) {
        msg("[%s] get_bs_prot_names64: found protocol GUID parameter at "
            "0x%016llX\n",
            g_plugin_name, u64_addr(guidCodeAddress));
        auto guid = get_guid_by_address(guidDataAddress);
        if (!valid_guid(guid)) {
          msg("[%s] Incorrect GUID at 0x%016llX\n", g_plugin_name,
              u64_addr(guidCodeAddress));
          continue;
        }

        add_protocol(g_boot_services_table64[i].name, guidDataAddress,
                     guidCodeAddress, ea);
      }
    }
  }
}

//--------------------------------------------------------------------------
// Get boot services protocols names for X86 modules
void efi_analysis::efi_analyser_x86_t::get_bs_prot_names32() {
  msg("[%s] protocols finding (boot services)\n", g_plugin_name);
  ea_t start = m_start_addr;
  segment_t *seg_info = get_segm_by_name(".text");
  if (seg_info != nullptr) {
    start = seg_info->start_ea;
  }
  for (int i = 0; i < g_boot_services_table32_count; i++) {
    ea_list_t addrs = m_boot_services[g_boot_services_table32[i].name];

    // for each boot service
    for (auto ea : addrs) {
      ea_t address = ea;
      msg("[%s] looking for protocols in the 0x%016llX area\n", g_plugin_name,
          u64_addr(address));
      insn_t insn;
      ea_t guidCodeAddress = 0;
      ea_t guidDataAddress = 0;
      auto found = false;
      uint16_t pushNumber = g_boot_services_table32[i].push_number;

      // if service is not currently being processed
      if (pushNumber == PUSH_NONE) {
        break;
      }

      // check current basic block
      uint16_t pushCounter = 0;
      while (true) {
        address = prev_head(address, m_start_addr);
        decode_insn(&insn, address);

        // exit from loop if end of previous basic block found
        if (is_basic_block_end(insn, false)) {
          break;
        }

        if (insn.itype == NN_push) {
          pushCounter += 1;
          if (pushCounter > pushNumber) {
            break;
          }
          if (pushCounter == pushNumber) {
            guidCodeAddress = address;
            guidDataAddress = insn.ops[0].value;
            if (insn.ops[0].value > start && insn.ops[0].value != BADADDR) {
              found = true;
              break;
            }
          }
        }
      }

      if (found) {
        msg("[%s] get_bs_prot_names32: found protocol GUID parameter at "
            "0x%016llX\n",
            g_plugin_name, u64_addr(guidCodeAddress));
        auto guid = get_guid_by_address(guidDataAddress);
        if (!valid_guid(guid)) {
          msg("[%s] Incorrect GUID at 0x%016llX\n", g_plugin_name,
              u64_addr(guidCodeAddress));
          continue;
        }

        add_protocol(g_boot_services_table32[i].name, guidDataAddress,
                     guidCodeAddress, ea);
      }
    }
  }
}

//--------------------------------------------------------------------------
// Get smm services protocols names for X64 modules
void efi_analysis::efi_analyser_x86_t::get_smm_prot_names64() {
  if (!textSegments.size()) {
    return;
  }
  segment_t *s = textSegments.at(0);
  ea_t start = s->start_ea;
  msg("[%s] protocols finding (smm services, start address = 0x%016llX)\n",
      g_plugin_name, u64_addr(start));
  for (int i = 0; i < g_smm_services_prot64_count; i++) {
    auto addrs = m_smm_services[g_smm_services_prot64[i].name];

    // for each SMM service
    for (auto ea : addrs) {
      ea_t address = ea;
      msg("[%s] looking for protocols in the 0x%016llX area\n", g_plugin_name,
          u64_addr(address));
      insn_t insn;
      ea_t guidCodeAddress = 0;
      ea_t guidDataAddress = 0;
      auto found = false;

      // check current basic block
      while (true) {
        address = prev_head(address, m_start_addr);
        decode_insn(&insn, address);

        // exit from loop if end of previous basic block found
        if (is_basic_block_end(insn, false)) {
          break;
        }

        if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
            insn.ops[0].reg == g_smm_services_prot64[i].reg) {
          guidCodeAddress = address;
          guidDataAddress = insn.ops[1].addr;
          if (insn.ops[1].addr > start && insn.ops[1].addr != BADADDR) {
            found = true;
            break;
          }
        }
      }

      if (found) {
        msg("[%s] get_smm_prot_names64: found protocol GUID parameter at "
            "0x%016llX\n",
            g_plugin_name, u64_addr(guidCodeAddress));
        auto guid = get_guid_by_address(guidDataAddress);
        if (!valid_guid(guid)) {
          msg("[%s] Incorrect GUID at 0x%016llX\n", g_plugin_name,
              u64_addr(guidCodeAddress));
          continue;
        }

        add_protocol(g_smm_services_prot64[i].name, guidDataAddress,
                     guidCodeAddress, ea);
      }
    }
  }
}

//--------------------------------------------------------------------------
// Mark protocols
void efi_analysis::efi_analyser_t::mark_interfaces() {
  msg("[%s] %s marking\n", g_plugin_name, m_pname.c_str());
  for (auto ifItemIt = m_ptable->begin(); ifItemIt != m_ptable->end();
       ++ifItemIt) {
    json ifItem = *ifItemIt;
    ea_t address = static_cast<ea_t>(ifItem["address"]);

    // check if guid on this address already marked
    bool marked = false;
    for (auto markedAddress = m_marked_interfaces.begin();
         markedAddress != m_marked_interfaces.end(); ++markedAddress) {
      if (*markedAddress == address) {
        marked = true;
        break;
      }
    }

    if (!marked) {
      std::string svcName = static_cast<std::string>(ifItem[m_pkey]);
      set_name(address, svcName.c_str(), SN_FORCE);
      set_guid_type(address);
      std::string comment = "EFI_GUID " + svcName;
      m_marked_interfaces.push_back(address);
      msg("[%s] address: 0x%016llX, comment: %s\n", g_plugin_name,
          u64_addr(address), comment.c_str());
    }
  }
}

//--------------------------------------------------------------------------
// Mark GUIDs found in the .text and .data segment
void efi_analysis::efi_analyser_t::mark_data_guids() {
  ea_t ptrSize = inf_is_64bit() ? 8 : 4;
  auto guids_segments = textSegments;
  // find GUIDs in .text and .data segments
  // TODO(yeggor): scan only the areas between the beginning of the .text
  // segment and the first function address (?)
  guids_segments.insert(guids_segments.end(), dataSegments.begin(),
                        dataSegments.end());
  for (auto s : guids_segments) {
    msg("[%s] marking GUIDs from 0x%016llX to 0x%016llX\n", g_plugin_name,
        u64_addr(s->start_ea), u64_addr(s->end_ea));
    ea_t ea = s->start_ea;
    while (ea != BADADDR && ea <= s->end_ea - 15) {
      if (get_wide_dword(ea) == 0x00000000 ||
          get_wide_dword(ea) == 0xffffffff) {
        ea += 1;
        continue;
      }
      auto guid = get_guid_by_address(ea);

      // find GUID name
      auto it = m_guiddb_map.find(guid);
      if (it != m_guiddb_map.end()) {
        std::string guidName = it->second;
        set_name(ea, guidName.c_str(), SN_FORCE);
        set_guid_type(ea);

        // rename PPI
        if (guidName.length() > 9 &&
            guidName.rfind("_PPI_GUID") == guidName.length() - 9) {
          auto xrefs = get_xrefs_util(ea);
          for (auto addr : xrefs) {
            std::string ppiName =
                "g" + type_to_name(guidName.substr(0, guidName.length() - 5));
            ea_t ppiEa = addr - ptrSize;
            // check flags
            if (ptrSize == 8 && get_wide_dword(ppiEa + 4)) {
              // 4 high bytes must be 0
              continue;
            }
            uint64_t flags = static_cast<uint64_t>(get_wide_dword(ppiEa));
            if (!uint64_in_vec(m_ppi_flags, flags)) {
              continue;
            }
            msg("[%s] address: 0x%016llX, PPI: %s\n", g_plugin_name,
                u64_addr(ppiEa), ppiName.c_str());
            set_name(ppiEa, ppiName.c_str(), SN_FORCE);
          }
        }

        std::string comment = "EFI_GUID " + guidName;
        msg("[%s] address: 0x%016llX, comment: %s\n", g_plugin_name,
            u64_addr(ea), comment.c_str());

        json guid_item;
        guid_item["address"] = ea;
        guid_item["name"] = guidName;
        guid_item["guid"] = guid_to_string(guid);
        m_all_guids.push_back(guid_item);
        dataGuids.push_back(guid_item);
      }
      ea += 1;
    }
  }
}

//--------------------------------------------------------------------------
// Mark GUIDs found in local variables for X64 modules
void efi_analysis::efi_analyser_x86_t::mark_local_guids64() {
  for (auto seg : textSegments) {
    segment_t *s = seg;
    ea_t ea = s->start_ea;
    insn_t insn;
    insn_t insn_next;
    msg("[%s] local GUIDs finding from 0x%016llX to 0x%016llX\n", g_plugin_name,
        u64_addr(s->start_ea), u64_addr(s->end_ea));
    while (ea <= s->end_ea) {
      ea = next_head(ea, BADADDR);
      decode_insn(&insn, ea);

      // check if insn like mov dword ptr [...], data1
      if (!(insn.itype == NN_mov && insn.ops[0].type == o_displ &&
            insn.ops[1].type == o_imm)) {
        continue;
      }

      // get guid->Data1 value
      uint32_t data1 = u32_addr(insn.ops[1].value);
      if (data1 == 0x00000000 || data1 == 0xffffffff) {
        ea = next_head(ea, BADADDR);
        continue;
      }

      // check 4 insns
      bool exit = false;
      for (auto i = 0; i < 4; i++) {
        auto ea_next = next_head(ea, BADADDR);
        decode_insn(&insn_next, ea_next);
        // check if insn like mov dword ptr [...], data2
        if (insn_next.itype == NN_mov && insn_next.ops[0].type == o_displ &&
            insn_next.ops[1].type == o_imm) {
          // get guid->Data2 value
          uint16_t data2 = static_cast<uint16_t>(insn_next.ops[1].value);
          if (data2 == 0x0000 || data2 == 0xffff) {
            ea = next_head(ea, BADADDR);
            continue;
          }

          // found guid->Data1 and guid->Data2 values, try to get
          // guid name
          for (auto dbItem = m_guiddb.begin(); dbItem != m_guiddb.end();
               ++dbItem) {
            auto guid = dbItem.value();
            if (data1 == static_cast<uint32_t>(guid[0]) &&
                data2 == static_cast<uint16_t>(guid[1])) {
              // mark local GUID
              std::string comment = "EFI_GUID " + dbItem.key();
              msg("[%s] address: 0x%016llX, comment: %s\n", g_plugin_name,
                  u64_addr(ea), comment.c_str());

              json guid_item;
              guid_item["address"] = ea;
              guid_item["name"] = dbItem.key();
              guid_item["guid"] = guid_to_string(guid);
              m_all_guids.push_back(guid_item);
              stackGuids.push_back(guid_item);
              exit = true;
              break;
            }
          }
        }
        if (exit) {
          break;
        }
      }
    }
  }
}

//--------------------------------------------------------------------------
// Search for callouts recursively
void findCalloutRec(func_t *func) {
  insn_t insn;
  for (ea_t ea = func->start_ea; ea < func->end_ea;
       ea = next_head(ea, BADADDR)) {
    decode_insn(&insn, ea);
    if (insn.itype == NN_call) {
      ea_t nextFuncAddr = insn.ops[0].addr;
      func_t *nextFunc = get_func(nextFuncAddr);
      if (nextFunc) {
        auto it = std::find(excFunctions.begin(), excFunctions.end(), nextFunc);
        if (it == excFunctions.end()) {
          excFunctions.push_back(nextFunc);
          findCalloutRec(nextFunc);
        }
      }
    }

    if (insn.itype == NN_mov && insn.ops[0].type == o_reg &&
        insn.ops[1].type == o_mem) {
      // search for callouts with gBS
      if (addr_in_vec(bs_list, insn.ops[1].addr)) {
        msg("[%s] SMM callout found: 0x%016llX\n", g_plugin_name, u64_addr(ea));
        // filter FP
        auto reg = insn.ops[0].reg;
        auto addr = ea;
        insn_t next_insn;
        auto fp = false;
        while (true) {
          addr = next_head(addr, BADADDR);
          decode_insn(&next_insn, addr);
          if ((next_insn.itype == NN_jmpni || next_insn.itype == NN_callni) &&
              next_insn.ops[0].type == o_displ && next_insn.ops[0].reg == reg &&
              next_insn.ops[0].addr == FreePoolOffset64) {
            fp = true;
            break;
          }
          if (is_basic_block_end(next_insn, false)) {
            break;
          }
        }
        if (!fp) {
          msg("[%s] SMM callout found (gBS): 0x%016llX\n", g_plugin_name,
              u64_addr(ea));
          calloutAddrs.push_back(ea);
          continue;
        }
      }

      // search for callouts with gRT
      if (addr_in_vec(rt_list, insn.ops[1].addr)) {
        msg("[%s] SMM callout found (gRT): 0x%016llX\n", g_plugin_name,
            u64_addr(ea));
        calloutAddrs.push_back(ea);
        continue;
      }

      // search for usage of interfaces installed with gBS->LocateProtocol()
      auto g_addr = insn.ops[1].addr;
      insn_t insn_xref;
      bool interface_callout_found = false;
      // check all xrefs for found global variable
      for (auto xref : get_xrefs_util(g_addr)) {
        // chcek if it looks like interface
        decode_insn(&insn_xref, xref);
        if (insn_xref.itype != NN_lea || insn_xref.ops[0].type != o_reg ||
            insn_xref.ops[0].reg != REG_R8) {
          continue;
        }

        // check rest of basic block to find gBS->LocateProtocol()
        insn_t next_insn;
        auto current_addr = xref;
        while (true) {
          current_addr = next_head(current_addr, BADADDR);
          decode_insn(&next_insn, current_addr);

          if (next_insn.itype == NN_callni &&
              next_insn.ops[0].type == o_displ &&
              next_insn.ops[0].reg == REG_RAX) {
            if (next_insn.ops[0].addr == LocateProtocolOffset64 ||
                next_insn.ops[0].addr == AllocatePoolOffset64) {
              // found callout
              msg("[%s] SMM callout found (usage of memory controlled by "
                  "the attacker inside SMI handler): 0x%016llX\n",
                  g_plugin_name, u64_addr(ea));
              calloutAddrs.push_back(ea);
              interface_callout_found = true;
            } // else: FP
            break;
          }

          if (is_basic_block_end(next_insn, false)) {
            break;
          }
        }
        if (interface_callout_found) {
          break;
        }
      }
    }
  }
}

//--------------------------------------------------------------------------
// find SmiHandler functions in SMM modules
void efi_analysis::efi_analyser_t::find_smi_handlers() {
  std::map<EfiGuid *, std::string> types = {
      {&m_sw_guid2, "Sw"},
      {&m_sw_guid, "Sw"},
      {&m_sx_guid2, "Sx"},
      {&m_sx_guid, "Sx"},
      {&m_io_trap_guid2, "IoTrap"},
      {&m_io_trap_guid, "IoTrap"},
      {&m_gpi_guid2, "Gpi"},
      {&m_gpi_guid, "Gpi"},
      {&m_usb_guid2, "Usb"},
      {&m_usb_guid, "Usb"},
      {&m_standby_button_guid2, "StandbyButton"},
      {&m_standby_button_guid, "StandbyButton"},
      {&m_periodic_timer_guid2, "PeriodicTimer"},
      {&m_periodic_timer_guid, "PeriodicTimer"},
      {&m_power_button_guid2, "PowerButton"},
      {&m_power_button_guid, "PowerButton"},
      {&m_ichn_guid, "Ichn"},
      {&m_ichn_guid2, "Ichn"},
      {&m_tco_guid, "Tco"},
      {&m_pcie_guid, "Pcie"},
      {&m_acpi_guid, "Acpi"},
      {&m_gpio_unlock_guid, "GpioUnlock"},
      {&m_pch_guid, "Pch"},
      {&m_espi_guid, "Espi"},
      {&m_acpi_en_guid, "AcpiEn"},
      {&m_acpi_dis_guid, "AcpiDis"},
      {&m_fch_gpi_guid2, "Gpi"},
      {&m_fch_io_trap_guid2, "IoTrap"},
      {&m_fch_periodical_guid2, "PeriodicTimer"},
      {&m_fch_pwr_btn_guid2, "PowerButton"},
      {&m_fch_sw_guid2, "Sw"},
      {&m_fch_sx_guid2, "Sx"},
      {&m_fch_usb_guid2, "Usb"},
      {&m_fch_usb_guid, "Usb"},
      {&m_fch_misc_guid, "Misc"},
      {&m_fch_apu_ras_guid, "ApuRas"},
  };
  for (auto &[guid, prefix] : types) {
    auto res = findSmiHandlersSmmDispatch(*guid, prefix);
    m_smi_handlers.insert(m_smi_handlers.end(), res.begin(), res.end());
  }
}

//--------------------------------------------------------------------------
// Find callouts inside SwSmiHandler function:
//  * find SwSmiHandler function
//  * find gBS->service_name and gRT->service_name inside SmiHandler function
bool efi_analysis::efi_analyser_t::find_smm_callout() {
  msg("[%s] Looking for SMM callout\n", g_plugin_name);
  if (!bs_list.size() && !rt_list.size()) {
    return false;
  }
  if (!m_smi_handlers.size() && !childSmiHandlers.size()) {
    msg("[%s] can't find a SwSmiHandler functions\n", g_plugin_name);
    return false;
  }
  for (auto func : m_smi_handlers) {
    findCalloutRec(func);
  }
  for (auto func : childSmiHandlers) {
    findCalloutRec(func);
  }
  return true;
}

bool efi_analysis::efi_analyser_t::find_double_get_variable_pei() {
  msg("[%s] Looking for PPI GetVariable buffer overflow, "
      "m_all_services.size() = %lu\n",
      g_plugin_name, m_all_services.size());
  ea_list_t getVariableServicesCalls;
  std::string getVariableStr("VariablePPI.GetVariable");
  for (auto j_service : m_all_services) {
    json service = j_service;
    std::string service_name =
        static_cast<std::string>(service["service_name"]);
    std::string table_name = static_cast<std::string>(service["table_name"]);
    ea_t addr = static_cast<ea_t>(service["address"]);
    if (service_name.compare(getVariableStr) == 0) {
      getVariableServicesCalls.push_back(addr);
    }
  }
  msg("[%s] Finished iterating over m_all_services, "
      "getVariableServicesCalls.size() = "
      "%lu\n",
      g_plugin_name, getVariableServicesCalls.size());
  sort(getVariableServicesCalls.begin(), getVariableServicesCalls.end());
  if (getVariableServicesCalls.size() < 2) {
    msg("[%s] less than 2 VariablePPI.GetVariable calls found\n",
        g_plugin_name);
    return false;
  }
  ea_t prev_addr = getVariableServicesCalls.at(0);
  for (auto i = 1; i < getVariableServicesCalls.size(); ++i) {
    ea_t curr_addr = getVariableServicesCalls.at(i);
    msg("[%s] VariablePPI.GetVariable_1: 0x%016llX, "
        "VariablePPI.GetVariable_2: "
        "0x%016llX\n",
        g_plugin_name, u64_addr(prev_addr), u64_addr(curr_addr));

    // check code from GetVariable_1 to GetVariable_2
    ea_t ea = next_head(prev_addr, BADADDR);
    bool ok = true;
    insn_t insn;
    while (ea < curr_addr) {
      decode_insn(&insn, ea);
      if (insn.itype == NN_callni || insn.itype == NN_call ||
          insn.itype == NN_retn || insn.itype == NN_jmp ||
          insn.itype == NN_jmpni) {
        ok = false;
        break;
      }
      ea = next_head(ea, BADADDR);
    }
    if (ok) {
      bool same_datasize = false;
      uint16_t pushNumber = 5;
      uint16_t pushCounter = 0;
      uint16_t arg5_reg = 0xffff;
      ea_t curr_datasize_addr = 0xffff;
      bool datasize_addr_found = false;
      ea_t address = curr_addr;
      for (auto j = 0; j < 15; j++) {
        address = prev_head(address, m_start_addr);
        decode_insn(&insn, address);
        if (insn.itype == NN_push) {
          pushCounter += 1;
          if (pushCounter == pushNumber) {
            if (insn.ops[0].type == o_reg) {
              arg5_reg = insn.ops[0].reg;
            } else {
              // if it's not push <reg>, just let the pattern
              // trigger - for manual review
              same_datasize = true;
            }
            break;
          }
        }
      }

      if (same_datasize) {
        peiGetVariableOverflow.push_back(curr_addr);
        msg("[%s] overflow can occur here: 0x%016llX\n", g_plugin_name,
            u64_addr(curr_addr));
        continue;
      }

      for (auto j = 0; j < 15; j++) {
        address = prev_head(address, m_start_addr);
        decode_insn(&insn, address);
        if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
            insn.ops[0].reg == arg5_reg && insn.ops[1].type == o_displ) {
          curr_datasize_addr = insn.ops[1].addr;
          datasize_addr_found = true;
          break;
        }
      }

      msg("[%s] curr_datasize_addr = 0x%016llX, datasize_addr_found = "
          "%d\n",
          g_plugin_name, u64_addr(curr_datasize_addr), datasize_addr_found);

      if (!datasize_addr_found) {
        // if datasize wasn't found, just let the pattern
        // trigger - for manual review
        peiGetVariableOverflow.push_back(curr_addr);
        msg("[%s] overflow can occur here: 0x%016llX\n", g_plugin_name,
            u64_addr(curr_addr));
        continue;
      }

      pushCounter = 0;
      arg5_reg = 0xffff;
      ea_t prev_datasize_addr = 0xffff;
      datasize_addr_found = false;
      address = prev_addr;
      for (auto j = 0; j < 15; j++) {
        address = prev_head(address, m_start_addr);
        decode_insn(&insn, address);
        if (insn.itype == NN_push) {
          pushCounter += 1;
          if (pushCounter == pushNumber) {
            if (insn.ops[0].type == o_reg) {
              arg5_reg = insn.ops[0].reg;
            } else {
              // if it's not push <reg>, just let the pattern
              // trigger - for manual review
              same_datasize = true;
            }
            break;
          }
        }
      }

      if (same_datasize) {
        peiGetVariableOverflow.push_back(curr_addr);
        msg("[%s] overflow can occur here: 0x%016llX\n", g_plugin_name,
            u64_addr(curr_addr));
        continue;
      }

      for (auto j = 0; j < 15; j++) {
        address = prev_head(address, m_start_addr);
        decode_insn(&insn, address);
        if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
            insn.ops[0].reg == arg5_reg && insn.ops[1].type == o_displ) {
          prev_datasize_addr = insn.ops[1].addr;
          datasize_addr_found = true;
          break;
        }
      }

      msg("[%s] prev_datasize_addr = 0x%016llX, datasize_addr_found = "
          "%d, "
          "(prev_datasize_addr == curr_datasize_addr) = %d\n",
          g_plugin_name, u64_addr(prev_datasize_addr), datasize_addr_found,
          (prev_datasize_addr == curr_datasize_addr));

      if (!datasize_addr_found) {
        peiGetVariableOverflow.push_back(curr_addr);
        msg("[%s] overflow can occur here: 0x%016llX\n", g_plugin_name,
            u64_addr(curr_addr));
      } else if (prev_datasize_addr == curr_datasize_addr) {
        peiGetVariableOverflow.push_back(curr_addr);
        msg("[%s] overflow can occur here: 0x%016llX "
            "(prev_datasize_addr == "
            "curr_datasize_addr)\n",
            g_plugin_name, u64_addr(curr_addr));
      }
    }
    prev_addr = curr_addr;
  }
  return (peiGetVariableOverflow.size() > 0);
}

//--------------------------------------------------------------------------
// Find potential stack/heap overflow with double GetVariable calls
bool efi_analysis::efi_analyser_t::find_double_get_variable(
    json_list_t m_all_services) {
  msg("[%s] Looking for GetVariable stack/heap overflow\n", g_plugin_name);
  ea_list_t getVariableServicesCalls;
  std::string getVariableStr("GetVariable");
  for (auto j_service : m_all_services) {
    json service = j_service;
    std::string service_name =
        static_cast<std::string>(service["service_name"]);
    ea_t addr = static_cast<ea_t>(service["address"]);
    if (service_name.compare(getVariableStr) == 0) {
      getVariableServicesCalls.push_back(addr);
    }
  }
  sort(getVariableServicesCalls.begin(), getVariableServicesCalls.end());
  if (getVariableServicesCalls.size() < 2) {
    msg("[%s] less than 2 GetVariable calls found\n", g_plugin_name);
    return false;
  }
  ea_t prev_addr = getVariableServicesCalls.at(0);
  ea_t ea;
  insn_t insn;
  for (auto i = 1; i < getVariableServicesCalls.size(); ++i) {
    ea_t curr_addr = getVariableServicesCalls.at(i);
    msg("[%s] GetVariable_1: 0x%016llX, GetVariable_2: 0x%016llX\n",
        g_plugin_name, u64_addr(prev_addr), u64_addr(curr_addr));

    // get dataSizeStackAddr
    int dataSizeStackAddr = 0;
    uint16 dataSizeOpReg = 0xFF;
    ea = prev_head(curr_addr, 0);
    for (auto i = 0; i < 10; ++i) {
      decode_insn(&insn, ea);
      if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
          insn.ops[0].reg == REG_R9) {
        dataSizeStackAddr = insn.ops[1].addr;
        dataSizeOpReg = insn.ops[1].phrase;
        break;
      }
      ea = prev_head(ea, 0);
    }

    // check code from GetVariable_1 to GetVariable_2
    ea = next_head(prev_addr, BADADDR);
    bool ok = true;
    size_t dataSizeUseCounter = 0;
    while (ea < curr_addr) {
      decode_insn(&insn, ea);
      if (((dataSizeStackAddr == insn.ops[0].addr) &&
           (dataSizeOpReg == insn.ops[0].phrase)) ||
          ((dataSizeStackAddr == insn.ops[1].addr) &&
           (dataSizeOpReg == insn.ops[1].phrase))) {
        dataSizeUseCounter++;
      }
      if ((insn.itype == NN_callni && insn.ops[0].addr == 0x48) ||
          insn.itype == NN_retn || insn.itype == NN_jmp ||
          insn.itype == NN_jmpni || dataSizeUseCounter > 1) {
        ok = false;
        break;
      }
      ea = next_head(ea, BADADDR);
    }
    if (ok) {
      // check for wrong GetVariable detection
      bool wrong_detection = false;
      ea = prev_head(curr_addr, 0);
      for (auto i = 0; i < 8; ++i) {
        decode_insn(&insn, ea);
        if (insn.itype == NN_mov && insn.ops[0].type == o_reg &&
            insn.ops[1].type == o_mem) {
          ea_t mem_addr = insn.ops[1].addr;
          if (addr_in_vec(bs_list, mem_addr)) {
            wrong_detection = true;
            break;
          }
        }
        ea = prev_head(ea, 0);
      }

      // check DataSize initialization
      bool init_ok = false;
      decode_insn(&insn, prev_head(curr_addr, 0));
      if (!wrong_detection &&
          !(insn.itype == NN_mov && insn.ops[0].type == o_displ &&
            (insn.ops[0].phrase == REG_RSP || insn.ops[0].phrase == REG_RBP) &&
            (insn.ops[0].addr == dataSizeStackAddr))) {
        init_ok = true;
      }

      // check that the DataSize argument variable is the same for two
      // calls
      if (init_ok) {
        ea = prev_head(prev_addr, 0);
        // for (auto i = 0; i < 10; ++i) {
        func_t *func_start = get_func(ea);
        if (func_start == nullptr) {
          return (getVariableOverflow.size() > 0);
        }
        uint16 stack_base_reg = 0xFF;
        decode_insn(&insn, func_start->start_ea);
        if (insn.itype == NN_mov && insn.ops[1].is_reg(REG_RSP) &&
            insn.ops[0].type == o_reg) {
          stack_base_reg = insn.ops[0].reg;
        }

        while (ea >= func_start->start_ea) {
          decode_insn(&insn, ea);
          if (insn.itype == NN_call)
            break;
          if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
              insn.ops[0].reg == REG_R9) {
            ea_t stack_addr = insn.ops[1].addr;
            sval_t sval = get_spd(func_start, ea) * -1;

            if ((insn.ops[1].phrase == stack_base_reg &&
                 (sval + stack_addr) == dataSizeStackAddr) ||
                (dataSizeStackAddr == insn.ops[1].addr)) {
              getVariableOverflow.push_back(curr_addr);
              msg("[%s] \toverflow can occur here: 0x%016llX\n", g_plugin_name,
                  u64_addr(curr_addr));
              break;
            }
          }
          ea = prev_head(ea, 0);
        }
      }
    }
    prev_addr = curr_addr;
  }
  return (getVariableOverflow.size() > 0);
}

//--------------------------------------------------------------------------
// Find potential stack/heap overflow with double SmmGetVariable calls
bool efi_analysis::efi_analyser_t::find_double_get_variable_smm() {
  msg("[%s] Looking for SmmGetVariable stack/heap overflow\n", g_plugin_name);
  ea_list_t smmGetVariableCalls =
      findSmmGetVariableCalls(dataSegments, &m_all_services);
  sort(smmGetVariableCalls.begin(), smmGetVariableCalls.end());
  if (smmGetVariableCalls.size() < 2) {
    msg("[%s] less than 2 GetVariable calls found\n", g_plugin_name);
    return false;
  }
  ea_t prev_addr = smmGetVariableCalls.at(0);
  ea_t ea;
  insn_t insn;
  for (auto i = 1; i < smmGetVariableCalls.size(); ++i) {
    ea_t curr_addr = smmGetVariableCalls.at(i);
    msg("[%s] SmmGetVariable_1: 0x%016llX, SmmGetVariable_2: 0x%016llX\n",
        g_plugin_name, u64_addr(prev_addr), u64_addr(curr_addr));

    // get dataSizeStackAddr
    uint32_t dataSizeStackAddr = 0xffffffff;
    ea = prev_head(curr_addr, 0);
    for (auto i = 0; i < 10; ++i) {
      decode_insn(&insn, ea);
      if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
          insn.ops[0].reg == REG_R9) {
        dataSizeStackAddr = insn.ops[1].addr;
        break;
      }
      ea = prev_head(ea, 0);
    }

    // check code from SmmGetVariable_1 to SmmGetVariable_2
    ea = next_head(prev_addr, BADADDR);
    bool ok = true;
    size_t dataSizeUseCounter = 0;
    while (ea < curr_addr) {
      decode_insn(&insn, ea);
      if (insn.itype == NN_callni || insn.itype == NN_retn ||
          insn.itype == NN_jmpni || insn.itype == NN_jmp) {
        ok = false;
        break;
      }
      ea = next_head(ea, BADADDR);
    }

    if (ok) {
      // check DataSize initialization
      bool init_ok = false;
      decode_insn(&insn, prev_head(curr_addr, 0));
      if (!(insn.itype == NN_mov && insn.ops[0].type == o_displ &&
            (insn.ops[0].phrase == REG_RSP || insn.ops[0].phrase == REG_RBP))) {
        init_ok = true;
      }

      // check that the DataSize argument variable is the same for two
      // calls
      if (init_ok) {
        ea = prev_head(prev_addr, 0);
        for (auto i = 0; i < 10; ++i) {
          decode_insn(&insn, ea);
          if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
              insn.ops[0].reg == REG_R9) {
            if (dataSizeStackAddr == insn.ops[1].addr) {
              smmGetVariableOverflow.push_back(curr_addr);
              msg("[%s] \toverflow can occur here: 0x%016llX\n", g_plugin_name,
                  u64_addr(curr_addr));
              break;
            }
            msg("[%s] \tDataSize argument variable is not the "
                "same: 0x%016llX\n",
                g_plugin_name, u64_addr(curr_addr));
          }
          ea = prev_head(ea, 0);
        }
      }
    }
    prev_addr = curr_addr;
  }
  return (smmGetVariableOverflow.size() > 0);
}

bool efi_analysis::efi_analyser_t::analyse_variable_service(
    ea_t ea, std::string service_str) {
  msg("[%s] %s call: 0x%016llX\n", g_plugin_name, service_str.c_str(),
      u64_addr(ea));
  json item;
  item["addr"] = ea;
  insn_t insn;
  bool name_found = false;
  bool guid_found = false;
  func_t *f = get_func(ea);
  if (f == nullptr) {
    return false;
  }
  eavec_t args;
  get_arg_addrs(&args, ea);
  if (args.size() < 3) {
    return false;
  }

  auto addr = args[0]; // Get VariableName
  decode_insn(&insn, addr);
  if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
      insn.ops[0].reg == REG_RCX && insn.ops[1].type == o_mem) {
    msg("[%s]  VariableName address: 0x%016llX\n", g_plugin_name,
        u64_addr(insn.ops[1].addr));
    std::string var_name = get_wide_string(insn.ops[1].addr);

    // retype CHAR16 to const CHAR16 to improve pseudocode quality
    set_const_char16_type(insn.ops[1].addr);

    msg("[%s]  VariableName: %s\n", g_plugin_name, var_name.c_str());
    item["VariableName"] = var_name;
    name_found = true;
  }

  addr = args[1]; // Get VendorGuid
  decode_insn(&insn, addr);
  // If GUID is global variable
  if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
      insn.ops[0].reg == REG_RDX && insn.ops[1].type == o_mem) {
    msg("[%s]  VendorGuid address (global): 0x%016llX\n", g_plugin_name,
        u64_addr(insn.ops[1].addr));
    EfiGuid guid = get_global_guid(insn.ops[1].addr);
    msg("[%s]  GUID: %s\n", g_plugin_name, guid.to_string().c_str());
    item["VendorGuid"] = guid.to_string();
    guid_found = true;
  }
  // If GUID is local variable
  if (!guid_found && insn.itype == NN_lea && insn.ops[0].type == o_reg &&
      insn.ops[0].reg == REG_RDX && insn.ops[1].type == o_displ) {
    switch (insn.ops[1].reg) {
    case REG_RBP: {
      msg("[%s]  VendorGuid address (regarding to RBP): 0x%016llX\n",
          g_plugin_name, u64_addr(insn.ops[1].addr));
      EfiGuid guid = get_local_guid(f, insn.ops[1].addr);
      msg("[%s]  GUID: %s\n", g_plugin_name, guid.to_string().c_str());
      item["VendorGuid"] = guid.to_string();
      guid_found = true;
    }
    case REG_RSP: {
      msg("[%s]  VendorGuid address (regarding to RSP): 0x%016llX\n",
          g_plugin_name, u64_addr(insn.ops[1].addr));
      EfiGuid guid = get_local_guid(f, insn.ops[1].addr);
      msg("[%s]  GUID: %s\n", g_plugin_name, guid.to_string().c_str());
      item["VendorGuid"] = guid.to_string();
      guid_found = true;
    }
    }
  }

  std::map<uint8_t, std::string> attributes_defs = {
      {0x00000001, "NON_VOLATILE"},
      {0x00000002, "BOOTSERVICE_ACCESS"},
      {0x00000004, "RUNTIME_ACCESS"},
      {0x00000008, "HARDWARE_ERROR_RECORD"},
      {0x00000010, "AUTHENTICATED_WRITE_ACCESS"}};

  addr = args[2]; // Get Attributes
  decode_insn(&insn, addr);
  if (insn.itype == NN_xor && insn.ops[0].type == o_reg &&
      insn.ops[1].type == o_reg && insn.ops[0].reg == insn.ops[1].reg &&
      insn.ops[0].reg == REG_R8) {
    item["Attributes"] = 0;
    std::string attributes_hr = "No attributes";
    item["AttributesHumanReadable"] = attributes_hr;
    msg("[%s]  Attributes: %d (%s)\n", g_plugin_name, 0, attributes_hr.c_str());
  } else {
#ifdef HEX_RAYS
    // Extract attributes with Hex-Rays SDK
    auto res = variables_info_extract_all(f, ea);
    item["Attributes"] = res;
    std::string attributes_hr = std::string();
    if (res == 0xff) {
      attributes_hr = "Unknown attributes";
    } else {
      for (auto &[attr, attr_def] : attributes_defs) {
        if (res & attr & 0x0f) {
          attributes_hr += attr_def + " | ";
        }
      }
      if (attributes_hr.size() >= 3) { // remove the last operation OR
        attributes_hr = attributes_hr.substr(0, attributes_hr.size() - 3);
      }
    }
    item["AttributesHumanReadable"] = attributes_hr;
    msg("[%s]  Attributes: %d (%s)\n", g_plugin_name, res,
        attributes_hr.c_str());
#else
    // If Hex-Rays analysis is not used, this feature does not work
    item["Attributes"] = 0xff;
    item["AttributesHumanReadable"] = "Unknown attributes";
#endif
  }

  if (name_found && guid_found) { // if only name or only GUID found, it will
                                  // now saved (check the logs)
    item["service"] = service_str;
    m_nvram_variables.push_back(item);
  }

  return true;
}

bool efi_analysis::efi_analyser_t::analyse_nvram_variables() {
  msg("[%s] Get NVRAM variables information\n", g_plugin_name);
  string_list_t nvram_services = {"GetVariable", "SetVariable"};
  for (auto service_str : nvram_services) {
    ea_list_t var_services;
    for (auto j_service : m_all_services) {
      json service = j_service;
      std::string service_name =
          static_cast<std::string>(service["service_name"]);
      ea_t addr = static_cast<ea_t>(service["address"]);
      if (!service_name.compare(service_str)) {
        var_services.push_back(addr);
      }
    }
    sort(var_services.begin(), var_services.end());
    for (auto ea : var_services) {
      analyse_variable_service(ea, service_str);
    }

    for (auto ea : g_smm_get_variable_calls) {
      analyse_variable_service(ea, "EFI_SMM_VARIABLE_PROTOCOL::SmmGetVariable");
    }

    for (auto ea : g_smm_set_variable_calls) {
      analyse_variable_service(ea, "EFI_SMM_VARIABLE_PROTOCOL::SmmSetVariable");
    }
  }
  return true;
}

//--------------------------------------------------------------------------
// Resolve EFI_SMM_CPU_PROTOCOL
bool efi_analysis::efi_analyser_t::smm_cpu_protocol_resolver() {
  readSaveStateCalls =
      resolveEfiSmmCpuProtocol(stackGuids, dataGuids, &m_all_services);
  return true;
}

//--------------------------------------------------------------------------
// Dump all info to JSON file
void efi_analysis::efi_analyser_t::dump_json() {
  json info;
  if (st_list.size()) {
    info["st_list"] = st_list;
  }
  if (bs_list.size()) {
    info["bs_list"] = bs_list;
  }
  if (rt_list.size()) {
    info["rt_list"] = rt_list;
  }
  if (smst_list.size()) {
    info["smst_list"] = smst_list;
  }
  if (image_handle_list.size()) {
    info["image_handle_list"] = image_handle_list;
  }
  if (m_all_ppis.size()) {
    info["all_ppis"] = m_all_ppis;
  }
  if (m_all_protocols.size()) {
    info["all_protocols"] = m_all_protocols;
  }
  if (m_all_services.size()) {
    info["all_services"] = m_all_services;
  }
  if (m_all_guids.size()) {
    info["all_guids"] = m_all_guids;
  }
  if (m_nvram_variables.size()) {
    info["m_nvram_variables"] = m_nvram_variables;
  }
  if (readSaveStateCalls.size()) {
    info["readSaveStateCalls"] = readSaveStateCalls;
  }
  if (calloutAddrs.size()) {
    info["vulns"]["smm_callout"] = calloutAddrs;
  }
  if (peiGetVariableOverflow.size()) {
    info["vulns"]["pei_get_variable_buffer_overflow"] = peiGetVariableOverflow;
  }
  if (getVariableOverflow.size()) {
    info["vulns"]["get_variable_buffer_overflow"] = getVariableOverflow;
  }
  if (smmGetVariableOverflow.size()) {
    info["vulns"]["smm_get_variable_buffer_overflow"] = smmGetVariableOverflow;
  }

  json_list_t m_smi_handlersAddrs;
  if (m_smi_handlers.size() > 0) {
    for (auto f : m_smi_handlers) {
      func_t *func = f;
      m_smi_handlersAddrs.push_back(func->start_ea);
    }
    info["m_smi_handlersAddrs"] = m_smi_handlersAddrs;
  }

  std::string idbPath;
  idbPath = get_path(PATH_TYPE_IDB);
  std::filesystem::path logFile;
  logFile /= idbPath;
  logFile.replace_extension(".json");
  std::ofstream out(logFile);
  out << std::setw(4) << info << std::endl;
  msg("[%s] the log is saved in a JSON file\n", g_plugin_name);
}

//--------------------------------------------------------------------------
// show all non-empty choosers windows (services, protocols, nvram, etc)
void efi_analysis::efi_analyser_x86_t::show_all_choosers() {
  qstring title;

  // open window with all services
  if (m_all_services.size()) {
    title = "efiXplorer: services";
    services_show(m_all_services, title);
  }

  // open window with protocols
  if (m_ftype == ffs_file_type_t::pei) {
    if (m_all_ppis.size()) {
      title = "efiXplorer: PPIs";
      ppis_show(m_all_ppis, title);
    }
  } else { // ffs_file_type_t::dxe_smm
    if (m_all_protocols.size()) {
      title = "efiXplorer: protocols";
      protocols_show(m_all_protocols, title);
    }
  }

  // open window with data guids
  if (m_all_guids.size()) {
    qstring title = "efiXplorer: GUIDs";
    guids_show(m_all_guids, title);
  }

  // open window with NVRAM variables
  if (m_nvram_variables.size()) {
    qstring title = "efiXplorer: NVRAM";
    nvram_show(m_nvram_variables, title);
  }

  // open window with vulnerabilities
  if (calloutAddrs.size() || peiGetVariableOverflow.size() ||
      getVariableOverflow.size() || smmGetVariableOverflow.size()) {
    json_list_t vulns;
    std::map<std::string, ea_list_t> vulns_map = {
        {"SmmCallout", calloutAddrs},
        {"PeiGetVariableOverflow", peiGetVariableOverflow},
        {"DxeGetVariableOverflow", getVariableOverflow},
        {"SmmGetVariableOverflow", smmGetVariableOverflow}};

    for (const auto &[type, addrs] : vulns_map) {
      for (auto addr : addrs) {
        json item;
        item["type"] = type;
        item["address"] = addr;
        vulns.push_back(item);
      }
    }

    qstring title = "efiXplorer: vulns";
    vulns_show(vulns, title);
  }
}

//--------------------------------------------------------------------------
// main function for x86 64-bit modules
bool efi_analysis::efi_analyse_main_x86_64() {
  show_wait_box("HIDECANCEL\nAnalysing module(s) with efiXplorer...");

  efi_analysis::efi_analyser_x86_t analyser;

  while (!auto_is_ok()) {
    auto_wait();
  }

  // find .text and .data segments
  analyser.get_segments();

  // analyse all
  auto res = ASKBTN_NO;
  if (analyser.m_arch == arch_file_type_t::uefi) {
    res =
        ask_yn(1, "Want to further analyse all drivers with auto_mark_range?");
  }
  if (res == ASKBTN_YES && textSegments.size() && dataSegments.size()) {
    segment_t *start_seg = textSegments.at(0);
    segment_t *end_seg = dataSegments.at(dataSegments.size() - 1);
    ea_t start_ea = start_seg->start_ea;
    ea_t end_ea = end_seg->end_ea;
    auto_mark_range(start_ea, end_ea, AU_USED);
    plan_and_wait(start_ea, end_ea, 1);
  }

  // mark GUIDs
  analyser.mark_data_guids();
  analyser.mark_local_guids64();

  if (g_args.disable_ui) {
    analyser.m_ftype = g_args.module_type == module_type_t::pei
                           ? analyser.m_ftype = ffs_file_type_t::pei
                           : analyser.m_ftype = ffs_file_type_t::dxe_smm;
  } else {
    analyser.m_ftype = ask_file_type(&analyser.m_all_guids);
  }

  analyser.set_pvalues();

  // find global vars for gImageHandle, gST, gBS, gRT, gSmst
  if (analyser.m_ftype == ffs_file_type_t::dxe_smm) {
    analyser.find_image_handle64();
    analyser.find_system_table64();
    analyser.find_boot_services_tables();
    analyser.find_runtime_services_tables();

    analyser.find_smst64();

    // find Boot services and Runtime services
    analyser.get_prot_boot_services64();
    analyser.find_other_boot_services_tables64();
    analyser.get_boot_services_all();
    analyser.get_runtime_services_all();

    analyser.get_bs_prot_names64();

#ifdef HEX_RAYS
    apply_all_types_for_interfaces(analyser.m_all_protocols);
    analyser.find_smst_postproc64();
#endif

    // find SMM services
    analyser.get_smm_services_all64();
    analyser.get_smm_prot_names64();

    // mark protocols
    analyser.mark_interfaces();

    // search for copies of global variables
    mark_copies_for_gvars(smst_list, "gSmst");
    mark_copies_for_gvars(bs_list, "gBS");
    mark_copies_for_gvars(rt_list, "gRT");

    // search for vulnerabilities
    if (!g_args.disable_vuln_hunt) {
      // find potential SMM callouts
      analyser.find_smi_handlers();
      analyser.find_smm_callout();

      // find potential OOB RW with GetVariable function
      analyser.find_double_get_variable(analyser.m_all_services);

      // find potential OOB RW with SmmGetVariable function
      analyser.find_double_get_variable_smm();
      analyser.smm_cpu_protocol_resolver();
    }

#ifdef HEX_RAYS
    apply_all_types_for_interfaces_smm(analyser.m_all_protocols);
#endif

    analyser.analyse_nvram_variables();

  } else {
    msg("[%s] Parsing of 64-bit PEI files is not supported yet\n",
        g_plugin_name);
  }

  // dump info to JSON file
  analyser.dump_json();

  // show all choosers windows
  if (!g_args.disable_ui) {
    analyser.show_all_choosers();
  }

  if (analyser.m_arch == arch_file_type_t::uefi) {
    // Init public EdiDependencies members
    g_deps.getProtocolsChooser(analyser.m_all_protocols);
    g_deps.getProtocolsByGuids(analyser.m_all_protocols);

    // Save all protocols information to build dependencies
    attachActionProtocolsDeps();
    attachActionModulesSeq();
  }

  hide_wait_box();

  return true;
}

//--------------------------------------------------------------------------
// main function for x86 32-bit modules
bool efi_analysis::efi_analyse_main_x86_32() {
  show_wait_box("HIDECANCEL\nAnalysing module(s) with efiXplorer...");

  efi_analysis::efi_analyser_x86_t analyser;

  while (!auto_is_ok()) {
    auto_wait();
  }

  // find .text and .data segments
  analyser.get_segments();

  // mark GUIDs
  analyser.mark_data_guids();

  if (g_args.disable_ui) {
    analyser.m_ftype = g_args.module_type == module_type_t::pei
                           ? analyser.m_ftype = ffs_file_type_t::pei
                           : analyser.m_ftype = ffs_file_type_t::dxe_smm;
  } else {
    analyser.m_ftype = ask_file_type(&analyser.m_all_guids);
  }

  analyser.set_pvalues();

  if (analyser.m_ftype == ffs_file_type_t::dxe_smm) {
    // find global vars for gST, gBS, gRT
    analyser.find_boot_services_tables();
    analyser.find_runtime_services_tables();

    // find boot services and runtime services
    analyser.get_runtime_services_all();
    analyser.get_prot_boot_services32();
    analyser.get_boot_services_all();

    // print and mark protocols
    analyser.get_bs_prot_names32();
    analyser.mark_interfaces();

#ifdef HEX_RAYS
    apply_all_types_for_interfaces(analyser.m_all_protocols);
    apply_all_types_for_interfaces_smm(analyser.m_all_protocols);
#endif
  } else if (analyser.m_ftype == ffs_file_type_t::pei) {
    set_entry_arg_to_pei_svc();
    add_struct_for_shifted_ptr();
#ifdef HEX_RAYS
    for (auto addr : analyser.m_funcs) {
      detect_pei_services(get_func(addr));
    }
#endif
    analyser.get_pei_services_all32();
    analyser.get_ppi_names32();
    analyser.get_variable_ppi_calls_all32();
    analyser.mark_interfaces();

    // search for vulnerabilities
    if (!g_args.disable_vuln_hunt) {
      analyser.find_double_get_variable_pei();
    }
  }

  // dump info to JSON file
  analyser.dump_json();

  // show all choosers windows
  if (!g_args.disable_ui) {
    analyser.show_all_choosers();
  }

  hide_wait_box();

  return true;
}
