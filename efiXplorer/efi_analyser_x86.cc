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

using namespace efi_analysis;

extern std::vector<ea_t> g_get_smst_location_calls;
extern std::vector<ea_t> g_smm_get_variable_calls;
extern std::vector<ea_t> g_smm_set_variable_calls;

std::vector<ea_t> st_list;
std::vector<ea_t> gPeiSvcList;
std::vector<ea_t> bs_list;
std::vector<ea_t> rt_list;
std::vector<ea_t> gSmstList;
std::vector<ea_t> gImageHandleList;
std::vector<ea_t> gRtServicesList;

std::vector<json> stackGuids;
std::vector<json> dataGuids;

// all .text and .data segments for compatibility with the efiLoader
std::vector<segment_t *> textSegments;
std::vector<segment_t *> dataSegments;

// for smm callouts finding
std::vector<ea_t> calloutAddrs;
std::vector<func_t *> excFunctions;
std::vector<func_t *> childSmiHandlers;
std::vector<ea_t> readSaveStateCalls;

// for GetVariable stack overflow finding
std::vector<ea_t> peiGetVariableOverflow;
std::vector<ea_t> getVariableOverflow;
std::vector<ea_t> smmGetVariableOverflow;

efi_analysis::EfiAnalyser::EfiAnalyser() {
  // 32-bit, 64-bit, ARM or UEFI (in loader instance)
  arch = input_file_type();

  // get guids.json path
  guidsJsonPath /= get_guids_json_file();

  // get base address
  base = get_imagebase();

  func_t *start_func = nullptr;
  func_t *end_func = nullptr;

  // get start address for scan
  start_func = getn_func(0);
  if (start_func) {
    startAddress = start_func->start_ea;
  }

  // get end address for scan
  end_func = getn_func(get_func_qty() - 1);
  if (end_func) {
    endAddress = end_func->end_ea;
  }

  // save all funcs
  for (auto i = 0; i < get_func_qty(); i++) {
    auto func = getn_func(i);
    funcs.push_back(func->start_ea);
  }

  std::vector<ea_t> addrs;
  for (auto service : protBsNames) {
    bootServices[service] = addrs;
  }

  for (auto service : protSmmNames) {
    smmServices[service] = addrs;
  }

  try {
    // load protocols from guids.json file
    std::ifstream in(guidsJsonPath);
    in >> dbProtocols;
  } catch (std::exception &e) {
    dbProtocols.clear();
    std::string msg_text = "guids.json file is invalid, check its contents";
    msg("[%s] %s\n", g_plugin_name, msg_text.c_str());
    warning("%s: %s\n", g_plugin_name, msg_text.c_str());
  }

  // get reverse dictionary
  for (auto g = dbProtocols.begin(); g != dbProtocols.end(); ++g) {
    dbProtocolsMap[static_cast<json>(g.value())] = static_cast<std::string>(g.key());
  }
}

efi_analysis::EfiAnalyser::~EfiAnalyser() {
  funcs.clear();

  st_list.clear();
  gPeiSvcList.clear();
  bs_list.clear();
  rt_list.clear();
  gSmstList.clear();
  gImageHandleList.clear();
  gRtServicesList.clear();
  stackGuids.clear();
  dataGuids.clear();

  textSegments.clear();
  dataSegments.clear();

  calloutAddrs.clear();
  excFunctions.clear();
  readSaveStateCalls.clear();
  smiHandlers.clear();
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

void efi_analysis::EfiAnalyser::setStrings() {
  if (file_type == FfsFileType::DxeAndTheLike) {
    if_name = " Protocol name ";
    if_pl = "protocols";
    if_key = "prot_name";
    if_tbl = &allProtocols;
  } else if (file_type == FfsFileType::Pei) {
    if_name = " PPI name ";
    if_pl = "PPIs";
    if_key = "ppi_name";
    if_tbl = &allPPIs;
  }
}

//--------------------------------------------------------------------------
// Get all .text and .data segments
void efi_analysis::EfiAnalyser::getSegments() {
  for (segment_t *s = get_first_seg(); s != NULL; s = get_next_seg(s->start_ea)) {
    qstring seg_name;
    get_segm_name(&seg_name, s);

    std::vector<std::string> codeSegNames{
        ".text", ".code"}; // for compatibility with ida-efitools2
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
bool efi_analysis::EfiAnalyserX86::findImageHandleX64() {
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
        msg("[%s] found ImageHandle at 0x%016llX, address = 0x%016llX\n", g_plugin_name,
            u64_addr(ea), u64_addr(insn.ops[0].addr));
        set_cmt(ea, "EFI_IMAGE_HANDLE gImageHandle", true);

        // set type and name
        set_type_and_name(insn.ops[0].addr, "gImageHandle", "EFI_IMAGE_HANDLE");
        gImageHandleList.push_back(insn.ops[0].addr);
        break;
      }
      ea = next_head(ea, endAddress);
    }
  }
  return true;
}

//--------------------------------------------------------------------------
// Find gST address for X64 modules
bool efi_analysis::EfiAnalyserX86::findSystemTableX64() {
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
        set_cmt(ea, "EFI_SYSTEM_TABLE *gST", true);
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
bool efi_analysis::EfiAnalyserX86::findSmstX64() {
  msg("[%s] gSmst finding\n", g_plugin_name);
  std::vector<ea_t> gSmstListSmmBase = findSmstSmmBase(bs_list);
  std::vector<ea_t> gSmstListSwDispatch = findSmstSwDispatch(bs_list);
  gSmstList.insert(gSmstList.end(), gSmstListSwDispatch.begin(),
                   gSmstListSwDispatch.end());
  gSmstList.insert(gSmstList.end(), gSmstListSmmBase.begin(), gSmstListSmmBase.end());

  // Deduplicate
  auto last = std::unique(gSmstList.begin(), gSmstList.end());
  gSmstList.erase(last, gSmstList.end());

  for (auto smst : gSmstList) {
    msg("[%s] 0x%016llX: gSmst\n", g_plugin_name, u64_addr(smst));
  }
  return gSmstList.size();
}

//--------------------------------------------------------------------------
// Find and mark gSmst global and local variable address for X64 module
// after Hex-Rays based analysis
bool efi_analysis::EfiAnalyserX86::findSmstPostProcX64() {
  for (auto ea : g_get_smst_location_calls) {
    msg("[%s] EfiSmmBase2Protocol->GetSmstLocation call: 0x%016llX\n", g_plugin_name,
        u64_addr(ea));
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
            set_cmt(addr, "_EFI_SMM_SYSTEM_TABLE2 *gSmst;", true);
          }
          break;
        case o_mem:
          smst_addr = insn.ops[1].addr;
          set_cmt(addr, "_EFI_SMM_SYSTEM_TABLE2 *gSmst;", true);
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
      if (!addr_in_vec(gSmstList, smst_addr)) {
        set_ptr_type_and_name(smst_addr, "gSmst", "_EFI_SMM_SYSTEM_TABLE2");
        gSmstList.push_back(smst_addr);
      }
    }

    if (!smst_stack.is_null()) {
      auto reg = smst_stack["reg"] == REG_RSP ? "RSP" : "RBP";
      msg("[%s]   Smst: 0x%016llX, reg = %s\n", g_plugin_name, u64_addr(smst_addr), reg);

      // try to extract ChildSwSmiHandler
      auto counter = 0;
      ea_t ea = static_cast<ea_t>(smst_stack["start"]);
      uint16_t smst_reg = BAD_REG;
      uint64_t rcx_last = BADADDR;
      while (ea < static_cast<ea_t>(smst_stack["end"])) {

        counter += 1;
        if (counter > 500) {
          break; // just in case
        }

        ea = next_head(ea, BADADDR);
        decode_insn(&insn, ea);

        if (insn.itype == NN_mov && insn.ops[0].type == o_reg &&
            insn.ops[1].type == o_displ && smst_stack["addr"] == insn.ops[1].addr) {
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

        if (rcx_last == BADADDR || smst_reg == BAD_REG) {
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
bool efi_analysis::EfiAnalyserX86::findBootServicesTables() {

  // init architecture-specific constants
  auto BS_OFFSET = BS_OFFSET_64;
  uint16_t REG_SP = static_cast<uint16_t>(REG_RSP);

  if (arch == ArchFileType::X8632) {
    BS_OFFSET = BS_OFFSET_32;
    REG_SP = static_cast<uint16_t>(REG_ESP);
  }

  insn_t insn;
  for (auto seg : textSegments) {
    segment_t *s = seg;
    msg("[%s] gEfiBootServices finding from 0x%016llX to 0x%016llX\n", g_plugin_name,
        u64_addr(s->start_ea), u64_addr(s->end_ea));
    ea_t ea = s->start_ea;
    uint16_t bsRegister = 0;
    uint16_t stRegister = 0;
    ea_t var_addr = BADADDR; // current global variable address
    while (ea <= s->end_ea) {
      ea = next_head(ea, endAddress);
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
            ea = next_head(ea, endAddress);
            decode_insn(&insn, ea);
            if (insn.itype == NN_mov && insn.ops[0].type == o_reg &&
                insn.ops[1].type == o_imm) {
              var_addr = insn.ops[1].value;
              auto phrase_reg = insn.ops[0].phrase;
              auto next_ea = next_head(ea, BADADDR);
              insn_t next_insn;
              decode_insn(&next_insn, next_ea);
              if (next_insn.itype == NN_mov && next_insn.ops[0].type == o_phrase &&
                  next_insn.ops[0].phrase == phrase_reg &&
                  next_insn.ops[1].type == o_reg && next_insn.ops[1].reg == bsRegister) {
                baseInsnAddr = ea;
                if (!addr_in_vec(bs_list, var_addr)) {
                  set_cmt(ea, "EFI_BOOT_SERVICES *gBS", true);
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
                  set_cmt(ea, "EFI_BOOT_SERVICES *gBS", true);
                  set_ptr_type_and_name(var_addr, "gBS", "EFI_BOOT_SERVICES");
                  bs_list.push_back(var_addr);
                }
                bsFound = true;
              }

              // here you can also find gST
              if (insn.ops[1].reg == stRegister && !stFound && stRegister != bsRegister) {
                var_addr = insn.ops[0].addr;
                if (!addr_in_tables(st_list, bs_list, rt_list, var_addr)) {
                  set_cmt(ea, "EFI_SYSTEM_TABLE *gST", true);
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
                addr = prev_head(addr, startAddress);
                decode_insn(&insn, addr);
                if (insn.itype == NN_mov && insn.ops[1].type == o_reg &&
                    insn.ops[1].reg == stRegister && insn.ops[0].type == o_mem) {
                  var_addr = insn.ops[0].addr;
                  if (!addr_in_tables(st_list, bs_list, rt_list, var_addr)) {
                    set_cmt(addr, "EFI_SYSTEM_TABLE *gST", true);
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
bool efi_analysis::EfiAnalyserX86::findRuntimeServicesTables() {

  // init architecture-specific constants
  auto RT_OFFSET = RT_OFFSET_64;
  uint16_t REG_SP = static_cast<uint16_t>(REG_RSP);

  if (arch == ArchFileType::X8632) {
    RT_OFFSET = RT_OFFSET_32;
    REG_SP = static_cast<uint16_t>(REG_ESP);
  }

  insn_t insn;
  for (auto seg : textSegments) {
    segment_t *s = seg;
    msg("[%s] gEfiRuntimeServices finding from 0x%016llX to 0x%016llX\n", g_plugin_name,
        u64_addr(s->start_ea), u64_addr(s->end_ea));
    ea_t ea = s->start_ea;
    uint16_t rtRegister = 0;
    uint16_t stRegister = 0;
    ea_t var_addr = BADADDR; // current global variable address
    while (ea <= s->end_ea) {
      ea = next_head(ea, endAddress);
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
            ea = next_head(ea, endAddress);
            decode_insn(&insn, ea);
            if (insn.itype == NN_mov && insn.ops[0].type == o_reg &&
                insn.ops[1].type == o_imm) {
              var_addr = insn.ops[1].value;
              auto phrase_reg = insn.ops[0].phrase;
              auto next_ea = next_head(ea, BADADDR);
              insn_t next_insn;
              decode_insn(&next_insn, next_ea);
              if (next_insn.itype == NN_mov && next_insn.ops[0].type == o_phrase &&
                  next_insn.ops[0].phrase == phrase_reg &&
                  next_insn.ops[1].type == o_reg && next_insn.ops[1].reg == rtRegister) {
                baseInsnAddr = ea;
                if (!addr_in_vec(rt_list, var_addr)) {
                  set_cmt(ea, "EFI_RUNTIME_SERVICES *gRT", true);
                  set_ptr_type_and_name(var_addr, "gRT", "EFI_RUNTIME_SERVICES");
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
                  set_cmt(ea, "EFI_RUNTIME_SERVICES *gRT", true);
                  set_ptr_type_and_name(var_addr, "gRT", "EFI_RUNTIME_SERVICES");
                  rt_list.push_back(var_addr);
                }
                rtFound = true;
              }

              // here you can also find gST
              if (insn.ops[1].reg == stRegister && !stFound && stRegister != rtRegister) {
                var_addr = insn.ops[0].addr;
                if (!addr_in_tables(st_list, bs_list, rt_list, var_addr)) {
                  set_cmt(ea, "EFI_SYSTEM_TABLE *gST", true);
                  set_ptr_type_and_name(insn.ops[0].addr, "gST", "EFI_SYSTEM_TABLE");
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
                addr = prev_head(addr, startAddress);
                decode_insn(&insn, addr);
                if (insn.itype == NN_mov && insn.ops[1].type == o_reg &&
                    insn.ops[1].reg == stRegister && insn.ops[0].type == o_mem) {
                  if (!addr_in_tables(st_list, bs_list, rt_list, var_addr)) {
                    set_cmt(addr, "EFI_SYSTEM_TABLE *gST", true);
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
void efi_analysis::EfiAnalyserX86::getAllBootServices() {
  msg("[%s] BootServices finding (xrefs)\n", g_plugin_name);

  if (!bs_list.size()) {
    return;
  }

  insn_t insn;
  for (auto bs : bs_list) {

    msg("[%s] BootServices finding by xrefs to gBS (0x%016llX)\n", g_plugin_name,
        u64_addr(bs));

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
            if (arch == ArchFileType::X8632) {
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
              bootServices[static_cast<std::string>(g_boot_services_table_all[j].name)]
                  .push_back(addr);

              // add item to allBootServices
              json bsItem;
              bsItem["address"] = addr;
              bsItem["service_name"] =
                  static_cast<std::string>(g_boot_services_table_all[j].name);
              bsItem["table_name"] = static_cast<std::string>("EFI_BOOT_SERVICES");
              bsItem["offset"] = offset;

              // add code addresses for arguments
              eavec_t args;
              get_arg_addrs(&args, addr);
              bsItem["args"] = args;

              if (!json_in_vec(allServices, bsItem)) {
                allServices.push_back(bsItem);
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
void efi_analysis::EfiAnalyserX86::getAllRuntimeServices() {
  msg("[%s] RuntimeServices finding (xrefs)\n", g_plugin_name);

  if (!rt_list.size()) {
    return;
  }

  insn_t insn;
  for (auto rt : rt_list) {
    auto xrefs = get_xrefs_util(rt);

    msg("[%s] RuntimeServices finding by xrefs to gRT (0x%016llX)\n", g_plugin_name,
        u64_addr(rt));

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
            if (arch == ArchFileType::X8632) {
              offset = g_runtime_services_table_all[j].offset32;
            }
            if (service_offset == u32_addr(offset)) {
              op_stroff_util(addr, "EFI_RUNTIME_SERVICES");
              msg("[%s] 0x%016llX : %s\n", g_plugin_name, u64_addr(addr),
                  static_cast<char *>(g_runtime_services_table_all[j].name));
              runtimeServicesAll[static_cast<std::string>(
                                     g_runtime_services_table_all[j].name)]
                  .push_back(addr);

              // add item to allRuntimeServices
              json rtItem;
              rtItem["address"] = addr;
              rtItem["service_name"] =
                  static_cast<std::string>(g_runtime_services_table_all[j].name);
              rtItem["table_name"] = static_cast<std::string>("EFI_RUNTIME_SERVICES");
              rtItem["offset"] = offset;

              // add code addresses for arguments
              eavec_t args;
              get_arg_addrs(&args, addr);
              rtItem["args"] = args;

              if (!json_in_vec(allServices, rtItem)) {
                allServices.push_back(rtItem);
              }
              gRtServicesList.push_back(addr);
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
void efi_analysis::EfiAnalyserX86::getAllSmmServicesX64() {
  msg("[%s] SmmServices finding (xrefs)\n", g_plugin_name);

  if (!gSmstList.size()) {
    return;
  }

  insn_t insn;
  for (auto smms : gSmstList) {
    auto xrefs = get_xrefs_util(smms);

    msg("[%s] SmmServices finding by xref to gSmst (0x%016llX)\n", g_plugin_name,
        u64_addr(smms));

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
            if (insn.ops[0].addr == u32_addr(g_smm_services_table_all[j].offset64)) {

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

              std::string cmt =
                  "gSmst->" + static_cast<std::string>(g_smm_services_table_all[j].name);
              set_cmt(addr, cmt.c_str(), true);
              op_stroff_util(addr, "_EFI_SMM_SYSTEM_TABLE2");
              msg("[%s] 0x%016llX : %s\n", g_plugin_name, u64_addr(addr),
                  static_cast<char *>(g_smm_services_table_all[j].name));

              // add address to smmServices[...]
              if (find(protSmmNames.begin(), protSmmNames.end(),
                       g_smm_services_table_all[j].name) != protSmmNames.end()) {
                smmServices[g_smm_services_table_all[j].name].push_back(addr);
              }
              smmServicesAll[static_cast<std::string>(g_smm_services_table_all[j].name)]
                  .push_back(addr);

              // add item to allSmmServices
              json smmsItem;
              smmsItem["address"] = addr;
              smmsItem["service_name"] =
                  static_cast<std::string>(g_smm_services_table_all[j].name);
              smmsItem["table_name"] = static_cast<std::string>("_EFI_SMM_SYSTEM_TABLE2");
              smmsItem["offset"] = g_smm_services_table_all[j].offset64;

              // add code addresses for arguments
              eavec_t args;
              get_arg_addrs(&args, addr);
              smmsItem["args"] = args;

              if (!json_in_vec(allServices, smmsItem)) {
                allServices.push_back(smmsItem);
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
void efi_analysis::EfiAnalyserX86::getAllPeiServicesX86() {
  msg("[%s] PeiServices finding from 0x%016llX to 0x%016llX (all)\n", g_plugin_name,
      u64_addr(startAddress), u64_addr(endAddress));
  ea_t ea = startAddress;
  insn_t insn;
  auto found = false;
  while (ea <= endAddress) {
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
            address = prev_head(address, startAddress);
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
            address = prev_head(address, startAddress);
            decode_insn(&aboveInst, address);
            if (aboveInst.itype == NN_push) {
              if (aboveInst.ops[0].type == o_reg && aboveInst.ops[0].reg == src_reg) {
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
            peiServicesAll[static_cast<std::string>(g_pei_services_table32[j].name)]
                .push_back(ea);
            json psItem;
            psItem["address"] = ea;
            psItem["service_name"] =
                static_cast<std::string>(g_pei_services_table32[j].name);
            psItem["table_name"] = static_cast<std::string>("EFI_PEI_SERVICES");
            psItem["offset"] = g_pei_services_table32[j].offset;

            // add code addresses for arguments
            psItem["args"] = args;

            if (!json_in_vec(allServices, psItem)) {
              allServices.push_back(psItem);
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
void efi_analysis::EfiAnalyserX86::getAllVariablePPICallsX86() {
  msg("[%s] Variable PPI calls finding from 0x%016llX to 0x%016llX (all)\n",
      g_plugin_name, u64_addr(startAddress), u64_addr(endAddress));
  ea_t ea = startAddress;
  insn_t insn;
  auto found = false;
  while (ea <= endAddress) {
    ea = next_head(ea, BADADDR);
    decode_insn(&insn, ea);
    if (insn.itype == NN_callni && insn.ops[0].type == o_phrase) {
      for (int j = 0; j < g_variable_ppi_table_all_count; j++) {
        if (insn.ops[0].addr == u32_addr(g_variable_ppi_table_all[j].offset32)) {
          uint16_t ppi_reg = insn.ops[0].reg;
          insn_t aboveInst;
          ea_t address = ea;
          bool found_push = false;

          for (auto j = 0; j < 15; j++) {
            address = prev_head(address, startAddress);
            decode_insn(&aboveInst, address);
            if (aboveInst.itype == NN_push) {
              if (aboveInst.ops[0].type == o_reg && aboveInst.ops[0].reg == ppi_reg) {
                found_push = true;
              }
              break;
            }
          }

          if (found_push) {
            op_stroff_util(ea, "EFI_PEI_READ_ONLY_VARIABLE2_PPI");
            msg("[%s] 0x%016llX : %s\n", g_plugin_name, u64_addr(ea),
                static_cast<char *>(g_variable_ppi_table_all[j].name));
            std::string ppi_call = "VariablePPI." + static_cast<std::string>(
                                                        g_variable_ppi_table_all[j].name);
            ppiCallsAll[ppi_call].push_back(ea);

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

            if (!json_in_vec(allServices, ppiItem)) {
              allServices.push_back(ppiItem);
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
void efi_analysis::EfiAnalyserX86::getPpiNamesX86() {
  msg("[%s] PPI finding (PEI services)\n", g_plugin_name);
  ea_t start = startAddress;
  segment_t *seg_info = get_segm_by_name(".text");
  if (seg_info != nullptr) {
    start = seg_info->start_ea;
  }
  for (int i = 0; i < g_pei_services_table32_count; i++) {
    if (g_pei_services_table32[i].push_number == PUSH_NONE ||
        !peiServicesAll.contains(g_pei_services_table_all[i].name)) {
      continue;
    }

    std::vector<ea_t> addrs = peiServicesAll[g_pei_services_table32[i].name];

    // for each PEI service
    for (auto ea : addrs) {
      ea_t address = ea;

      insn_t insn;
      ea_t guidCodeAddress = 0;
      ea_t guidDataAddress = 0;
      auto found = false;

      uint16_t pushCounter = 0;
      msg("[%s] looking for PPIs in the 0x%016llX area (push number: %d)\n",
          g_plugin_name, u64_addr(address), g_pei_services_table32[i].push_number);

      // Check current basic block
      while (true) {
        address = prev_head(address, startAddress);
        decode_insn(&insn, address);

        if (insn.itype == NN_push) {
          pushCounter += 1;
        }

        if (pushCounter == g_pei_services_table32[i].push_number &&
            insn.ops[0].type == o_imm && (insn.ops[0].value & 0xffffffff) >= start &&
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

      msg("[%s] GUID address: 0x%016llX\n", g_plugin_name, u64_addr(guidDataAddress));

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
        auto it = dbProtocolsMap.find(guid);
        if (it != dbProtocolsMap.end()) {
          std::string name = it->second;
          ppiItem["ppi_name"] = name;

          // check if item already exists
          if (!json_in_vec(allPPIs, ppiItem)) {
            allPPIs.push_back(ppiItem);
          }
          continue;
        }

        // proprietary PPI
        if (ppiItem["ppi_name"].is_null()) {
          ppiItem["ppi_name"] = "ProprietaryPpi";

          // check if item already exists
          if (!json_in_vec(allPPIs, ppiItem)) {
            allPPIs.push_back(ppiItem);
          }
          continue;
        }
      }
    }
  }
}

//--------------------------------------------------------------------------
// Get boot services by protocols for X64 modules
void efi_analysis::EfiAnalyserX86::getProtBootServicesX64() {
  insn_t insn;
  for (auto s : textSegments) {
    msg("[%s] BootServices finding from 0x%016llX to 0x%016llX (protocols)\n",
        g_plugin_name, u64_addr(s->start_ea), u64_addr(s->end_ea));
    ea_t ea = s->start_ea;
    uint16_t bsRegister = 0;
    while (ea <= s->end_ea) {
      ea = next_head(ea, endAddress);
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
        bootServices[static_cast<std::string>(g_boot_services_table64[i].name)].push_back(
            ea);

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

        if (!json_in_vec(allServices, bsItem)) {
          allServices.push_back(bsItem);
        }
        break;
      }
    }
  }
}

//--------------------------------------------------------------------------
// Get boot services by protocols for X86 modules
void efi_analysis::EfiAnalyserX86::getProtBootServicesX86() {
  msg("[%s] BootServices finding from 0x%016llX to 0x%016llX (protocols)\n",
      g_plugin_name, u64_addr(startAddress), u64_addr(endAddress));
  ea_t ea = startAddress;
  insn_t insn;
  uint16_t bsRegister = 0;
  while (ea <= endAddress) {
    ea = next_head(ea, endAddress);
    decode_insn(&insn, ea);
    if (insn.itype == NN_callni && insn.ops[0].reg == REG_EAX) {
      for (auto i = 0; i < g_boot_services_table32_count; i++) {
        if (insn.ops[0].addr == u32_addr(g_boot_services_table32[i].offset)) {
          op_stroff_util(ea, "EFI_BOOT_SERVICES");
          msg("[%s] 0x%016llX : %s\n", g_plugin_name, u64_addr(ea),
              static_cast<char *>(g_boot_services_table32[i].name));
          bootServices[static_cast<std::string>(g_boot_services_table32[i].name)]
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

          if (!json_in_vec(allServices, bsItem)) {
            allServices.push_back(bsItem);
          }
          break;
        }
      }
    }
  }
}

//--------------------------------------------------------------------------
// find other addresses of global gBS vars for X64 modules
void efi_analysis::EfiAnalyserX86::findOtherBsTablesX64() {
  msg("[%s] Finding of other addresses of global gBS variables\n", g_plugin_name);
  for (auto s : allServices) {
    std::string table_name = s["table_name"];
    if (table_name.compare(static_cast<std::string>("EFI_BOOT_SERVICES"))) {
      continue;
    }
    auto offset = u32_addr(s["offset"]);
    if (offset < 0xf0) {
      continue;
    }
    ea_t addr = static_cast<ea_t>(s["address"]);
    msg("[%s] current service: 0x%016llX\n", g_plugin_name, u64_addr(addr));
    ea_t addr_bs = find_unknown_bs_var_64(addr);
    if (!addr_bs || addr_in_vec(bs_list, addr_bs) || addr_in_vec(rt_list, addr_bs)) {
      continue;
    }
    msg("[%s] found BootServices table at 0x%016llX, address = 0x%016llX\n",
        g_plugin_name, u64_addr(addr), u64_addr(addr_bs));
    set_ptr_type_and_name(addr_bs, "gBS", "EFI_BOOT_SERVICES");
    bs_list.push_back(addr_bs);
  }
}

bool efi_analysis::EfiAnalyser::AddProtocol(std::string serviceName, ea_t guidAddress,
                                            ea_t xrefAddress, ea_t call_address) {

  if (arch != ArchFileType::Uefi && guidAddress >= startAddress &&
      guidAddress <= endAddress) {
    msg("[%s] wrong service call detection: 0x%016llX\n", g_plugin_name,
        u64_addr(call_address));
    return false; // filter FP
  }

  json protocol;
  auto guid = get_guid_by_address(guidAddress);
  protocol["address"] = guidAddress;
  protocol["xref"] = xrefAddress;
  protocol["service"] = serviceName;
  protocol["guid"] = guid_to_string(guid);
  protocol["ea"] = call_address;

  qstring moduleName("Current");
  if (input_file_type() == ArchFileType::Uefi) {
    moduleName = get_module_name_loader(call_address);
  }
  protocol["module"] = static_cast<std::string>(moduleName.c_str());

  // find GUID name
  auto it = dbProtocolsMap.find(guid);
  if (it != dbProtocolsMap.end()) {
    std::string name = it->second;
    protocol["prot_name"] = name;
  } else {
    protocol["prot_name"] = "UNKNOWN_PROTOCOL_GUID";
    set_type_and_name(guidAddress, "UNKNOWN_PROTOCOL_GUID", "EFI_GUID");
  }
  if (!json_in_vec(allProtocols, protocol)) {
    allProtocols.push_back(protocol);
  }
  return true;
}

//--------------------------------------------------------------------------
// Extract protocols from InstallMultipleProtocolInterfaces service call
bool efi_analysis::EfiAnalyserX86::InstallMultipleProtocolInterfacesHandler() {
  std::vector<ea_t> addrs = bootServices["InstallMultipleProtocolInterfaces"];
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
      address = prev_head(address, startAddress);
      decode_insn(&insn, address);

      if (!check_stack && found) {
        break; // installed only one protocol
      }

      // Exit loop if end of previous basic block found
      if (is_basic_block_end(insn, false)) {
        break;
      }

      // Get handle stack/data parameter
      if (handle_arg == BADADDR && insn.itype == NN_lea && insn.ops[0].reg == REG_RCX) {
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

      // Exit from loop if found last argument (NULL)
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
          AddProtocol("InstallMultipleProtocolInterfaces", insn.ops[1].addr, address, ea);
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
        AddProtocol("InstallMultipleProtocolInterfaces", param.second, param.first, ea);
      }
    }
  }

  return true;
}

//--------------------------------------------------------------------------
// Get boot services protocols names for X64 modules
void efi_analysis::EfiAnalyserX86::getBsProtNamesX64() {
  if (!textSegments.size()) {
    return;
  }
  segment_t *s = textSegments.at(0);
  ea_t start = s->start_ea;
  msg("[%s] protocols finding (boot services, start address = 0x%016llX)\n",
      g_plugin_name, u64_addr(start));

  InstallMultipleProtocolInterfacesHandler();
  for (int i = 0; i < g_boot_services_table64_count; i++) {

    if (g_boot_services_table64[i].offset == InstallMultipleProtocolInterfacesOffset64) {
      // Handle InstallMultipleProtocolInterfaces separately
      continue;
    }

    std::vector<ea_t> addrs = bootServices[g_boot_services_table64[i].name];
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
        address = prev_head(address, startAddress);
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
        msg("[%s] getBsProtNamesX64: found protocol GUID parameter at "
            "0x%016llX\n",
            g_plugin_name, u64_addr(guidCodeAddress));
        auto guid = get_guid_by_address(guidDataAddress);
        if (!valid_guid(guid)) {
          msg("[%s] Incorrect GUID at 0x%016llX\n", g_plugin_name,
              u64_addr(guidCodeAddress));
          continue;
        }

        AddProtocol(g_boot_services_table64[i].name, guidDataAddress, guidCodeAddress,
                    ea);
      }
    }
  }
}

//--------------------------------------------------------------------------
// Get boot services protocols names for X86 modules
void efi_analysis::EfiAnalyserX86::getBsProtNamesX86() {
  msg("[%s] protocols finding (boot services)\n", g_plugin_name);
  ea_t start = startAddress;
  segment_t *seg_info = get_segm_by_name(".text");
  if (seg_info != nullptr) {
    start = seg_info->start_ea;
  }
  for (int i = 0; i < g_boot_services_table32_count; i++) {
    std::vector<ea_t> addrs = bootServices[g_boot_services_table32[i].name];

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
        address = prev_head(address, startAddress);
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
        msg("[%s] getBsProtNamesX86: found protocol GUID parameter at "
            "0x%016llX\n",
            g_plugin_name, u64_addr(guidCodeAddress));
        auto guid = get_guid_by_address(guidDataAddress);
        if (!valid_guid(guid)) {
          msg("[%s] Incorrect GUID at 0x%016llX\n", g_plugin_name,
              u64_addr(guidCodeAddress));
          continue;
        }

        AddProtocol(g_boot_services_table32[i].name, guidDataAddress, guidCodeAddress,
                    ea);
      }
    }
  }
}

//--------------------------------------------------------------------------
// Get smm services protocols names for X64 modules
void efi_analysis::EfiAnalyserX86::getSmmProtNamesX64() {
  if (!textSegments.size()) {
    return;
  }
  segment_t *s = textSegments.at(0);
  ea_t start = s->start_ea;
  msg("[%s] protocols finding (smm services, start address = 0x%016llX)\n", g_plugin_name,
      u64_addr(start));
  for (int i = 0; i < g_smm_services_prot64_count; i++) {
    auto addrs = smmServices[g_smm_services_prot64[i].name];

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
        address = prev_head(address, startAddress);
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
        msg("[%s] getSmmProtNamesX64: found protocol GUID parameter at "
            "0x%016llX\n",
            g_plugin_name, u64_addr(guidCodeAddress));
        auto guid = get_guid_by_address(guidDataAddress);
        if (!valid_guid(guid)) {
          msg("[%s] Incorrect GUID at 0x%016llX\n", g_plugin_name,
              u64_addr(guidCodeAddress));
          continue;
        }

        AddProtocol(g_smm_services_prot64[i].name, guidDataAddress, guidCodeAddress, ea);
      }
    }
  }
}

//--------------------------------------------------------------------------
// Mark protocols
void efi_analysis::EfiAnalyser::markInterfaces() {
  msg("[%s] %s marking\n", g_plugin_name, if_pl.c_str());
  for (auto ifItemIt = if_tbl->begin(); ifItemIt != if_tbl->end(); ++ifItemIt) {
    json ifItem = *ifItemIt;
    ea_t address = static_cast<ea_t>(ifItem["address"]);

    // check if guid on this address already marked
    bool marked = false;
    for (auto markedAddress = markedInterfaces.begin();
         markedAddress != markedInterfaces.end(); ++markedAddress) {
      if (*markedAddress == address) {
        marked = true;
        break;
      }
    }

    if (!marked) {
      std::string svcName = static_cast<std::string>(ifItem[if_key]);
      set_name(address, svcName.c_str(), SN_FORCE);
      set_guid_type(address);
      std::string comment = "EFI_GUID " + svcName;
      markedInterfaces.push_back(address);
      msg("[%s] address: 0x%016llX, comment: %s\n", g_plugin_name, u64_addr(address),
          comment.c_str());
    }
  }
}

//--------------------------------------------------------------------------
// Mark GUIDs found in the .text and .data segment
void efi_analysis::EfiAnalyser::markDataGuids() {
  ea_t ptrSize = inf_is_64bit() ? 8 : 4;
  auto guids_segments = textSegments;
  // find GUIDs in .text and .data segments
  // TODO: scan only the areas between the beginning of the .text segment and the first
  // function address (?)
  guids_segments.insert(guids_segments.end(), dataSegments.begin(), dataSegments.end());
  for (auto s : guids_segments) {
    msg("[%s] marking GUIDs from 0x%016llX to 0x%016llX\n", g_plugin_name,
        u64_addr(s->start_ea), u64_addr(s->end_ea));
    ea_t ea = s->start_ea;
    while (ea != BADADDR && ea <= s->end_ea - 15) {
      if (get_wide_dword(ea) == 0x00000000 || get_wide_dword(ea) == 0xffffffff) {
        ea += 1;
        continue;
      }
      auto guid = get_guid_by_address(ea);

      // find GUID name
      auto it = dbProtocolsMap.find(guid);
      if (it != dbProtocolsMap.end()) {
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
            if (!uint64_in_vec(ppiFlags, flags)) {
              continue;
            }
            msg("[%s] address: 0x%016llX, PPI: %s\n", g_plugin_name, u64_addr(ppiEa),
                ppiName.c_str());
            set_name(ppiEa, ppiName.c_str(), SN_FORCE);
          }
        }

        std::string comment = "EFI_GUID " + guidName;
        msg("[%s] address: 0x%016llX, comment: %s\n", g_plugin_name, u64_addr(ea),
            comment.c_str());

        json guid_item;
        guid_item["address"] = ea;
        guid_item["name"] = guidName;
        guid_item["guid"] = guid_to_string(guid);
        allGuids.push_back(guid_item);
        dataGuids.push_back(guid_item);
      }
      ea += 1;
    }
  }
}

//--------------------------------------------------------------------------
// Mark GUIDs found in local variables for X64 modules
void efi_analysis::EfiAnalyserX86::markLocalGuidsX64() {
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
          for (auto dbItem = dbProtocols.begin(); dbItem != dbProtocols.end(); ++dbItem) {
            auto guid = dbItem.value();
            if (data1 == static_cast<uint32_t>(guid[0]) &&
                data2 == static_cast<uint16_t>(guid[1])) {

              // mark local GUID
              std::string comment = "EFI_GUID " + dbItem.key();
              msg("[%s] address: 0x%016llX, comment: %s\n", g_plugin_name, u64_addr(ea),
                  comment.c_str());
              set_cmt(ea, comment.c_str(), true);

              json guid_item;
              guid_item["address"] = ea;
              guid_item["name"] = dbItem.key();
              guid_item["guid"] = guid_to_string(guid);
              allGuids.push_back(guid_item);
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
  for (ea_t ea = func->start_ea; ea < func->end_ea; ea = next_head(ea, BADADDR)) {
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

    if (insn.itype == NN_mov && insn.ops[0].type == o_reg && insn.ops[1].type == o_mem) {
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
          msg("[%s] SMM callout found (gBS): 0x%016llX\n", g_plugin_name, u64_addr(ea));
          calloutAddrs.push_back(ea);
          continue;
        }
      }

      // search for callouts with gRT
      if (addr_in_vec(rt_list, insn.ops[1].addr)) {
        msg("[%s] SMM callout found (gRT): 0x%016llX\n", g_plugin_name, u64_addr(ea));
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

          if (next_insn.itype == NN_callni && next_insn.ops[0].type == o_displ &&
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
// Find SmiHandler function inside SMM drivers
void efi_analysis::EfiAnalyser::findSwSmiHandlers() {
  std::map<EfiGuid *, std::string> types = {
      {&sw_guid2, "Sw"},
      {&sw_guid, "Sw"},
      {&sx_guid2, "Sx"},
      {&sx_guid, "Sx"},
      {&io_trap_guid2, "IoTrap"},
      {&io_trap_guid, "IoTrap"},
      {&gpi_guid2, "Gpi"},
      {&gpi_guid, "Gpi"},
      {&usb_guid2, "Usb"},
      {&usb_guid, "Usb"},
      {&standby_button_guid2, "StandbyButton"},
      {&standby_button_guid, "StandbyButton"},
      {&periodic_timer_guid2, "PeriodicTimer"},
      {&periodic_timer_guid, "PeriodicTimer"},
      {&power_button_guid2, "PowerButton"},
      {&power_button_guid, "PowerButton"},
      {&ichn_guid, "Ichn"},
      {&ichn_guid2, "Ichn"},
      {&tco_guid, "Tco"},
      {&pcie_guid, "Pcie"},
      {&acpi_guid, "Acpi"},
      {&gpio_unlock_guid, "GpioUnlock"},
      {&pch_guid, "Pch"},
      {&espi_guid, "Espi"},
      {&acpi_en_guid, "AcpiEn"},
      {&acpi_dis_guid, "AcpiDis"},
      {&fch_gpi_guid2, "Gpi"},
      {&fch_io_trap_guid2, "IoTrap"},
      {&fch_periodical_guid2, "PeriodicTimer"},
      {&fch_pwr_btn_guid2, "PowerButton"},
      {&fch_sw_guid2, "Sw"},
      {&fch_sx_guid2, "Sx"},
      {&fch_usb_guid2, "Usb"},
      {&fch_usb_guid, "Usb"},
      {&fch_misc_guid, "Misc"},
      {&fch_apu_ras_guid, "ApuRas"},
  };
  for (auto &[guid, prefix] : types) {
    auto res = findSmiHandlersSmmDispatch(*guid, prefix);
    smiHandlers.insert(smiHandlers.end(), res.begin(), res.end());
  }
}

//--------------------------------------------------------------------------
// Find callouts inside SwSmiHandler function:
//  * find SwSmiHandler function
//  * find gBS->service_name and gRT->service_name inside SmiHandler function
bool efi_analysis::EfiAnalyser::findSmmCallout() {
  msg("[%s] Looking for SMM callout\n", g_plugin_name);
  if (!bs_list.size() && !rt_list.size()) {
    return false;
  }
  if (!smiHandlers.size() && !childSmiHandlers.size()) {
    msg("[%s] can't find a SwSmiHandler functions\n", g_plugin_name);
    return false;
  }
  for (auto func : smiHandlers) {
    findCalloutRec(func);
  }
  for (auto func : childSmiHandlers) {
    findCalloutRec(func);
  }
  return true;
}

bool efi_analysis::EfiAnalyser::findPPIGetVariableStackOveflow() {
  msg("[%s] Looking for PPI GetVariable buffer overflow, "
      "allServices.size() = %lu\n",
      g_plugin_name, allServices.size());
  std::vector<ea_t> getVariableServicesCalls;
  std::string getVariableStr("VariablePPI.GetVariable");
  for (auto j_service : allServices) {
    json service = j_service;
    std::string service_name = static_cast<std::string>(service["service_name"]);
    std::string table_name = static_cast<std::string>(service["table_name"]);
    ea_t addr = static_cast<ea_t>(service["address"]);
    if (service_name.compare(getVariableStr) == 0) {
      getVariableServicesCalls.push_back(addr);
    }
  }
  msg("[%s] Finished iterating over allServices, "
      "getVariableServicesCalls.size() = "
      "%lu\n",
      g_plugin_name, getVariableServicesCalls.size());
  sort(getVariableServicesCalls.begin(), getVariableServicesCalls.end());
  if (getVariableServicesCalls.size() < 2) {
    msg("[%s] less than 2 VariablePPI.GetVariable calls found\n", g_plugin_name);
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
      if (insn.itype == NN_callni || insn.itype == NN_call || insn.itype == NN_retn ||
          insn.itype == NN_jmp || insn.itype == NN_jmpni) {
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
        address = prev_head(address, startAddress);
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
        address = prev_head(address, startAddress);
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
        address = prev_head(address, startAddress);
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
        address = prev_head(address, startAddress);
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
bool efi_analysis::EfiAnalyser::findGetVariableOveflow(std::vector<json> allServices) {
  msg("[%s] Looking for GetVariable stack/heap overflow\n", g_plugin_name);
  std::vector<ea_t> getVariableServicesCalls;
  std::string getVariableStr("GetVariable");
  for (auto j_service : allServices) {
    json service = j_service;
    std::string service_name = static_cast<std::string>(service["service_name"]);
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
    msg("[%s] GetVariable_1: 0x%016llX, GetVariable_2: 0x%016llX\n", g_plugin_name,
        u64_addr(prev_addr), u64_addr(curr_addr));

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
          insn.itype == NN_retn || insn.itype == NN_jmp || insn.itype == NN_jmpni ||
          dataSizeUseCounter > 1) {
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
bool efi_analysis::EfiAnalyser::findSmmGetVariableOveflow() {
  msg("[%s] Looking for SmmGetVariable stack/heap overflow\n", g_plugin_name);
  std::vector<ea_t> smmGetVariableCalls =
      findSmmGetVariableCalls(dataSegments, &allServices);
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
    msg("[%s] SmmGetVariable_1: 0x%016llX, SmmGetVariable_2: 0x%016llX\n", g_plugin_name,
        u64_addr(prev_addr), u64_addr(curr_addr));

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
      if (insn.itype == NN_callni || insn.itype == NN_retn || insn.itype == NN_jmpni ||
          insn.itype == NN_jmp) {
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

bool efi_analysis::EfiAnalyser::AnalyseVariableService(ea_t ea, std::string service_str) {
  msg("[%s] %s call: 0x%016llX\n", g_plugin_name, service_str.c_str(), u64_addr(ea));
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
  if (insn.itype == NN_lea && insn.ops[0].type == o_reg && insn.ops[0].reg == REG_RCX &&
      insn.ops[1].type == o_mem) {
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
  if (insn.itype == NN_lea && insn.ops[0].type == o_reg && insn.ops[0].reg == REG_RDX &&
      insn.ops[1].type == o_mem) {
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
      msg("[%s]  VendorGuid address (regarding to RBP): 0x%016llX\n", g_plugin_name,
          u64_addr(insn.ops[1].addr));
      EfiGuid guid = get_local_guid(f, insn.ops[1].addr);
      msg("[%s]  GUID: %s\n", g_plugin_name, guid.to_string().c_str());
      item["VendorGuid"] = guid.to_string();
      guid_found = true;
    }
    case REG_RSP: {
      msg("[%s]  VendorGuid address (regarding to RSP): 0x%016llX\n", g_plugin_name,
          u64_addr(insn.ops[1].addr));
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
  if (insn.itype == NN_xor && insn.ops[0].type == o_reg && insn.ops[1].type == o_reg &&
      insn.ops[0].reg == insn.ops[1].reg && insn.ops[0].reg == REG_R8) {
    item["Attributes"] = 0;
    std::string attributes_hr = "No attributes";
    item["AttributesHumanReadable"] = attributes_hr;
    msg("[%s]  Attributes: %d (%s)\n", g_plugin_name, 0, attributes_hr.c_str());
  } else {
#ifdef HEX_RAYS
    // Extract attributes with Hex-Rays SDK
    auto res = VariablesInfoExtractAll(f, ea);
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
    msg("[%s]  Attributes: %d (%s)\n", g_plugin_name, res, attributes_hr.c_str());
#else
    // If Hex-Rays analysis is not used, this feature does not work
    item["Attributes"] = 0xff;
    item["AttributesHumanReadable"] = "Unknown attributes";
#endif
  }

  if (name_found && guid_found) { // if only name or only GUID found, it will
                                  // now saved (check the logs)
    item["service"] = service_str;
    nvramVariables.push_back(item);
  }

  return true;
}

bool efi_analysis::EfiAnalyser::analyseNvramVariables() {
  msg("[%s] Get NVRAM variables information\n", g_plugin_name);
  std::vector<std::string> nvram_services = {"GetVariable", "SetVariable"};
  for (auto service_str : nvram_services) {
    std::vector<ea_t> var_services;
    for (auto j_service : allServices) {
      json service = j_service;
      std::string service_name = static_cast<std::string>(service["service_name"]);
      ea_t addr = static_cast<ea_t>(service["address"]);
      if (!service_name.compare(service_str)) {
        var_services.push_back(addr);
      }
    }
    sort(var_services.begin(), var_services.end());
    for (auto ea : var_services) {
      AnalyseVariableService(ea, service_str);
    }

    for (auto ea : g_smm_get_variable_calls) {
      AnalyseVariableService(ea, "EFI_SMM_VARIABLE_PROTOCOL::SmmGetVariable");
    }

    for (auto ea : g_smm_set_variable_calls) {
      AnalyseVariableService(ea, "EFI_SMM_VARIABLE_PROTOCOL::SmmSetVariable");
    }
  }
  return true;
}

//--------------------------------------------------------------------------
// Resolve EFI_SMM_CPU_PROTOCOL
bool efi_analysis::EfiAnalyser::efiSmmCpuProtocolResolver() {
  readSaveStateCalls = resolveEfiSmmCpuProtocol(stackGuids, dataGuids, &allServices);
  return true;
}

//--------------------------------------------------------------------------
// Dump all info to JSON file
void efi_analysis::EfiAnalyser::dumpInfo() {
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
  if (gSmstList.size()) {
    info["gSmstList"] = gSmstList;
  }
  if (gImageHandleList.size()) {
    info["gImageHandleList"] = gImageHandleList;
  }
  if (allPPIs.size()) {
    info["allPPIs"] = allPPIs;
  }
  if (allProtocols.size()) {
    info["allProtocols"] = allProtocols;
  }
  if (allServices.size()) {
    info["allServices"] = allServices;
  }
  if (allGuids.size()) {
    info["allGuids"] = allGuids;
  }
  if (nvramVariables.size()) {
    info["nvramVariables"] = nvramVariables;
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

  std::vector<json> smiHandlersAddrs;
  if (smiHandlers.size() > 0) {
    for (auto f : smiHandlers) {
      func_t *func = f;
      smiHandlersAddrs.push_back(func->start_ea);
    }
    info["smiHandlersAddrs"] = smiHandlersAddrs;
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
// Show all non-empty choosers windows
void showAllChoosers(efi_analysis::EfiAnalyserX86 analyser) {
  qstring title;

  // open window with all services
  if (analyser.allServices.size()) {
    title = "efiXplorer: services";
    services_show(analyser.allServices, title);
  }

  // open window with protocols
  if (analyser.file_type == FfsFileType::Pei) {
    if (analyser.allPPIs.size()) {
      title = "efiXplorer: PPIs";
      ppis_show(analyser.allPPIs, title);
    }

  } else { // FfsFileType::DxeAndTheLike
    if (analyser.allProtocols.size()) {
      title = "efiXplorer: protocols";
      protocols_show(analyser.allProtocols, title);
    }
  }

  // open window with data guids
  if (analyser.allGuids.size()) {
    qstring title = "efiXplorer: GUIDs";
    guids_show(analyser.allGuids, title);
  }

  // open window with NVRAM variables
  if (analyser.nvramVariables.size()) {
    qstring title = "efiXplorer: NVRAM";
    nvram_show(analyser.nvramVariables, title);
  }

  // open window with vulnerabilities
  if (calloutAddrs.size() || peiGetVariableOverflow.size() ||
      getVariableOverflow.size() || smmGetVariableOverflow.size()) {
    std::vector<json> vulns;
    std::map<std::string, std::vector<ea_t>> vulns_map = {
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
// Main function for X64 modules
bool efi_analysis::efiAnalyserMainX64() {
  show_wait_box("HIDECANCEL\nAnalysing module(s) with efiXplorer...");

  efi_analysis::EfiAnalyserX86 analyser;

  while (!auto_is_ok()) {
    auto_wait();
  };

  // find .text and .data segments
  analyser.getSegments();

  // analyse all
  auto res = ASKBTN_NO;
  if (analyser.arch == ArchFileType::Uefi) {
    res = ask_yn(1, "Want to further analyse all drivers with auto_mark_range?");
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
  analyser.markDataGuids();
  analyser.markLocalGuidsX64();

  if (g_args.disable_ui) {
    analyser.file_type = g_args.module_type == ModuleType::Pei
                             ? analyser.file_type = FfsFileType::Pei
                             : analyser.file_type = FfsFileType::DxeAndTheLike;
  } else {
    analyser.file_type = ask_file_type(&analyser.allGuids);
  }

  analyser.setStrings();

  // find global vars for gImageHandle, gST, gBS, gRT, gSmst
  if (analyser.file_type == FfsFileType::DxeAndTheLike) {
    analyser.findImageHandleX64();
    analyser.findSystemTableX64();
    analyser.findBootServicesTables();
    analyser.findRuntimeServicesTables();

    analyser.findSmstX64();

    // find Boot services and Runtime services
    analyser.getProtBootServicesX64();
    analyser.findOtherBsTablesX64();
    analyser.getAllBootServices();
    analyser.getAllRuntimeServices();

    analyser.getBsProtNamesX64();

#ifdef HEX_RAYS
    applyAllTypesForInterfacesBootServices(analyser.allProtocols);
    analyser.findSmstPostProcX64();
#endif

    // find SMM services
    analyser.getAllSmmServicesX64();
    analyser.getSmmProtNamesX64();

    // mark protocols
    analyser.markInterfaces();

    // search for copies of global variables
    mark_copies_for_gvars(gSmstList, "gSmst");
    mark_copies_for_gvars(bs_list, "gBS");
    mark_copies_for_gvars(rt_list, "gRT");

    // search for vulnerabilities
    if (!g_args.disable_vuln_hunt) {

      // find potential SMM callouts
      analyser.findSwSmiHandlers();
      analyser.findSmmCallout();

      // find potential OOB RW with GetVariable function
      analyser.findGetVariableOveflow(analyser.allServices);

      // find potential OOB RW with SmmGetVariable function
      analyser.findSmmGetVariableOveflow();
      analyser.efiSmmCpuProtocolResolver();
    }

#ifdef HEX_RAYS
    applyAllTypesForInterfacesSmmServices(analyser.allProtocols);
#endif

    analyser.analyseNvramVariables();

  } else {
    msg("[%s] Parsing of 64-bit PEI files is not supported yet\n", g_plugin_name);
  }

  // dump info to JSON file
  analyser.dumpInfo();

  // show all choosers windows
  if (!g_args.disable_ui) {
    showAllChoosers(analyser);
  }

  if (analyser.arch == ArchFileType::Uefi) {
    // Init public EdiDependencies members
    g_deps.getProtocolsChooser(analyser.allProtocols);
    g_deps.getProtocolsByGuids(analyser.allProtocols);

    // Save all protocols information to build dependencies
    attachActionProtocolsDeps();
    attachActionModulesSeq();
  }

  hide_wait_box();

  return true;
}

//--------------------------------------------------------------------------
// Main function for X86 modules
bool efi_analysis::efiAnalyserMainX86() {

  show_wait_box("HIDECANCEL\nAnalysing module(s) with efiXplorer...");

  efi_analysis::EfiAnalyserX86 analyser;

  while (!auto_is_ok()) {
    auto_wait();
  };

  // find .text and .data segments
  analyser.getSegments();

  // mark GUIDs
  analyser.markDataGuids();

  if (g_args.disable_ui) {
    analyser.file_type = g_args.module_type == ModuleType::Pei
                             ? analyser.file_type = FfsFileType::Pei
                             : analyser.file_type = FfsFileType::DxeAndTheLike;
  } else {
    analyser.file_type = ask_file_type(&analyser.allGuids);
  }

  analyser.setStrings();

  if (analyser.file_type == FfsFileType::DxeAndTheLike) {

    // find global vars for gST, gBS, gRT
    analyser.findBootServicesTables();
    analyser.findRuntimeServicesTables();

    // find boot services and runtime services
    analyser.getAllRuntimeServices();
    analyser.getProtBootServicesX86();
    analyser.getAllBootServices();

    // print and mark protocols
    analyser.getBsProtNamesX86();
    analyser.markInterfaces();

#ifdef HEX_RAYS
    applyAllTypesForInterfacesBootServices(analyser.allProtocols);
    applyAllTypesForInterfacesSmmServices(analyser.allProtocols);
#endif

  } else if (analyser.file_type == FfsFileType::Pei) {
    set_entry_arg_to_pei_svc();
    add_struct_for_shifted_ptr();
#ifdef HEX_RAYS
    for (auto addr : analyser.funcs) {
      DetectPeiServices(get_func(addr));
    }
#endif
    analyser.getAllPeiServicesX86();
    analyser.getPpiNamesX86();
    analyser.getAllVariablePPICallsX86();
    analyser.markInterfaces();

    // search for vulnerabilities
    if (!g_args.disable_vuln_hunt) {
      analyser.findPPIGetVariableStackOveflow();
    }
  }

  // dump info to JSON file
  analyser.dumpInfo();

  // show all choosers windows
  if (!g_args.disable_ui) {
    showAllChoosers(analyser);
  }

  hide_wait_box();

  return true;
}
