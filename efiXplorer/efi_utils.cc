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

#include "efi_utils.h"

#include "efi_global.h"
#include <algorithm>

// can be used after Hex-Rays based analysis
ea_list_t g_get_smst_location_calls;
ea_list_t g_smm_get_variable_calls;
ea_list_t g_smm_set_variable_calls;

//--------------------------------------------------------------------------
// get file format name
std::string file_format_name() {
  char file_format[256] = {0};
  get_file_type_name(file_format, 256);
  return file_format;
}

//--------------------------------------------------------------------------
// get input file type (PEI or DXE-like). No reliable way to determine FFS
// file type given only its PE/TE image section, so hello heuristics
ffs_file_type_t guess_file_type(arch_file_type_t arch,
                                json_list_t *m_all_guids) {
  if (arch == arch_file_type_t::uefi) {
    return ffs_file_type_t::dxe_smm;
  }

  segment_t *hdr_seg = get_segm_by_name("HEADER");
  if (hdr_seg == nullptr) {
    return ffs_file_type_t::dxe_smm;
  }

  uint64_t signature = get_wide_word(hdr_seg->start_ea);
  bool has_pei_guids = false;
  for (auto guid = m_all_guids->begin(); guid != m_all_guids->end(); guid++) {
    json guid_value = *guid;

    if (static_cast<std::string>(guid_value["name"]).find("PEI") !=
        std::string::npos) {
      has_pei_guids = true;
      break;
    }
  }

  bool has_pei_in_path = false;

  char file_name[256] = {0};
  get_input_file_path(file_name, sizeof(file_name));
  std::string file_name_str = file_name;

  if ((file_name_str.find("Pei") != std::string::npos ||
       file_name_str.find("pei") != std::string::npos || signature == VZ) &&
      arch == arch_file_type_t::x86_64) {
    has_pei_in_path = true;
  }

  if (signature == VZ || has_pei_guids) {
    efi_utils::log("analysing binary file as PEI, signature: %llx\n",
                   signature);
    return ffs_file_type_t::pei;
  }

  efi_utils::log("analysing binary file as DXE/SMM\n");
  return ffs_file_type_t::dxe_smm;
}

int parse_efi_pei_svc4() {
  return parse_decls(nullptr,
                     "struct EFI_PEI_SERVICES_4 {\n"
                     "  EFI_PEI_SERVICES **PeiServices;\n"
                     "  UINT32 BaseAddress;\n"
                     "};",
                     msg, HTI_DCL);
}

int parse_efi_pei_sidt() {
  return parse_decls(nullptr,
                     "struct EFI_PEI_SIDT {\n"
                     "  UINT16 Limit;\n"
                     "  int *__shifted(EFI_PEI_SERVICES_4, 4) BaseAddress;\n"
                     "};",
                     msg, HTI_DCL | HTI_PAK1);
}

bool mark_copy(ea_t code_addr, ea_t var_addr, std::string type) {
  insn_t insn;
  int reg = -1;
  ea_t ea = code_addr;
  ea_t var_copy = BADADDR;
  decode_insn(&insn, ea);

  if (insn.itype == NN_mov && insn.ops[0].type == o_reg &&
      insn.ops[1].type == o_mem && insn.ops[1].addr == var_addr) {
    reg = insn.ops[0].reg;
  }

  if (reg == -1) {
    return false;
  }

  for (auto i = 0; i < 8; ++i) {
    ea = next_head(ea, BADADDR);
    decode_insn(&insn, ea);

    if (is_basic_block_end(insn, false)) {
      break;
    }

    if ((insn.itype == NN_callni || insn.itype == NN_call) ||
        (insn.ops[0].type == o_reg && insn.ops[0].reg == reg)) {
      break;
    }

    if (insn.itype == NN_mov && insn.ops[0].type == o_mem &&
        insn.ops[1].type == o_reg && insn.ops[1].reg == reg) {
      var_copy = insn.ops[0].addr;
      efi_utils::log("found copy for global variable: 0x%" PRIx64 "\n",
                     u64_addr(ea));
      break;
    }
  }

  if (var_copy == BADADDR) {
    return false;
  }

  std::string name;

  if (type == "gSmst") {
    efi_utils::set_ptr_type_and_name(var_copy, "gSmst",
                                     "_EFI_SMM_SYSTEM_TABLE2");
  }

  if (type == "gBS") {
    efi_utils::set_ptr_type_and_name(var_copy, "gBS", "EFI_BOOT_SERVICES");
  }

  if (type == "gRT") {
    efi_utils::set_ptr_type_and_name(var_copy, "gRT", "EFI_RUNTIME_SERVICES");
  }

  return true;
}

//--------------------------------------------------------------------------
// msg wrapper
int efi_utils::log(const char *fmt, ...) {
  auto nbytes = msg("[%s] ", g_plugin_name);

  va_list va;
  va_start(va, fmt);

  nbytes += vmsg(fmt, va);

  va_end(va);
  return nbytes;
}

//--------------------------------------------------------------------------
// set EFI_GUID type
void efi_utils::set_guid_type(ea_t ea) {
  tinfo_t tinfo;
  if (tinfo.get_named_type(get_idati(), "EFI_GUID")) {
    apply_tinfo(ea, tinfo, TINFO_DEFINITE);
  }
}

//--------------------------------------------------------------------------
// set type and name
void efi_utils::set_type_and_name(ea_t ea, std::string name, std::string type) {
  set_name(ea, name.c_str(), SN_FORCE);
  tinfo_t tinfo;
  if (tinfo.get_named_type(get_idati(), type.c_str())) {
    apply_tinfo(ea, tinfo, TINFO_DEFINITE);
  }
}

//--------------------------------------------------------------------------
// set const CHAR16 type
void efi_utils::set_const_char16_type(ea_t ea) {
  tinfo_t tinfo;
  if (tinfo.get_named_type(get_idati(), "CHAR16")) {
    tinfo.set_const();
    apply_tinfo(ea, tinfo, TINFO_DEFINITE);
  }
}

//--------------------------------------------------------------------------
// get input file type (64-bit, 32-bit module or UEFI firmware)
arch_file_type_t efi_utils::input_file_type() {
  processor_t &ph = PH;
  auto filetype = inf_get_filetype();
  auto bits = inf_is_64bit() ? 64 : inf_is_32bit_exactly() ? 32 : 16;

  // check if the input file is a UEFI firmware image
  if (file_format_name().find("UEFI") != std::string::npos) {
    return arch_file_type_t::uefi;
  }

  if (filetype == f_PE || filetype == f_ELF) {
    if (ph.id == PLFM_386) {
      if (bits == 64)
        return arch_file_type_t::x86_64;
      if (bits == 32)
        return arch_file_type_t::x86_32;
    }
    if (ph.id == PLFM_ARM) {
      if (bits == 64)
        return arch_file_type_t::aarch64;
    }
  }
  return arch_file_type_t::unsupported;
}

ffs_file_type_t efi_utils::ask_file_type(json_list_t *m_all_guids) {
  auto arch = efi_utils::input_file_type();
  if (arch == arch_file_type_t::uefi || arch == arch_file_type_t::x86_64) {
    return ffs_file_type_t::dxe_smm;
  }
  auto ftype = guess_file_type(arch, m_all_guids);
  auto deflt = ftype == ffs_file_type_t::dxe_smm;
  auto fmt_param = ftype == ffs_file_type_t::dxe_smm ? "DXE/SMM" : "PEI";
  auto btn_id =
      ask_buttons("DXE/SMM", "PEI", "", deflt, "Analyse file as %s", fmt_param);
  if (btn_id == ASKBTN_YES) {
    return ffs_file_type_t::dxe_smm;
  }

  return ffs_file_type_t::pei;
}

//--------------------------------------------------------------------------
// find address of global gBS var for x86 64-bit module for each service
ea_t efi_utils::find_unknown_bs_var64(ea_t ea) {
  ea_t res = BADADDR;
  insn_t insn;

  // check 10 instructions below
  for (int i = 0; i < 10; i++) {
    decode_insn(&insn, ea);
    if (insn.itype == NN_mov && insn.ops[0].type == o_reg &&
        insn.ops[0].reg == R_RAX && insn.ops[1].type == o_mem) {
      res = insn.ops[1].addr;
      break;
    }
    ea = prev_head(ea, 0);
  }
  return res;
}

//--------------------------------------------------------------------------
// get all xrefs for given address
ea_list_t efi_utils::get_xrefs(ea_t addr) {
  ea_list_t xrefs;
  ea_t xref = get_first_dref_to(addr);
  while (xref != BADADDR) {
    xrefs.push_back(xref);
    xref = get_next_dref_to(addr, xref);
  }
  return xrefs;
}

//--------------------------------------------------------------------------
// get all xrefs for given array element
ea_list_t efi_utils::get_xrefs_to_array(ea_t addr) {
  ea_t first_ea;
  ea_t ea = addr;
  while (true) {
    auto ptr = get_qword(ea);
    auto xrefs = efi_utils::get_xrefs(ptr);
    if (std::find(xrefs.begin(), xrefs.end(), ea) == xrefs.end()) {
      break;
    }
    first_ea = ea;
    ea -= 8;
  }
  return efi_utils::get_xrefs(first_ea);
}

//--------------------------------------------------------------------------
// wrapper for op_stroff function
bool efi_utils::op_stroff(ea_t addr, std::string type) {
#if IDA_SDK_VERSION >= 840
  tinfo_t tinfo;
  if (!tinfo.get_named_type(get_idati(), type.c_str())) {
    return false;
  }

  // use force_tid() instead of get_tid()
  // to import type if it's not imported
  tid_t tid = tinfo.force_tid();
  if (tid == BADADDR) {
    return false;
  }
#else
  tid_t tid = get_struc_id(type.c_str());
#endif

  insn_t insn;
  decode_insn(&insn, addr);
  return op_stroff(insn, 0, &tid, 1, 0);
}

//--------------------------------------------------------------------------
// get pointer to named type and apply it
bool efi_utils::set_ptr_type(ea_t addr, std::string type) {
  tinfo_t tinfo;
  if (!tinfo.get_named_type(get_idati(), type.c_str())) {
    return false;
  }
  tinfo_t p_tinfo;
  p_tinfo.create_ptr(tinfo);
  apply_tinfo(addr, p_tinfo, TINFO_DEFINITE);
  return true;
}

//--------------------------------------------------------------------------
// set name and apply pointer to named type
void efi_utils::set_ptr_type_and_name(ea_t ea, std::string name,
                                      std::string type) {
  set_name(ea, name.c_str(), SN_FORCE);
  efi_utils::set_ptr_type(ea, type.c_str());
}

//--------------------------------------------------------------------------
// get guids.json file name
std::filesystem::path efi_utils::get_guids_json_file() {
  std::filesystem::path guids_json_path;

  // check {idadir}/plugins/guids.json
  guids_json_path /= idadir("plugins");
  guids_json_path /= "guids.json";
  if (std::filesystem::exists(guids_json_path)) {
    return guids_json_path;
  }

  // check {idadir}/plugins/guids/guids.json
  guids_json_path.clear();
  guids_json_path /= idadir("plugins");
  guids_json_path /= "guids";
  guids_json_path /= "guids.json";
  if (std::filesystem::exists(guids_json_path)) {
    return guids_json_path;
  }

  // try to load it from the per-user directory.
  guids_json_path.clear();
  guids_json_path /= get_user_idadir();
  guids_json_path /= "plugins";
  guids_json_path /= "guids.json";
  if (std::filesystem::exists(guids_json_path)) {
    return guids_json_path;
  }

  guids_json_path.clear();
  guids_json_path /= get_user_idadir();
  guids_json_path /= "plugins";
  guids_json_path /= "guids";
  guids_json_path /= "guids.json";
  if (std::filesystem::exists(guids_json_path)) {
    return guids_json_path;
  }

  // does not exist
  guids_json_path.clear();
  return guids_json_path;
}

//--------------------------------------------------------------------------
// get json summary file name
std::filesystem::path efi_utils::get_summary_file() {
  std::string idb_path;
  idb_path = get_path(PATH_TYPE_IDB);
  std::filesystem::path log_file;
  log_file /= idb_path;
  log_file.replace_extension(".json");
  return log_file;
}

//--------------------------------------------------------------------------
// check if summary json file exists
bool efi_utils::summary_json_exists() {
  std::string idb_path;
  idb_path = get_path(PATH_TYPE_IDB);
  std::filesystem::path log_file;
  log_file /= idb_path;
  log_file.replace_extension(".json");
  return std::filesystem::exists(log_file);
}

//--------------------------------------------------------------------------
// change EFI_SYSTEM_TABLE *SystemTable to EFI_PEI_SERVICES **PeiService
// at ModuleEntryPoint
void efi_utils::set_entry_arg_to_pei_svc() {
  for (auto idx = 0; idx < get_entry_qty(); idx++) {
    uval_t ord = get_entry_ordinal(idx);
    ea_t start_ea = get_entry(ord);
    tinfo_t tif_ea;
    if (guess_tinfo(&tif_ea, start_ea) == GUESS_FUNC_FAILED) {
      continue;
    }

    func_type_data_t funcdata;
    if (!tif_ea.get_func_details(&funcdata)) {
      continue;
    }

    tinfo_t tif_pei;
    bool res = tif_pei.get_named_type(get_idati(), "EFI_PEI_SERVICES");
    if (!res) {
      continue;
    }

    tinfo_t p_tinfo;
    tinfo_t pp_tinfo;
    p_tinfo.create_ptr(tif_pei);
    pp_tinfo.create_ptr(p_tinfo);

    // funcdata.size() does not work for aarch64
    if (funcdata.size() == 2) {
      funcdata[1].type = pp_tinfo;
      funcdata[1].name = "PeiServices";
      tinfo_t f_tinfo;
      if (!f_tinfo.create_func(funcdata)) {
        continue;
      }

      if (!apply_tinfo(start_ea, f_tinfo, TINFO_DEFINITE)) {
        continue;
      }
    }
  }
}

bool efi_utils::set_ret_to_pei_svc(ea_t start_ea) {
  tinfo_t tif_ea;
  if (guess_tinfo(&tif_ea, start_ea) == GUESS_FUNC_FAILED) {
    return false;
  }
  func_type_data_t fi;
  if (!tif_ea.get_func_details(&fi)) {
    return false;
  }
  tinfo_t tif_pei;
  if (!tif_pei.get_named_type(get_idati(), "EFI_PEI_SERVICES")) {
    return false;
  }
  tinfo_t p_tinfo;
  tinfo_t pp_tinfo;
  p_tinfo.create_ptr(tif_pei);
  pp_tinfo.create_ptr(p_tinfo);

  fi.rettype = pp_tinfo;

  tinfo_t f_tinfo;
  if (!f_tinfo.create_func(fi)) {
    return false;
  }

  if (!apply_tinfo(start_ea, f_tinfo, TINFO_DEFINITE)) {
    return false;
  }

  return true;
}

//--------------------------------------------------------------------------
// add EFI_PEI_SERVICES_4 structure
bool efi_utils::add_struct_for_shifted_ptr() {
#if IDA_SDK_VERSION < 900
  auto sid = add_struc(BADADDR, "EFI_PEI_SERVICES_4");
  if (sid == BADADDR) {
    return false;
  }

  auto new_struct = get_struc(sid);
  if (new_struct == nullptr) {
    return false;
  }

  add_struc_member(new_struct, nullptr, 0, dword_flag(), nullptr, 4);
  add_struc_member(new_struct, nullptr, 4, dword_flag(), nullptr, 4);
  set_member_name(new_struct, 0, "PeiServices");
  set_member_name(new_struct, 4, "BaseAddress");

  tinfo_t tinfo;
  if (!tinfo.get_named_type(get_idati(), "EFI_PEI_SERVICES")) {
    return false;
  }

  // set type "EFI_PEI_SERVICES **PeiServices"
  tinfo_t p_tinfo;
  tinfo_t pp_tinfo;
  p_tinfo.create_ptr(tinfo);
  pp_tinfo.create_ptr(p_tinfo);

  auto member = get_member_by_name(new_struct, "PeiServices");
  set_member_tinfo(new_struct, member, 0, pp_tinfo, 0);

  return true;
#else
  // return true if there are no errors from parse_decls()
  return !parse_efi_pei_svc4() && !parse_efi_pei_sidt();
#endif
}

//--------------------------------------------------------------------------
// get module name by address
qstring efi_utils::get_module_name_loader(ea_t addr) {
  segment_t *seg = getseg(addr);
  qstring seg_name;
  get_segm_name(&seg_name, seg);
  return seg_name.remove(seg_name.size() - 7, seg_name.size());
}

//--------------------------------------------------------------------------
// get GUID data by address
json efi_utils::get_guid_by_address(ea_t addr) {
  return json::array({get_wide_dword(addr), get_wide_word(addr + 4),
                      get_wide_word(addr + 6), get_wide_byte(addr + 8),
                      get_wide_byte(addr + 9), get_wide_byte(addr + 10),
                      get_wide_byte(addr + 11), get_wide_byte(addr + 12),
                      get_wide_byte(addr + 13), get_wide_byte(addr + 14),
                      get_wide_byte(addr + 15)});
}

//--------------------------------------------------------------------------
// validate GUID value
bool efi_utils::valid_guid(json guid) {
  uint32_t data0 = guid[0];
  uint32_t data1 = guid[1];

  auto invalid = (!data0 && !data1) || (data0 == 0xffffffff && data1 == 0xffff);
  return !invalid;
}

//--------------------------------------------------------------------------
// convert GUID value to string
std::string efi_utils::guid_to_string(json guid) {
  char guid_str[37] = {0};
  snprintf(guid_str, sizeof(guid_str),
           "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
           static_cast<uint32_t>(guid[0]), static_cast<uint16_t>(guid[1]),
           static_cast<uint16_t>(guid[2]), static_cast<uint8_t>(guid[3]),
           static_cast<uint8_t>(guid[4]), static_cast<uint8_t>(guid[5]),
           static_cast<uint8_t>(guid[6]), static_cast<uint8_t>(guid[7]),
           static_cast<uint8_t>(guid[8]), static_cast<uint8_t>(guid[9]),
           static_cast<uint8_t>(guid[10]));
  return guid_str;
}

uint8_list_t efi_utils::unpack_guid(std::string guid) {
  uint8_list_t res;
  std::string delim = "-";
  std::string byte_str;
  uint8_t byte;
  size_t pos = 0;

  auto index = 0;
  while ((pos = guid.find(delim)) != std::string::npos) {
    uint8_list_t tmp;
    auto hex = guid.substr(0, pos);
    if (hex.size() % 2) {
      break;
    }
    for (auto i = 0; i < hex.size(); i += 2) {
      byte_str = hex.substr(i, 2);
      byte = strtol(byte_str.c_str(), nullptr, 16);
      tmp.push_back(byte);
    }
    if (index != 3) {
      res.insert(res.end(), tmp.rbegin(), tmp.rend());
    } else {
      res.insert(res.end(), tmp.begin(), tmp.end());
    }
    index += 1;
    guid.erase(0, pos + delim.size());
    tmp.clear();
  }

  for (auto i = 0; i < guid.size(); i += 2) {
    byte_str = guid.substr(i, 2);
    byte = strtol(byte_str.c_str(), nullptr, 16);
    res.push_back(byte);
  }

  return res;
}

ea_list_t efi_utils::search_protocol(std::string protocol) {
  uchar bytes[17] = {0};
  ea_list_t res;
  auto guid_bytes = efi_utils::unpack_guid(protocol);
  std::copy(guid_bytes.begin(), guid_bytes.end(), bytes);
  ea_t start = 0;
  while (true) {
#if IDA_SDK_VERSION < 900
    ea_t addr =
        bin_search2(start, BADADDR, bytes, nullptr, 16, BIN_SEARCH_FORWARD);
#else
    ea_t addr =
        bin_search(start, BADADDR, bytes, nullptr, 16, BIN_SEARCH_FORWARD);
#endif
    if (addr == BADADDR) {
      break;
    }
    res.push_back(addr);
    start = addr + 16;
  }
  return res;
}

bool efi_utils::check_install_protocol(ea_t ea) {
  insn_t insn;
  // search for `call [R + offset]` insn
  // offset in [0x80, 0xA8, 0x148]
  ea_t addr = ea;
  for (auto i = 0; i < 16; i++) {
    addr = next_head(addr, BADADDR);
    decode_insn(&insn, addr);
    if ((insn.itype == NN_jmpni || insn.itype == NN_callni) &&
        insn.ops[0].type == o_displ) {
      auto service = insn.ops[0].addr;
      // check for InstallProtocolInterface, InstallMultipleProtocolInterfaces,
      // SmmInstallProtocolInterface
      if (service == 0x80 || service == 0xa8 || service == 0x148) {
        return true;
      }
    }
  }
  return false;
}

//--------------------------------------------------------------------------
// convert 64-bit value to hex string
std::string efi_utils::as_hex(uint64_t value) {
  char hexstr[21] = {0};
  snprintf(hexstr, sizeof(hexstr), "%" PRIX64, value);
  return hexstr;
}

//--------------------------------------------------------------------------
// make sure that the first argument looks like a protocol
bool efi_utils::check_boot_service_protocol(ea_t call_addr) {
  bool valid = false;
  auto addr = prev_head(call_addr, 0);
  insn_t insn;
  decode_insn(&insn, addr);
  while (!is_basic_block_end(insn, false)) {
    // for next iteration
    decode_insn(&insn, addr);
    addr = prev_head(addr, 0);

    // check current instruction
    if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
        insn.ops[0].reg == R_RCX) {
      if (insn.ops[1].type == o_mem) {
        // will still be a false positive if the Handle in
        // SmmInstallProtocolInterface is a global variable)
        valid = true;
      }
      break;
    }
  }
  return valid;
}

//--------------------------------------------------------------------------
// make sure that the address does not belong to the protocol interface
bool efi_utils::check_boot_service_protocol_xrefs(ea_t call_addr) {
  insn_t insn;
  for (auto xref : efi_utils::get_xrefs(call_addr)) {
    decode_insn(&insn, xref);
    if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
        insn.ops[0].reg == R_R8) {
      // load interface instruction
      return false;
    }
  }
  return true;
}

bool efi_utils::mark_copies_for_gvars(ea_list_t gvars, std::string type) {
  for (auto var : gvars) {
    auto xrefs = efi_utils::get_xrefs(var);
    for (auto addr : xrefs) {
      mark_copy(addr, var, type);
    }
  }
  return true;
}

//--------------------------------------------------------------------------
// generate name string from type
std::string efi_utils::type_to_name(std::string type) {
  std::string result;
  size_t counter = 0;
  for (char const &c : type) {
    if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
      result.push_back(c);
      counter += 1;
      continue;
    }

    if (c >= 'A' && c <= 'Z') {
      if (counter > 0) {
        result.push_back(c + 32);
      } else {
        result.push_back(c);
      }
      counter += 1;
      continue;
    }

    if (c == '_') {
      counter = 0;
    } else {
      counter += 1;
    }
  }
  return result;
}

void op_stroff_for_addr(ea_t ea, qstring type_name) {
  insn_t insn;

  for (auto i = 0; i < 16; i++) {
    ea = next_head(ea, BADADDR);
    decode_insn(&insn, ea);
    // check for interface function call
    if ((insn.itype == NN_call || insn.itype == NN_callfi ||
         insn.itype == NN_callni) &&
        (insn.ops[0].type == o_displ || insn.ops[0].type == o_phrase) &&
        insn.ops[0].reg == R_RAX) {
      efi_utils::op_stroff(ea, type_name.c_str());
      efi_utils::log("mark arguments at address 0x%" PRIx64
                     " (interface type: %s)\n",
                     u64_addr(ea), type_name.c_str());

      // check for EfiSmmBase2Protocol->GetSmstLocation
      if (type_name == "EFI_SMM_BASE2_PROTOCOL" &&
          insn.ops[0].type == o_displ && insn.ops[0].addr == 8) {
        if (!efi_utils::addr_in_vec(g_get_smst_location_calls, ea)) {
          g_get_smst_location_calls.push_back(ea);
        }
      }

      if (type_name == "EFI_SMM_VARIABLE_PROTOCOL" &&
          insn.ops[0].type == o_phrase) {
        if (!efi_utils::addr_in_vec(g_smm_get_variable_calls, ea)) {
          g_smm_get_variable_calls.push_back(ea);
        }
      }

      if (type_name == "EFI_SMM_VARIABLE_PROTOCOL" &&
          insn.ops[0].type == o_displ && insn.ops[0].addr == 0x10) {
        if (!efi_utils::addr_in_vec(g_smm_set_variable_calls, ea)) {
          g_smm_set_variable_calls.push_back(ea);
        }
      }
      break;
    }

    // if the RAX value is overridden
    if (insn.ops[0].reg == R_RAX) {
      break;
    }
  }
}

//--------------------------------------------------------------------------
// mark the arguments of each function from an interface derived from
// a local variable
void efi_utils::op_stroff_for_interface(xreflist_t local_xrefs,
                                        qstring type_name) {
  insn_t insn;
  for (auto xref : local_xrefs) {
    decode_insn(&insn, xref.ea);
    if (insn.itype == NN_mov && insn.ops[0].reg == R_RAX) {
      op_stroff_for_addr(xref.ea, type_name);
    }
  }
}

//--------------------------------------------------------------------------
// mark the arguments of each function from an interface derived from
// a global variable
void efi_utils::op_stroff_for_global_interface(ea_list_t xrefs,
                                               qstring type_name) {
  insn_t insn;
  for (auto ea : xrefs) {
    decode_insn(&insn, ea);
    if (insn.itype == NN_mov && insn.ops[0].reg == R_RAX) {
      op_stroff_for_addr(ea, type_name);
    }
  }
}

bool efi_utils::uint64_in_vec(uint64_list_t vec, uint64_t value) {
  return find(vec.begin(), vec.end(), value) != vec.end();
}

bool efi_utils::addr_in_vec(ea_list_t vec, ea_t addr) {
  return find(vec.begin(), vec.end(), addr) != vec.end();
}

bool efi_utils::json_in_vec(json_list_t vec, json item) {
  return find(vec.begin(), vec.end(), item) != vec.end();
}

bool efi_utils::addr_in_tables(ea_list_t t1, ea_list_t t2, ea_t ea) {
  return (efi_utils::addr_in_vec(t1, ea) || efi_utils::addr_in_vec(t2, ea));
}

bool efi_utils::addr_in_tables(ea_list_t t1, ea_list_t t2, ea_list_t t3,
                               ea_t ea) {
  return (efi_utils::addr_in_vec(t1, ea) || efi_utils::addr_in_vec(t2, ea) ||
          efi_utils::addr_in_vec(t3, ea));
}

ea_list_t efi_utils::find_data(ea_t start_ea, ea_t end_ea, uchar *data,
                               size_t len) {
  ea_list_t res;
  ea_t start = start_ea;
  int counter = 0;
  while (true) {
#if IDA_SDK_VERSION < 900
    auto ea =
        bin_search2(start, end_ea, data, nullptr, len, BIN_SEARCH_FORWARD);
#else
    auto ea = bin_search(start, end_ea, data, nullptr, len, BIN_SEARCH_FORWARD);
#endif
    if (ea == BADADDR) {
      break;
    }
    res.push_back(ea);
    start = ea + len;
  }
  return res;
}

//--------------------------------------------------------------------------
// get wide string by address
std::string efi_utils::get_wide_string(ea_t addr) {
  std::string res;
  int index = 0;
  while (get_wide_word(addr + index)) {
    auto byte = get_wide_byte(addr + index);
    if (byte < 0x20 || byte > 0x7e) {
      return "invalid string";
    }
    res.push_back(byte);
    index += 2;
  }
  return res;
}

//--------------------------------------------------------------------------
// get efi_guid_t by address
efi_guid_t efi_utils::get_global_guid(ea_t addr) {
  efi_guid_t guid;
  guid.data1 = get_wide_dword(addr);
  guid.data2 = get_wide_word(addr + 4);
  guid.data3 = get_wide_word(addr + 6);
  for (auto i = 0; i < 8; i++) {
    guid.data4[i] = get_wide_byte(addr + 8 + i);
  }
  return guid;
}

//--------------------------------------------------------------------------
// get efi_guid_t by stack offset
efi_guid_t efi_utils::get_local_guid(func_t *f, uint64_t offset) {
  efi_guid_t guid;
  insn_t insn;
  auto ea = f->start_ea;
  int counter = 0;
  while (ea <= f->end_ea) {
    if (counter == 16) {
      break;
    }
    ea = next_head(ea, BADADDR);
    decode_insn(&insn, ea);
    if (insn.itype == NN_mov && insn.ops[0].type == o_displ &&
        (insn.ops[0].reg == R_RSP || insn.ops[0].reg == R_RBP) &&
        insn.ops[1].type == o_imm) {
      if (insn.ops[0].addr == offset) {
        guid.data1 = insn.ops[1].value;
        counter += 4;
        continue;
      }
      if (insn.ops[0].addr == offset + 4) {
        guid.data2 = insn.ops[1].value & 0xffff;
        guid.data3 = (insn.ops[1].value >> 16) & 0xffff;
        counter += 4;
        continue;
      }
      if (insn.ops[0].addr == offset + 8) {
        auto dword = insn.ops[1].value;
        guid.data4[0] = dword & 0xff;
        guid.data4[1] = (dword >> 8) & 0xff;
        guid.data4[2] = (dword >> 16) & 0xff;
        guid.data4[3] = (dword >> 24) & 0xff;
        counter += 4;
        continue;
      }
      if (insn.ops[0].addr == offset + 12) {
        auto dword = insn.ops[1].value;
        guid.data4[4] = dword & 0xff;
        guid.data4[5] = (dword >> 8) & 0xff;
        guid.data4[6] = (dword >> 16) & 0xff;
        guid.data4[7] = (dword >> 24) & 0xff;
        counter += 4;
        continue;
      }
    }
  }
  return guid;
}

std::string efi_utils::get_table_name(std::string service_name) {
  for (auto i = 0; i < g_boot_services_table_all_count; i++) {
    if (g_boot_services_table_all[i].name == service_name) {
      return "EFI_BOOT_SERVICES";
    }
  }

  for (auto i = 0; i < g_runtime_services_table_all_count; i++) {
    if (g_runtime_services_table_all[i].name == service_name) {
      return "EFI_RUNTIME_SERVICES";
    }
  }

  return "Unknown";
}

std::string efi_utils::lookup_boot_service_name(uint64_t offset) {
  for (auto i = 0; i < g_boot_services_table_all_count; i++) {
    if (g_boot_services_table_all[i].offset64 == offset) {
      return g_boot_services_table_all[i].name;
    }
  }

  return "Unknown";
}

std::string efi_utils::lookup_runtime_service_name(uint64_t offset) {
  for (auto i = 0; i < g_runtime_services_table_all_count; i++) {
    if (g_runtime_services_table_all[i].offset64 == offset) {
      return g_runtime_services_table_all[i].name;
    }
  }

  return "Unknown";
}

uint16_t get_machine_type() {
  ea_t pe_offset = get_dword(0x3c);
  return get_word(pe_offset + 4);
}

uint32_t u32_addr(ea_t addr) { return addr; }
uint64_t u64_addr(ea_t addr) { return addr; }

size_t get_ptrsize() { return inf_is_64bit() ? 8 : 4; }

#if IDA_SDK_VERSION >= 900
tid_t import_type(const til_t *til, int _idx, const char *name) {
  tinfo_t tinfo;
  if (!tinfo.get_named_type(til, name)) {
    return BADADDR;
  }

  return tinfo.force_tid();
}
#endif
