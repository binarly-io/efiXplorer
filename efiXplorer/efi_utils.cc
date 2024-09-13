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
#include "efi_defs.h"
#include "efi_global.h"

// can be used after Hex-Rays based analysis
std::vector<ea_t> g_get_smst_location_calls;
std::vector<ea_t> g_smm_get_variable_calls;
std::vector<ea_t> g_smm_set_variable_calls;

//--------------------------------------------------------------------------
// Set EFI_GUID type
void setGuidType(ea_t ea) {
  tinfo_t tinfo;
  if (tinfo.get_named_type(get_idati(), "EFI_GUID")) {
    apply_tinfo(ea, tinfo, TINFO_DEFINITE);
  }
}

//--------------------------------------------------------------------------
// Set type and name
void setTypeAndName(ea_t ea, std::string name, std::string type) {
  set_name(ea, name.c_str(), SN_FORCE);
  tinfo_t tinfo;
  if (tinfo.get_named_type(get_idati(), type.c_str())) {
    apply_tinfo(ea, tinfo, TINFO_DEFINITE);
  }
}

//--------------------------------------------------------------------------
// Set const CHAR16 type
void setConstChar16Type(ea_t ea) {
  tinfo_t tinfo;
  if (tinfo.get_named_type(get_idati(), "CHAR16")) {
    tinfo.set_const();
    apply_tinfo(ea, tinfo, TINFO_DEFINITE);
  }
}

//--------------------------------------------------------------------------
// get file format name (fileformatname)
std::string file_format_name() {
  char file_format[256] = {0};
  get_file_type_name(file_format, 256);
  return static_cast<std::string>(file_format);
}

//--------------------------------------------------------------------------
// get input file type (64-bit, 32-bit module or UEFI firmware)
ArchFileType input_file_type() {
  processor_t &ph = PH;
  auto filetype = inf_get_filetype();
  auto bits = inf_is_64bit() ? 64 : inf_is_32bit_exactly() ? 32 : 16;

  // check if the input file is a UEFI firmware image
  if (file_format_name().find("UEFI") != std::string::npos) {
    return ArchFileType::Uefi;
  }

  if (filetype == f_PE || filetype == f_ELF) {
    if (ph.id == PLFM_386) {
      if (bits == 64)
        return ArchFileType::X8664;
      if (bits == 32)
        return ArchFileType::X8632;
    }
    if (ph.id == PLFM_ARM) {
      if (bits == 64)
        return ArchFileType::Aarch64;
    }
  }
  return ArchFileType::Unsupported;
}

//--------------------------------------------------------------------------
// get input file type (PEI or DXE-like). No reliable way to determine FFS
// file type given only its PE/TE image section, so hello heuristics
FfsFileType guess_file_type(ArchFileType arch, std::vector<json> *all_guids) {
  if (arch == ArchFileType::Uefi) {
    return FfsFileType::DxeAndTheLike;
  }

  segment_t *hdr_seg = get_segm_by_name("HEADER");
  if (hdr_seg == nullptr) {
    return FfsFileType::DxeAndTheLike;
  }

  uint64_t signature = get_wide_word(hdr_seg->start_ea);
  bool has_pei_guids = false;
  for (auto guid = all_guids->begin(); guid != all_guids->end(); guid++) {
    json guid_value = *guid;

    if (static_cast<std::string>(guid_value["name"]).find("PEI") != std::string::npos) {
      has_pei_guids = true;
      break;
    }
  }

  bool has_pei_in_path = false;
  char file_name[0x1000] = {0};
  get_input_file_path(file_name, sizeof(file_name));
  auto file_name_str = static_cast<std::string>(file_name);
  if ((file_name_str.find("Pei") != std::string::npos ||
       file_name_str.find("pei") != std::string::npos || signature == VZ) &&
      arch == ArchFileType::X8664) {
    has_pei_in_path = true;
  }

  if (signature == VZ || has_pei_guids) {
    msg("[%s] parsing binary file as PEI, signature = %llx, has_pei_guids = %d\n",
        g_plugin_name, signature, has_pei_guids);
    return FfsFileType::Pei;
  }

  msg("[%s] parsing binary file as DXE/SMM, signature = %llx, has_pei_guids = %d\n",
      g_plugin_name, signature, has_pei_guids);
  return FfsFileType::DxeAndTheLike;
}

FfsFileType ask_file_type(std::vector<json> *all_guids) {
  auto arch = input_file_type();
  if (arch == ArchFileType::Uefi || arch == ArchFileType::X8664) {
    return FfsFileType::DxeAndTheLike;
  }
  auto ftype = guess_file_type(arch, all_guids);
  auto deflt = ftype == FfsFileType::DxeAndTheLike;
  auto fmt_param = ftype == FfsFileType::DxeAndTheLike ? "DXE/SMM" : "PEI";
  auto btn_id = ask_buttons("DXE/SMM", "PEI", "", deflt, "Parse file as %s", fmt_param);
  if (btn_id == ASKBTN_YES) {
    return FfsFileType::DxeAndTheLike;
  }

  return FfsFileType::Pei;
}

//--------------------------------------------------------------------------
// Find address of global gBS var for X64 module for each service
ea_t findUnknownBsVarX64(ea_t ea) {
  ea_t resAddr = 0;
  insn_t insn;

  // Check 10 instructions below
  for (int i = 0; i < 10; i++) {
    decode_insn(&insn, ea);
    if (insn.itype == NN_mov && insn.ops[0].type == o_reg && insn.ops[0].reg == REG_RAX &&
        insn.ops[1].type == o_mem) {
      resAddr = insn.ops[1].addr;
      break;
    }
    ea = prev_head(ea, 0);
  }
  return resAddr;
}

//--------------------------------------------------------------------------
// Get all xrefs for given address
std::vector<ea_t> getXrefs(ea_t addr) {
  std::vector<ea_t> xrefs;
  ea_t xref = get_first_dref_to(addr);
  while (xref != BADADDR) {
    xrefs.push_back(xref);
    xref = get_next_dref_to(addr, xref);
  }
  return xrefs;
}

//--------------------------------------------------------------------------
// Get all xrefs for given array element
std::vector<ea_t> getXrefsToArray(ea_t addr) {
  ea_t first_ea;
  ea_t ea = addr;
  while (true) {
    auto ptr = get_qword(ea);
    auto xrefs = getXrefs(ptr);
    if (std::find(xrefs.begin(), xrefs.end(), ea) == xrefs.end()) {
      break;
    }
    first_ea = ea;
    ea -= 8;
  }
  return getXrefs(first_ea);
}

//--------------------------------------------------------------------------
// Wrapper for op_stroff function
bool opStroff(ea_t addr, std::string type) {
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

  insn_t insn;
  decode_insn(&insn, addr);
  return op_stroff(insn, 0, &tid, 1, 0);
}

//--------------------------------------------------------------------------
// Get pointer to named type and apply it
bool setPtrType(ea_t addr, std::string type) {
  tinfo_t tinfo;
  if (!tinfo.get_named_type(get_idati(), type.c_str())) {
    return false;
  }
  tinfo_t ptrTinfo;
  ptrTinfo.create_ptr(tinfo);
  apply_tinfo(addr, ptrTinfo, TINFO_DEFINITE);
  return true;
}

//--------------------------------------------------------------------------
// Set name and apply pointer to named type
void setPtrTypeAndName(ea_t ea, std::string name, std::string type) {
  set_name(ea, name.c_str(), SN_FORCE);
  setPtrType(ea, type.c_str());
}

//--------------------------------------------------------------------------
// Get guids.json file name
std::filesystem::path getGuidsJsonFile() {
  std::filesystem::path guidsJsonPath;

  // check {idadir}/plugins/guids.json
  guidsJsonPath /= idadir("plugins");
  guidsJsonPath /= "guids.json";
  if (std::filesystem::exists(guidsJsonPath)) {
    return guidsJsonPath;
  }

  // check {idadir}/plugins/guids/guids.json
  guidsJsonPath.clear();
  guidsJsonPath /= idadir("plugins");
  guidsJsonPath /= "guids";
  guidsJsonPath /= "guids.json";
  if (std::filesystem::exists(guidsJsonPath)) {
    return guidsJsonPath;
  }

  // Try to load it from the per-user directory.
  guidsJsonPath.clear();
  guidsJsonPath /= get_user_idadir();
  guidsJsonPath /= "plugins";
  guidsJsonPath /= "guids.json";
  if (std::filesystem::exists(guidsJsonPath)) {
    return guidsJsonPath;
  }

  guidsJsonPath.clear();
  guidsJsonPath /= get_user_idadir();
  guidsJsonPath /= "plugins";
  guidsJsonPath /= "guids";
  guidsJsonPath /= "guids.json";
  if (std::filesystem::exists(guidsJsonPath)) {
    return guidsJsonPath;
  }

  // Does not exist.
  guidsJsonPath.clear();
  return guidsJsonPath;
}

//--------------------------------------------------------------------------
// Get json summary file name
std::filesystem::path getSummaryFile() {
  std::string idbPath;
  idbPath = get_path(PATH_TYPE_IDB);
  std::filesystem::path logFile;
  logFile /= idbPath;
  logFile.replace_extension(".json");
  return logFile;
}

//--------------------------------------------------------------------------
// Check for summary json file exist
bool summaryJsonExist() {
  std::string idbPath;
  idbPath = get_path(PATH_TYPE_IDB);
  std::filesystem::path logFile;
  logFile /= idbPath;
  logFile.replace_extension(".json");
  return std::filesystem::exists(logFile);
}

//--------------------------------------------------------------------------
// Change EFI_SYSTEM_TABLE *SystemTable to EFI_PEI_SERVICES **PeiService
// for ModuleEntryPoint
void setEntryArgToPeiSvc() {
  for (auto idx = 0; idx < get_entry_qty(); idx++) {
    uval_t ord = get_entry_ordinal(idx);
    ea_t start_ea = get_entry(ord);
    tinfo_t tif_ea;
    if (guess_tinfo(&tif_ea, start_ea) == GUESS_FUNC_FAILED) {
      msg("[%s] guess_tinfo failed, start_ea = 0x%016llX, idx=%d\n", g_plugin_name,
          u64_addr(start_ea), idx);
      continue;
    }
    func_type_data_t funcdata;
    if (!tif_ea.get_func_details(&funcdata)) {
      msg("[%s] get_func_details failed, %d\n", g_plugin_name, idx);
      continue;
    }
    tinfo_t tif_pei;
    bool res = tif_pei.get_named_type(get_idati(), "EFI_PEI_SERVICES");
    if (!res) {
      msg("[%s] get_named_type failed, res = %d, idx=%d\n", g_plugin_name, res, idx);
      continue;
    }
    tinfo_t ptrTinfo;
    tinfo_t ptrPtrTinfo;
    ptrTinfo.create_ptr(tif_pei);
    ptrPtrTinfo.create_ptr(ptrTinfo);
    // funcdata.size() does not work for aarch64
    if (funcdata.size() == 2) {
      funcdata[1].type = ptrPtrTinfo;
      funcdata[1].name = "PeiServices";
      tinfo_t func_tinfo;
      if (!func_tinfo.create_func(funcdata)) {
        msg("[%s] create_func failed, idx=%d\n", g_plugin_name, idx);
        continue;
      }
      if (!apply_tinfo(start_ea, func_tinfo, TINFO_DEFINITE)) {
        msg("[%s] apply_tinfo failed, idx=%d\n", g_plugin_name, idx);
        continue;
      }
    }
  }
}

bool setRetToPeiSvc(ea_t start_ea) {
  tinfo_t tif_ea;
  if (guess_tinfo(&tif_ea, start_ea) == GUESS_FUNC_FAILED) {
    msg("[%s] guess_tinfo failed, function = 0x%016llX", g_plugin_name,
        u64_addr(start_ea));
    return false;
  }
  func_type_data_t fi;
  if (!tif_ea.get_func_details(&fi)) {
    msg("[%s] get_func_details failed, function = 0x%016llX", g_plugin_name,
        u64_addr(start_ea));
    return false;
  }
  tinfo_t tif_pei;
  bool res = tif_pei.get_named_type(get_idati(), "EFI_PEI_SERVICES");
  if (!res) {
    msg("[%s] get_named_type failed, res = %d\n", g_plugin_name, res);
    return false;
  }
  tinfo_t ptrTinfo;
  tinfo_t ptrPtrTinfo;
  ptrTinfo.create_ptr(tif_pei);
  ptrPtrTinfo.create_ptr(ptrTinfo);

  fi.rettype = ptrPtrTinfo;

  tinfo_t func_tinfo;
  if (!func_tinfo.create_func(fi)) {
    msg("[%s] create_func failed, function = 0x%016llX", g_plugin_name,
        u64_addr(start_ea));
    return false;
  }
  if (!apply_tinfo(start_ea, func_tinfo, TINFO_DEFINITE)) {
    msg("[%s] apply_tinfo failed, function = 0x%016llX", g_plugin_name,
        u64_addr(start_ea));
    return false;
  }
  return true;
}

int parseEfiPeiServices4() {
  return parse_decls(nullptr,
                     "struct EFI_PEI_SERVICES_4 {\n"
                     "  EFI_PEI_SERVICES **PeiServices;\n"
                     "  UINT32 BaseAddress;\n"
                     "};",
                     msg, HTI_DCL);
}

int parseEfiPeiSidt() {
  return parse_decls(nullptr,
                     "struct EFI_PEI_SIDT {\n"
                     "  UINT16 Limit;\n"
                     "  int *__shifted(EFI_PEI_SERVICES_4, 4) BaseAddress;\n"
                     "};",
                     msg, HTI_DCL | HTI_PAK1);
}

//--------------------------------------------------------------------------
// Add EFI_PEI_SERVICES_4 structure
bool addStrucForShiftedPtr() {
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
  tinfo_t ptrTinfo;
  tinfo_t ptr2Tinfo;
  ptrTinfo.create_ptr(tinfo);
  ptr2Tinfo.create_ptr(ptrTinfo);

  auto member = get_member_by_name(new_struct, "PeiServices");
  set_member_tinfo(new_struct, member, 0, ptr2Tinfo, 0);

  return true;
#endif

  // return true if there are no errors from parse_decls()
  return !parseEfiPeiServices4() && !parseEfiPeiSidt();
}

//--------------------------------------------------------------------------
// Change the value of a number to match the data type
uval_t truncImmToDtype(uval_t value, op_dtype_t dtype) {
  switch (dtype) {
  case dt_byte:
    return value & 0xff;
  case dt_word:
    return value & 0xffff;
  case dt_dword:
    return value & 0xffffffff;
  default:
    return value;
  }
}

//--------------------------------------------------------------------------
// Get module name by address
qstring getModuleNameLoader(ea_t address) {
  segment_t *seg = getseg(address);
  qstring seg_name;
  get_segm_name(&seg_name, seg);
  return seg_name.remove(seg_name.size() - 7, seg_name.size());
}

//--------------------------------------------------------------------------
// Get GUID data by address
json getGuidByAddr(ea_t addr) {
  return json::array(
      {get_wide_dword(addr), get_wide_word(addr + 4), get_wide_word(addr + 6),
       get_wide_byte(addr + 8), get_wide_byte(addr + 9), get_wide_byte(addr + 10),
       get_wide_byte(addr + 11), get_wide_byte(addr + 12), get_wide_byte(addr + 13),
       get_wide_byte(addr + 14), get_wide_byte(addr + 15)});
}

//--------------------------------------------------------------------------
// Validate GUID value
bool checkGuid(json guid) {
  if (static_cast<uint32_t>(guid[0]) == 0x00000000 && (uint16_t)guid[1] == 0x0000) {
    return false;
  }
  if (static_cast<uint32_t>(guid[0]) == 0xffffffff && (uint16_t)guid[1] == 0xffff) {
    return false;
  }
  return true;
}

//--------------------------------------------------------------------------
// Convert GUID value to string
std::string getGuidFromValue(json guid) {
  char guidStr[37] = {0};
  snprintf(guidStr, 37, "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
           static_cast<uint32_t>(guid[0]), static_cast<uint16_t>(guid[1]),
           static_cast<uint16_t>(guid[2]), static_cast<uint8_t>(guid[3]),
           static_cast<uint8_t>(guid[4]), static_cast<uint8_t>(guid[5]),
           static_cast<uint8_t>(guid[6]), static_cast<uint8_t>(guid[7]),
           static_cast<uint8_t>(guid[8]), static_cast<uint8_t>(guid[9]),
           static_cast<uint8_t>(guid[10]));
  return static_cast<std::string>(guidStr);
}

std::vector<uint8_t> unpackGuid(std::string guid) {
  std::vector<uint8_t> res;
  std::string delimiter = "-";
  std::string byte_str;
  uint8_t byte;
  size_t pos = 0;

  auto index = 0;
  while ((pos = guid.find(delimiter)) != std::string::npos) {
    std::vector<uint8_t> tmp;
    auto hex = guid.substr(0, pos);
    if (hex.size() % 2) {
      break;
    }
    for (auto i = 0; i < hex.size(); i += 2) {
      byte_str = hex.substr(i, 2);
      byte = static_cast<uint8_t>(strtol(byte_str.c_str(), NULL, 16));
      tmp.push_back(byte);
    }
    if (index != 3) {
      res.insert(res.end(), tmp.rbegin(), tmp.rend());
    } else {
      res.insert(res.end(), tmp.begin(), tmp.end());
    }
    index += 1;
    guid.erase(0, pos + delimiter.size());
    tmp.clear();
  }

  for (auto i = 0; i < guid.size(); i += 2) {
    byte_str = guid.substr(i, 2);
    byte = static_cast<uint8_t>(strtol(byte_str.c_str(), NULL, 16));
    res.push_back(byte);
  }

  return res;
}

std::vector<ea_t> searchProtocol(std::string protocol) {
  uchar bytes[17] = {0};
  std::vector<ea_t> res;
  auto guid_bytes = unpackGuid(protocol);
  std::copy(guid_bytes.begin(), guid_bytes.end(), bytes);
  ea_t start = 0;
  while (true) {
#if IDA_SDK_VERSION < 900
    ea_t addr = bin_search2(start, BADADDR, bytes, nullptr, 16, BIN_SEARCH_FORWARD);
#else
    ea_t addr = bin_search3(start, BADADDR, bytes, nullptr, 16, BIN_SEARCH_FORWARD);
#endif
    if (addr == BADADDR) {
      break;
    }
    res.push_back(addr);
    start = addr + 16;
  }
  return res;
}

bool checkInstallProtocol(ea_t ea) {
  insn_t insn;
  // search for `call [REG + offset]` insn
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
// Convert 64-bit value to hex string
std::string getHex(uint64_t value) {
  char hexstr[21] = {};
  snprintf(hexstr, 21, "%llX", value);
  return static_cast<std::string>(hexstr);
}

//--------------------------------------------------------------------------
// Make sure the first argument looks like protocol
bool bootServiceProtCheck(ea_t callAddr) {
  bool valid = false;
  insn_t insn;
  auto addr = prev_head(callAddr, 0);
  decode_insn(&insn, addr);
  while (!is_basic_block_end(insn, false)) {

    // for next iteration
    decode_insn(&insn, addr);
    addr = prev_head(addr, 0);

    // check current instruction
    if (insn.itype == NN_lea && insn.ops[0].type == o_reg && insn.ops[0].reg == REG_RCX) {
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
// Make sure that the address does not belong to the protocol interface
bool bootServiceProtCheckXrefs(ea_t callAddr) {
  insn_t insn;
  for (auto xref : getXrefs(callAddr)) {
    decode_insn(&insn, xref);
    if (insn.itype == NN_lea && insn.ops[0].type == o_reg && insn.ops[0].reg == REG_R8) {
      // load interface instruction
      return false;
    }
  }
  return true;
}

bool markCopy(ea_t codeAddr, ea_t varAddr, std::string type) {
  insn_t insn;
  int reg = -1;
  ea_t ea = codeAddr;
  ea_t varCopy = BADADDR;
  decode_insn(&insn, ea);

  // get `reg` value
  if (insn.itype == NN_mov && insn.ops[0].type == o_reg && insn.ops[1].type == o_mem &&
      insn.ops[1].addr == varAddr) {
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

    // get `varCopy`
    if (insn.itype == NN_mov && insn.ops[0].type == o_mem && insn.ops[1].type == o_reg &&
        insn.ops[1].reg == reg) {
      varCopy = insn.ops[0].addr;
      msg("[efiXplorer] Found copy for global variable: 0x%016llX\n", u64_addr(ea));
      break;
    }
  }

  if (varCopy == BADADDR) {
    return false;
  }

  std::string name;

  if (type == "gSmst") {
    setPtrTypeAndName(varCopy, "gSmst", "_EFI_SMM_SYSTEM_TABLE2");
  }

  if (type == "gBS") {
    setPtrTypeAndName(varCopy, "gBS", "EFI_BOOT_SERVICES");
  }

  if (type == "gRT") {
    setPtrTypeAndName(varCopy, "gRT", "EFI_RUNTIME_SERVICES");
  }

  return true;
}

bool markCopiesForGlobalVars(std::vector<ea_t> globalVars, std::string type) {
  for (auto var : globalVars) {
    auto xrefs = getXrefs(var);
    for (auto addr : xrefs) {
      markCopy(addr, var, type);
    }
  }
  return true;
}

//--------------------------------------------------------------------------
// Generate name string from type
std::string typeToName(std::string type) {
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
      } else
        result.push_back(c);
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

xreflist_t xrefsToStackVar(ea_t funcEa, qstring varName) {
  xreflist_t xrefs_list;

#if IDA_SDK_VERSION < 900
  struc_t *frame = get_frame(funcEa);
  func_t *func = get_func(funcEa);
  member_t member; // Get member by name
  for (int i = 0; i < frame->memqty; i++) {
    member = frame->members[i];
    qstring name;
    get_member_name(&name, frame->members[i].id);
    if (name == varName) {
      build_stkvar_xrefs(&xrefs_list, func, &member);
      return xrefs_list;
    }
  }
#endif

  // TODO: rewrite for idasdk90
  return xrefs_list;
}

void opstroffForAddress(ea_t ea, qstring typeName) {
  insn_t insn;

  for (auto i = 0; i < 16; i++) {
    ea = next_head(ea, BADADDR);
    decode_insn(&insn, ea);
    // Found interface function call
    if ((insn.itype == NN_call || insn.itype == NN_callfi || insn.itype == NN_callni) &&
        (insn.ops[0].type == o_displ || insn.ops[0].type == o_phrase) &&
        insn.ops[0].reg == REG_RAX) {
      opStroff(ea, static_cast<std::string>(typeName.c_str()));
      msg("[%s] Mark arguments at address 0x%016llX (interface type: %s)\n",
          g_plugin_name, u64_addr(ea), typeName.c_str());

      // check for EfiSmmBase2Protocol->GetSmstLocation
      if (typeName == "EFI_SMM_BASE2_PROTOCOL" && insn.ops[0].type == o_displ &&
          insn.ops[0].addr == 8) {
        if (!addrInVec(g_get_smst_location_calls, ea)) {
          g_get_smst_location_calls.push_back(ea);
        }
      }

      if (typeName == "EFI_SMM_VARIABLE_PROTOCOL" && insn.ops[0].type == o_phrase) {
        if (!addrInVec(g_smm_get_variable_calls, ea)) {
          g_smm_get_variable_calls.push_back(ea);
        }
      }

      if (typeName == "EFI_SMM_VARIABLE_PROTOCOL" && insn.ops[0].type == o_displ &&
          insn.ops[0].addr == 0x10) {
        if (!addrInVec(g_smm_set_variable_calls, ea)) {
          g_smm_set_variable_calls.push_back(ea);
        }
      }

      break;
    }
    // If the RAX value is overridden
    if (insn.ops[0].reg == REG_RAX) {
      break;
    }
  }
}

//--------------------------------------------------------------------------
// Mark the arguments of each function from an interface derived from
// a local variable
void opstroffForInterface(xreflist_t localXrefs, qstring typeName) {
  insn_t insn;
  for (auto xref : localXrefs) {
    decode_insn(&insn, xref.ea);
    if (insn.itype == NN_mov && insn.ops[0].reg == REG_RAX) {
      opstroffForAddress(xref.ea, typeName);
    }
  }
}

//--------------------------------------------------------------------------
// Mark the arguments of each function from an interface derived from
// a global variable
void opstroffForGlobalInterface(std::vector<ea_t> xrefs, qstring typeName) {
  insn_t insn;
  for (auto ea : xrefs) {
    decode_insn(&insn, ea);
    if (insn.itype == NN_mov && insn.ops[0].reg == REG_RAX) {
      opstroffForAddress(ea, typeName);
    }
  }
}

bool qwordInVec(std::vector<uint64_t> vec, uint64_t value) {
  return find(vec.begin(), vec.end(), value) != vec.end();
}

bool addrInVec(std::vector<ea_t> vec, ea_t addr) {
  return find(vec.begin(), vec.end(), addr) != vec.end();
}

bool jsonInVec(std::vector<json> vec, json item) {
  return find(vec.begin(), vec.end(), item) != vec.end();
}

bool addrInTables(std::vector<ea_t> gStList, std::vector<ea_t> gBsList,
                  std::vector<ea_t> gRtList, ea_t ea) {
  return (addrInVec(gStList, ea) || addrInVec(gBsList, ea) || addrInVec(gRtList, ea));
}

std::vector<ea_t> findData(ea_t start_ea, ea_t end_ea, uchar *data, size_t len) {
  std::vector<ea_t> res;
  ea_t start = start_ea;
  int counter = 0;
  while (true) {
#if IDA_SDK_VERSION < 900
    auto ea = bin_search2(start, end_ea, data, nullptr, len, BIN_SEARCH_FORWARD);
#else
    auto ea = bin_search3(start, end_ea, data, nullptr, len, BIN_SEARCH_FORWARD);
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
std::string getWideString(ea_t addr) {
  std::string res;
  int index = 0;
  while (get_wide_word(addr + index)) {
    auto byte = get_wide_byte(addr + index);
    if (byte < 0x20 || byte > 0x7e) {
      return "INVALID_STRING";
    }
    res.push_back(byte);
    index += 2;
  }
  return res;
}

//--------------------------------------------------------------------------
// Get EfiGuid by address
EfiGuid getGlobalGuid(ea_t addr) {
  EfiGuid guid;
  guid.data1 = get_wide_dword(addr);
  guid.data2 = get_wide_word(addr + 4);
  guid.data3 = get_wide_word(addr + 6);
  for (auto i = 0; i < 8; i++) {
    guid.data4[i] = static_cast<uint8_t>(get_wide_byte(addr + 8 + i));
  }
  return guid;
}

//--------------------------------------------------------------------------
// Get EfiGuid by stack offset
EfiGuid getStackGuid(func_t *f, uint64_t offset) {
  EfiGuid guid;
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
        (insn.ops[0].reg == REG_RSP || insn.ops[0].reg == REG_RBP) &&
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

std::string getTable(std::string service_name) {
  for (auto i = 0; i < bootServicesTableAllCount; i++) {
    if (static_cast<std::string>(bootServicesTableAll[i].name) == service_name) {
      return "EFI_BOOT_SERVICES";
    }
  }
  for (auto i = 0; i < runtimeServicesTableAllCount; i++) {
    if (static_cast<std::string>(runtimeServicesTableAll[i].name) == service_name) {
      return "EFI_RUNTIME_SERVICES";
    }
  }
  return "OTHER";
}

std::string lookupBootServiceName(uint64_t offset) {
  for (auto i = 0; i < bootServicesTableAllCount; i++) {
    if (bootServicesTableAll[i].offset64 == offset) {
      return static_cast<std::string>(bootServicesTableAll[i].name);
    }
  }
  return "Unknown";
}

std::string lookupRuntimeServiceName(uint64_t offset) {
  for (auto i = 0; i < runtimeServicesTableAllCount; i++) {
    if (runtimeServicesTableAll[i].offset64 == offset) {
      return static_cast<std::string>(runtimeServicesTableAll[i].name);
    }
  }
  return "Unknown";
}

uint64_t u64_addr(ea_t addr) { return static_cast<uint64_t>(addr); }

uint32_t u32_addr(ea_t addr) { return static_cast<uint32_t>(addr); }

uint16_t get_machine_type() {
  ea_t pe_offset = get_dword(0x3c);
  return get_word(pe_offset + 4);
}

#if IDA_SDK_VERSION >= 900
tid_t import_type(const til_t *til, int _idx, const char *name) {
  tinfo_t tinfo;
  if (!tinfo.get_named_type(til, name)) {
    return BADADDR;
  }

  return tinfo.force_tid();
}
#endif
