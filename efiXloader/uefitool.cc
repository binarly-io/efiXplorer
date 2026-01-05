// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2020-2026 Binarly

#include "uefitool.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

void efiloader::Uefitool::show_messages() {
  for (size_t i = 0; i < messages.size(); i++) {
    msg("[uefitool] %s\n", messages[i].first.toLocal8Bit());
  }
}

void efiloader::Uefitool::get_unique_name(qstring &name) {
  // if the given name is already in use, create a new one
  qstring new_name = name;
  std::string suf;
  int index = 0;
  while (!(unique_names.insert(new_name).second)) {
    suf = "_" + std::to_string(++index);
    new_name = name + static_cast<qstring>(suf.c_str());
  }
  name = new_name;
}

void efiloader::Uefitool::get_image_guid(qstring &image_guid,
                                         UModelIndex index) {
  UString guid;
  UModelIndex guid_index;
  switch (model.subtype(model.parent(index))) {
  case EFI_SECTION_GUID_DEFINED:
    if (model.type(model.parent(index)) == Types::File) {
      guid_index = model.parent(index);
    } else {
      guid_index = model.parent(model.parent(index));
    }
    if (model.subtype(guid_index) == EFI_SECTION_COMPRESSION)
      guid_index = model.parent(guid_index);
    break;
  case EFI_SECTION_COMPRESSION:
    guid_index = model.parent(model.parent(index));
    break;
  default:
    guid_index = model.parent(index);
  }
  // get parent header and read GUID
  guid = guidToUString(
      readUnaligned((const EFI_GUID *)(model.header(guid_index).constData())));
  image_guid = reinterpret_cast<char *>(guid.data);
}

std::vector<std::string>
efiloader::Uefitool::parse_depex_section_body(const UModelIndex &index,
                                              UString &parsed) {
  // Adopted from FfsParser::parseDepexSectionBody
  std::vector<std::string> res;

  if (!index.isValid())
    return res;

  UByteArray body = model.body(index);

  // check data to be present
  if (body.size() < 2) { // 2 is a minimal sane value, i.e TRUE + END
    return res;
  }

  const EFI_GUID *guid;
  const UINT8 *current = (const UINT8 *)body.constData();

  // special cases of first opcode
  switch (*current) {
  case EFI_DEP_BEFORE:
    if (body.size() != 2 * EFI_DEP_OPCODE_SIZE + sizeof(EFI_GUID)) {
      return res;
    }
    guid = (const EFI_GUID *)(current + EFI_DEP_OPCODE_SIZE);
    parsed += UString("\nBEFORE ") + guidToUString(readUnaligned(guid));
    current += EFI_DEP_OPCODE_SIZE + sizeof(EFI_GUID);
    if (*current != EFI_DEP_END) {
      return res;
    }
    return res;
  case EFI_DEP_AFTER:
    if (body.size() != 2 * EFI_DEP_OPCODE_SIZE + sizeof(EFI_GUID)) {
      return res;
    }
    guid = (const EFI_GUID *)(current + EFI_DEP_OPCODE_SIZE);
    parsed += UString("\nAFTER ") + guidToUString(readUnaligned(guid));
    current += EFI_DEP_OPCODE_SIZE + sizeof(EFI_GUID);
    if (*current != EFI_DEP_END) {
      return res;
    }
    return res;
  case EFI_DEP_SOR:
    if (body.size() <= 2 * EFI_DEP_OPCODE_SIZE) {
      return res;
    }
    parsed += UString("\nSOR");
    current += EFI_DEP_OPCODE_SIZE;
    break;
  }

  // parse the rest of depex
  while (current - (const UINT8 *)body.constData() < body.size()) {
    switch (*current) {
    case EFI_DEP_BEFORE: {
      return res;
    }
    case EFI_DEP_AFTER: {
      return res;
    }
    case EFI_DEP_SOR: {
      return res;
    }
    case EFI_DEP_PUSH:
      // check that the rest of depex has correct size
      if ((UINT32)body.size() -
              (UINT32)(current - (const UINT8 *)body.constData()) <=
          EFI_DEP_OPCODE_SIZE + sizeof(EFI_GUID)) {
        parsed.clear();
        return res;
      }
      guid = (const EFI_GUID *)(current + EFI_DEP_OPCODE_SIZE);
      parsed += UString("\nPUSH ") + guidToUString(readUnaligned(guid));
      // add protocol GUID to result vector
      res.push_back(
          reinterpret_cast<char *>(guidToUString(readUnaligned(guid)).data));
      current += EFI_DEP_OPCODE_SIZE + sizeof(EFI_GUID);
      break;
    case EFI_DEP_AND:
      parsed += UString("\nAND");
      current += EFI_DEP_OPCODE_SIZE;
      break;
    case EFI_DEP_OR:
      parsed += UString("\nOR");
      current += EFI_DEP_OPCODE_SIZE;
      break;
    case EFI_DEP_NOT:
      parsed += UString("\nNOT");
      current += EFI_DEP_OPCODE_SIZE;
      break;
    case EFI_DEP_TRUE:
      parsed += UString("\nTRUE");
      current += EFI_DEP_OPCODE_SIZE;
      break;
    case EFI_DEP_FALSE:
      parsed += UString("\nFALSE");
      current += EFI_DEP_OPCODE_SIZE;
      break;
    case EFI_DEP_END:
      parsed += UString("\nEND");
      current += EFI_DEP_OPCODE_SIZE;
      // check that END is the last opcode
      if (current - (const UINT8 *)body.constData() < body.size()) {
        parsed.clear();
      }
      break;
    default:
      return res;
      break;
    }
  }

  return res;
}

std::vector<std::string>
efiloader::Uefitool::parse_apriori_raw_section(const UModelIndex &index) {
  // adopted from FfsParser::parseDepexSectionBody
  std::vector<std::string> res;

  if (!index.isValid())
    return res;

  UByteArray body = model.body(index);

  // sanity check
  if (body.size() % sizeof(EFI_GUID)) {
    return res;
  }

  UINT32 count = (UINT32)(body.size() / sizeof(EFI_GUID));
  if (count > 0) {
    for (UINT32 i = 0; i < count; i++) {
      const EFI_GUID *guid = (const EFI_GUID *)body.constData() + i;
      res.push_back(
          reinterpret_cast<char *>(guidToUString(readUnaligned(guid)).data));
    }
  }

  return res;
}

void efiloader::Uefitool::set_machine_type(UByteArray pe_body) {
  const char *data = pe_body.constData();
  if (pe_body.size() < 64) {
    return;
  }
  uint32_t _pe_header_off = *(uint32_t *)(data + 0x3c);
  if (pe_body.size() < _pe_header_off + 6) {
    return;
  }
  if (*(uint32_t *)(data + _pe_header_off) == 0x4550) {
    machine_type = *(uint16_t *)(data + _pe_header_off + 4);
    machine_type_initialised = true;
  }
}

void efiloader::Uefitool::handle_raw_section(const UModelIndex &index) {
  UModelIndex parent_file = model.findParentOfType(index, Types::File);
  if (!parent_file.isValid()) {
    return;
  }
  UByteArray parent_file_guid(model.header(parent_file).constData(),
                              sizeof(EFI_GUID));
  if (parent_file_guid == EFI_PEI_APRIORI_FILE_GUID) {
    msg("[efiXloader] PEI Apriori file found\n");
    get_apriori(index, "PEI_APRIORI_FILE");
  }
  if (parent_file_guid == EFI_DXE_APRIORI_FILE_GUID) {
    msg("[efiXloader] DXE Apriori file found\n");
    get_apriori(index, "DXE_APRIORI_FILE");
  }
}

inline void get_module_name(qstring &module_name, efiloader::File *file) {
  utf16_utf8(&module_name,
             reinterpret_cast<const wchar16_t *>(file->uname.data()));
}

void efiloader::Uefitool::dump(const UModelIndex &index, int i,
                               efiloader::File *file) {
  qstring name;
  qstring guid;

  switch (model.subtype(index)) {
  case EFI_SECTION_RAW:
    handle_raw_section(index);
    break;
  case EFI_SECTION_TE:
    file->is_te = true;
    file->ubytes = model.body(index);
    file->module_kind = get_kind(index);
    break;
  case EFI_SECTION_PE32:
    file->is_pe = true;
    file->ubytes = model.body(index);
    file->module_kind = get_kind(index);
    if (!machine_type_initialised) {
      set_machine_type(model.body(index));
    }
    break;
  case EFI_SECTION_USER_INTERFACE:
    file->has_ui = true;
    file->uname = model.body(index);
    break;
  case EFI_SECTION_COMPRESSION:
  case EFI_SECTION_GUID_DEFINED:
    for (int i = 0; i < model.rowCount(index); i++) {
      dump(index.child(i, 0), i, file);
    }
    break;
  case EFI_SECTION_DXE_DEPEX:
    get_deps(index, "EFI_SECTION_DXE_DEPEX");
    break;
  case EFI_SECTION_MM_DEPEX:
    get_deps(index, "EFI_SECTION_MM_DEPEX");
    break;
  case EFI_SECTION_PEI_DEPEX:
    get_deps(index, "EFI_SECTION_PEI_DEPEX");
    break;
  case EFI_SECTION_VERSION:
    break;
  default:
    break;
  }

  // update file
  if (file->is_pe || file->is_te) {
    get_image_guid(guid, index);
    if (file->has_ui) {
      // get module name from UI section
      get_module_name(name, file);
    } else {
      // use module GUID as module name
      name = guid;
    }
    file->module_name.swap(name);
    file->module_guid.swap(guid);
  }

  dump(index);
}

void efiloader::Uefitool::dump(const UModelIndex &index) {
  USTATUS err;

  if (is_file_index(index)) {
    auto file = std::make_unique<File>();
    for (int i = 0; i < model.rowCount(index); i++) {
      dump(index.child(i, 0), i, file.get());
    }

    // append file
    if (file->is_ok()) {
      all_modules[file->module_guid.c_str()] = {
          {"name", file->module_name.c_str()},
          {"kind", file->module_kind.c_str()}};
      file->write();
      files.push_back(std::move(file));
    }
  } else {
    for (int i = 0; i < model.rowCount(index); i++) {
      dump(index.child(i, 0));
    }
  }
}

void efiloader::Uefitool::dump() { return dump(model.index(0, 0)); }

void efiloader::Uefitool::get_deps(UModelIndex index, std::string key) {
  UString parsed;
  std::vector<std::string> deps;
  qstring image_guid("");

  get_image_guid(image_guid, index);
  deps = parse_depex_section_body(index, parsed);
  if (deps.size()) {
    msg("[efiXloader] dependency section for image with GUID %s: %s\n",
        image_guid.c_str(), parsed.data);
    all_deps[key][image_guid.c_str()] = deps;
  }
}

void efiloader::Uefitool::get_apriori(UModelIndex index, std::string key) {
  if (all_deps.contains(key)) {
    return;
  }
  auto deps = parse_apriori_raw_section(index);
  if (deps.empty()) {
    return;
  }
  all_deps[key] = deps;
}

void efiloader::Uefitool::dump_jsons() {
  // dump JSON with DEPEX and GUIDs information for each image
  std::filesystem::path out;
  out /= get_path(PATH_TYPE_IDB);
  out.replace_extension(".deps.json");
  std::ofstream out_deps(out);
  out_deps << std::setw(2) << all_deps << std::endl;

  out.replace_extension("").replace_extension(".images.json");
  std::ofstream out_guids(out);
  out_guids << std::setw(2) << all_modules << std::endl;
}
