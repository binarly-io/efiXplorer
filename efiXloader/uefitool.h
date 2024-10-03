/*
 * efiXloader
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

#pragma once

#include <set>
#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#endif
#include <codecvt>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>

#include "3rd/uefitool/common/LZMA/LzmaCompress.h"
#include "3rd/uefitool/common/LZMA/LzmaDecompress.h"
#include "3rd/uefitool/common/Tiano/EfiTianoCompress.h"
#include "3rd/uefitool/common/Tiano/EfiTianoDecompress.h"
#include "3rd/uefitool/common/basetypes.h"
#include "3rd/uefitool/common/ffs.h"
#include "3rd/uefitool/common/ffsparser.h"
#include "3rd/uefitool/common/ffsreport.h"
#include "3rd/uefitool/common/filesystem.h"
#include "3rd/uefitool/common/guiddatabase.h"
#include "3rd/uefitool/common/treeitem.h"
#include "3rd/uefitool/common/treemodel.h"
#include "3rd/uefitool/common/ustring.h"
#include "3rd/uefitool/version.h"

#include "3rd/uefitool/UEFIExtract/ffsdumper.h"
#include "3rd/uefitool/UEFIExtract/uefidump.h"
#include "fstream"
#include "json.hpp"

#include "ida_core.h"

using nlohmann::json;

enum FILE_SECTION_TYPE {
  PE_DEPENDENCY_SECTION = 0,
  PE_TE_IMAGE_SECTION = 1,
  UI_SECTION = 2,
  VERSION_SECTION = 3
};

namespace efiloader {
class File {
public:
  File() {}
  void set_data(char *data_in, uint32_t size_in) {
    qname.qclear();
    bytes.resize(size_in);
    memcpy(&bytes[0], data_in, size_in);
  }
  void write() {
    qstring idb_path(get_path(PATH_TYPE_IDB));
    qstring images_path = idb_path + qstring(".efiloader");
#ifdef WIN32
    _mkdir(images_path.c_str());
#else
    mkdir(images_path.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
#endif
    if (!qname.empty()) {
      qstring image_path = images_path + qstring("/") + qstring(qname.c_str());
      std::ofstream file;
      file.open(image_path.c_str(), std::ios::out | std::ios::binary);
      file.write(ubytes.constData(), ubytes.size());
      file.close();
      dump_name.swap(image_path);
    }
  }
  void print();
  UByteArray ubytes;
  UByteArray uname;
  bytevec_t bytes;
  char *data = NULL;
  uint32_t size = 0;
  std::string name_utf8;
  std::string name_utf16;
  qstring qname;
  qstring dump_name;
  bool is_pe = false;
  bool is_te = false;
  bool has_ui = false;
};

class Uefitool {
public:
  explicit Uefitool(bytevec_t &data) {
    buffer = (const char *)&data[0];
    buffer_size = data.size();
    UByteArray ubuffer(buffer, buffer_size);
    FfsParser ffs(&model);
    if (ffs.parse(ubuffer)) {
      loader_failure("failed to parse data via UEFITool");
    }
    messages = ffs.getMessages();
  }
  ~Uefitool() {}
  void show_messages();
  bool messages_occurs() { return !messages.empty(); }
  void dump();
  void dump(const UModelIndex &index);
  void dump(const UModelIndex &index, uint8_t el_type, File *pe_file);
  void handle_raw_section(const UModelIndex &index);
  bool is_pe_index(const UModelIndex &index) {
    return model.rowCount(index) == 4;
  }
  bool is_file_index(const UModelIndex &index) {
    return model.type(index) == Types::File;
  }
  void get_unique_name(qstring &image_name);
  void get_image_guid(qstring &image_guid, UModelIndex index);
  std::vector<std::string> parseDepexSectionBody(const UModelIndex &index,
                                                 UString &parsed);
  std::vector<std::string> parseAprioriRawSection(const UModelIndex &index);
  void get_deps(UModelIndex index, std::string key);
  void get_apriori(UModelIndex index, std::string key);
  void
  dump_jsons();  // dump JSON with DEPEX and GUIDs information for each image
  json all_deps; // DEPEX information for each image
  json images_guids; // matching the modules to the parent's GUIDs
  json mod_types;    // EFI module name and its type
  TreeModel model;
  const char *buffer;
  uint32_t buffer_size;
  std::vector<std::pair<UString, UModelIndex>> messages;
  std::set<qstring> unique_names;
  std::vector<efiloader::File *> files;
  USTATUS err;
  void set_machine_type(UByteArray pe_body);
  uint16_t machine_type = 0xffff;
  bool machine_type_detected = false;
};
} // namespace efiloader
