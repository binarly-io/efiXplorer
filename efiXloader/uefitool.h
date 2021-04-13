/*
 *        __ ___   ___                 _
 *       / _(_) \ / / |               | |
 *   ___| |_ _ \ V /| | ___   __ _  __| | ___ _ __
 *  / _ \  _| | > < | |/ _ \ / _` |/ _` |/ _ \ '__|
 * |  __/ | | |/ . \| | (_) | (_| | (_| |  __/ |
 *  \___|_| |_/_/ \_\_|\___/ \__,_|\__,_|\___|_|
 *
 * efiXloader
 * Copyright (C) 2020  Binarly
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
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * uefitool.h
 */

#ifndef EFILOADER_UEFITOOL_H
#define EFILOADER_UEFITOOL_H

#define _SILENCE_EXPERIMENTAL_FILESYSTEM_DEPRECATION_WARNING

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

#include "ida_core.h"

#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#endif

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
    };
    void write() {
        qstring idb_path(get_path(PATH_TYPE_IDB));
        msg("[efiloader] IDB path %s\n", idb_path.c_str());
        qstring images_path = idb_path + qstring(".efiloader");
        msg("[efiloader] creating directory %s\n", images_path.c_str());
#ifdef WIN32
        _mkdir(images_path.c_str());
#else
        mkdir(images_path.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
#endif
        if (!qname.empty()) {
            qstring image_path =
                images_path + qstring("/") + qstring(qname.c_str());
            msg("[efiloader] writing images to %s\n", image_path.c_str());
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
};

class Uefitool {
  public:
    Uefitool(bytevec_t &data) {
        buffer = (const char *)&data[0];
        buffer_size = data.size();
        UByteArray ubuffer(buffer, buffer_size);
        FfsParser ffs(&model);
        if (ffs.parse(ubuffer)) {
            loader_failure("failed to parse data via UEFITool");
            ;
        }
        messages = ffs.getMessages();
    }
    ~Uefitool() { ; }
    void show_messages();
    bool messages_occurs() { return !messages.empty(); };
    void dump();
    void dump(const UModelIndex &index);
    void dump(const UModelIndex &index, uint8_t el_type, File *pe_file);
    bool is_pe_index(const UModelIndex &index) {
        return model.rowCount(index) == 4;
    };
    bool is_file_index(const UModelIndex &index) {
        return model.type(index) == Types::File;
    };
    TreeModel model;
    const char *buffer;
    uint32_t buffer_size;
    std::vector<std::pair<UString, UModelIndex>> messages;
    std::vector<efiloader::File *> files;
    USTATUS err;
};
} // namespace efiloader

#endif // EFILOADER_UEFITOOL_H
