/*
 * efiXloader
 * Copyright (C) 2020-2021 Binarly
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
 * uefitool.cpp
 */

#include "uefitool.h"
#include <codecvt>
#include <vector>

#define DEBUG

void efiloader::File::print() {
    msg("[UEFITOOL PARSER] file ( %s )  \n", qname.c_str());
    for (int i = 0; i < 0x10; i++) {
        msg("%02X ", ubytes[i]);
    };
    msg("\n");
}

void efiloader::Uefitool::show_messages() {
    for (size_t i = 0; i < messages.size(); i++) {
        msg("[UEFITOOL PARSER] %s\n", messages[i].first.toLocal8Bit());
    }
}

void efiloader::Uefitool::dump(const UModelIndex &index, uint8_t el_type,
                               efiloader::File *file) {
    qstring module_name("");
    qstring module_guid("");
    UString guid;

    switch (model.subtype(index)) {
    case EFI_SECTION_PE32:
        file->is_pe = true;
        file->ubytes = model.body(index);
        break;
    case EFI_SECTION_USER_INTERFACE:
        file->has_ui = true;
        if (file->is_pe) {
            file->uname = model.body(index);
            utf16_utf8(&module_name,
                       reinterpret_cast<const wchar16_t *>(file->uname.data()));
            file->qname.swap(module_name);
            file->write();
            files.push_back(file);
        }
        break;
    case EFI_SECTION_COMPRESSION:
        for (int i = 0; i < model.rowCount(index); i++) {
            dump(index.child(i, 0), i, file);
        }
        break;
    default:
        break;
    }

    // if there is no UI section, then the image name is GUID
    if (file->is_pe && !file->has_ui) {
        // get parent body and read GUID
        guid = guidToUString(readUnaligned(
            (const EFI_GUID *)(model.header(model.parent(index)).constData())));
        module_guid = reinterpret_cast<char *>(guid.data);
        file->qname.swap(module_guid);
        file->write();
        files.push_back(file);
    }

    return dump(index);
}

void efiloader::Uefitool::dump(const UModelIndex &index) {
    USTATUS err;
    msg("[UEFITOOL PARSER] file (%s, %s)\n", itemTypeToUString(model.type(index)).data,
        itemSubtypeToUString(model.type(index), model.subtype(index)).data);
    msg("[UEFITOOL PARSER] number of items: %#x\n", model.rowCount(index));
    if (is_file_index(index)) {
        efiloader::File *file = new File;
        for (int i = 0; i < model.rowCount(index); i++) {
            dump(index.child(i, 0), i, file);
        }
    } else {
        for (int i = 0; i < model.rowCount(index); i++) {
            dump(index.child(i, 0));
        }
    }
}

void efiloader::Uefitool::dump() { return dump(model.index(0, 0)); }
