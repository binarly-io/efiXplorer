/*
 *        __ ___   __      _
 *       / _(_) \ / /     | |
 *   ___| |_ _ \ V / _ __ | | ___  _ __ ___ _ __
 *  / _ \  _| | > < | '_ \| |/ _ \| '__/ _ \ '__|
 * |  __/ | | |/ . \| |_) | | (_) | | |  __/ |
 *  \___|_| |_/_/ \_\ .__/|_|\___/|_|  \___|_|
 *                  | |
 *                  |_|
 *
 * efiXplorer
 * Copyright (C) 2020  binarly-io
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
 * efiUtils.cpp
 *
 */

#include "efiUtils.h"
#include "tables/efi_system_tables.h"

static const char plugin_name[] = "efiXplorer";

//--------------------------------------------------------------------------
// Create EFI_GUID structure
void setGuidStructure(ea_t ea) {
    static const char struct_name[] = "_EFI_GUID";
    struc_t *sptr = get_struc(get_struc_id(struct_name));
    if (sptr == nullptr) {
        sptr = get_struc(add_struc(-1, struct_name));
        if (sptr == nullptr)
            return;
        add_struc_member(sptr, "data1", -1, dword_flag(), NULL, 4);
        add_struc_member(sptr, "data2", -1, word_flag(), NULL, 2);
        add_struc_member(sptr, "data3", -1, word_flag(), NULL, 2);
        add_struc_member(sptr, "data4", -1, byte_flag(), NULL, 8);
    }
    size_t size = get_struc_size(sptr);
    create_struct(ea, size, sptr->id);
}

//--------------------------------------------------------------------------
// Get input file type (X64 or X86)
uint8_t getFileType() {
    char fileType[256] = {};
    get_file_type_name(fileType, 256);
    auto fileTypeStr = static_cast<string>(fileType);
    int index = fileTypeStr.find("AMD64");
    if (index > 0) {
        /* Portable executable for AMD64 (PE) */
        return X64;
    }
    index = fileTypeStr.find("80386");
    if (index > 0) {
        /* Portable executable for 80386 (PE) */
        return X86;
    }
    return 0;
}

//--------------------------------------------------------------------------
// Get boot service description comment
string getBsComment(ea_t offset, size_t arch) {
    ea_t offset_arch;
    string cmt = "";
    cmt += "gBS->";
    for (auto i = 0; i < BTABLE_LEN; i++) {
        offset_arch = (ea_t)boot_services_table[i].offset64;
        if (arch == X86) {
            offset_arch = (ea_t)boot_services_table[i].offset86;
        }
        if (offset == offset_arch) {
            cmt += boot_services_table[i].name;
            cmt += "()\n";
            cmt += boot_services_table[i].prototype;
            cmt += "\n";
            cmt += boot_services_table[i].parameters;
            break;
        }
    }
    return cmt;
}

//--------------------------------------------------------------------------
// Get runtime service description comment
string getRtComment(ea_t offset, size_t arch) {
    ea_t offset_arch;
    string cmt = "";
    cmt += "gRT->";
    for (auto i = 0; i < RTABLE_LEN; i++) {
        offset_arch = (ea_t)runtime_services_table[i].offset64;
        if (arch == X86) {
            offset_arch = (ea_t)runtime_services_table[i].offset86;
        }
        if (offset == offset_arch) {
            cmt += runtime_services_table[i].name;
            cmt += "()\n";
            cmt += runtime_services_table[i].prototype;
            cmt += "\n";
            cmt += runtime_services_table[i].parameters;
            break;
        }
    }
    return cmt;
}
