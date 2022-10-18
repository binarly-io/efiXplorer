/*
 * efiXloader
 * Copyright (C) 2020-2022 Binarly
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
#include <filesystem>
#include <vector>

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

void efiloader::Uefitool::get_unique_name(qstring &name) {
    // If the given name is already in use, create a new one
    qstring new_name = name;
    std::string suf;
    int index = 0;
    while (!(unique_names.insert(new_name).second)) {
        suf = "_" + std::to_string(++index);
        new_name = name + static_cast<qstring>(suf.c_str());
    }
    name = new_name;
}

void efiloader::Uefitool::get_image_guid(qstring &image_guid, UModelIndex index) {
    UString guid;
    UModelIndex guid_index;
    switch (model.subtype(model.parent(index))) {
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
efiloader::Uefitool::parseDepexSectionBody(const UModelIndex &index, UString &parsed) {
    // Adopted from FfsParser::parseDepexSectionBody
    std::vector<std::string> res;

    if (!index.isValid())
        return res;

    UByteArray body = model.body(index);

    // Check data to be present
    if (body.size() < 2) { // 2 is a minimal sane value, i.e TRUE + END
        return res;
    }

    const EFI_GUID *guid;
    const UINT8 *current = (const UINT8 *)body.constData();

    // Special cases of first opcode
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

    // Parse the rest of depex
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
            // Check that the rest of depex has correct size
            if ((UINT32)body.size() -
                    (UINT32)(current - (const UINT8 *)body.constData()) <=
                EFI_DEP_OPCODE_SIZE + sizeof(EFI_GUID)) {
                parsed.clear();
                return res;
            }
            guid = (const EFI_GUID *)(current + EFI_DEP_OPCODE_SIZE);
            parsed += UString("\nPUSH ") + guidToUString(readUnaligned(guid));
            // Add protocol GUID to result vector
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
            // Check that END is the last opcode
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
        machine_type_detected = true;
    }
}

void efiloader::Uefitool::dump(const UModelIndex &index, uint8_t el_type,
                               efiloader::File *file) {
    qstring module_name("");
    qstring guid("");

    switch (model.subtype(index)) {
    case EFI_SECTION_TE:
        file->is_te = true;
        file->ubytes = model.body(index);
        break;
    case EFI_SECTION_PE32:
        file->is_pe = true;
        file->ubytes = model.body(index);
        if (!machine_type_detected) {
            set_machine_type(model.body(index));
        }
        break;
    case EFI_SECTION_USER_INTERFACE:
        file->has_ui = true;
        if (file->is_pe || file->is_te) {
            file->uname = model.body(index);
            utf16_utf8(&module_name,
                       reinterpret_cast<const wchar16_t *>(file->uname.data()));
            if (module_name.size()) {
                // save image to the images_guids
                get_image_guid(guid, index);
                if (images_guids[guid.c_str()]
                        .is_null()) { // check if GUID already exists
                    get_unique_name(module_name);
                    images_guids[guid.c_str()] = module_name.c_str();
                    file->qname.swap(module_name);
                    file->write();
                    files.push_back(file);
                }
            }
        }
        break;
    case EFI_SECTION_COMPRESSION:
        for (int i = 0; i < model.rowCount(index); i++) {
            dump(index.child(i, 0), i, file);
        }
        break;
    // Get DEPEX information
    case EFI_SECTION_DXE_DEPEX:
        get_deps(index, "EFI_SECTION_DXE_DEPEX");
        break;
    case EFI_SECTION_MM_DEPEX:
        get_deps(index, "EFI_SECTION_MM_DEPEX");
        break;
    case EFI_SECTION_PEI_DEPEX:
        get_deps(index, "EFI_SECTION_PEI_DEPEX");
        break;
    default:
        // if there is no UI section, then the image name is GUID
        if ((file->is_pe || file->is_te) && !file->has_ui) {
            get_image_guid(module_name, index);
            file->qname.swap(module_name);
            file->write();
            files.push_back(file);
            if (module_name.size()) {
                // save image to the images_guids
                images_guids[module_name.c_str()] = module_name.c_str();
            }
        }
        break;
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

void efiloader::Uefitool::get_deps(UModelIndex index, std::string key) {
    UString parsed;
    std::vector<std::string> deps;
    qstring image_guid("");

    get_image_guid(image_guid, index);
    deps = parseDepexSectionBody(index, parsed);
    if (deps.size()) {
        msg("[efiXloader] dependency section for image with GUID %s: %s\n",
            image_guid.c_str(), parsed.data);
        all_deps[key][image_guid.c_str()] = deps;
    }
}

void efiloader::Uefitool::dump_jsons() {
    // Dump deps
    std::filesystem::path out;
    out /= get_path(PATH_TYPE_IDB);
    out.replace_extension(".deps.json");
    std::ofstream out_deps(out);
    out_deps << std::setw(4) << all_deps << std::endl;
    // Dump images
    out.replace_extension("").replace_extension(".images.json");
    std::ofstream out_guids(out);
    out_guids << std::setw(4) << images_guids << std::endl;
}
