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
 * pe.cpp
 */

#include "pe.h"

#include <bytes.hpp>
#include <fixup.hpp>
#include <idp.hpp>
#include <map>
#include <pro.h>
#include <segregs.hpp>

#define DEBUG

#define DIRECTORIES_MAX_ID 15

std::map<uint32_t, const char *> DIRECTORIES = {
    {0, "Export Directory"},
    {1, "Import Directory"},
    {2, "Resource Directory"},
    {3, "Exception Directory"},
    {4, "Security Directory"},
    {5, "Base Relocation Table"},
    {6, "Debug Directory"},
    {7, "Architecture Specific Data"},
    {8, "RVA of GP"},
    {9, "TLS Directory"},
    {10, "Load Configuration Directory"},
    {11, "Bound Import Directory in headers"},
    {12, "Import Address Table"},
    {13, "Delay Load Import Descriptors"},
    {14, "COM Runtime descriptor"},
    {15, "Image data directory"},
};

//
// efiLoader core routines
//

qoff64_t efiloader::PE::head_start() {
    qoff64_t off = 0;
    qlseek(li, 0x3c);
    off = readshort(li);
    reset();
    return off;
}

//
// Functions to extract PE features
//

bool efiloader::PE::good() {
    uint16_t mz = 0;
    qlread(li, &mz, sizeof(uint16_t));
    if (mz != MZ_SIGN) {
        return false;
    }
    _pe_header_off = head_start();
    if (is_p32_plus()) {
        _bits = 64;
    } else if (!is_p32()) {
        loader_failure("[efiLoader] failed to guess PE bitness");
    } else {
        _bits = 32;
    }
    return is_pe();
}

bool efiloader::PE::is_p32() {
    uint16_t magic = 0;
    qlseek(li, _pe_header_off + sizeof(uint32_t));
    qlread(li, &magic, sizeof(uint16_t));
    reset();
    return magic == I386;
}

bool efiloader::PE::is_p32_plus() {
    uint16_t magic = 0;
    qlseek(li, _pe_header_off + sizeof(uint32_t));
    qlread(li, &magic, sizeof(uint16_t));
    reset();
    return magic == AMD64;
}

bool efiloader::PE::is_pe() {
    uint16_t pe_sign = 0;
    qlseek(li, _pe_header_off);
    pe_sign = readshort(li);
    reset();
    return pe_sign == PE_SIGN;
}

uint16_t efiloader::PE::arch() {
    qlseek(li, head_off + sizeof(uint32_t));
    qlread(li, &pe, sizeof(peheader_t));
    return pe.machine;
}

bool efiloader::PE::process() {
    preprocess();
    *pe_base = image_base + image_size;
    return true;
}

const char *efiloader::PE::_machine_name() {
    switch (pe64.machine) {
    case PECPU_80386:
        return "80386";
    case PECPU_80486:
        return "80486";
    case PECPU_80586:
        return "80586";
    case PECPU_SH3:
        return "SH3";
    case PECPU_SH3DSP:
        return "SH3DSP";
    case PECPU_SH3E:
        return "SH3E";
    case PECPU_SH4:
        return "SH4";
    case PECPU_SH5:
        return "SH5";
    case PECPU_ARM:
        return "ARM";
    case PECPU_ARMI:
        return "ARMI";
    case PECPU_ARMV7:
        return "ARMv7";
    case PECPU_EPOC:
        return "ARM EPOC";
    case PECPU_PPC:
        return "PPC";
    case PECPU_PPCFP:
        return "PPC FP";
    case PECPU_PPCBE:
        return "PPC BE";
    case PECPU_IA64:
        return "IA64";
    case PECPU_R3000:
        return "MIPS R3000";
    case PECPU_R4000:
        return "MIPS R4000";
    case PECPU_R6000:
        return "MIPS R6000";
    case PECPU_R10000:
        return "MIPS R10000";
    case PECPU_MIPS16:
        return "MIPS16";
    case PECPU_WCEMIPSV2:
        return "MIPS WCEv2";
    case PECPU_ALPHA:
        return "ALPHA";
    case PECPU_ALPHA64:
        return "ALPHA 64";
    case PECPU_AMD64:
        return "AMD64";
    case PECPU_ARM64:
        return "ARM64";
    case PECPU_M68K:
        return "M68K";
    case PECPU_MIPSFPU:
        return "MIPS FPU";
    case PECPU_MIPSFPU16:
        return "MIPS16 FPU";
    case PECPU_EBC:
        return "EFI Bytecode";
    case PECPU_AM33:
        return "AM33";
    case PECPU_M32R:
        return "M32R";
    case PECPU_CEF:
        return "CEF";
    case PECPU_CEE:
        return "CEE";
    case PECPU_TRICORE:
        return "TRICORE";
    }
    return NULL;
}

//
// Functions processing
//

void efiloader::PE::make_entry(ea_t ea) {
    char func_name[MAXNAMESIZE] = {0};
    ea_t new_ea = image_base + ea;
    qsnprintf(func_name, sizeof(func_name), "%s_entry_%08X",
              _image_name.c_str(), calc_file_crc32(li));
    add_entry(new_ea, new_ea, func_name, true);
    memset(func_name, 0, sizeof(func_name));
}

//
// PE image pre-processing
//

inline size_t efiloader::PE::make_named_word(ea_t ea, const char *name,
                                             const char *extra, size_t count) {
    if (extra) {
        add_extra_cmt(ea, true, extra);
    }
    create_word(ea, 2 * count);
    set_cmt(ea, name, 0);
    op_hex(ea, 0);
    return 2 * count;
}

inline size_t efiloader::PE::make_named_dword(ea_t ea, const char *name,
                                              const char *extra, size_t count) {
    if (extra) {
        add_extra_cmt(ea, true, extra);
    }
    create_word(ea, 4 * count);
    set_cmt(ea, name, 0);
    op_hex(ea, 0);
    return 4 * count;
}

inline size_t efiloader::PE::make_named_qword(ea_t ea, const char *name,
                                              const char *extra, size_t count) {
    if (extra) {
        add_extra_cmt(ea, true, extra);
    }
    create_word(ea, 8 * count);
    set_cmt(ea, name, 0);
    op_hex(ea, 0);
    return 8 * count;
}

//
// Segments processing
//

segment_t *efiloader::PE::make_head_segment(ea_t start, ea_t end,
                                            char *section_name) {
    segment_t *seg = new segment_t;
    seg->bitness = 2;
    seg->perm = SEG_DATA;
    seg->sel = allocate_selector(0x0);
    seg->start_ea = start;
    seg->end_ea = end;
    add_segm_ex(seg, section_name, "DATA", ADDSEG_NOAA | ADDSEG_NOSREG);
    return seg;
}

segment_t *efiloader::PE::make_generic_segment(ea_t seg_ea, ea_t seg_ea_end,
                                            char *section_name,
                                            uint32_t flags) {
    segment_t *generic_segm = new segment_t;
    generic_segm->sel = allocate_selector(0x0);
    generic_segm->start_ea = seg_ea;
    generic_segm->end_ea = seg_ea_end;
    generic_segm->bitness = 2;
    generic_segm->perm = SEGPERM_READ;
    if (flags & PEST_EXEC)
        generic_segm->perm |= SEGPERM_EXEC;
    if (flags & PEST_WRITE)
        generic_segm->perm |= SEGPERM_WRITE;

    if (!qstrstr(section_name, ".")) {
        qstring tmp_section_name = qstring(section_name) + qstring(".unkn");
        section_name = (char *)tmp_section_name.c_str();
    }

    if (flags & PEST_EXEC) {
        generic_segm->type = SEG_CODE;
        add_segm_ex(generic_segm, section_name, "CODE", ADDSEG_NOAA);   
    } else {
        generic_segm->type = SEG_DATA;
        add_segm_ex(generic_segm, section_name, "DATA", ADDSEG_NOAA);   
    }

    if (!qstrcmp(section_name, ".text")) {
        code_segm_name.insert(section_name);
    } else if (!qstrcmp(section_name, ".data")) {
        data_segm_name.insert(section_name);
        data_segment_sel = get_segm_by_name(data_segm_name.c_str())->sel;
    }

    secs_names.push_back(qstring(section_name));
    return generic_segm;
}

int efiloader::PE::preprocess_sections() {
    qlseek(li, _pe_header_off);
    qlread(li, &pe, sizeof(peheader_t));

    // x86
    number_of_sections = pe.nobjs;
    int section_headers_offset = pe.first_section_pos(_pe_header_off);
    headers_size = pe.allhdrsize;

    if (pe.machine == PECPU_AMD64) { // x64
        qlseek(li, _pe_header_off);
        qlread(li, &pe64, sizeof(peheader64_t));
        number_of_sections = pe64.nobjs;
        section_headers_offset = pe64.first_section_pos(_pe_header_off);
        headers_size = pe64.allhdrsize;
    }

    _sec_headers.resize(number_of_sections);
    qlseek(li, section_headers_offset);
    for (int i = 0; i < number_of_sections; i++) {
        qlread(li, &_sec_headers[i], sizeof(pesection_t));
    }

    return 0;
}

ea_t efiloader::PE::process_section_entry(ea_t next_ea) {
    create_strlit(next_ea, 8, STRTYPE_C);
    set_cmt(next_ea, "Name", 0);
    op_hex(next_ea, 0);
    size_t segm_name_len = get_max_strlit_length(next_ea, STRTYPE_C);
    get_strlit_contents(&segm_names.push_back(), next_ea, segm_name_len,
                        STRTYPE_C);
    next_ea += 8;
    create_dword(next_ea, 4);
    set_cmt(next_ea, "Virtual size", 0);
    op_hex(next_ea, 0);
    segm_sizes.push_back(get_dword(next_ea));
    next_ea += 4;
    create_dword(next_ea, 4);
    set_cmt(next_ea, "Virtual address", 0);
    op_hex(next_ea, 0);
    segm_entries.push_back(get_dword(next_ea));
    next_ea += 4;
    create_dword(next_ea, 4);
    set_cmt(next_ea, "Size of raw data", 0);
    op_hex(next_ea, 0);
    segm_raw_sizes.push_back(get_dword(next_ea));
    next_ea += 4;
    create_dword(next_ea, 4);
    set_cmt(next_ea, "Pointer to raw data", 0);
    op_hex(next_ea, 0);
    next_ea += 4;
    create_dword(next_ea, 4);
    set_cmt(next_ea, "Pointer to relocations", 0);
    op_hex(next_ea, 0);
    next_ea += 4;
    create_dword(next_ea, 4);
    set_cmt(next_ea, "Pointer to line numbers", 0);
    op_hex(next_ea, 0);
    next_ea += 4;
    create_word(next_ea, 2);
    set_cmt(next_ea, "Number of relocations", 0);
    op_hex(next_ea, 0);
    next_ea += 2;
    create_word(next_ea, 2);
    set_cmt(next_ea, "Number of linenumbers", 0);
    op_hex(next_ea, 0);
    next_ea += 2;
    create_dword(next_ea, 4);
    set_cmt(next_ea, "Characteristics", 0);
    op_hex(next_ea, 0);
    uint32_t section_characteristics = get_dword(next_ea);
    next_ea += 4;
    qstring section_name = qstring(_image_name.c_str());
    section_name += qstring("_") + qstring(segm_names[0].c_str());
    ea_t seg_ea = image_base + segm_entries[0];
    ea_t seg_ea_end = seg_ea + segm_raw_sizes[0];
    msg("[efiloader]\tprocessing: %s\n", segm_names[0].c_str());

    segments.push_back(make_generic_segment(seg_ea, seg_ea_end,
                                             (char *)section_name.c_str(),
                                             section_characteristics));
    segm_names.pop_back();
    segm_sizes.pop_back();
    segm_raw_sizes.pop_back();
    segm_entries.pop_back();
    return next_ea;
}

void efiloader::PE::setup_ds_selector() {
    for (; !secs_names.empty(); secs_names.pop_back()) {
        msg("[efiloader]\tsetting DS ( %#x ) for %s segment\n",
            data_segment_sel, secs_names[secs_names.size() - 1].c_str());
        segment_t *seg =
            get_segm_by_name(secs_names[secs_names.size() - 1].c_str());
        set_default_sreg_value(seg, str2reg("DS"), data_segment_sel);
    }
}

//
// PE core processing
//

void efiloader::PE::preprocess() {
    char seg_name[MAXNAMESIZE] = {0};
    char seg_header_name[MAXNAMESIZE] = {0};
    char image_base_name[MAXNAMESIZE] = {0};
    char section_name[MAXNAMESIZE] = {0};
    ea_t next_ea = 0;
    ea_t ea = align_up(*pe_base, PAGE_SIZE);
    image_base = ea;
    ea_t start = ea;
    ea_t end = ea + qlsize(li);
    qsnprintf(seg_name, sizeof(seg_name), "%s_%08X", _image_name.c_str(),
              calc_file_crc32(li));
    qsnprintf(seg_header_name, sizeof(seg_header_name), "%s_HEADER",
              _image_name.c_str());
    qsnprintf(image_base_name, sizeof(image_base_name), "%s_IMAGE_BASE",
              _image_name.c_str());

    preprocess_sections();
    push_to_idb(start, end);
    segments.push_back(make_head_segment(image_base, image_base + headers_size,
                                         seg_header_name));
    secs_names.push_back(qstring(seg_header_name));
    create_word(ea, 2);
    set_cmt(ea, "PE magic number", 0);
    op_hex(ea, 0);
    create_word(ea + 2, 2);
    set_cmt(ea + 2, "Bytes on last page of file", 0);
    op_hex(ea + 2, 0);
    create_word(ea + 4, 2);
    set_cmt(ea + 4, "Pages in file", 0);
    op_hex(ea + 4, 0);
    create_word(ea + 6, 2);
    set_cmt(ea + 6, "Relocations", 0);
    op_hex(ea + 6, 0);
    create_word(ea + 8, 2);
    set_cmt(ea + 8, "Size of header in paragraphs", 0);
    op_hex(ea + 8, 0);
    create_word(ea + 10, 2);
    set_cmt(ea + 10, "Minimum extra paragraphs needed", 0);
    op_hex(ea + 10, 0);
    create_word(ea + 10, 2);
    set_cmt(ea + 12, "Maximum extra paragraphs needed", 0);
    op_hex(ea + 12, 0);
    create_word(ea + 14, 2);
    set_cmt(ea + 14, "Initial (relative) SS value", 0);
    op_hex(ea + 12, 0);
    create_word(ea + 16, 2);
    set_cmt(ea + 16, "Initial SP value", 0);
    op_hex(ea + 16, 0);
    create_word(ea + 18, 2);
    set_cmt(ea + 18, "Checksum", 0);
    op_hex(ea + 18, 0);
    create_word(ea + 20, 2);
    set_cmt(ea + 20, "Initial IP value", 0);
    op_hex(ea + 20, 0);
    create_word(ea + 22, 2);
    set_cmt(ea + 22, "Initial (relative) CS value", 0);
    op_hex(ea + 22, 0);
    create_word(ea + 24, 2);
    set_cmt(ea + 24, "File address of relocation table", 0);
    op_hex(ea + 24, 0);
    op_offset(ea + 24, 0, REF_OFF64, BADADDR, image_base);
    create_word(ea + 26, 2);
    set_cmt(ea + 26, "Overlay number", 0);
    op_hex(ea + 26, 0);
    create_word(ea + 28, 8);
    set_cmt(ea + 28, "Reserved words", 0);
    op_hex(ea + 28, 0);
    create_word(ea + 36, 2);
    set_cmt(ea + 36, "OEM identifier (for e_oeminfo)", 0);
    op_hex(ea + 36, 0);
    create_word(ea + 38, 2);
    set_cmt(ea + 38, "OEM information; e_oemid specific", 0);
    op_hex(ea + 38, 0);
    create_word(ea + 40, 2);
    set_cmt(ea + 40, "Reserved words", 0);
    op_hex(ea + 38, 0);
    ea_t old_ea = ea;
    ea = ea + 0x3c;
    create_dword(ea, 4);
    if (is_loaded(ea) && get_dword(ea)) {
        msg("[efiloader] making relative offset: %#x\n", ea);
        op_plain_offset(ea, 0, *pe_base);
    }
    set_cmt(ea, "File address of new exe header", 0);
    uint32_t nt_headers_off = get_dword(ea);
    create_byte(old_ea + 0x40, nt_headers_off - 0x40);
    set_cmt(old_ea + 0x40, "DOS Stub code", 0);
    ea_t nt_headers_ea = old_ea + nt_headers_off;
    add_extra_cmt(nt_headers_ea, 1, "IMAGE_NT_HEADERS");
    switch (get_word(old_ea)) {
    case 0x20B:
        del_items(nt_headers_ea, 3, 0x108);
        break;
    default:
        del_items(nt_headers_ea, 3, 0xf8);
        break;
    }
    create_dword(nt_headers_ea, 4);
    set_cmt(nt_headers_ea, "Signature", 0);
    op_hex(nt_headers_ea, 0);
    ea_t image_file_header_ea = nt_headers_ea + 4;
    add_extra_cmt(image_file_header_ea, 1, "IMAGE_FILE_HEADER");
    create_word(image_file_header_ea, 2);
    set_cmt(image_file_header_ea, "Machine", 0);
    op_hex(image_file_header_ea, 0);
    image_file_header_ea += 2;
    create_word(image_file_header_ea, 2);
    set_cmt(image_file_header_ea, "Number of sections", 0);
    number_of_sections = get_word(image_file_header_ea);
    op_hex(image_file_header_ea, 0);
    ea_t timestamp_ea = image_file_header_ea + 2;
    create_dword(timestamp_ea, 4);
    set_cmt(timestamp_ea, "Time stamp", 0);
    ea_t pointer_to_symbol_table = timestamp_ea + 4;
    create_dword(pointer_to_symbol_table, 4);
    set_cmt(pointer_to_symbol_table, "Pointer to symbol table", 0);
    op_hex(pointer_to_symbol_table, 0);
    next_ea = pointer_to_symbol_table + 4;
    create_dword(next_ea, 4);
    set_cmt(next_ea, "Number of symbols", 0);
    op_hex(next_ea, 0);
    next_ea += 4;
    uint16_t size_of_optional_header = get_word(next_ea);
    create_word(next_ea, 2);
    set_cmt(next_ea, "Size of optional header", 0);
    op_hex(next_ea, 0);
    next_ea += 2;
    create_word(next_ea, 2);
    set_cmt(next_ea, "Characteristics", 0);
    op_hex(next_ea, 0);
    next_ea += 2;
    add_extra_cmt(next_ea, 1, "IMAGE_OPTIONAL_HEADER");
    ea_t image_optional_header = next_ea;
    create_word(next_ea, 2);
    set_cmt(next_ea, "Magic number", 0);
    op_hex(next_ea, 0);
    next_ea += 2;
    create_byte(next_ea, 1);
    set_cmt(next_ea, "Major linker version", 0);
    op_hex(next_ea, 0);
    next_ea += 1;
    create_byte(next_ea, 1);
    set_cmt(next_ea, "Minor linker version", 0);
    op_hex(next_ea, 0);
    next_ea += 1;
    create_dword(next_ea, 4);
    set_cmt(next_ea, "Size of code", 0);
    op_hex(next_ea, 0);
    next_ea += 4;
    create_dword(next_ea, 4);
    set_cmt(next_ea, "Size of initialized data", 0);
    op_hex(next_ea, 0);
    next_ea += 4;
    create_dword(next_ea, 4);
    set_cmt(next_ea, "Size of uninitialized data", 0);
    op_hex(next_ea, 0);
    next_ea += 4;
    create_dword(next_ea, 4);
    set_cmt(next_ea, "Address of entry point", 0);
    make_entry(get_dword(next_ea));
    refinfo_t ri;
    ri.init(REF_OFF64, image_base);
    if (is_loaded(next_ea) && get_dword(next_ea)) {
        op_offset_ex(next_ea, 0, &ri);
    }
    next_ea += 4;
    create_dword(next_ea, 4);
    if (is_loaded(next_ea) && get_dword(next_ea)) {
        op_offset_ex(next_ea, 0, &ri);
    }
    set_cmt(next_ea, "Base of code", 0);
    make_entry(get_dword(next_ea));
    next_ea += 4;
    uint64_t default_image_base = get_qword(next_ea);
    create_qword(next_ea, 8);
    set_cmt(next_ea, "Image base", 0);
    op_hex(next_ea, 0);
    op_plain_offset(next_ea, 0, *pe_base);
    next_ea += 8;
    create_dword(next_ea, 4);
    set_cmt(next_ea, "Section alignment", 0);
    op_hex(next_ea, 0);
    next_ea += 4;
    create_dword(next_ea, 4);
    set_cmt(next_ea, "File alignment", 0);
    op_hex(next_ea, 0);
    next_ea += 4;
    create_word(next_ea, 2);
    set_cmt(next_ea, "Major operating system version", 0);
    op_hex(next_ea, 0);
    next_ea += 2;
    create_word(next_ea, 2);
    set_cmt(next_ea, "Minor operating system version", 0);
    op_hex(next_ea, 0);
    next_ea += 2;
    create_word(next_ea, 2);
    set_cmt(next_ea, "Major image version", 0);
    op_hex(next_ea, 0);
    next_ea += 2;
    create_word(next_ea, 2);
    set_cmt(next_ea, "Minor image version", 0);
    op_hex(next_ea, 0);
    next_ea += 2;
    create_word(next_ea, 2);
    set_cmt(next_ea, "Major subsystem version", 0);
    op_hex(next_ea, 0);
    next_ea += 2;
    create_word(next_ea, 2);
    set_cmt(next_ea, "Minor subsystem version", 0);
    op_hex(next_ea, 0);
    next_ea += 2;
    create_dword(next_ea, 4);
    set_cmt(next_ea, "Win32 Version value", 0);
    op_hex(next_ea, 0);
    next_ea += 4;
    create_dword(next_ea, 4);
    set_cmt(next_ea, "Size of image", 0);
    op_hex(next_ea, 0);
    image_size = get_dword(next_ea);
    next_ea += 4;
    create_dword(next_ea, 4);
    set_cmt(next_ea, "Size of headers", 0);
    op_hex(next_ea, 0);
    next_ea += 4;
    create_dword(next_ea, 4);
    set_cmt(next_ea, "Checksum", 0);
    op_hex(next_ea, 0);
    next_ea += 4;
    create_word(next_ea, 2);
    set_cmt(next_ea, "Subsystem", 0);
    op_hex(next_ea, 0);
    next_ea += 2;
    create_word(next_ea, 2);
    set_cmt(next_ea, "Dll characteristics", 0);
    op_hex(next_ea, 0);
    next_ea += 2;
    create_qword(next_ea, 8);
    set_cmt(next_ea, "Size of stack reserve", 0);
    op_hex(next_ea, 0);
    next_ea += 8;
    create_qword(next_ea, 8);
    set_cmt(next_ea, "Size of stack commit", 0);
    op_hex(next_ea, 0);
    next_ea += 8;
    create_qword(next_ea, 8);
    set_cmt(next_ea, "Size of heap reserve", 0);
    op_hex(next_ea, 0);
    next_ea += 8;
    create_qword(next_ea, 8);
    set_cmt(next_ea, "Size of heap commit", 0);
    op_hex(next_ea, 0);
    next_ea += 8;
    create_dword(next_ea, 4);
    set_cmt(next_ea, "Loader flag", 0);
    op_hex(next_ea, 0);
    next_ea += 4;
    create_dword(next_ea, 4);
    set_cmt(next_ea, "Number of data directories", 0);
    op_hex(next_ea, 0);
    while (!is_loaded(next_ea)) {
        continue;
    }
    number_of_dirs = get_dword(next_ea);
    uint32_t va = 0;
    uint32_t size = 0;
    next_ea += 4;
    for (int i = 0; i < number_of_dirs; i++) {
        if (is_reloc_dir(i)) {
            uint32_t relocs_rva = get_dword(next_ea);
            uint32_t relocs_size = get_dword(next_ea + 4);
            if (relocs_rva && relocs_size) {
                ea_t relocs_va = image_base + relocs_rva;
                ea_t relocs_va_end = relocs_va + relocs_size;
                ea_t delta = image_base - default_image_base;
                ea_t block_addr = get_dword(relocs_va);
                ea_t block_size = get_dword(relocs_va + 4);
                while (block_size && relocs_va < relocs_va_end) {
                    ea_t block_base = image_base + block_addr;
                    int block_reloc_count = (block_size - 8) / 2;

                    ea_t block_ptr = relocs_va + 8;
                    while (block_reloc_count--) {
                        uint16_t reloc_value = get_word(block_ptr);
                        uint16_t type = reloc_value & PER_TYPE;
                        uint16_t offset = reloc_value & PER_OFF;
                        if (type == PER_DIR64)
                            add_qword(block_base + offset, delta);
                        else if (type == PER_HIGHLOW)
                            add_dword(block_base + offset, (uint32_t)delta);
                        else if (type == PER_HIGH)
                            add_word(block_base + offset, (uint16_t)(delta >> 16));
                        else if (type == PER_LOW)
                            add_word(block_base + offset, (uint16_t)delta);
                        block_ptr += 2;
                    }
                    relocs_va += block_size;

                    block_addr = get_dword(relocs_va);
                    block_size = get_dword(relocs_va + 4);
                }
            }
        }
        if (is_reloc_dir(i) || is_debug_dir(i)) {
            add_extra_cmt(next_ea, true, DIRECTORIES[i]);
            create_dword(next_ea, 4);
            create_dword(next_ea + 4, 4);
            ;
            op_hex(next_ea, 0);
            op_hex(next_ea + 4, 0);
            set_cmt(next_ea, "Virtual address", 0);
            set_cmt(next_ea + 4, "Size", 0);
        } else {
            create_qword(next_ea, 8);
            set_cmt(next_ea, DIRECTORIES[i], 0);
        }
        next_ea += 8;
    }
    del_items(next_ea, DELIT_EXPAND | DELIT_DELNAMES, 0x28 * number_of_sections);
    for (int i = 0; i < number_of_sections; i++) {
        next_ea = process_section_entry(next_ea);
        memset(seg_name, 0, sizeof(seg_name));
        memset(seg_header_name, 0, sizeof(seg_name));
        memset(image_base_name, 0, sizeof(seg_name));
        memset(section_name, 0, sizeof(seg_name));
    }
}
