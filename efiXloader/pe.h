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
 * pe.h
 */

#ifndef EFILOADER_PE_H
#define EFILOADER_PE_H

//
// IDA header
//
#include "ida_core.h"
#include "pe_ida.h"
//
// Utilities
//
#include "utils.h"

#include <typeinf.hpp>

#define PAGE_SIZE 0x1000

#define MZ_SIGN 0x5A4D       // MZ header
#define MAGIC_P32 0x10B      // Normal PE file
#define MAGIC_P32_PLUS 0x20B // 64-bit image
#define PE_SIGN 0x4550       // PE signature

namespace efiloader {

class PE {
  public:
    PE(linput_t *i_li, std::basic_string<char> fname, ea_t *base,
       ushort *sel_base, int ord) {
        _image_name = fname.substr(fname.find_last_of("/\\") + 1);
        msg("[efiloader] image name is %s\n", _image_name.c_str());
        pe_base = base;
        pe_sel_base = sel_base;
        li = i_li;
        utils = new Utils;
        _sec_off = 0;
        _sec_ea = 0;
        _sel = 0;
        _ord = ord;
        inf_set_64bit();
        set_processor_type("metapc", SETPROC_LOADER);
        if (default_compiler() == COMP_UNK)
            set_compiler_id(COMP_MS);
        reset();
    };
    ~PE() {
        close_linput(li);
        delete utils;
    }
    uint32_t number_of_sections;
    uint32_t number_of_dirs;
    char *name;
    bool is_reloc_dir(uint32_t i) { return i == 5; };
    bool is_debug_dir(uint32_t i) { return i == 6; };
    void set_64_bit_segm_and_rabase(ea_t ea) {
        segment_t *tmp_seg = getseg(ea);
        set_segm_addressing(tmp_seg, 2);
        set_segm_base(tmp_seg, *pe_base);
    }
    void set_64_bit(ea_t ea) {
        segment_t *tmp_seg = getseg(ea);
        set_segm_addressing(tmp_seg, 2);
    };
    bool is_p32();
    bool is_p32_plus();
    bool is_pe();
    bool good();
    bool process();
    uint16_t arch();
    // data processing
    inline size_t make_named_byte(ea_t ea, const char *name,
                                  const char *extra = NULL, size_t count = 1);
    inline size_t make_named_word(ea_t ea, const char *name,
                                  const char *extra = NULL, size_t count = 1);
    inline size_t make_named_dword(ea_t ea, const char *name,
                                   const char *extra = NULL, size_t count = 1);
    inline size_t make_named_qword(ea_t ea, const char *name,
                                   const char *extra = NULL, size_t count = 1);
    inline ea_t skip(ea_t ea, qoff64_t off) { return ea + off; };
    // ida db processing
    void push_to_idb(ea_t start, ea_t end) {
        // Map header
        file2base(li, 0x0, start, start + headers_size, FILEREG_PATCHABLE);
        // Map sections
        for (int i = 0; i < number_of_sections; i++) {
            file2base(li, _sec_headers[i].s_scnptr,
                      start + _sec_headers[i].s_vaddr,
                      start + _sec_headers[i].s_vaddr  + _sec_headers[i].s_psize,
                      FILEREG_PATCHABLE);
        }
    };

  private:
    qvector<ea_t> segments_ea;
    std::basic_string<char> _full_path;
    std::basic_string<char> _image_name;
    efiloader::Utils *utils;
    linput_t *li;
    qoff64_t head_start();
    qoff64_t head_off;
    qoff64_t _pe_header_off;
    uint16_t headers_size;
    peheader_t pe;
    peheader64_t pe64;
    uint16_t _sec_num;
    uint16_t _bits;
    qvector<sel_t> selectors;
    qvector<sel_t> data_selectors;
    qvector<qstring> ds_seg_names;
    qvector<qstring> cs_seg_names;
    void reset() { qlseek(li, 0); };
    const char *_machine_name();
    //
    // PE image preprocessing
    //
    void preprocess();
    //
    // sections processing
    //
    qvector<pesection_t> _sec_headers;
    ea_t *pe_base;
    ushort *pe_sel_base;
    ushort _sel;
    ea_t _sec_off;
    ea_t _sec_ea;
    // pe ord
    uval_t _ord;
    ea_t image_base;
    uint32_t image_size;
    qvector<size_t> segm_sizes;
    qvector<size_t> segm_raw_sizes;
    qvector<ea_t> segm_entries;

    int preprocess_sections();
    //
    // functions processing
    //
    void make_entry(ea_t ea);
    void make_code(ea_t ea);
    //
    // segments processing
    //
    qstring code_segm_name;
    qstring data_segm_name;
    sel_t data_segment_sel;
    qvector<segment_t *> segments;
    qvector<qstring> segm_names;
    qvector<qstring> secs_names;
    ea_t process_section_entry(ea_t ea);
    segment_t *make_generic_segment(ea_t seg_ea, ea_t seg_ea_end,
                                 char *section_name, uint32_t flags);
    segment_t *make_head_segment(ea_t start, ea_t end, char *name);
    void setup_ds_selector();
};
} // namespace efiloader

enum machine_type { AMD64 = 0x8664, I386 = 0x014C };

#endif // EFILOADER_PE_H
