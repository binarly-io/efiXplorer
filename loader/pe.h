// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2020-2026 Binarly

#pragma once

#include <memory>
#include <string>

#include "ida_core.h"
#include "pe_ida.h"
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
  PE(linput_t *i_li, const std::string &fname, ea_t *base, ushort *sel_base,
     int ord, uint16_t mt)
      : _image_name(fname.substr(fname.find_last_of("/\\") + 1)), pe_base(base),
        pe_sel_base(sel_base), li(i_li), _sec_off(0), _sec_ea(0), _sel(0),
        _ord(ord) {
    inf_set_64bit();
    if (mt == PECPU_ARM64) {
      set_processor_type("arm", SETPROC_LOADER);
    } else {
      set_processor_type("metapc", SETPROC_LOADER);
    }
    cm_t cm = inf_get_cc_cm() & ~CM_MASK;
    inf_set_cc_cm(cm | CM_N64);
    if (default_compiler() == COMP_UNK) {
      set_compiler_id(COMP_MS);
    }
    reset();
  }

  ~PE() { close_linput(li); }
  uint32_t number_of_sections;
  uint32_t number_of_dirs;
  char *name;
  bool is_reloc_dir(uint32_t i) { return i == 5; }
  bool is_debug_dir(uint32_t i) { return i == 6; }
  void set_64_bit_segm_and_rabase(ea_t ea) {
    segment_t *tmp_seg = getseg(ea);
    set_segm_addressing(tmp_seg, 2);
    set_segm_base(tmp_seg, *pe_base);
  }
  void set_64_bit(ea_t ea) {
    segment_t *tmp_seg = getseg(ea);
    set_segm_addressing(tmp_seg, 2);
  }
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
  inline ea_t skip(ea_t ea, qoff64_t off) { return ea + off; }
  // ida db processing
  void push_to_idb(ea_t start, ea_t end) {
    // Map header
    file2base(li, 0x0, start, start + headers_size, FILEREG_PATCHABLE);
    // Map sections
    for (int i = 0; i < number_of_sections; i++) {
      file2base(li, _sec_headers[i].s_scnptr, start + _sec_headers[i].s_vaddr,
                start + _sec_headers[i].s_vaddr + _sec_headers[i].s_psize,
                FILEREG_PATCHABLE);
    }
  }

private:
  qvector<ea_t> segments_ea;
  std::string _full_path;
  std::string _image_name;
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
  void reset() { qlseek(li, 0); }
  const char *_machine_name();
  //
  // PE image preprocessing
  //
  void preprocess();
  ea_t create_byte_with(ea_t ea, const char *comment);
  ea_t create_word_with(ea_t ea, const char *comment);
  ea_t create_dword_with(ea_t ea, const char *comment);
  ea_t create_qword_with(ea_t ea, const char *comment);
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
  uint64_t default_image_base;
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
                                  const char *section_name, uint32_t flags);
  segment_t *make_head_segment(ea_t start, ea_t end, const char *name);
  void setup_ds_selector();
};
} // namespace efiloader

enum MachineType { AMD64 = 0x8664, I386 = 0x014C, AARCH64 = 0xaa64 };
