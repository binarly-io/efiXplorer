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
 * ida_core.h
 */

#ifndef EFILOADER_IDA_CORE_H
#define EFILOADER_IDA_CORE_H

#define USE_STANDARD_FILE_FUNCTIONS

#include <auto.hpp>
#include <bytes.hpp>
#include <diskio.hpp>
#include <entry.hpp>
#include <fixup.hpp>
#include <fpro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include <loader.hpp>
#include <name.hpp>
#include <offset.hpp>
#include <pro.h>
#include <segment.hpp>
#include <segregs.hpp>

//----------------------------------

#define CLASS_CODE "CODE"
#define NAME_CODE ".text"
#define CLASS_DATA "DATA"
#define CLASS_CONST "CONST"
#define NAME_DATA ".data"
#define CLASS_BSS "BSS"
#define NAME_BSS ".bss"
#define NAME_EXTERN "extern"
#define NAME_COMMON "common"
#define NAME_ABS "abs"
#define NAME_UNDEF "UNDEF"
#define CLASS_STACK "STACK"
#define CLASS_RES16 "RESOURCE"
#define LDR_NODE "$ IDALDR node for ids loading $"
#define LDR_INFO_NODE "$ IDALDR node for unload $"

//--------------------------------------------------------------------------
template <class T>
bool _validate_array_count(linput_t *li, T *p_cnt, size_t elsize,
                           int64 current_offset = -1, int64 max_offset = -1) {
    if (current_offset == -1)
        current_offset = qltell(li);
    if (max_offset == -1)
        max_offset = qlsize(li);
    int64 rest = max_offset - current_offset;
    T cnt = *p_cnt;
    if (current_offset >= 0 && rest >= 0) {
#ifndef __X86__
        typedef size_t biggest_t;
#else
        typedef ea_t biggest_t;
#endif
        if (is_mul_ok<biggest_t>(elsize, cnt)) {
            biggest_t needed = elsize * cnt;
#ifdef __X86__
            if (needed == size_t(needed))
#endif
                if (rest >= needed)
                    return true; // all ok
        }
        cnt = rest / elsize;
    } else {
        cnt = 0;
    }
    *p_cnt = cnt;
    return false;
}

//--------------------------------------------------------------------------
// Validate a counter taken from the input file. If there are not enough bytes
// in the input file, ask the user if we may continue and fix the counter.
template <class T>
void validate_array_count(linput_t *li, T *p_cnt, size_t elsize,
                          const char *counter_name, int64 curoff = -1,
                          int64 maxoff = -1) {
    T old = *p_cnt;
    if (!_validate_array_count(li, p_cnt, elsize, curoff, maxoff)) {
        static const char *const format =
            "AUTOHIDE SESSION\n"
            "HIDECANCEL\n"
            "%s %" FMT_64 "u is incorrect, maximum possible value is %" FMT_64
            "u%s";
#ifndef __KERNEL__
        if (ask_yn(ASKBTN_YES, format, counter_name, uint64(old),
                   uint64(*p_cnt),
                   ". Do you want to continue with the new value?") !=
            ASKBTN_YES) {
            loader_failure(NULL);
        }
#else
        warning(format, counter_name, uint64(old), uint64(*p_cnt), "");
#endif
    }
}

//--------------------------------------------------------------------------
// Validate a counter taken from the input file. If there are not enough bytes
// in the input file, die.
template <class T>
void validate_array_count_or_die(linput_t *li, T cnt, size_t elsize,
                                 const char *counter_name, int64 curoff = -1,
                                 int64 maxoff = -1) {
    if (!_validate_array_count(li, &cnt, elsize, curoff, maxoff)) {
        static const char *const format =
            "%s is incorrect, maximum possible value is %u%s";
#ifndef __KERNEL__
        loader_failure(format, counter_name, uint(cnt), "");
#else
        error(format, counter_name, uint(cnt), "");
#endif
    }
}

//----------------------------------
inline uchar readchar(linput_t *li) {
    uchar x;
    lread(li, &x, sizeof(x));
    return x;
}

//----------------------------------
inline uint16 readshort(linput_t *li) {
    uint16 x;
    lread(li, &x, sizeof(x));
    return x;
}

//----------------------------------
inline uint32 readlong(linput_t *li) {
    uint32 x;
    lread(li, &x, sizeof(x));
    return x;
}

inline uint32 mf_readlong(linput_t *li) { return swap32(readlong(li)); }
inline uint16 mf_readshort(linput_t *li) { return swap16(readshort(li)); }

#endif // EFILOADER_IDA_CORE_H
