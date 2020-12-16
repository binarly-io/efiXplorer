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
 * utils.h
 */

#ifndef EFILOADER_UTILS_H
#define EFILOADER_UTILS_H

#include "ida_core.h"
#include <cstdint>

namespace efiloader {

class Utils {
  public:
    Utils() { ; };
    void show_hex(void *buffer, size_t length, const char *prefix);
    bool find_vol(bytevec_t &frm, std::string &sig, qoff64_t &vol_off);
    qoff64_t find_vol_new(linput_t *li, char *sig);
    qoff64_t find_vol_test(bytevec_t &data);
    void skip(memory_deserializer_t *ser, size_t size, size_t count);
};
} // namespace efiloader

#endif // EFILOADER_UTILS_H
