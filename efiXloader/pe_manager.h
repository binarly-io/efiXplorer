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
 * pe_manager.h
 */

#ifndef EFILOADER_PE_MANAGER_H
#define EFILOADER_PE_MANAGER_H

#include "ida_core.h"
#include "pe.h"

namespace efiloader {
class PeManager {
  public:
    PeManager() {
        inf_set_64bit();
        set_imagebase(0x0);
        set_processor_type("metapc", SETPROC_LOADER);
        pe_base = 0;
        pe_sel_base = 0;
    };
    void process(linput_t *li, std::basic_string<char> fname, int ord);

  private:
    void to_base(linput_t *);
    efiloader::PE *pe;
    qvector<efiloader::PE *> pe_files;
    ushort pe_sel_base;
    ea_t pe_base;
    // head processing
    void pe_head_to_base(linput_t *li);
};
} // namespace efiloader

#endif // EFILOADER_PE_MANAGER_H
