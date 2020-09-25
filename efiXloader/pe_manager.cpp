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
 * pe_manager.cpp
 */

#include "pe_manager.h"

void efiloader::PeManager::process(linput_t *li, std::basic_string<char> fname,
                                   int ord) {
    efiloader::PE pe(li, fname, &pe_base, &pe_sel_base, ord);
    // pe = new efiloader::PE(li, fname, &pe_base, &pe_sel_base, ord);
    if (pe.good() && pe.is_p32_plus()) {
        msg("[efiloader] PE detected\n");
        pe.process();
    } else if (pe.is_p32()) {
        msg("[efiloader] this loader is not ready for PE32\n");
    } else {
        warning("[efiloader] not PE\n");
    }
    // delete pe;
}
