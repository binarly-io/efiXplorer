/*
 * efiXloader
 * Copyright (C) 2020-2025 Binarly
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
 */

#include "pe_manager.h"

void efiloader::PeManager::process(linput_t *li, std::basic_string<char> fname,
                                   int ord) {
  // 32-bit modules and modules in the TE format will not be loaded
  efiloader::PE pe(li, fname, &pe_base, &pe_sel_base, ord, machine_type);
  if (pe.good() && pe.is_p32_plus()) {
    pe.process();
  }
}
