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

#pragma once

#include <memory>
#include <string>

#include "ida_core.h"
#include "pe.h"

namespace efiloader {
class PeManager {
public:
  explicit PeManager(uint16_t mt) {
    inf_set_64bit();
    set_imagebase(0x0);
    if (mt == PECPU_ARM64) {
      set_processor_type("arm", SETPROC_LOADER);
    } else {
      set_processor_type("metapc", SETPROC_LOADER);
    }
    pe_base = 0;
    pe_sel_base = 0;
    machine_type = mt;
  }
  void process(linput_t *li, const std::string &fname, int ord);
  uint16_t machine_type;

private:
  void to_base(linput_t *);
  std::unique_ptr<efiloader::PE> pe;
  qvector<std::unique_ptr<efiloader::PE>> pe_files;
  ushort pe_sel_base;
  ea_t pe_base;
  // head processing
  void pe_head_to_base(linput_t *li);
};
} // namespace efiloader
