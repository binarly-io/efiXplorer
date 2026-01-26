// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2020-2026 Binarly

#pragma once

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include "ida_core.h"

namespace efiloader {

class Utils {
public:
  Utils() {}
  void show_hex(void *buffer, size_t length, const char *prefix);
  bool find_vol(bytevec_t &frm, std::string &sig, qoff64_t &vol_off);
  qoff64_t find_vol_new(linput_t *li, char *sig);
  qoff64_t find_vol_test(bytevec_t &data);
  void skip(memory_deserializer_t *ser, size_t size, size_t count);
};
} // namespace efiloader
