// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2020-2026 Binarly

#include "utils.h"

#include <string>

void efiloader::Utils::show_hex(void *buffer, size_t length,
                                const char *prefix) {
  uint8_t *buf = reinterpret_cast<uint8_t *>(buffer);
  msg("[efiXloader] %s = ", prefix);
  for (int i = 0; i < length; i++) {
    msg("%02x", buf[i]);
  }
  msg("\n");
}

bool efiloader::Utils::find_vol(bytevec_t &frm, std::string &sig,
                                qoff64_t &vol_off) {
  auto found = std::search(frm.begin(), frm.end(), sig.begin(), sig.end());
  if (found != frm.end()) {
    vol_off = std::distance(frm.begin(), found);
    return true;
  } else {
    return false;
  }
}

qoff64_t efiloader::Utils::find_vol_new(linput_t *li, char *sig) {
  qoff64_t sig_off;
  char buf[5] = {0};
  while (qltell(li) != qlsize(li)) {
    qlread(li, &buf, 4);
    if (strneq(buf, sig, 4)) {
#ifdef DEBUG
      msg("[efiloader:PARSER] found FV sign %s: %#x\n", buf, qltell(li) - 4);
#endif
      return qltell(li) - 4 - 0x28;
    }
  }
  return -1;
}

qoff64_t efiloader::Utils::find_vol_test(bytevec_t &data) {
  std::string tmp(data.begin(), data.end());
  std::size_t res = tmp.find("_FVH");
  if (res != std::string::npos) {
    return res - 0x28;
  }
  return res;
}

void efiloader::Utils::skip(memory_deserializer_t *ser, size_t size,
                            size_t count) {
  switch (size) {
  case 1:
    for (int i = 0; i < count; i++) {
      ser->unpack_db();
    }
    break;
  case 2:
    for (int i = 0; i < count; i++) {
      ser->unpack_dw();
    }
    break;
  case 4:
    for (int i = 0; i < count; i++) {
      ser->unpack_dd();
    }
    break;
  case 8:
    for (int i = 0; i < count; i++) {
      ser->unpack_dq();
    }
    break;
  default:
    break;
  }
}
