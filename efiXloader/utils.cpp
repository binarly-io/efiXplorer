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
 * utils.cpp
 */

#include "utils.h"
#include <algorithm>
#include <string>

void efiloader::Utils::show_hex(void *buffer, size_t length,
                                const char *prefix) {
    uint8_t *buf = (uint8_t *)buffer;
    msg("[efiLoader] %s = ", prefix);
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
            msg("[efiloader:PARSER] found FV sign %s: %#x\n", buf,
                qltell(li) - 4);
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
