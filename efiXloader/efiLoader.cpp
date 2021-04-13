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
 * efiLoader.cpp
 */

#include "efiLoader.h"
#include "uefitool.h"
#include "utils.h"

#define USE_UEFITOOL_PARSER

bool first_uefi_image = true;

//------------------------
// IDA wrappers
//------------------------

void idaapi load_binary(const char *fname) {
    load_info_t *ld = NULL;
    linput_t *li = NULL;
    ushort nflags =
        NEF_SEGS | NEF_RSCS | NEF_NAME | NEF_IMPS | NEF_LALL | NEF_FLAT;
    if (first_uefi_image) {
        nflags |= NEF_FIRST;
    }
    first_uefi_image = false;
    // linput
    li = open_linput(fname, false);
    if (li == NULL) {
        error("failed to process input source: %s", fname);
    }
    // get loaders
    ld = build_loaders_list(li, fname);
    msg("[efiLoader] using %s to load %s\n", ld->dllname.c_str(), fname);
    // load EFI binary into database
    if ((load_nonbinary_file(fname, li, ".", nflags, ld))) {
        msg("[efiLoader] successfully loaded %s\n", fname);
    } else {
        loader_failure("[efiLoader] 'load_nonbinary_file' failed");
    }
    close_linput(li);
    free_loaders_list(ld);
    return;
}

void idaapi wait(void) {
    while (!auto_is_ok()) {
        auto_wait();
    }
}

//
// IDA analyzing
//

void inline idaapi reanalyze_all(void) {
    plan_range(inf_get_min_ea(), inf_get_max_ea());
    auto_wait();
    auto_make_proc(inf_get_min_ea());
}

void efi_til_init(const char *til_name) {
    qstring err;
    til_t *res;
    res = load_til(til_name, &err);
    if (!res) {
        loader_failure("failed to load %s", til_name);
    } else {
        msg("[efiloader] lib %s is ready: %#x\n", res);
    }
}

//------------------------
// IDA loader
//------------------------

static int idaapi accept_file(qstring *fileformatname, qstring *processor,
                              linput_t *li, const char *filename) {
    efiloader::Utils utils;
    bytevec_t data;
    data.resize(qlsize(li));
    qlseek(li, 0);
    qlread(li, data.begin(), qlsize(li));
    *fileformatname = "UEFI firmware image";
    return utils.find_vol_test(data) != std::string::npos;
}

void idaapi load_file(linput_t *li, ushort neflag, const char *fileformatname) {
    bool ok = true;
    bool is_pe;
    Ui ui;
    bytevec_t data;
    data.resize(qlsize(li));
    qlread(li, data.begin(), qlsize(li));
    efiloader::Uefitool uefiParser(data);
    if (uefiParser.messages_occurs()) {
        uefiParser.show_messages();
    }
    uefiParser.dump();
    efiloader::PeManager peManager;
    close_linput(li);
    add_til("uefi.til", ADDTIL_DEFAULT);
    add_til("uefi64.til", ADDTIL_DEFAULT);
    qstring err;
    const til_t *idati = get_idati();
    if (!idati) {
        loader_failure("failed to load IDA types");
    } else {
        msg("[efiloader] loaded IDA types: %#x\n", idati);
    }
    tid_t struct_err = import_type(idati, -1, "EFI_GUID");
    if (struct_err == BADNODE) {
        loader_failure("failed to import \"EFI_GUID\"");
    }
    msg("processing UEFI binaries:\n");
    if (uefiParser.files.size()) {
        for (int i = 0; i < uefiParser.files.size(); i++) {
            li = open_linput(uefiParser.files[i]->dump_name.c_str(), false);
            peManager.process(li, uefiParser.files[i]->dump_name.c_str(), i);
        }
    } else {
        efiloader::Utils utils;
        std::vector<qstring> files = utils.get_images();
        for (int i = 0; i < files.size(); i++) {
            msg("[efiloader] current file: %s\n", files[i].c_str());
            li = open_linput(files[i].c_str(), false);
            peManager.process(li, files[i].c_str(), i);
        }
    }
}

static int idaapi move_segm(ea_t from, ea_t to, asize_t, const char *) {
    return 1;
}

//----------------------------------------------------------------------
//
//      LOADER DESCRIPTION BLOCK
//
//----------------------------------------------------------------------
loader_t LDSC = {
    IDP_INTERFACE_VERSION,
    // loader flags
    0,
    // check input file format. if recognized, then return 1
    // and fill 'fileformatname'.
    // otherwise return 0
    accept_file,
    // load file into the database.
    load_file,
    // create output file from the database.
    // this function may be absent.
    NULL,
    // take care of a moved segment (fix up relocations, for example)
    NULL,
    NULL,
};
