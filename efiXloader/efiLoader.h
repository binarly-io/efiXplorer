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
 * efiLoader.h
 */

#ifndef EFILOADER_EFILOADER_H
#define EFILOADER_EFILOADER_H

#include "ida_core.h"
#include "pe.h"
#include "pe_manager.h"
#include "uefitool.h"

extern loader_t LDSC;

//-----------------------
// definitions
//-----------------------

void idaapi load_binary(const char *fname);
void idaapi close_and_save_db(const char *fname);
void idaapi reanalyze_all(void);
void idaapi wait(void);
void idaapi idb_to_asm(const char *fname);
void idaapi clean_db(void);

void idaapi efi_til_init();

// UI

class Ui {
  public:
    Ui() { ; }
    int ask_for_single_image();
};

class driver_chooser_t : public chooser_t {
  protected:
    static const int widths_drivers[];
    static const char *const drivers_headers[];

  public:
    /* remember the addresses in this qvector */
    qvector<qstring> drivers_names;

    /* this object must be allocated using `new` */
    driver_chooser_t(const char *title, bool ok,
                     std::vector<efiloader::File *> drivers);

    /* function that is used to decide whether a new chooser should be opened or
     * we can use the existing one. The contents of the window are completely
     * determined by its title */
    virtual const void *get_obj_id(size_t *len) const {
        *len = strlen(title);
        return title;
    }

    /* function that returns number of lines in the list */
    virtual size_t idaapi get_count() const { return drivers_names.size(); }

    /* function that generates the list line */
    virtual void idaapi get_row(qstrvec_t *cols, int *icon_,
                                chooser_item_attrs_t *attrs, size_t n) const;

    /* function that is called when the user hits Enter */
    virtual cbret_t idaapi enter(size_t n) {
        if (n < drivers_names.size())
            // jumpto(list[n]);
            return cbret_t();
    }

  protected:
    void build_list(bool ok, std::vector<efiloader::File *> files) {
        size_t n = 0;
        for (auto file : files) {
            drivers_names.push_back(qstring(file->qname));
            n++;
        }
        ok = true;
    };
};

#endif // EFILOADER_EFILOADER_H
