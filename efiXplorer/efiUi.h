/*
 * efiXplorer
 * Copyright (C) 2020-2021 Binarly
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
 * efiUi.h
 *
 */

#pragma once

#include "efiUtils.h"

//-------------------------------------------------------------------------
// Vulns chooser
class vulns_chooser_t : public chooser_t {
  protected:
    static const int widths_vulns[];
    static const char *const header_vulns[];

  public:
    eavec_t list;
    json chooser_vulns;

    // this object must be allocated using `new`
    vulns_chooser_t(const char *title, bool ok, std::vector<json> vulns);

    // function that is used to decide whether a new chooser should be opened or
    // we can use the existing one. The contents of the window are completely
    // determined by its title
    virtual const void *get_obj_id(size_t *len) const {
        *len = strlen(title);
        return title;
    }

    // function that returns number of lines in the list
    virtual size_t idaapi get_count() const { return list.size(); }

    // function that generates the list line
    virtual void idaapi get_row(qstrvec_t *cols, int *icon_, chooser_item_attrs_t *attrs,
                                size_t n) const;

    // function that is called when the user hits `Enter`
    virtual cbret_t idaapi enter(size_t n) {
        if (n < list.size())
            jumpto(list[n]);
        return cbret_t();
    }

  protected:
    void build_list(bool ok, std::vector<json> vulns) {
        size_t n = 0;
        for (auto vuln : vulns) {
            list.push_back(vuln["address"]);
            chooser_vulns[n] = vuln;
            n++;
        }
        ok = true;
    };
};

//-------------------------------------------------------------------------
// GUIDs chooser
class guids_chooser_t : public chooser_t {
  protected:
    static const int widths_guids[];
    static const char *const header_guids[];

  public:
    eavec_t list;
    json chooser_guids;

    // this object must be allocated using `new`
    guids_chooser_t(const char *title, bool ok, std::vector<json> guids);

    // function that is used to decide whether a new chooser should be opened or
    // we can use the existing one. The contents of the window are completely
    // determined by its title
    virtual const void *get_obj_id(size_t *len) const {
        *len = strlen(title);
        return title;
    }

    // function that returns number of lines in the list
    virtual size_t idaapi get_count() const { return list.size(); }

    // function that generates the list line
    virtual void idaapi get_row(qstrvec_t *cols, int *icon_, chooser_item_attrs_t *attrs,
                                size_t n) const;

    // function that is called when the user hits `Enter`
    virtual cbret_t idaapi enter(size_t n) {
        if (n < list.size())
            jumpto(list[n]);
        return cbret_t();
    }

  protected:
    void build_list(bool ok, std::vector<json> guids) {
        size_t n = 0;
        for (auto guid : guids) {
            list.push_back(guid["address"]);
            chooser_guids[n] = guid;
            n++;
        }
        ok = true;
    };
};

//-------------------------------------------------------------------------
// Protocols chooser
class protocols_chooser_t : public chooser_t {
  protected:
    static const int widths_protocols[];
    static const char *const header_protocols[];

  public:
    eavec_t list;
    json chooser_protocols;
    std::string name_key;

    // this object must be allocated using `new`
    protocols_chooser_t(const char *title, bool ok, std::vector<json> interfaces,
                        std::string name_key);

    // function that is used to decide whether a new chooser should be opened or
    // we can use the existing one. The contents of the window are completely
    // determined by its title
    virtual const void *get_obj_id(size_t *len) const {
        *len = strlen(title);
        return title;
    }

    // function that returns number of lines in the list
    virtual size_t idaapi get_count() const { return list.size(); }

    // function that generates the list line
    virtual void idaapi get_row(qstrvec_t *cols, int *icon_, chooser_item_attrs_t *attrs,
                                size_t n) const;

    // function that is called when the user hits `Enter`
    virtual cbret_t idaapi enter(size_t n) {
        if (n < list.size())
            jumpto(list[n]);
        return cbret_t();
    }

  protected:
    void build_list(bool ok, std::vector<json> protocols) {
        size_t n = 0;
        for (auto protocol : protocols) {
            list.push_back(protocol["xref"]);
            chooser_protocols[n] = protocol;
            n++;
        }
        ok = true;
    };
};

//-------------------------------------------------------------------------
// Service chooser (address : service_name)
class s_chooser_t : public chooser_t {
  protected:
    static const int widths_s[];
    static const char *const header_s[];

  public:
    eavec_t list;
    json chooser_s;

    // this object must be allocated using `new`
    s_chooser_t(const char *title, bool ok, std::vector<json> services);

    // function that is used to decide whether a new chooser should be opened or
    // we can use the existing one. The contents of the window are completely
    // determined by its title
    virtual const void *get_obj_id(size_t *len) const {
        *len = strlen(title);
        return title;
    }

    // function that returns number of lines in the list
    virtual size_t idaapi get_count() const { return list.size(); }

    // function that generates the list line
    virtual void idaapi get_row(qstrvec_t *cols, int *icon_, chooser_item_attrs_t *attrs,
                                size_t n) const;

    // function that is called when the user hits `Enter`
    virtual cbret_t idaapi enter(size_t n) {
        if (n < list.size())
            jumpto(list[n]);
        return cbret_t();
    }

  protected:
    void build_list(bool ok, std::vector<json> services) {
        size_t n = 0;
        for (auto j_service : services) {
            list.push_back(j_service["address"]);
            chooser_s[n] = j_service;
            n++;
        }
        ok = true;
    };
};

extern action_desc_t action_load_report;

bool vulns_show(std::vector<json> vulns, qstring title);
bool guids_show(std::vector<json> guid, qstring title);
bool protocols_show(std::vector<json> protocols, qstring title);
bool ppis_show(std::vector<json> protocols, qstring title);
bool services_show(std::vector<json> services, qstring title);
