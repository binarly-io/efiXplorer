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
 * efiUi.cpp
 *
 */

#include "efiUi.h"

// vulns column widths
const int vulns_chooser_t::widths_vulns[] = {
    16, // Address
    32, // Vuln type
};

// vulns column headers
const char *const vulns_chooser_t::header_vulns[] = {
    "Address", // 0
    "Type",    // 1
};

// guids column widths
const int guids_chooser_t::widths_guids[] = {
    16, // Address
    32, // GUID
    32  // Name
};

// guids column headers
const char *const guids_chooser_t::header_guids[] = {
    "Address", // 0
    "GUID",    // 1
    "Name"     // 2
};

// protocols column widths
const int interfaces_chooser_t::widths_protocols[] = {
    16, // Address
    32, // GUID
    32, // Name
    32, // Service
    32  // Module
};

// protocols column headers
const char *const interfaces_chooser_t::header_protocols[] = {
    "Address", // 0
    "GUID",    // 1
    "Name",    // 2
    "Service", // 3
    "Module"   // 4
};

// services column widths
const int s_chooser_t::widths_s[] = {
    16, // Address
    32, // Service name
    32, // Table name
};

// services column widths
const char *const s_chooser_t::header_s[] = {
    "Address",      // 0
    "Service name", // 1
    "Table name"    // 2
};

inline vulns_chooser_t::vulns_chooser_t(const char *title_, bool ok,
                                        std::vector<json> vulns)
    : chooser_t(0, qnumber(widths_vulns), widths_vulns, header_vulns, title_), list() {
    CASSERT(qnumber(widths_vulns) == qnumber(header_vulns));
    build_list(ok, vulns);
}

void idaapi vulns_chooser_t::get_row(qstrvec_t *cols_, int *, chooser_item_attrs_t *,
                                     size_t n) const {
    ea_t ea = list[n];
    qstrvec_t &cols = *cols_;
    json item = chooser_vulns[n];
    std::string type = static_cast<std::string>(item["type"]);
    cols[0].sprnt("%016llX", static_cast<uint64_t>(ea));
    cols[1].sprnt("%s", type.c_str());
    CASSERT(qnumber(header_vulns) == 2);
}

inline guids_chooser_t::guids_chooser_t(const char *title_, bool ok,
                                        std::vector<json> guids)
    : chooser_t(0, qnumber(widths_guids), widths_guids, header_guids, title_), list() {
    CASSERT(qnumber(widths_guids) == qnumber(header_guids));
    build_list(ok, guids);
}

void idaapi guids_chooser_t::get_row(qstrvec_t *cols_, int *, chooser_item_attrs_t *,
                                     size_t n) const {
    ea_t ea = list[n];
    qstrvec_t &cols = *cols_;
    json item = chooser_guids[n];
    std::string guid = static_cast<std::string>(item["guid"]);
    std::string name = static_cast<std::string>(item["name"]);
    cols[0].sprnt("%016llX", static_cast<uint64_t>(ea));
    cols[1].sprnt("%s", guid.c_str());
    cols[2].sprnt("%s", name.c_str());
    CASSERT(qnumber(header_guids) == 3);
}

inline interfaces_chooser_t::interfaces_chooser_t(const char *title_, bool ok,
                                                  std::vector<json> protocols,
                                                  std::string name_key_)
    : chooser_t(0, qnumber(widths_protocols), widths_protocols, header_protocols, title_),
      list() {
    CASSERT(qnumber(widths_protocols) == qnumber(header_protocols));
    name_key = name_key_;
    build_list(ok, protocols);
}

void idaapi interfaces_chooser_t::get_row(qstrvec_t *cols_, int *, chooser_item_attrs_t *,
                                          size_t n) const {
    ea_t ea = list[n];
    qstrvec_t &cols = *cols_;
    json item = chooser_protocols[n];
    auto guid = item["guid"];
    std::string name = static_cast<std::string>(item[name_key]);
    std::string service = static_cast<std::string>(item["service"]);
    std::string protGuid = getGuidFromValue(guid);
    qstring moduleName("Current");
    if (getArch() == UEFI) { // to see dependencies between modules in efiloader instance
        moduleName = getModuleNameLoader(ea);
    }
    cols[0].sprnt("%016llX", static_cast<uint64_t>(ea));
    cols[1].sprnt("%s", protGuid.c_str());
    cols[2].sprnt("%s", name.c_str());
    cols[3].sprnt("%s", service.c_str());
    cols[4].sprnt("%s", moduleName.c_str());
    CASSERT(qnumber(header_protocols) == 5);
}

inline s_chooser_t::s_chooser_t(const char *title_, bool ok, std::vector<json> services)
    : chooser_t(0, qnumber(widths_s), widths_s, header_s, title_), list() {
    CASSERT(qnumber(widths_s) == qnumber(header_s));
    build_list(ok, services);
}

void idaapi s_chooser_t::get_row(qstrvec_t *cols_, int *, chooser_item_attrs_t *,
                                 size_t n) const {
    ea_t ea = list[n];
    qstrvec_t &cols = *cols_;
    json item = chooser_s[n];
    std::string service_name = static_cast<std::string>(item["service_name"]);
    std::string table_name = static_cast<std::string>(item["table_name"]);
    cols[0].sprnt("%016llX", static_cast<uint64_t>(ea));
    cols[1].sprnt("%s", service_name.c_str());
    cols[2].sprnt("%s", table_name.c_str());
    CASSERT(qnumber(header_s) == 3);
}

bool vulns_show(std::vector<json> vulns, qstring title) {
    bool ok;
    // open the window
    vulns_chooser_t *ch = new vulns_chooser_t(title.c_str(), ok, vulns);
    // default cursor position is 0 (first row)
    ch->choose();
    return true;
}

bool guids_show(std::vector<json> guids, qstring title) {
    bool ok;
    // open the window
    guids_chooser_t *ch = new guids_chooser_t(title.c_str(), ok, guids);
    // default cursor position is 0 (first row)
    ch->choose();
    return true;
}

bool protocols_show(std::vector<json> protocols, qstring title) {
    bool ok;
    // open the window
    interfaces_chooser_t *ch =
        new interfaces_chooser_t(title.c_str(), ok, protocols, "prot_name");
    // default cursor position is 0 (first row)
    ch->choose();
    return true;
}

bool ppis_show(std::vector<json> ppis, qstring title) {
    bool ok;
    // open the window
    interfaces_chooser_t *ch =
        new interfaces_chooser_t(title.c_str(), ok, ppis, "ppi_name");
    // default cursor position is 0 (first row)
    ch->choose();
    return true;
}

bool services_show(std::vector<json> services, qstring title) {
    bool ok;
    // open the window
    s_chooser_t *ch = new s_chooser_t(title.c_str(), ok, services);
    // default cursor position is 0 (first row)
    ch->choose();
    return true;
}
