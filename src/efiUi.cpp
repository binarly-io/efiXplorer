/* efiUi.cpp
 * This file is part of efiXplorer
 */

#include "efiUi.h"

/* guids column widths */
const int guids_chooser_t::widths_guids[] = {
    16, // Address
    32, // GUID
    32  // Name
};

/* guids column headers */
const char *const guids_chooser_t::header_guids[] = {
    "Address", // 0
    "GUID",    // 1
    "Name"     // 2
};

/* protocols column widths */
const int protocols_chooser_t::widths_protocols[] = {
    16, // Address
    32, // GUID
    32, // Name
    32  // Service
};

/* protocols column headers */
const char *const protocols_chooser_t::header_protocols[] = {
    "Address", // 0
    "GUID",    // 1
    "Name",    // 2
    "Service"  // 3
};

/* services column widths */
const int s_chooser_t::widths_s[] = {
    16, // Address
    32, // Service name
};

/* services column widths */
const char *const s_chooser_t::header_s[] = {
    "Address",      // 0
    "Service name", // 1
};

inline guids_chooser_t::guids_chooser_t(const char *title_, bool ok,
                                        vector<json> guids)
    : chooser_t(0, qnumber(widths_guids), widths_guids, header_guids, title_),
      list() {
    CASSERT(qnumber(widths_guids) == qnumber(header_guids));
    build_list(ok, guids);
}

void idaapi guids_chooser_t::get_row(qstrvec_t *cols_, int *,
                                     chooser_item_attrs_t *, size_t n) const {
    ea_t ea = list[n];
    /* generate the line */
    qstrvec_t &cols = *cols_;
    json item = chooser_guids[n];
    string guid = (string)item["guid"];
    string name = (string)item["name"];
    cols[0].sprnt("%016X", ea);
    cols[1].sprnt("%s", guid.c_str());
    cols[2].sprnt("%s", name.c_str());
    CASSERT(qnumber(header_guids) == 3);
}

inline protocols_chooser_t::protocols_chooser_t(const char *title_, bool ok,
                                                vector<json> protocols)
    : chooser_t(0, qnumber(widths_protocols), widths_protocols,
                header_protocols, title_),
      list() {
    CASSERT(qnumber(widths_protocols) == qnumber(header_protocols));
    build_list(ok, protocols);
}

void idaapi protocols_chooser_t::get_row(qstrvec_t *cols_, int *,
                                         chooser_item_attrs_t *,
                                         size_t n) const {
    ea_t ea = list[n];
    /* generate the line */
    qstrvec_t &cols = *cols_;
    json item = chooser_protocols[n];
    auto guid = item["guid"];
    string name = (string)item["prot_name"];
    string service = (string)item["service"];
    char protGuid[37] = {0};
    snprintf(protGuid, 36, "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
             (uint32_t)guid[0], (uint16_t)guid[1], (uint16_t)guid[2],
             (uint8_t)guid[3], (uint8_t)guid[4], (uint8_t)guid[5],
             (uint8_t)guid[6], (uint8_t)guid[7], (uint8_t)guid[8],
             (uint8_t)guid[9], (uint8_t)guid[10]);
    cols[0].sprnt("%016X", ea);
    cols[1].sprnt("%s", protGuid);
    cols[2].sprnt("%s", name.c_str());
    cols[3].sprnt("%s", service.c_str());
    CASSERT(qnumber(header_protocols) == 4);
}

inline s_chooser_t::s_chooser_t(const char *title_, bool ok,
                                vector<json> services)
    : chooser_t(0, qnumber(widths_s), widths_s, header_s, title_), list() {
    CASSERT(qnumber(widths_s) == qnumber(header_s));
    build_list(ok, services);
}

void idaapi s_chooser_t::get_row(qstrvec_t *cols_, int *,
                                 chooser_item_attrs_t *, size_t n) const {
    ea_t ea = list[n];
    /* generate the line */
    qstrvec_t &cols = *cols_;
    json item = chooser_s[n];
    string name = (string)item["service_name"];
    cols[0].sprnt("%016X", ea);
    cols[1].sprnt("%s", name.c_str());
    CASSERT(qnumber(header_s) == 2);
}

bool guids_show(vector<json> guids, qstring title) {
    bool ok;
    /* open the window */
    guids_chooser_t *ch = new guids_chooser_t(title.c_str(), ok, guids);
    /* default cursor position is 0 (first row) */
    ch->choose();
    return true;
}

bool protocols_show(vector<json> protocols, qstring title) {
    bool ok;
    /* open the window */
    protocols_chooser_t *ch =
        new protocols_chooser_t(title.c_str(), ok, protocols);
    /* default cursor position is 0 (first row) */
    ch->choose();
    return true;
}

bool services_show(vector<json> services, qstring title) {
    bool ok;
    /* open the window */
    s_chooser_t *ch = new s_chooser_t(title.c_str(), ok, services);
    /* default cursor position is 0 (first row) */
    ch->choose();
    return true;
}
