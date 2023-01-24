/*
 * efiXplorer
 * Copyright (C) 2020-2023 Binarly
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
#include "efiDeps.h"
#include "efiGlobal.h"

static const char plugin_name[] = "efiXplorer";

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
const int protocols_chooser_t::widths_protocols[] = {
    16, // Address
    32, // GUID
    32, // Name
    32, // Service
    32  // Module
};

// protocols column headers
const char *const protocols_chooser_t::header_protocols[] = {
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

// services column headers
const char *const s_chooser_t::header_s[] = {
    "Address",      // 0
    "Service name", // 1
    "Table name"    // 2
};

// services column widths
const int nvram_chooser_t::widths_nvram[] = {
    16, // Address
    32, // Variable name
    32, // Variable GUID
    32, // Service
    64, // Attributes
};

// NVRAMs column headers
const char *const nvram_chooser_t::header_nvram[] = {
    "Address",       // 0
    "Variable name", // 1
    "Variable GUID", // 2
    "Service",       // 3
    "Attributes"     // 4
};

inline nvram_chooser_t::nvram_chooser_t(const char *title_, bool ok,
                                        std::vector<json> nvram)
    : chooser_t(0, qnumber(widths_nvram), widths_nvram, header_nvram, title_), list() {
    CASSERT(qnumber(widths_nvram) == qnumber(header_nvram));
    build_list(ok, nvram);
}

void idaapi nvram_chooser_t::get_row(qstrvec_t *cols_, int *, chooser_item_attrs_t *,
                                     size_t n) const {
    ea_t ea = list[n];
    qstrvec_t &cols = *cols_;
    json item = chooser_nvram[n];
    std::string name = static_cast<std::string>(item["VariableName"]);
    std::string guid = static_cast<std::string>(item["VendorGuid"]);
    std::string service = static_cast<std::string>(item["service"]);
    std::string attributes = static_cast<std::string>(item["AttributesHumanReadable"]);
    cols[0].sprnt("%016llX", u64_addr(ea));
    cols[1].sprnt("%s", name.c_str());
    cols[2].sprnt("%s", guid.c_str());
    cols[3].sprnt("%s", service.c_str());
    cols[4].sprnt("%s", attributes.c_str());
    CASSERT(qnumber(header_nvram) == 5);
}

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
    cols[0].sprnt("%016llX", u64_addr(ea));
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
    cols[0].sprnt("%016llX", u64_addr(ea));
    cols[1].sprnt("%s", guid.c_str());
    cols[2].sprnt("%s", name.c_str());
    CASSERT(qnumber(header_guids) == 3);
}

inline protocols_chooser_t::protocols_chooser_t(const char *title_, bool ok,
                                                std::vector<json> protocols,
                                                std::string name_key_)
    : chooser_t(0, qnumber(widths_protocols), widths_protocols, header_protocols, title_),
      list() {
    CASSERT(qnumber(widths_protocols) == qnumber(header_protocols));
    name_key = name_key_;
    build_list(ok, protocols);
}

void idaapi protocols_chooser_t::get_row(qstrvec_t *cols_, int *, chooser_item_attrs_t *,
                                         size_t n) const {
    ea_t ea = list[n];
    qstrvec_t &cols = *cols_;
    json item = chooser_protocols[n];
    std::string name = static_cast<std::string>(item[name_key]);
    std::string service = static_cast<std::string>(item["service"]);
    std::string protGuid = static_cast<std::string>(item["guid"]);
    std::string moduleName = static_cast<std::string>(item["module"]);
    cols[0].sprnt("%016llX", u64_addr(ea));
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
    cols[0].sprnt("%016llX", u64_addr(ea));
    cols[1].sprnt("%s", service_name.c_str());
    cols[2].sprnt("%s", table_name.c_str());
    CASSERT(qnumber(header_s) == 3);
}

bool nvram_show(std::vector<json> nvram, qstring title) {
    bool ok;
    // open the window
    nvram_chooser_t *ch = new nvram_chooser_t(title.c_str(), ok, nvram);
    // default cursor position is 0 (first row)
    ch->choose();
    return true;
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
    protocols_chooser_t *ch =
        new protocols_chooser_t(title.c_str(), ok, protocols, "prot_name");
    // default cursor position is 0 (first row)
    ch->choose();
    return true;
}

bool ppis_show(std::vector<json> ppis, qstring title) {
    bool ok;
    // open the window
    protocols_chooser_t *ch =
        new protocols_chooser_t(title.c_str(), ok, ppis, "ppi_name");
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

//-------------------------------------------------------------------------
// Action handler for protocols dependencies
struct protocols_deps_handler_t : public action_handler_t {
    virtual int idaapi activate(action_activation_ctx_t *ctx) {
        auto n = ctx->chooser_selection.at(0);
        json info = g_deps.protocolsChooser[n];

        if (info.is_null()) {
            return -1; // protocol not found
        }

        // get dependencies for protocol
        std::string guid = info["guid"];
        json d = g_deps.protocolsByGuids[guid];

        // print dependencies for current
        // protocol in output window
        std::string s = d.dump(2);
        msg("[%s] dependencies for protocol with GUID %s: %s\n", plugin_name,
            guid.c_str(), s.c_str());

        return 0;
    }

    virtual action_state_t idaapi update(action_update_ctx_t *ctx) {
        return AST_ENABLE_ALWAYS;
    }
};

static protocols_deps_handler_t protocols_deps_ah;
action_desc_t protocols_deps = ACTION_DESC_LITERAL(
    "efiXplorer:protocolsDeps", "Show dependencies", &protocols_deps_ah, NULL, NULL, -1);

void attachActionProtocolsDeps() {
    // Attach action in protocols chooser
    TWidget *widget = find_widget("efiXplorer: protocols");
    if (widget == nullptr) {
        msg("[%s] can not find efiXplorer: protocols chooser", plugin_name);
        return;
    }
    register_action(protocols_deps);
    attach_action_to_popup(widget, nullptr, protocols_deps.name);
}

//-------------------------------------------------------------------------
// Action handler for showing the sequence of modules execution
struct modules_seq_handler_t : public action_handler_t {
    virtual int idaapi activate(action_activation_ctx_t *ctx) {
        g_deps.buildModulesSequence();
        std::string s = g_deps.modulesSequence.dump(2);
        msg("[%s] sequence of modules execution: %s\n", plugin_name, s.c_str());

        return 0;
    }

    virtual action_state_t idaapi update(action_update_ctx_t *ctx) {
        return AST_ENABLE_ALWAYS;
    }
};

static modules_seq_handler_t modules_seq_ah;
action_desc_t modules_seq =
    ACTION_DESC_LITERAL("efiXplorer:modulesSeq", "Show the sequence of modules execution",
                        &modules_seq_ah, NULL, NULL, -1);

void attachActionModulesSeq() {
    // Attach action in protocols chooser
    TWidget *widget = find_widget("efiXplorer: protocols");
    if (widget == nullptr) {
        msg("[%s] can not find efiXplorer: protocols chooser", plugin_name);
        return;
    }
    register_action(modules_seq);
    attach_action_to_popup(widget, nullptr, modules_seq.name);
}

//-------------------------------------------------------------------------
// Action handler (load efiXplorer analysis report)
struct action_handler_loadreport_t : public action_handler_t {
    virtual int idaapi activate(action_activation_ctx_t *ctx) {
        std::filesystem::path reportPath;
        char *file = ask_file(false, "*.json", "Load efiXplorer analysis report");
        if (file == nullptr) {
            msg("[%s] report file not specified\n", plugin_name);
            return -1;
        }
        reportPath /= file;
        msg("[%s] loading report from %s file\n", plugin_name, reportPath.c_str());

        json reportData;
        try {
            std::ifstream in(reportPath);
            in >> reportData;
        } catch (std::exception &e) {
            msg("[%s] report file is invalid, check its contents\n", plugin_name);
            return -1;
        }

        // Initialize vuln types list
        std::vector<std::string> vulnTypes{
            "smm_callout", "pei_get_variable_buffer_overflow",
            "get_variable_buffer_overflow", "smm_get_variable_buffer_overflow"};

        // Show all choosers with data from report
        qstring title;

        try {
            auto protocols = reportData["allProtocols"];
            if (!protocols.is_null()) { // show protocols
                title = "efiXplorer: protocols";
                protocols_show(protocols, title);
            }
            auto ppis = reportData["allPPIs"];
            if (!ppis.is_null()) { // show PPIs
                title = "efiXplorer: PPIs";
                protocols_show(ppis, title);
            }
            auto services = reportData["allServices"];
            if (!services.is_null()) { // show services
                title = "efiXplorer: services";
                services_show(services, title);
            }
            auto guids = reportData["allGuids"];
            if (!guids.is_null()) { // show GUIDs
                title = "efiXplorer: GUIDs";
                guids_show(guids, title);
            }
            auto nvram = reportData["nvramVariables"];
            if (!nvram.is_null()) { // show NVRAM
                title = "efiXplorer: NVRAM";
                nvram_show(nvram, title);
            }
            auto vulns = reportData["vulns"];
            if (!vulns.is_null()) { // show vulns
                std::vector<json> vulnsRes;
                for (auto vulnType : vulnTypes) {
                    // For each vuln type add list of vulns in `vulnsRes`
                    auto vulnAddrs = vulns[vulnType];
                    if (vulnAddrs.is_null()) {
                        continue;
                    }
                    for (auto addr : vulnAddrs) {
                        json item;
                        item["type"] = vulnType;
                        item["address"] = addr;
                        vulnsRes.push_back(item);
                    }
                }
                if (vulnsRes.size()) {
                    title = "efiXplorer: vulns";
                    vulns_show(vulnsRes, title);
                }
            }

            // Init public EdiDependencies members
            g_deps.getProtocolsChooser(protocols);
            g_deps.getProtocolsByGuids(protocols);

            // Save all protocols information to build dependencies
            attachActionProtocolsDeps();
            attachActionModulesSeq();
        } catch (std::exception &e) {
            msg("[%s] report file is invalid, check its contents\n", plugin_name);
            return -1;
        }

        return 0;
    }

    virtual action_state_t idaapi update(action_update_ctx_t *ctx) {
        return AST_ENABLE_ALWAYS;
    }
};
static action_handler_loadreport_t load_report_handler;

//-------------------------------------------------------------------------
// Action to load efiXplorer analysis report
action_desc_t action_load_report =
    ACTION_DESC_LITERAL("efiXplorer:loadReport", "efiXplorer analysis report...",
                        &load_report_handler, NULL, NULL, -1);
