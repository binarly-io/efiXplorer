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
 * efiDeps.cpp
 *
 */

#include "efiDeps.h"

EfiDependencies::EfiDependencies() {
    // Read DEPEX (for protocols) from
    // .deps.json file if this file exists
    loadDepsFromUefiTool();
};
EfiDependencies::~EfiDependencies() {
    uefitoolDeps.clear();
    protocolsChooser.clear();
    protocolsByGuids.clear();
};

json EfiDependencies::getDeps(std::string guid) {
    json res;

    std::vector installers({"InstallProtocolInterface",
                            "InstallMultipleProtocolInterfaces",
                            "SmmInstallProtocolInterface"});

    for (auto &it : protocolsChooser.items()) {
        auto p = it.value();
        if (p["guid"] != guid) {
            continue;
        }
        if (find(installers.begin(), installers.end(), p["service"]) !=
            installers.end()) {
            res["installed"].push_back(p);
        } else {
            res["used"].push_back(p);
        }
    }

    return res;
}

void EfiDependencies::getProtocolsByGuids(std::vector<json> protocols) {
    for (auto p : protocols) {
        // check if entry for GUID already exist
        std::string guid = p["guid"];
        auto deps = protocolsByGuids[guid];
        if (deps.is_null()) {
            protocolsByGuids[guid] = getDeps(guid);
        }
    }
}

void EfiDependencies::getProtocolsChooser(std::vector<json> protocols) {
    auto i = 0;
    for (auto p : protocols) {
        protocolsChooser[i] = p;
        ++i;
    }
}

void EfiDependencies::loadDepsFromUefiTool() {
    std::filesystem::path deps_json;
    deps_json /= get_path(PATH_TYPE_IDB);
    deps_json.replace_extension(".deps.json");
    if (std::filesystem::exists(deps_json)) {
        std::ifstream file(deps_json);
        file >> uefitoolDeps;
    }
}

bool EfiDependencies::installerFound(std::string protocol) {
    auto deps_prot = protocolsByGuids[protocol];
    if (deps_prot.is_null()) {
        return false;
    }
    auto installers = deps_prot["installed"];
    if (installers.is_null()) {
        return false;
    }
    return true;
}

void EfiDependencies::getProtocolsWithoutInstallers() {
    // Check DXE_DEPEX and MM_DEPEX
    std::vector<std::string> sections{"EFI_SECTION_DXE_DEPEX", "EFI_SECTION_MM_DEPEX"};
    for (auto section : sections) {
        auto images = uefitoolDeps[section];
        for (auto &element : images.items()) {
            auto protocols = element.value();
            for (auto p : protocols) {
                std::string ps = static_cast<std::string>(p);
                if (!installerFound(ps)) {
                    protocolsWithoutInstallers.insert(ps);
                }
            }
        }
    }
}

void EfiDependencies::getInstallersModules() {
    // search for this protocols in binary
    for (auto &protocol : protocolsWithoutInstallers) {
        auto addrs = searchProtocol(protocol);
        bool installerFound = false;
        for (auto addr : addrs) {
            auto xrefs = getXrefs(addr);
            if (!xrefs.size()) {
                continue;
            }
            if (xrefs.size() == 1) {
                func_t *func = get_func(xrefs.at(0));
                if (func == nullptr) {
                    xrefs = getXrefsToArray(xrefs.at(0));
                }
            }
            for (auto ea : xrefs) {
                if (checkInstallProtocol(ea)) {
                    auto module = getModuleNameLoader(ea);
                    additionalInstallers[protocol] =
                        static_cast<std::string>(module.c_str());
                    installerFound = true;
                    break;
                }
            }
            if (installerFound) {
                break;
            }
        }
    }
}

void EfiDependencies::getAdditionalInstallers() {
    getProtocolsWithoutInstallers();
    getInstallersModules();
    // DEBUG
    std::string installers = additionalInstallers.dump(2);
    msg("Additional installers: %s\n", installers.c_str());
}
