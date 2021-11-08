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

EfiDependencies::EfiDependencies(){};
EfiDependencies::~EfiDependencies() { protocolsByGuids.clear(); };

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

    // DEBUG: print res
    std::string s = res.dump(2);

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
