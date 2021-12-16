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
    // Get images names from IDB
    getImages();
    // Read images with GUIDs from
    // .images.json file if this file exists
    loadImagesWithGuids();
};

EfiDependencies::~EfiDependencies() {
    imagesInfo.clear();
    imagesGuids.clear();
    imagesFromIdb.clear();
    uefitoolDeps.clear();
    protocolsChooser.clear();
    protocolsByGuids.clear();
    additionalInstallers.clear();
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

bool EfiDependencies::loadDepsFromUefiTool() {
    std::filesystem::path deps_json;
    deps_json /= get_path(PATH_TYPE_IDB);
    deps_json.replace_extension(".deps.json");
    if (!std::filesystem::exists(deps_json)) {
        return false;
    }
    std::ifstream file(deps_json);
    file >> uefitoolDeps;
    return true;
}

bool EfiDependencies::loadImagesWithGuids() {
    std::filesystem::path images_json;
    images_json /= get_path(PATH_TYPE_IDB);
    images_json.replace_extension(".images.json");
    if (!std::filesystem::exists(images_json)) {
        return false;
    }
    std::ifstream file(images_json);
    file >> imagesGuids;
    return true;
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
        if (!installerFound) {
            untrackedProtocols.push_back(protocol);
        }
    }
}

void EfiDependencies::getAdditionalInstallers() {
    getProtocolsWithoutInstallers();
    getInstallersModules();
    std::string installers = additionalInstallers.dump(2);
    msg("Additional installers: %s\n", installers.c_str());
    msg("Untracked protocols:\n");
    for (auto protocol : untrackedProtocols) {
        msg("%s\n", protocol.c_str());
    }
}

void EfiDependencies::getImages() {
    for (segment_t *s = get_first_seg(); s != nullptr; s = get_next_seg(s->start_ea)) {
        qstring seg_name;
        get_segm_name(&seg_name, s);

        std::vector<std::string> codeSegNames{"_.text", "_.code"};
        for (auto name : codeSegNames) {
            auto index = seg_name.find(name.c_str());
            if (index != std::string::npos) {
                std::string image_name =
                    static_cast<std::string>(seg_name.c_str()).substr(0, index);
                if (!image_name.rfind("_", 0)) {
                    image_name = image_name.erase(0, 1);
                }
                imagesFromIdb.push_back(image_name);
            }
        }
    }
}

json EfiDependencies::getImageInfo(std::string image) {
    json info;
    std::vector<std::string> installedProtocols;
    json depsProtocols;
    std::vector installers({"InstallProtocolInterface",
                            "InstallMultipleProtocolInterfaces",
                            "SmmInstallProtocolInterface"});

    // Get installed protocols
    for (auto &p : additionalInstallers.items()) { // check additional installers
        std::string adInstImage = p.value();
        std::string adInstProtocol = p.key();
        if (adInstImage == image) {
            installedProtocols.push_back(adInstProtocol);
            break;
        }
    }

    for (auto &element : protocolsChooser.items()) { // check efiXplorer report
        json p = element.value();
        std::string image_name = p["module"];
        if (!image_name.rfind("_", 0)) {
            image_name = image_name.erase(0, 1);
        }
        if (image_name != image) {
            continue;
        }
        if (find(installers.begin(), installers.end(), p["service"]) !=
            installers.end()) {
            installedProtocols.push_back(p["guid"]);
        }
    }

    // Get deps
    bool found = false;
    std::vector<std::string> sections{"EFI_SECTION_DXE_DEPEX", "EFI_SECTION_MM_DEPEX"};
    for (auto section : sections) {
        json deps_images = uefitoolDeps[section];
        for (auto &element : deps_images.items()) {
            std::string dimage_guid = element.key();
            if (imagesGuids[dimage_guid].is_null()) {
                msg("Can not get name for image with guid: %s\n", dimage_guid.c_str());
                continue;
            }
            std::string dimage_name = imagesGuids[dimage_guid];
            if (dimage_name == image) {
                depsProtocols = element.value();
                found = true;
                break;
            }
        }
        if (found) {
            break;
        }
    }

    info["installed_protocols"] = installedProtocols;
    info["deps_protocols"] = depsProtocols;

    return info;
}

void EfiDependencies::getImagesInfo() {
    for (auto image : imagesFromIdb) {
        imagesInfo[image] = getImageInfo(image);
    }
}

void EfiDependencies::buildModulesSequence() {
    std::vector<std::string> modulesSeq;
    std::set<std::string> installed_protocols;
    auto imagesToLoad = imagesFromIdb;

    while (!imagesToLoad.empty()) {
        bool changed = false;

        for (auto image : imagesFromIdb) {
            auto deps = imagesInfo[image]["deps_protocols"];
            auto prots_module = imagesInfo[image]["installed_protocols"];

            // if image has not any dependencies
            // add image to list and save all protocols installed by this image
            if (deps.is_null()) {
                modulesSeq.push_back(image);
                remove(imagesToLoad.begin(), imagesToLoad.end(), image);
                // add installed protocols
                for (std::string p : prots_module) {
                    installed_protocols.insert(p);
                }
                bool changed = true;
                continue;
            }

            // if image has dependencies
            // check if it can be loaded
            bool load = true;
            for (std::string dep_protocol : deps) {
                // if all protocols are present in installed protocols or untracked
                // protocols, we can load this module
                if (find(untrackedProtocols.begin(), untrackedProtocols.end(),
                         dep_protocol) != untrackedProtocols.end()) {
                    continue;
                }
                if (installed_protocols.find(dep_protocol) == installed_protocols.end()) {
                    load = false;
                    break;
                }
            }

            // Load image, add installed protocols
            if (load) {
                modulesSeq.push_back(image);
                remove(imagesToLoad.begin(), imagesToLoad.end(), image);
                // add installed protocols
                for (std::string p : prots_module) {
                    installed_protocols.insert(p);
                }
                bool changed = false;
            }
        }
        if (!changed) {
            break;
        }
    }

    for (auto module : modulesSeq) {
        msg("%s\n", module.c_str());
    }
    msg("Loaded %lu/%lu modules\n", modulesSeq.size(), imagesFromIdb.size());
}
