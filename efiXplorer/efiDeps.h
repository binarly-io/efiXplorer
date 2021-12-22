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
 * efiDeps.h
 *
 */

#pragma once

#include "efiUtils.h"

class EfiDependencies {
  public:
    EfiDependencies();
    ~EfiDependencies();
    json protocolsByGuids; // protocols sorted by GUIDs
    json protocolsChooser; // numbered json with protocols
    json uefitoolDeps;
    json imagesGuids;
    json additionalInstallers; // getAdditionalInstallers result
    json imagesInfo;
    json modulesSequence; // buildModulesSequence result
    std::vector<std::string> imagesFromIdb;
    std::set<std::string> untrackedProtocols;
    // Input: protocols from report
    void getProtocolsByGuids(std::vector<json> protocols);
    void getProtocolsChooser(std::vector<json> protocols);
    json getDeps(std::string protocol); // get dependencies for specific protocol
    void getAdditionalInstallers(); // get installers by protocol GUIDs by searching in
                                    // the firmware and analyzing xrefs
    bool buildModulesSequence();
    bool getImagesInfo();

  private:
    void getImages();
    std::set<std::string> protocolsWithoutInstallers;
    void getProtocolsWithoutInstallers();
    void getInstallersModules();
    bool loadDepsFromUefiTool();
    bool loadImagesWithGuids();
    bool installerFound(std::string protocol);
    json getImageInfo(std::string image);
};
