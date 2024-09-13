/*
 * efiXplorer
 * Copyright (C) 2020-2024 Binarly
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
 */

#include "efi_deps.h"

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
  modulesSequence.clear();
  protocolsChooser.clear();
  protocolsByGuids.clear();
  additionalInstallers.clear();
  protocolsWithoutInstallers.clear();
};

json EfiDependencies::getDeps(std::string guid) {
  json res;
  std::vector installers({"InstallProtocolInterface", "InstallMultipleProtocolInterfaces",
                          "SmmInstallProtocolInterface"});
  for (auto &it : protocolsChooser.items()) {
    auto p = it.value();
    if (p["guid"] != guid) {
      continue;
    }
    p["ea"] = as_hex(u64_addr(p["ea"]));
    p["xref"] = as_hex(u64_addr(p["xref"]));
    p["address"] = as_hex(u64_addr(p["address"]));
    if (find(installers.begin(), installers.end(), p["service"]) != installers.end()) {
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
    auto addrs = search_protocol(protocol);
    bool installerFound = false;
    for (auto addr : addrs) {
      auto xrefs = get_xrefs_util(addr);
      if (!xrefs.size()) {
        continue;
      }
      if (xrefs.size() == 1) {
        func_t *func = get_func(xrefs.at(0));
        if (func == nullptr) {
          xrefs = get_xrefs_to_array(xrefs.at(0));
        }
      }
      for (auto ea : xrefs) {
        if (check_install_protocol(ea)) {
          auto module = get_module_name_loader(ea);
          additionalInstallers[protocol] = static_cast<std::string>(module.c_str());
          installerFound = true;
          break;
        }
      }
      if (installerFound) {
        break;
      }
    }
    if (!installerFound) {
      untrackedProtocols.insert(protocol);
    }
  }
}

void EfiDependencies::getAdditionalInstallers() {
  getProtocolsWithoutInstallers();
  getInstallersModules();
  std::string installers = additionalInstallers.dump(2);
  msg("Additional installers: %s\n", installers.c_str());
  msg("Untracked protocols:\n");
  for (auto &protocol : untrackedProtocols) {
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
  std::vector installers({"InstallProtocolInterface", "InstallMultipleProtocolInterfaces",
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
    if (find(installers.begin(), installers.end(), p["service"]) != installers.end()) {
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
        // Can not get name for image
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

bool EfiDependencies::getImagesInfo() {
  if (imagesInfo.size()) {
    return true;
  }
  for (auto image : imagesFromIdb) {
    imagesInfo[image] = getImageInfo(image);
  }
  return true;
}

std::string EfiDependencies::getInstaller(std::string protocol) {
  std::string res;
  for (auto &e : imagesInfo.items()) {
    std::string image = e.key();
    std::vector<std::string> installers = imagesInfo[image]["installed_protocols"];
    if (find(installers.begin(), installers.end(), protocol) != installers.end()) {
      return image;
    }
  }
  return res;
}

bool EfiDependencies::buildModulesSequence() {
  if (modulesSequence.size()) {
    return true;
  }

  std::set<std::string> modulesSeq;
  std::set<std::string> installed_protocols;

  getProtocolsWithoutInstallers(); // hard to find installers for all protocols in
                                   // statiс
  getImagesInfo();

  size_t index = 0;
  while (modulesSeq.size() != imagesInfo.size()) {
    bool changed = false;
    for (auto &e : imagesInfo.items()) {
      std::string image = e.key(); // current module

      // check if the image is already loaded
      if (modulesSeq.find(image) != modulesSeq.end()) {
        continue;
      }

      std::vector<std::string> installers = imagesInfo[image]["installed_protocols"];

      // if there are no dependencies
      if (imagesInfo[image]["deps_protocols"].is_null()) {
        for (auto protocol : installers) {
          installed_protocols.insert(protocol);
        }
        modulesSeq.insert(image);
        json info;
        info["module"] = image;
        modulesSequence[index++] = info;
        changed = true;
        continue;
      }

      std::vector<std::string> deps = imagesInfo[image]["deps_protocols"];
      std::vector<std::string> unresolved_deps;
      bool load = true;
      for (auto protocol : deps) {
        if (installed_protocols.find(protocol) != installed_protocols.end()) {
          continue;
        }
        if (protocolsWithoutInstallers.find(protocol) !=
            protocolsWithoutInstallers.end()) {
          unresolved_deps.push_back(protocol);
          continue;
        }
        load = false;
        break;
      }

      if (load) {
        for (auto protocol : installers) {
          installed_protocols.insert(protocol);
        }
        modulesSeq.insert(image);
        json info;
        info["image"] = image;
        info["deps"] = deps;
        if (unresolved_deps.size()) {
          info["unresolved_deps"] = unresolved_deps;
        }
        modulesSequence[index++] = info;
        changed = true;
      }
    }

    if (!changed) { // we are in a loop, we need to load a module that installs the
                    // most popular protocol
      std::map<std::string, size_t> protocols_usage; // get the most popular protocol
      for (auto &e : imagesInfo.items()) {
        std::string image = e.key();

        // check if the image is already loaded
        if (modulesSeq.find(image) != modulesSeq.end()) {
          continue;
        }

        if (imagesInfo[image]["deps_protocols"].is_null()) {
          continue;
        }

        std::vector<std::string> deps_protocols = imagesInfo[image]["deps_protocols"];
        for (auto protocol : deps_protocols) {
          if (installed_protocols.find(protocol) != installed_protocols.end()) {
            continue;
          }
          if (protocolsWithoutInstallers.find(protocol) !=
              protocolsWithoutInstallers.end()) {
            continue;
          }
          if (protocols_usage.find(protocol) == protocols_usage.end()) {
            protocols_usage[protocol] = 1;
          } else {
            protocols_usage[protocol] += 1;
          }
        }
      }
      std::string mprotocol;
      size_t mnum = 0;
      for (auto const &[prot, counter] : protocols_usage) {
        if (counter > mnum) {
          mnum = static_cast<size_t>(counter);
          mprotocol = static_cast<std::string>(prot);
        }
      }
      if (!mnum) {
        break; // the most popular protocol was not found
      }
      // find installer module for mprotocol
      std::string installer_image = getInstaller(mprotocol);
      if (!installer_image.size()) {
        msg("Can not find installer for protocol %s\n", mprotocol.c_str());
        break; // something went wrong, extra mitigation for an infinite loop
      }
      // load installer_image
      std::vector<std::string> current_installers =
          imagesInfo[installer_image]["installed_protocols"];
      for (auto protocol : current_installers) {
        installed_protocols.insert(protocol);
      }
      modulesSeq.insert(installer_image);
      json info;
      info["image"] = installer_image;
      info["deps"] = imagesInfo[installer_image]["deps_protocols"];
      modulesSequence[index++] = info;
    }
  }

  return true;
}
