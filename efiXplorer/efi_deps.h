/*
 * efiXplorer
 * Copyright (C) 2020-2025 Binarly
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

#pragma once

#include "efi_utils.h"
#include <map>
#include <string>

class efi_deps_t {
public:
  efi_deps_t();
  ~efi_deps_t();

  json m_additional_installers;
  json m_modules_guids;
  json m_modules_info;
  json m_modules_sequence;
  json m_protocols_by_guids;
  json m_protocols_chooser;
  json m_uefitool_deps;
  string_set_t m_modules_from_idb;
  string_set_t m_untracked_protocols;

  // input: protocols from report
  void get_protocols_by_guids(json_list_t protocols);
  void get_protocols_chooser(json_list_t protocols);
  // get dependencies for specific protocol
  json get_deps_for(std::string protocol);
  // get installers by protocol GUIDs by searching
  // in the firmware and analysing xrefs
  void get_additional_installers();
  bool build_modules_sequence();
  bool get_modules_info();

private:
  string_set_t m_protocols_without_installers;

  bool installer_found(std::string protocol);
  bool load_deps_from_uefitool();
  bool load_modules_with_guids();
  json get_module_info(std::string module);
  std::string get_installer(std::string protocol);
  string_set_t get_apriori_modules();
  void get_installers_modules();
  void get_modules();
  void get_protocols_without_installers();
};
