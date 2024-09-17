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

#include "efi_analyser.h"
#include "efi_global.h"
#include "efi_ui.h"

static const char hotkey[] = "Ctrl+Alt+E";
static const char description[] =
    "This plugin performs automatic analysis of the input UEFI module";
static const char welcome_msg[] = "      ____ _  __     __\n"
                                  " ___ / _(_) |/_/__  / /__  _______ ____\n"
                                  "/ -_) _/ />  </ _ \\/ / _ \\/ __/ -_) __/\n"
                                  "\\__/_//_/_/|_/ .__/_/\\___/_/  \\__/_/\n"
                                  "            /_/\n";

// default arguments
struct args g_args = {module_type_t::dxe_smm, 0, 0};

#if IDA_SDK_VERSION < 760
hexdsp_t *hexdsp = nullptr;
#endif

//--------------------------------------------------------------------------
static plugmod_t *idaapi init(void) {
  arch_file_type_t file_type = input_file_type();
  if (file_type == arch_file_type_t::unsupported) {
    return PLUGIN_SKIP;
  }

  msg(welcome_msg);
  msg("%s\n\n", COPYRIGHT);

  // Register action
  register_action(action_load_report);
  attach_action_to_menu("File/Load file/", action_load_report.name,
                        SETMENU_APP);

  return PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
bool idaapi run(size_t arg) {
  if (arg >> 0 & 1) {
    // parse arg value:
    // - arg = 0 (000): default (DXE)
    // - arg = 1 (001): default (PEI, 32-bit binaries only)
    // - arg = 2 (010): disable_ui (DXE)
    // - arg = 3 (011): disable_ui (PEI, 32-bit binaries only)
    // - arg = 4 (100): disable_vuln_hunt (DXE)
    // - arg = 5 (101): disable_vuln_hunt (PEI, 32-bit binaries only)
    // - arg = 6 (110): disable_ui & disable_vuln_hunt for DXE
    // - arg = 7 (111): disable_ui & disable_vuln_hunt for PEI
    g_args.module_type = module_type_t::pei;
  }

  if (arg >> 1 & 1) {
    g_args.disable_ui = 1;
  }
  if (arg >> 2 & 1) {
    g_args.disable_vuln_hunt = 1;
  }

  msg("[%s] plugin run with argument %lu (sdk version: %d)\n", g_plugin_name,
      arg, IDA_SDK_VERSION);
  msg("[%s] disable_ui = %d, disable_vuln_hunt = %d\n", g_plugin_name,
      g_args.disable_ui, g_args.disable_vuln_hunt);

  auto guids_path = get_guids_json_file();
  msg("[%s] guids.json exists: %s\n", g_plugin_name, BTOA(!guids_path.empty()));

  if (guids_path.empty()) {
    std::string msg_text = "guids.json file not found, copy \"guids\" "
                           "directory to <IDA_DIR>/plugins";
    msg("[%s] %s\n", g_plugin_name, msg_text.c_str());
    warning("%s: %s\n", g_plugin_name, msg_text.c_str());
    return false;
  }

  arch_file_type_t arch = input_file_type();
  if (arch == arch_file_type_t::x86_64) {
    msg("[%s] input file is 64-bit module (x86)\n", g_plugin_name);
    efi_analysis::efi_analyse_main_x86_64();
  } else if (arch == arch_file_type_t::x86_32) {
    msg("[%s] input file is 32-bit module (x86)\n", g_plugin_name);
    efi_analysis::efi_analyse_main_x86_32();
  } else if (arch == arch_file_type_t::uefi) {
    msg("[%s] input file is UEFI firmware\n", g_plugin_name);
    warning("%s: analysis may take some time, please wait for it to complete\n",
            g_plugin_name);
    if (get_machine_type() == AARCH64) {
      msg("[%s] analyse AARCH64 modules\n", g_plugin_name);
      efi_analysis::efi_analyse_main_aarch64();
    } else {
      msg("[%s] analyse AMD64 modules\n", g_plugin_name);
      efi_analysis::efi_analyse_main_x86_64();
    }
  } else if (arch == arch_file_type_t::aarch64) {
    msg("[%s] input file is 64-bit module (ARM)\n", g_plugin_name);
    efi_analysis::efi_analyse_main_aarch64();
  }

  // Reset arguments
  g_args = {module_type_t::dxe_smm, 0, 0};

  return true;
}

//--------------------------------------------------------------------------
// PLUGIN DESCRIPTION BLOCK
plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    0,             // plugin flags
    init,          // initialize plugin
    nullptr,       // terminate plugin
    run,           // invoke plugin
    description,   // long comment about the plugin
    description,   // multiline help about the plugin
    g_plugin_name, // the preferred short name of the plugin
    hotkey         // the preferred hotkey to run the plugin
};
