/*
 *        __ ___   __      _
 *       / _(_) \ / /     | |
 *   ___| |_ _ \ V / _ __ | | ___  _ __ ___ _ __
 *  / _ \  _| | > < | '_ \| |/ _ \| '__/ _ \ '__|
 * |  __/ | | |/ . \| |_) | | (_) | | |  __/ |
 *  \___|_| |_/_/ \_\ .__/|_|\___/|_|  \___|_|
 *                  | |
 *                  |_|
 *
 * efiXplorer
 * Copyright (C) 2020  Binarly
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
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * efiXplorer.cpp
 *
 */

#include "efiXplorer.h"
#include "efiAnalysis.h"

static bool inited = false;
static const char plugin_name[] = "efiXplorer";
static const char plugin_hotkey[] = "Ctrl+Alt+E";
static const char plugin_comment[] =
    "This plugin performs automatic analysis of the input UEFI module";
static const char plugin_help[] =
    "This plugin performs automatic analysis of the input UEFI module";
static const char welcome_msg[] =
    "        __ ___   __      _\n"
    "       / _(_) \\ / /     | |\n"
    "   ___| |_ _ \\ V / _ __ | | ___  _ __ ___ _ __\n"
    "  / _ \\  _| | > < | '_ \\| |/ _ \\| '__/ _ \\ '__|\n"
    " |  __/ | | |/ . \\| |_) | | (_) | | |  __/ |\n"
    "  \\___|_| |_/_/ \\_\\ .__/|_|\\___/|_|  \\___|_|\n"
    "                  | |\n"
    "                  |_|\n";

//--------------------------------------------------------------------------
// Initialize
#if IDA_SDK_VERSION == 740
int idaapi init(void) {
#else
plugmod_t *idaapi init(void) {
#endif
    msg(welcome_msg);
    msg("%s\n\n", COPYRIGHT);
    inited = true;
    return PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
// The plugin method
// This is the main function of plugin
bool idaapi run(size_t) {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    DEBUG_MSG("[%s] plugin run\n", plugin_name);
    bool guidsJsonOk = guidsJsonExists();
    DEBUG_MSG("[%s] guids.json exists: %s\n", plugin_name, BTOA(guidsJsonOk));
    if (!guidsJsonOk) {
        string msg_text = "guids.json file not found, copy \"guids\" directory "
                          "to <IDA_DIR>/plugins";
        DEBUG_MSG("[%s] %s\n", plugin_name, msg_text.c_str());
        warning("%s: %s\n", plugin_name, msg_text.c_str());
        return false;
    }
    uint8_t arch = getArch();
    if (arch == X64) {
        DEBUG_MSG("[%s] input file is portable executable for AMD64 (PE)\n",
                  plugin_name);
        efiAnalysis::efiAnalyzerMainX64();
    }
    if (arch == X86) {
        DEBUG_MSG("[%s] input file is portable executable for 80386 (PE)\n",
                  plugin_name);
        efiAnalysis::efiAnalyzerMainX86();
    }
    if (arch == UEFI) {
        DEBUG_MSG("[%s] input file is UEFI firmware\n", plugin_name);
        efiAnalysis::efiAnalyzerMainX64();
    }
    return true;
}

//--------------------------------------------------------------------------
// PLUGIN DESCRIPTION BLOCK
plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    (PLUGIN_MOD | PLUGIN_PROC | PLUGIN_FIX), // plugin flags
    init,                                    // initialize
    NULL,                                    // terminate
    run,                                     // invoke plugin
    plugin_comment,                          // long comment about the plugin
    plugin_help,                             // multiline help about the plugin
    plugin_name,                             // short name of the plugin
    plugin_hotkey                            // hotkey to run the plugin
};
