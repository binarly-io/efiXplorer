/*
 * efiXplorer
 * Copyright (C) 2020-2022 Binarly
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
 * efiXplorer.cpp
 *
 */

#include "efiXplorer.h"
#include "efiAnalysis.h"
#include "efiGlobal.h"
#include "efiUi.h"

static bool inited = false;
static const char plugin_name[] = "efiXplorer";
static const char plugin_hotkey[] = "Ctrl+Alt+E";
static const char plugin_comment[] =
    "This plugin performs automatic analysis of the input UEFI module";
static const char plugin_help[] =
    "This plugin performs automatic analysis of the input UEFI module";
static const char welcome_msg[] = "      ____ _  __     __\n"
                                  " ___ / _(_) |/_/__  / /__  _______ ____\n"
                                  "/ -_) _/ />  </ _ \\/ / _ \\/ __/ -_) __/\n"
                                  "\\__/_//_/_/|_/ .__/_/\\___/_/  \\__/_/\n"
                                  "            /_/\n";

// Default arguments
struct args g_args = {/* disable_ui */ 0, /* disable_vuln_hunt */ 0};

//--------------------------------------------------------------------------
static plugmod_t *idaapi init(void) {
    uint8_t arch = getInputFileType();
    if ((arch != X86 && arch != X64 && arch != UEFI) || !is_idaq()) {
        return PLUGIN_SKIP;
    }

    msg(welcome_msg);
    msg("%s\n\n", COPYRIGHT);

    // Register action
    register_action(action_load_report);
    attach_action_to_menu("File/Load file/", action_load_report.name, SETMENU_APP);

    return PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
bool idaapi run(size_t arg) {
    if (arg >> 0 & 1) { // arg = 0 (00): default
                        // arg = 1 (01): disable_ui
                        // arg = 2 (10): disable_vuln_hunt
                        // arg = 3 (11): disable_ui & disable_vuln_hunt
        g_args.disable_ui = 1;
    }
    if (arg >> 1 & 1) {
        g_args.disable_vuln_hunt = 1;
    }

    msg("[%s] plugin run with argument %lu\n", plugin_name, arg);
    msg("[%s] disable_ui = %d, disable_vuln_hunt = %d\n", plugin_name, g_args.disable_ui,
        g_args.disable_vuln_hunt);

    bool guidsJsonOk = guidsJsonExists();
    msg("[%s] guids.json exists: %s\n", plugin_name, BTOA(guidsJsonOk));

    if (!guidsJsonOk) {
        std::string msg_text =
            "guids.json file not found, copy \"guids\" directory to <IDA_DIR>/plugins";
        msg("[%s] %s\n", plugin_name, msg_text.c_str());
        warning("%s: %s\n", plugin_name, msg_text.c_str());
        return false;
    }

    uint8_t arch = getInputFileType();
    if (arch == X64) {
        msg("[%s] input file is portable executable for AMD64 (PE)\n", plugin_name);
        EfiAnalysis::efiAnalyzerMainX64();
    }

    if (arch == X86) {
        msg("[%s] input file is portable executable for 80386 (PE)\n", plugin_name);
        EfiAnalysis::efiAnalyzerMainX86();
    }

    if (arch == UEFI) {
        warning("%s: analysis may take some time, please wait for it to complete\n",
                plugin_name);
        msg("[%s] input file is UEFI firmware\n", plugin_name);
        EfiAnalysis::efiAnalyzerMainX64();
    }

    // Reset arguments
    g_args = {/* disable_ui */ 0, /* disable_vuln_hunt */ 0};

    return true;
}

//--------------------------------------------------------------------------
// PLUGIN DESCRIPTION BLOCK
plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_MOD | PLUGIN_PROC | PLUGIN_FIX,
    init,           // initialize plugin
    nullptr,        // terminate plugin
    run,            // invoke plugin
    plugin_comment, // long comment about the plugin
    plugin_help,    // multiline help about the plugin
    plugin_name,    // the preferred short name of the plugin
    plugin_hotkey   // the preferred hotkey to run the plugin
};
