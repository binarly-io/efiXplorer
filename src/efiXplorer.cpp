/* efiXplorer.cpp
 * This file is part of efiXplorer
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
plugmod_t *idaapi init(void) {
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
    uint8_t arch = getFileType();
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
