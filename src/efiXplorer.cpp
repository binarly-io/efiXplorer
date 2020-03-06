// efiXplorer.cpp : Defines the entry point for the plugin
//

#include "efiXplorer.h"

using namespace std;

int main()
{
	return 0;
}

/*
#include <hexrays.hpp>

extern plugin_t PLUGIN;

// Hex-Rays API pointer
hexdsp_t* hexdsp = NULL;


//--------------------------------------------------------------------------
int idaapi init(void)
{
	if (!init_hexrays_plugin())
		return PLUGIN_SKIP; // no decompiler
	const char* hxver = get_hexrays_version();
	msg("Hex-rays version %s has been detected, %s ready to use\n", hxver, PLUGIN.wanted_name);

	return PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
void idaapi term(void)
{
	if (hexdsp != NULL)
	{
		term_hexrays_plugin();
	}
}

//--------------------------------------------------------------------------
bool idaapi run(size_t arg)
{
	if (arg == 0xbeef)
	{
		PLUGIN.flags |= PLUGIN_UNL;
		return true;
	}
	if (arg == 2)
	{
		FixCallsToAllocaProbe();
		return true;
	}

	return true;
}

//--------------------------------------------------------------------------
static const char comment[] = "Show microcode";


//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	0,                    // plugin flags
	init,                 // initialize
	term,                 // terminate. this pointer may be NULL.
	run,                  // invoke plugin
	comment,              // long comment about the plugin
						  // it could appear in the status line
						  // or as a hint
	"",                   // multiline help about the plugin
	"EFI Explorer", // the preferred short name of the plugin
	""                    // the preferred hotkey to run the plugin
};
*/