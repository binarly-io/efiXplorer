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
 * efiXplorer.cpp
 *
 */

#include "efiXplorer.h"
#include "efiAnalysis.h"
#include "efiPluginArgs.h"

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

#if BATCH

//--------------------------------------------------------------------------
plugmod_t *idaapi init(void) {
    uint8_t arch = getArch();
    if (arch != X86 && arch != X64 && arch != UEFI) {
        return PLUGIN_SKIP;
    }
    msg(welcome_msg);
    msg("%s\n\n", COPYRIGHT);
    inited = true;
    return PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
bool idaapi run(size_t) {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    g_args.disable_ui = 1;
    g_args.disable_vuln_hunt = 1;
    DEBUG_MSG("[%s] plugin run\n", plugin_name);
    DEBUG_MSG("[%s] disable_ui = %d, disable_vuln_hunt = %d\n", plugin_name,
              g_args.disable_ui, g_args.disable_vuln_hunt);
    uint8_t arch = getArch();
    if (arch == X64) {
        DEBUG_MSG("[%s] input file is portable executable for AMD64 (PE)\n", plugin_name);
        efiAnalysis::efiAnalyzerMainX64();
    }
    if (arch == X86) {
        DEBUG_MSG("[%s] input file is portable executable for 80386 (PE)\n", plugin_name);
        efiAnalysis::efiAnalyzerMainX86();
    }
    return true;
}

//--------------------------------------------------------------------------
// PLUGIN DESCRIPTION BLOCK
plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    0,              // plugin flags
    init,           // initialize plugin
    nullptr,        // terminate plugin
    run,            // invoke plugin
    plugin_comment, // long comment about the plugin
    plugin_help,    // multiline help about the plugin
    plugin_name,    // the preferred short name of the plugin
    plugin_hotkey   // the preferred hotkey to run the plugin
};

#else

std::vector<json> depJson;
std::vector<std::string> depNodes;
std::vector<json> depEdges;

//-------------------------------------------------------------------------
struct graph_data_t {
    qstrvec_t text;
    void refresh(mutable_graph_t *g);
};

//-------------------------------------------------------------------------
void graph_data_t::refresh(mutable_graph_t *g) {
    // Clear nodes & edges information
    g->clear();

    // Add nodes
    const size_t nnodes = depNodes.size();
    g->resize(nnodes);

    // Add edges
    for (auto e : depEdges) {
        g->add_edge(e["from"], e["to"], NULL);
    }

    // Generate names
    text.resize(nnodes);
    for (size_t i = 0; i < nnodes; ++i) {
        text[i] = static_cast<qstring>(depNodes[i].c_str());
    }

    // Clear previously-registered custom
    for (size_t i = 0; i < nnodes; ++i)
        del_node_info(g->gid, i);
}

//-------------------------------------------------------------------------
struct plugin_ctx_t;

//-------------------------------------------------------------------------
// A base action handler, ensuring the action is only available on the
// right widget, and possibly only if a (or more) node(s) is(are)
// selected.
struct base_depgraph_ah_t : public action_handler_t {
    plugin_ctx_t &plg;
    bool requires_node;

    base_depgraph_ah_t(plugin_ctx_t &_plg, bool _requires_node = false)
        : plg(_plg), requires_node(_requires_node) {}
    virtual action_state_t idaapi update(action_update_ctx_t *ctx) override;

    struct node_visitor_t {
        virtual ~node_visitor_t() {}
        virtual bool on_node(int node, node_info_t &ni) newapi = 0;
    };

  protected:
    bool get_nodes(intvec_t *out, const action_ctx_base_t &ctx) const;

    bool for_each_node(const action_ctx_base_t &ctx, node_visitor_t &visitor);
};

//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t, public event_listener_t {
    graph_data_t data;
    graph_viewer_t *gv = nullptr;

    plugin_ctx_t() { hook_event_listener(HT_VIEW, this); }
    ~plugin_ctx_t() {
        // listeners are uninstalled automatically
        // when the owner module is unloaded
    }

    virtual bool idaapi run(size_t) override;
    virtual ssize_t idaapi on_event(ssize_t code, va_list va) override;
    static ssize_t idaapi gr_callback(void *ud, int code, va_list va);
};

//--------------------------------------------------------------------------
ssize_t idaapi plugin_ctx_t::gr_callback(void *ud, int code, va_list va) {

    plugin_ctx_t &ctx = *(plugin_ctx_t *)ud;
    ssize_t result = 0;
    switch (code) {

    case grcode_user_refresh: {
        mutable_graph_t *g = va_arg(va, mutable_graph_t *);
        ctx.data.refresh(g);
        result = true;
    } break;

    case grcode_user_text: {
        mutable_graph_t *g = va_arg(va, mutable_graph_t *);
        int node = va_arg(va, int);
        const char **text = va_arg(va, const char **);
        bgcolor_t *bgcolor = va_arg(va, bgcolor_t *);
        *text = ctx.data.text[node].c_str();
        if (bgcolor != NULL)
            *bgcolor = DEFCOLOR;
        result = true;
        qnotused(g);
    } break;

    case grcode_user_hint: {
        mutable_graph_t *g = va_arg(va, mutable_graph_t *);
        int mousenode = va_argi(va, int);
        int mouseedge_src = va_argi(va, int);
        int mouseedge_dst = va_argi(va, int);
        char **hint = va_arg(va, char **);
        char buf[MAXSTR];
        buf[0] = '\0';
        if (mousenode != -1) {
            // hint: module name
            qsnprintf(buf, sizeof(buf), "%s", ctx.data.text[mousenode].c_str());
        } else if (mouseedge_src != -1) {
            // hint: src -> dst
            qsnprintf(buf, sizeof(buf), "%s -> %s", ctx.data.text[mouseedge_src].c_str(),
                      ctx.data.text[mouseedge_dst].c_str());
        }
        if (buf[0] != '\0')
            *hint = qstrdup(buf);
        result = true; // use our hint
        qnotused(g);
    } break;
    }
    return result;
}

//-------------------------------------------------------------------------
ssize_t idaapi plugin_ctx_t::on_event(ssize_t code, va_list va) {
    if (code == static_cast<ssize_t>(view_close)) {
        TWidget *view = va_arg(va, TWidget *);
        if (view == (TWidget *)gv)
            gv = nullptr;
    }
    return 0;
}

//-------------------------------------------------------------------------
action_state_t idaapi base_depgraph_ah_t::update(action_update_ctx_t *ctx) {
    if (ctx->widget != (TWidget *)plg.gv)
        return AST_DISABLE_FOR_WIDGET;
    if (requires_node) {
        // If this requires nodes, we want to be called again as
        // soon as something (i.e., the selection) changes
        return get_nodes(nullptr, *ctx) ? AST_ENABLE : AST_DISABLE;
    } else {
        return AST_ENABLE_FOR_WIDGET;
    }
}

//-------------------------------------------------------------------------
bool base_depgraph_ah_t::get_nodes(intvec_t *out, const action_ctx_base_t &ctx) const {
    screen_graph_selection_t *s = ctx.graph_selection;
    if (s == nullptr)
        return false;
    intvec_t tmp;
    size_t nitems = s->size();
    for (size_t i = 0; i < nitems; ++i) {
        const selection_item_t &item = s->at(i);
        if (item.is_node)
            tmp.push_back(item.node);
    }
    bool ok = !tmp.empty();
    if (out != nullptr)
        out->swap(tmp);
    return ok;
}

//-------------------------------------------------------------------------
bool base_depgraph_ah_t::for_each_node(const action_ctx_base_t &ctx,
                                       node_visitor_t &visitor) {
    mutable_graph_t *g = get_viewer_graph(plg.gv);
    intvec_t nodes;
    bool ok = get_nodes(&nodes, ctx);
    if (ok) {
        size_t nnodes = nodes.size();
        for (size_t i = 0; i < nnodes; ++i) {
            int node = nodes[i];
            node_info_t ni;
            get_node_info(&ni, g->gid, node);
            visitor.on_node(node, ni);
            uint32 niflags = ni.get_flags_for_valid();
            if (niflags != 0)
                set_node_info(g->gid, node, ni, niflags);
            else
                del_node_info(g->gid, node);
        }
    }
    return ok;
}

//--------------------------------------------------------------------------
static plugmod_t *idaapi init() {
    uint8_t arch = getArch();
    if ((arch != X86 && arch != X64 && arch != UEFI) || !is_idaq()) {
        return nullptr;
    }
    msg(welcome_msg);
    msg("%s\n\n", COPYRIGHT);
    inited = true;
    return new plugin_ctx_t;
}

//--------------------------------------------------------------------------
static const char wanted_title[] = "efiXplorer: dependency graph";
bool idaapi plugin_ctx_t::run(size_t arg) {
    DEBUG_MSG("[%s] ========================================================\n",
              plugin_name);
    if (arg >> 0 & 1) { // arg = 0 (00): default
                        // arg = 1 (01): disable_ui
                        // arg = 2 (10): disable_vuln_hunt
                        // arg = 3 (11): disable_ui & disable_vuln_hunt
        g_args.disable_ui = 1;
    }
    if (arg >> 1 & 1) {
        g_args.disable_vuln_hunt = 1;
    }

    DEBUG_MSG("[%s] plugin run with argument %lu\n", plugin_name, arg);
    DEBUG_MSG("[%s] disable_ui = %d, disable_vuln_hunt = %d\n", plugin_name,
              g_args.disable_ui, g_args.disable_vuln_hunt);

    bool guidsJsonOk = guidsJsonExists();
    DEBUG_MSG("[%s] guids.json exists: %s\n", plugin_name, BTOA(guidsJsonOk));

    if (!guidsJsonOk) {
        std::string msg_text =
            "guids.json file not found, copy \"guids\" directory to <IDA_DIR>/plugins";
        DEBUG_MSG("[%s] %s\n", plugin_name, msg_text.c_str());
        warning("%s: %s\n", plugin_name, msg_text.c_str());
        return false;
    }

    uint8_t arch = getArch();
    if (arch == X64) {
        DEBUG_MSG("[%s] input file is portable executable for AMD64 (PE)\n", plugin_name);
        efiAnalysis::efiAnalyzerMainX64();
    }

    if (arch == X86) {
        DEBUG_MSG("[%s] input file is portable executable for 80386 (PE)\n", plugin_name);
        efiAnalysis::efiAnalyzerMainX86();
    }

    if (arch == UEFI) {
        warning("%s: analysis may take some time, please wait for it to complete\n",
                plugin_name);
        DEBUG_MSG("[%s] input file is UEFI firmware\n", plugin_name);
        efiAnalysis::efiAnalyzerMainX64();

        if (summaryJsonExist()) {

            // Build dependency graph (based on upgraph example from idasdk)
            depJson = getDependenciesLoader();
            depNodes = getNodes(depJson);
            depEdges = getEdges(depNodes, depJson);
            TWidget *widget = find_widget(wanted_title);
            if (widget != nullptr) {
                close_widget(widget, 0);
            }

            // Get a unique graph id
            netnode id;
            id.create("$ efiXplorer graph");
            gv = create_graph_viewer(wanted_title, id, gr_callback, this, 0);
            if (gv != nullptr) {
                display_widget(gv, WOPN_DP_TAB);
                viewer_fit_window(gv);
                widget = find_widget(wanted_title);
            }
        }

        depJson.clear();
        depNodes.clear();
        depEdges.clear();
    }

    // Reset arguments
    g_args = {/* disable_ui */ 0, /* disable_vuln_hunt */ 0};

    return true;
}

//--------------------------------------------------------------------------
// PLUGIN DESCRIPTION BLOCK
plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_MULTI,   // the plugin can work with multiple idbs in parallel
    init,           // initialize plugin
    nullptr,        // terminate plugin
    nullptr,        // invoke plugin
    plugin_comment, // long comment about the plugin
    plugin_help,    // multiline help about the plugin
    plugin_name,    // the preferred short name of the plugin
    plugin_hotkey   // the preferred hotkey to run the plugin
};

#endif
