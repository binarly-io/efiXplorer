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

#define GRAPH_DEBUG 0

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

vector<json> depJson;
vector<string> depNodes;
vector<json> depEdges;

//-------------------------------------------------------------------------
struct plugin_ctx_t;
struct change_layout_ah_t : public action_handler_t {
    plugin_ctx_t &plg;
    change_layout_ah_t(plugin_ctx_t &_plg) : plg(_plg) {}
    virtual int idaapi activate(action_activation_ctx_t *ctx) override;
    virtual action_state_t idaapi update(action_update_ctx_t *ctx) override;
};

//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t, public event_listener_t {
    change_layout_ah_t change_layout_ah = change_layout_ah_t(*this);
    const action_desc_t change_layout_desc =
        ACTION_DESC_LITERAL_PLUGMOD("ugraph:ChangeLayout", "User function",
                                    &change_layout_ah, this, NULL, NULL, -1);

    qstrvec_t graph_text;
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

//-------------------------------------------------------------------------
// Graph settings
int idaapi change_layout_ah_t::activate(action_activation_ctx_t *ctx) {
    plg.gv = (graph_viewer_t *)ctx->widget;
    mutable_graph_t *g = get_viewer_graph(plg.gv);
    node_info_t ni;
    ni.bg_color = 0x44FF55;
    ni.text = "efiXplorer: dependency graph";
    set_node_info(g->gid, 7, ni, NIF_BG_COLOR | NIF_TEXT);
    g->circle_center = point_t(200, 200);
    g->circle_radius = 200;
    g->redo_layout();
    refresh_viewer(plg.gv);
    return 1;
}

//-------------------------------------------------------------------------
action_state_t idaapi change_layout_ah_t::update(action_update_ctx_t *ctx) {
    if (ctx->widget == (TWidget *)plg.gv)
        return AST_ENABLE_FOR_WIDGET;
    else
        return AST_DISABLE_FOR_WIDGET;
}

//--------------------------------------------------------------------------
static const char *get_node_name(int n) {
    if (n >= depNodes.size())
        return "?";
    return depNodes[n].c_str();
}

//--------------------------------------------------------------------------
ssize_t idaapi plugin_ctx_t::gr_callback(void *ud, int code, va_list va) {
    plugin_ctx_t &ctx = *(plugin_ctx_t *)ud;
    ssize_t result = 0;
    switch (code) {
    case grcode_calculating_layout:
        // calculating user-defined graph layout
        // in: mutable_graph_t *g
        // out: 0-not implemented
        //      1-graph layout calculated by the plugin
        if (GRAPH_DEBUG)
            msg("calculating graph layout...\n");
        break;

    case grcode_clicked: // a graph has been clicked
                         // in:  graph_viewer_t *gv
                         //      selection_item_t *current_item
                         // out: 0-ok, 1-ignore click
    {
        graph_viewer_t *v = va_arg(va, graph_viewer_t *);
        qnotused(v);
        selection_item_t *it = va_arg(va, selection_item_t *);
        qnotused(it);
        graph_item_t *m = va_arg(va, graph_item_t *);
        if (GRAPH_DEBUG)
            msg("clicked on ");
        switch (m->type) {
        case git_none:
            if (GRAPH_DEBUG)
                msg("background\n");
            break;
        case git_edge:
            if (GRAPH_DEBUG)
                msg("edge (%d, %d)\n", m->e.src, m->e.dst);
            break;
        case git_node:
            if (GRAPH_DEBUG)
                msg("node %d\n", m->n);
            break;
        case git_tool:
            if (GRAPH_DEBUG)
                msg("toolbutton %d\n", m->b);
            break;
        case git_text:
            if (GRAPH_DEBUG)
                msg("text (x,y)=(%d,%d)\n", m->p.x, m->p.y);
            break;
        case git_elp:
            if (GRAPH_DEBUG)
                msg("edge layout point (%d, %d) #%d\n", m->elp.e.src,
                    m->elp.e.dst, m->elp.pidx);
            break;
        }
    } break;

    case grcode_dblclicked: // a graph node has been double clicked
                            // in:  graph_viewer_t *gv
                            //      selection_item_t *current_item
                            // out: 0-ok, 1-ignore click
    {
        graph_viewer_t *v = va_arg(va, graph_viewer_t *);
        selection_item_t *s = va_arg(va, selection_item_t *);
        if (GRAPH_DEBUG) {
            msg("%p: dblclicked on ", v);
            if (s == NULL)
                msg("background\n");
            else if (s->is_node)
                msg("node %d\n", s->node);
            else
                msg("edge (%d, %d) layout point #%d\n", s->elp.e.src,
                    s->elp.e.dst, s->elp.pidx);
        }
    } break;

    case grcode_creating_group:
        // a group is being created
        // in:  mutable_graph_t *g
        //      intvec_t *nodes
        // out: 0-ok, 1-forbid group creation
        {
            mutable_graph_t *g = va_arg(va, mutable_graph_t *);
            intvec_t &nodes = *va_arg(va, intvec_t *);
            if (GRAPH_DEBUG) {
                msg("%p: creating group", g);
                for (intvec_t::iterator p = nodes.begin(); p != nodes.end();
                     ++p)
                    msg(" %d", *p);
                msg("...\n");
            }
        }
        break;

    case grcode_deleting_group:
        // a group is being deleted
        // in:  mutable_graph_t *g
        //      int old_group
        // out: 0-ok, 1-forbid group deletion
        {
            mutable_graph_t *g = va_arg(va, mutable_graph_t *);
            int group = va_argi(va, int);
            if (GRAPH_DEBUG)
                msg("%p: deleting group %d\n", g, group);
        }
        break;

    case grcode_group_visibility:
        // a group is being collapsed/uncollapsed
        // in:  mutable_graph_t *g
        //      int group
        //      bool expand
        // out: 0-ok, 1-forbid group modification
        {
            mutable_graph_t *g = va_arg(va, mutable_graph_t *);
            int group = va_argi(va, int);
            bool expand = va_argi(va, bool);
            if (GRAPH_DEBUG)
                msg("%p: %scollapsing group %d\n", g, expand ? "un" : "",
                    group);
        }
        break;

    case grcode_gotfocus: // a graph viewer got focus
                          // in:  graph_viewer_t *gv
                          // out: must return 0
    {
        graph_viewer_t *g = va_arg(va, graph_viewer_t *);
        if (GRAPH_DEBUG)
            msg("%p: got focus\n", g);
    } break;

    case grcode_lostfocus: // a graph viewer lost focus
                           // in:  graph_viewer_t *gv
                           // out: must return 0
    {
        graph_viewer_t *g = va_arg(va, graph_viewer_t *);
        if (GRAPH_DEBUG)
            msg("%p: lost focus\n", g);
    } break;

    case grcode_user_refresh: // refresh user-defined graph nodes and edges
                              // in:  mutable_graph_t *g
                              // out: success
    {
        mutable_graph_t *g = va_arg(va, mutable_graph_t *);
        if (GRAPH_DEBUG)
            msg("%p: refresh\n", g);
        /* add all edges to graph */
        if (g->empty())
            g->resize(depNodes.size());
        for (vector<json>::iterator edge = depEdges.begin();
             edge != depEdges.end(); ++edge) {
            json e = *edge;
            g->add_edge(e["from"], e["to"], NULL);
        }
        result = true;
    } break;

    case grcode_user_gentext: // generate text for user-defined graph nodes
                              // in:  mutable_graph_t *g
                              // out: must return 0
    {
        mutable_graph_t *g = va_arg(va, mutable_graph_t *);
        if (GRAPH_DEBUG)
            msg("%p: generate text for graph nodes\n", g);
        ctx.graph_text.resize(g->size());
        for (node_iterator p = g->begin(); p != g->end(); ++p) {
            int n = *p;
            ctx.graph_text[n] = get_node_name(n);
        }
        result = true;
    } break;

    case grcode_user_text: // retrieve text for user-defined graph node
                           // in:  mutable_graph_t *g
                           //      int node
                           //      const char **result
                           //      bgcolor_t *bg_color (maybe NULL)
                           // out: must return 0, result must be filled
                           // NB: do not use anything calling GDI!
    {
        mutable_graph_t *g = va_arg(va, mutable_graph_t *);
        int node = va_arg(va, int);
        const char **text = va_arg(va, const char **);
        bgcolor_t *bgcolor = va_arg(va, bgcolor_t *);
        *text = ctx.graph_text[node].c_str();
        if (bgcolor != NULL)
            *bgcolor = DEFCOLOR;
        result = true;
        qnotused(g);
    } break;

    case grcode_user_size: // calculate node size for user-defined graph
                           // in:  mutable_graph_t *g
                           //      int node
                           //      int *cx
                           //      int *cy
                           // out: 0-did not calculate, ida will use node text
                           // size
                           //      1-calculated. ida will add node title to the
                           //      size
        if (GRAPH_DEBUG)
            msg("calc node size - not implemented\n");
        // ida will calculate the node size based on the node text
        break;

    case grcode_user_title: // render node title of a user-defined graph
                            // in:  mutable_graph_t *g
                            //      int node
                            //      rect_t *title_rect
                            //      int title_bg_color
                            //      HDC dc
                            // out: 0-did not render, ida will fill it with
                            // title_bg_color
                            //      1-rendered node title
        // ida will draw the node title itself
        break;

    case grcode_user_draw: // render node of a user-defined graph
                           // in:  mutable_graph_t *g
                           //      int node
                           //      rect_t *node_rect
                           //      HDC dc
                           // out: 0-not rendered, 1-rendered
                           // NB: draw only on the specified DC and nowhere
                           // else!
        // ida will draw the node text itself
        break;

    case grcode_user_hint: // retrieve hint for the user-defined graph
                           // in:  mutable_graph_t *g
                           //      int mousenode
                           //      int mouseedge_src
                           //      int mouseedge_dst
                           //      char **hint
                           // 'hint' must be allocated by qalloc() or qstrdup()
                           // out: 0-use default hint, 1-use proposed hint
    {
        mutable_graph_t *g = va_arg(va, mutable_graph_t *);
        int mousenode = va_argi(va, int);
        int mouseedge_src = va_argi(va, int);
        int mouseedge_dst = va_argi(va, int);
        char **hint = va_arg(va, char **);
        char buf[MAXSTR];
        buf[0] = '\0';
        if (mousenode != -1)
            /* Hint for node %d */
            qsnprintf(buf, sizeof(buf), "node: %d", mousenode);
        else if (mouseedge_src != -1)
            /* Hovering on (%d,%d) */
            qsnprintf(buf, sizeof(buf), "hovering on: (%d,%d)", mouseedge_src,
                      mouseedge_dst);
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
    if (code == view_close) {
        TWidget *view = va_arg(va, TWidget *);
        if (view == (TWidget *)gv)
            gv = nullptr;
    }
    return 0;
}

//--------------------------------------------------------------------------
static plugmod_t *idaapi init() {
    msg(welcome_msg);
    msg("%s\n\n", COPYRIGHT);
    inited = true;
    if (!is_idaq())
        return nullptr;
    return new plugin_ctx_t;
}

//--------------------------------------------------------------------------
static const char wanted_title[] = "efiXplorer: dependency graph";
bool idaapi plugin_ctx_t::run(size_t) {
    /* analyzer staff start */
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
        /* warning to user */
        warning(
            "%s: analysis may take some time, please wait for it to complete\n",
            plugin_name);
        /* analyzer staff */
        DEBUG_MSG("[%s] input file is UEFI firmware\n", plugin_name);
        efiAnalysis::efiAnalyzerMainX64();
        if (summaryJsonExist()) {
            /* build dependency graph (based on ugraph example from idasdk) */
            /* TODO: move it to separate file */
            depJson = getDependenciesLoader();
            depNodes = getNodes(depJson);
            depEdges = getEdges(depNodes, depJson);
            TWidget *widget = find_widget(wanted_title);
            if (widget != nullptr) {
                close_widget(widget, 0);
            }
            /* get a unique graph id */
            netnode id;
            id.create("$ efiXplorer graph");
            gv = create_graph_viewer(wanted_title, id, gr_callback, this, 0);
            if (gv != nullptr) {
                display_widget(gv, WOPN_DP_TAB);
                viewer_fit_window(gv);
                register_action(change_layout_desc);
                viewer_attach_menu_item(gv, change_layout_desc.name);
            }
        }
        /* clear */
        depJson.clear();
        depNodes.clear();
        depEdges.clear();
    }
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
