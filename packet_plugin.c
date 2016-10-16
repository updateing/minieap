#include "linkedlist.h"
#include "packet_plugin.h"
#include "logging.h"

#include <string.h>
#include <malloc.h>

#define TRUE 1
#define FALSE 0

typedef struct _packet_plugin_info {
    PACKET_PLUGIN* plugin;
    int active;
} PACKET_PLUGIN_INFO;

/* content of this list is PACKET_PLUGIN_INFO* */
static LIST_ELEMENT* g_packet_plugin_info_list;

PACKET_PLUGIN* packet_plugin_rjv3_new();

int init_packet_plugin_info_list() {
    PACKET_PLUGIN* (*list[])() = {
//#include "packet_pluginl_list_gen.h" TODO autogen
        packet_plugin_rjv3_new
    };
    int i = 0;
    for (; i < sizeof(list) / sizeof(PACKET_PLUGIN*); ++i) {
        PACKET_PLUGIN_INFO* _info = (PACKET_PLUGIN_INFO*)malloc(sizeof(PACKET_PLUGIN_INFO));
        if (_info < 0) {
            PR_ERRNO("无法为插件分配内存");
            return -1;
        }
        PACKET_PLUGIN* (*func)() = list[i];
        _info->plugin = func();
        _info->active = FALSE;
        insert_data(&g_packet_plugin_info_list, _info);
    }
    return i;
}

static int plugin_name_cmp(void* to_find, void* curr) {
    return memcmp(to_find, ((PACKET_PLUGIN_INFO*)curr)->plugin->name, strlen(curr));
}

RESULT select_packet_plugin(const char* name) {
    PACKET_PLUGIN_INFO* _info;
    _info = (PACKET_PLUGIN_INFO*)lookup_data(g_packet_plugin_info_list, (void*)name, plugin_name_cmp);
    if (_info != NULL) {
        _info->active = TRUE;
        return SUCCESS;
    }
    return FAILURE;
}

/* 
 * I know this is silly, but is there better way to do it
 * since list_traverse takes none extra parameters?
 * Even if it takes user-defined extra params, I'd make
 * lots of useless structs to pass variable number of actual params...
 */
#define PLUGIN_INFO ((PACKET_PLUGIN_INFO*)plugin_info)
#define PLUGIN (PLUGIN_INFO->plugin)
void packet_plugin_destroy() {
    LIST_ELEMENT *plugin_info = g_packet_plugin_info_list;
    do {
        if (PLUGIN_INFO->active) {
            PLUGIN->destroy(PLUGIN);
        }
    } while ((plugin_info = plugin_info->next));
}

void packet_plugin_process_cmdline_opts(int argc, char* argv[]) {
    LIST_ELEMENT *plugin_info = g_packet_plugin_info_list;
    do {
        if (PLUGIN_INFO->active) {
            PLUGIN->process_cmdline_opts(PLUGIN, argc, argv);
        }
    } while ((plugin_info = plugin_info->next));
}

void packet_plugin_print_cmdline_help() {
    LIST_ELEMENT *plugin_info = g_packet_plugin_info_list;
    do {
        if (PLUGIN_INFO->active) {
            PLUGIN->print_cmdline_help(PLUGIN);
        }
    } while ((plugin_info = plugin_info->next));
}

void packet_plugin_prepare_frame(ETH_EAP_FRAME* frame) {
    LIST_ELEMENT *plugin_info = g_packet_plugin_info_list;
    do {
        if (PLUGIN_INFO->active) {
            PLUGIN->prepare_frame(PLUGIN, frame);
        }
    } while ((plugin_info = plugin_info->next));
}

void packet_plugin_on_frame_received(ETH_EAP_FRAME* frame) {
    LIST_ELEMENT *plugin_info = g_packet_plugin_info_list;
    do {
        if (PLUGIN_INFO->active) {
            PLUGIN->on_frame_received(PLUGIN, frame);
        }
    } while ((plugin_info = plugin_info->next));
}

void packet_plugin_set_auth_round(int round) {
    LIST_ELEMENT *plugin_info = g_packet_plugin_info_list;
    do {
        if (PLUGIN_INFO->active) {
            PLUGIN->set_auth_round(PLUGIN, round);
        }
    } while ((plugin_info = plugin_info->next));
}
