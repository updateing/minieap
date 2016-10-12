#include "linkedlist.h"
#include "if_plugin.h"
#include <string.h>

/* content of this list is if_plugin* */
static list_element* g_if_plugin_list;

if_plugin* sockraw_new();

void init_if_plugin_list() {
    if_plugin* (*list[])() = {
//#include "if_plugin_list_gen.h"
        sockraw_new
    };
    int i = 0;
    for (; i < sizeof(list) / sizeof(if_plugin*); ++i) {
        if_plugin* (*func)() = list[i];
        insert_data(&g_if_plugin_list, (*func)());
    }
}

static int plugin_name_cmp(void* to_find, void* curr) {
    return memcmp(to_find, ((if_plugin*)curr)->name, strlen(curr));
}

if_plugin* find_if_plugin_by_name(const char* name) {
    return (if_plugin*)lookup_data(g_if_plugin_list, (void*)name, plugin_name_cmp);
}

