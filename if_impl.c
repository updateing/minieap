#include "linkedlist.h"
#include "if_impl.h"
#include "logging.h"
#include <string.h>

/* content of this list is IF_IMPL* */
static LIST_ELEMENT* g_if_impl_list;
static IF_IMPL* g_selected_impl;

IF_IMPL* sockraw_new();

int init_if_impl_list() {
    IF_IMPL* (*list[])() = {
//#include "if_impl_list_gen.h" TODO autogen
        sockraw_new
    };
    int i = 0;
    for (; i < sizeof(list) / sizeof(IF_IMPL*); ++i) {
        IF_IMPL* (*func)() = list[i];
        insert_data(&g_if_impl_list, (*func)());
    }
    return i;
}

static int impl_name_cmp(void* to_find, void* curr) {
    return memcmp(to_find, ((IF_IMPL*)curr)->name, strlen(to_find));
}

RESULT select_if_impl(const char* name) {
    g_selected_impl = (IF_IMPL*)lookup_data(g_if_impl_list, (void*)name, impl_name_cmp);
    return g_selected_impl == NULL ? FAILURE : SUCCESS;
}

IF_IMPL* get_if_impl() { return g_selected_impl; }

static void free_one_impl(void* impl, void* unused) {
    ((IF_IMPL*)impl)->destroy((IF_IMPL*)impl);
}

void free_if_impl() {
    list_traverse(g_if_impl_list, free_one_impl, NULL);
    list_destroy(&g_if_impl_list, FALSE);
}
