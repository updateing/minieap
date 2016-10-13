#include "linkedlist.h"
#include "if_impl.h"
#include <string.h>

/* content of this list is if_impl* */
static list_element* g_if_impl_list;

if_impl* sockraw_new();

int init_if_impl_list() {
    if_impl* (*list[])() = {
//#include "if_impl_list_gen.h" TODO autogen
        sockraw_new
    };
    int i = 0;
    for (; i < sizeof(list) / sizeof(if_impl*); ++i) {
        if_impl* (*func)() = list[i];
        insert_data(&g_if_impl_list, (*func)());
    }
    return i;
}

static int impl_name_cmp(void* to_find, void* curr) {
    return memcmp(to_find, ((if_impl*)curr)->name, strlen(curr));
}

if_impl* find_if_impl_by_name(const char* name) {
    return (if_impl*)lookup_data(g_if_impl_list, (void*)name, impl_name_cmp);
}

