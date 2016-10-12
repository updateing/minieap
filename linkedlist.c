#include "linkedlist.h"
#include <malloc.h>
#include <string.h>

/* Rather naive! */
static list_element* find_last_node(list_element* start) {
    if (start == NULL) return NULL;
    list_element* node = start;
    while (node->next != NULL && (node = node->next)){};
    return node;
}

static void insert_node(list_element** start, list_element* new_node) {
    if (*start == NULL) {
        *start = new_node;
    } else {
        list_element* last = find_last_node(*start);
        last->next = new_node;
    }
}

void insert_data(list_element** start, void* data) {
    list_element* new_node = (list_element*)malloc(sizeof(list_element));
    new_node->next = NULL;
    new_node->content = data;
    insert_node(start, new_node);
}

/* cmpfunc should return 0 if match */
void* lookup_data(list_element* start, void* elem_to_find, int(*cmpfunc)(void*, void*)) {
    if (start == NULL) return NULL;
    list_element* node = start;
    do {
        if (cmpfunc(elem_to_find, node->content) == 0) {
            return node->content;
        }
    } while ((node = node->next));
    return NULL;
}

void traverse_list(list_element* start, void(*func)(void*)) {
    if (start == NULL) return;
    list_element* node = start;
    do {
        func(node->content);
    } while ((node = node->next));
}
