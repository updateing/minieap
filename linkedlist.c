#include "linkedlist.h"
#include "misc.h"
#include <malloc.h>
#include <string.h>

/* Rather naive! */
static LIST_ELEMENT* find_last_node(LIST_ELEMENT* start) {
    if (start == NULL) return NULL;
    LIST_ELEMENT* node = start;
    while (node->next != NULL && (node = node->next)){};
    return node;
}

static void insert_node(LIST_ELEMENT** start, LIST_ELEMENT* new_node) {
    if (*start == NULL) {
        *start = new_node;
    } else {
        LIST_ELEMENT* last = find_last_node(*start);
        last->next = new_node;
    }
}

void insert_data(LIST_ELEMENT** start, void* data) {
    LIST_ELEMENT* new_node = (LIST_ELEMENT*)malloc(sizeof(LIST_ELEMENT));
    new_node->next = NULL;
    new_node->content = data;
    insert_node(start, new_node);
}

/* cmpfunc should return 0 if match */
void* lookup_data(LIST_ELEMENT* start, void* elem_to_find, int(*cmpfunc)(void*, void*)) {
    if (start == NULL) return NULL;
    LIST_ELEMENT* node = start;
    do {
        if (cmpfunc(elem_to_find, node->content) == 0) {
            return node->content;
        }
    } while ((node = node->next));
    return NULL;
}

void list_traverse(LIST_ELEMENT* start, void(*func)(void*, void*), void* user) {
    if (start == NULL) return;
    LIST_ELEMENT* node = start;
    do {
        func(node->content, user);
    } while ((node = node->next));
}

void list_destroy(LIST_ELEMENT** ref, int free_content) {
    LIST_ELEMENT* curr = NULL, *next = *ref;
    while ((curr = next)) {
        next = curr->next;
        if (free_content) {
            free(curr->content);
        }
        free(curr);
    }
    *ref = NULL;
}

void remove_data(LIST_ELEMENT** start, void* elem_to_remove, int(*cmpfunc)(void*, void*), int free_content) {
    LIST_ELEMENT *curr = NULL, **curr_ref = start;
    if (curr_ref == NULL) return;

    while ((curr = *curr_ref)) {
        if (cmpfunc(elem_to_remove, curr->content) == 0) {
            *curr_ref = curr->next;
            if (free_content) {
                free(curr->content);
            }
            free(curr);
            return;
        }
        curr_ref = &curr->next;
    }
}
