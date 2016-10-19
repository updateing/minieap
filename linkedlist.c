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

void list_destroy(LIST_ELEMENT** start) {
    LIST_ELEMENT *curr, *next = *start;
    while ((curr = next)) {
        next = curr->next;
        free(curr);
    }
    *start = NULL;
}

void remove_data(LIST_ELEMENT** start, void* elem_to_remove, int(*cmpfunc)(void*, void*)) {
    LIST_ELEMENT *curr = NULL, *last = NULL;
    if (start == NULL) return;
    
    curr = *start;
    do {
        if (cmpfunc(curr, elem_to_remove) == 0) {
            if (last) {
                last->next = curr->next;
            } else {
                /* This means the 1st item is to be removed.
                 * We can not use **curr and chk_free (no this else branch) here, since
                 * **curr will hold reference to last->next, zeroing it will destory the
                 * last node.
                 * Thus, only zero out the reference to current node when the node is the
                 * first one.
                 */
                *start = NULL;
            }
            free(curr)
            return;
        }
        last = curr;
    } while ((curr = curr->next));
}

