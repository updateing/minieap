#ifndef _MINIEAP_LINKEDLIST_H
#define _MINIEAP_LINKEDLIST_H

typedef struct _element {
    struct _element* next;
    void* content;
} LIST_ELEMENT;

/*
 * Insert data to the list. If the list which the reference points to (**) does not exist, create one
 * and update the reference.
 */
void insert_data(LIST_ELEMENT** start, void* data);

/*
 * elem_to_find is a pointer to the actual data
 * Prototype of cmpfunc: int cmpfunc(void* elem_to_find, void* node_content);
 * cmpfunc returns 0 for equalvity, others for non-
 */
void* lookup_data(LIST_ELEMENT* start, void* elem_to_find, int(*cmpfunc)(void*, void*));

/*
 * Remove all nodes matching specific data using custom compartor, zeroing its reference
 */
void remove_data(LIST_ELEMENT** start, void* elem_to_remove, int(*cmpfunc)(void*, void*), int free_content);

/*
 * user pointer is passed to func directly, for private use
 * Prototype of func: void func(void* current_data, void* user);
 */
void list_traverse(LIST_ELEMENT* start, void(*func)(void*, void*), void* user);

/*
 * Destroy a list, freeing all the memory all nodes take up, zeroing its reference
 */
void list_destroy(LIST_ELEMENT** start, int free_content);

/*
 * Concatenate two lists. This will NOT duplicate the nodes in second list.
 * So make sure they are always available.
 */
void list_concat(LIST_ELEMENT** org_list, LIST_ELEMENT* new_list);
#endif
