#ifndef _MINIEAP_LINKEDLIST_H
#define _MINIEAP_LINKEDLIST_H

typedef struct _element {
    struct _element* next;
    void* content;
} list_element;

void insert_data(list_element** start, void* data);
void* lookup_data(list_element* start, void* elem_to_find, int(*cmpfunc)(void*, void*));
#endif
