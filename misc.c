#include <malloc.h>
#include <ctype.h>
#include <stdint.h>
#include "linkedlist.h"

void chk_free(void** pptr) {
    if (pptr == NULL || *pptr == NULL)
        return;

    free(*pptr);
    *pptr = NULL;
}

uint8_t char2hex(const char* str) {
#define LOWER2HEX(digit) ((digit >= 'a') ? (10 + (digit - 'a')) : (digit - '0'))
    const char digit0 = tolower(str[0]);
    const char digit1 = tolower(str[1]);

    if (digit1 == 0) {
        return LOWER2HEX(digit0);
    }

    return 16 * LOWER2HEX(digit0) + LOWER2HEX(digit1);
}

/* List implementation should not care about the content */
void free_list_with_content(LIST_ELEMENT** list_ref) {
    while (*list_ref) {
        free((*list_ref)->content);
        list_ref = &(*list_ref)->next;
        chk_free((void**)list_ref);
    }
}
