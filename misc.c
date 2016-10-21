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

uint8_t bit_reverse(uint8_t in) {
    static const uint8_t half_reverse_table[] = {
        0x0, 0x8, 0x4, 0xc, 0x2, 0xa, 0x6, 0x3,
        0x1, 0x9, 0x5, 0xd, 0x3, 0xb, 0x7, 0xf
    };

    return half_reverse_table[in & 0xf] << 4 | half_reverse_table[(in & 0xf0) >> 4];
}
