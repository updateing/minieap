#ifndef _MINIEAP_MISC_H
#define _MINIEAP_MISC_H

#include <stdint.h>

/*
 * Check if it's free-able, free it, then clear the pointer
 */
void chk_free(void** pptr);

/*
 * Convert 2 ASCII hex bytes to number value
 * "ff" -> 255
 */
uint8_t char2hex(const char* str);
#endif
