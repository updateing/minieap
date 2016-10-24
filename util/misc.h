#ifndef _MINIEAP_MISC_H
#define _MINIEAP_MISC_H

#include "minieap_common.h"
#include <stdint.h>
#include <sys/types.h>

/*
 * Check if it's free-able, free it, then clear the pointer
 */
void chk_free(void** pptr);

/*
 * Convert 2 ASCII hex bytes to number value
 * "ff" -> 255
 */
uint8_t char2hex(const char* str);

/* 10110001b -> 10001101b */
uint8_t bit_reverse(uint8_t in);

void gbk2utf8(char* out, char* in, size_t len);
void pr_info_gbk(char* in, size_t inlen);

/*
 * Similar to daemon() but simpler.
 * Could avoid uclibc's daemon() bug, which causes hang
 * on pthread_create() later.
 */
RESULT go_background();
#endif
