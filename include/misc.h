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

/*
 * Convert one byte to its ASCII hex representation.
 * 0xff -> "ff", written directly to `out`
 */
void hex2char(uint8_t hex, char* out);

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

/*
 * Duplicate/Free/Print string array
 */
char** strarraydup(int count, char* array[]);
void strarrayfree(int count, char* array[]);
void strarrayprint(int count, char* array[]);
#endif
