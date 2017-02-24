#ifndef _MINIEAP_MISC_H
#define _MINIEAP_MISC_H

#include "minieap_common.h"
#include <stdint.h>
#include <sys/types.h>
#include <getopt.h>

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

/*
 * Some platform does not provide itoa
 */
char* my_itoa(int val, char* buf, uint32_t radix);

/*
 * Find index of long option corresponding to short option in the array.
 * Requires the `val` fields in `longopts` are set to the char of short option.
 * If found, the index of long option will be returned. Otherwise, it returns -1.
 */
int shortopt2longindex(int opt, const struct option* longopts, int array_len);

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

/*
 * Similar to strndup but without trailing 0
 */
void* memdup(const void* src, int n);
#endif
