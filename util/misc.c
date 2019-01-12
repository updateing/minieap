#include <stdlib.h>
#include <ctype.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <getopt.h>

#include "linkedlist.h"
#include "logging.h"
#include "minieap_common.h"

// From cmdline
#ifdef ENABLE_ICONV
#include <iconv.h>
#elif ENABLE_GBCONV
#include "gbconv.h"
#endif

void chk_free(void** pptr) {
    if (pptr == NULL || *pptr == NULL)
        return;

    free(*pptr);
    *pptr = NULL;
}

uint8_t char2hex(const char* str) {
#define LOWER2HEX(digit) (((digit) >= 'a') ? (10 + ((digit) - 'a')) : ((digit) - '0'))
    const char digit0 = tolower(str[0]);
    const char digit1 = tolower(str[1]);

    if (digit1 == 0) {
        return LOWER2HEX(digit0);
    }

    return 16 * LOWER2HEX(digit0) + LOWER2HEX(digit1);
}

void hex2char(uint8_t hex, char* out) {
#define HEX2LOWER(digit) (((digit) >= 0xa) ? ((digit) - 0xa + 'a') : ((digit) + '0'))
    out[0] = HEX2LOWER((hex & 0xf0) >> 4);
    out[1] = HEX2LOWER(hex & 0xf);
}

char* my_itoa(int val, char* buf, uint32_t radix) {
    if (val < 0) {
        buf[0] = '-';
        val = -val; /* For easier dividing */
    }

    char* curr_pos = buf;
    do { /* Fill it in reversed order */
        *curr_pos++ = HEX2LOWER(val % radix);
        val /= radix;
    } while (val > 0);

    *curr_pos-- = 0;

    char tmp;
    char* rev_pos = buf;
    while (rev_pos < curr_pos) { /* Reverse the buffer to get normal order */
        tmp = *curr_pos;
        *curr_pos-- = *rev_pos;
        *rev_pos++ = tmp;
    };

    return buf;
}

int shortopt2longindex(int opt, const struct option* longopts, int array_len) {
    int index;
    for (index = 0; index < array_len; index++) {
        if (longopts[index].val == opt) {
            return index;
        }
    }
    return -1;
}

uint8_t bit_reverse(uint8_t in) {
    static const uint8_t half_reverse_table[] = {
        0x0, 0x8, 0x4, 0xc, 0x2, 0xa, 0x6, 0xe,
        0x1, 0x9, 0x5, 0xd, 0x3, 0xb, 0x7, 0xf
    };

    return half_reverse_table[in & 0xf] << 4 | half_reverse_table[(in & 0xf0) >> 4];
}

void gbk2utf8(char* in, size_t inlen, char* out, size_t outlen) {
#ifdef ENABLE_ICONV
    iconv_t _cd = iconv_open("utf-8", "gbk");
    if (_cd == NULL) {
        PR_WARN("无法从 iconv 获取编码描述符，服务器消息可能会出现乱码");
        memmove(out, in, inlen);
    } else {
        iconv(_cd, &in, &inlen, &out, &outlen);
        iconv_close(_cd);
    }
#elif defined(ENABLE_GBCONV)
    gbconv8(in, inlen, out, outlen);
#else
    memmove(out, in, inlen);
#endif
}

void pr_info_gbk(char* in, size_t inlen) {
    size_t _utf8_size = inlen << 2;
    char* _utf8_buf = (char*)malloc(_utf8_size);
    memset(_utf8_buf, 0, _utf8_size);
    if (_utf8_buf != NULL) {
        gbk2utf8(in, inlen, _utf8_buf, _utf8_size);
        PR_INFO("%s", _utf8_buf);
        free(_utf8_buf);
    } else {
        _utf8_buf = in;
        PR_INFO("%s", _utf8_buf);
    }
}

RESULT go_background() {
    pid_t pid;

    pid = fork();
    if (pid < 0)
        return FAILURE;
    if (pid > 0)
        _exit(0); /* Do not call exit_handler() */

   if (setsid() < 0)
      return FAILURE;
   return SUCCESS;
}

char** strarraydup(int count, char* array[]) {
    if (array == 0) return NULL;

    char** _ret = (char**)malloc(count * sizeof(char*));
    if (_ret == NULL) {
        PR_ERR("无法为命令行选项创建缓冲区");
        return NULL;
    }

    int _curr_seq = 0;
    for (;_curr_seq < count; _curr_seq++) {
        _ret[_curr_seq] = array[_curr_seq] ? strdup(array[_curr_seq]) : NULL;
    }
    return _ret;
}

void strarrayfree(int count, char* array[]) {
    if (array == 0) return;

    int _curr_seq = 0;
    for (;_curr_seq < count; _curr_seq++) {
        free(array[_curr_seq]);
    }
}

void strarrayprint(int count, char* array[]) {
    if (array == 0) return;

    int _curr_seq = 0;
    for (;_curr_seq < count; _curr_seq++) {
        PR_DBG("Element %d: %s", _curr_seq, array[_curr_seq]);
    }
}

void* memdup(const void* src, int n) {
    if (n <= 0) {
        // Make sure this is consistent
        return NULL;
    }

    void* ret = malloc(n);

    if (ret == NULL) {
        // Suggest this is an error.
        return NULL;
    }

    memmove(ret, src, n);
    return ret;
}
