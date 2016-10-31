#include <stdlib.h>
#include <ctype.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include "linkedlist.h"
#include "logging.h"
#include "minieap_common.h"

// From cmdline
#ifdef ENABLE_ICONV
#include <iconv.h>
#endif

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
        0x0, 0x8, 0x4, 0xc, 0x2, 0xa, 0x6, 0xe,
        0x1, 0x9, 0x5, 0xd, 0x3, 0xb, 0x7, 0xf
    };

    return half_reverse_table[in & 0xf] << 4 | half_reverse_table[(in & 0xf0) >> 4];
}

void gbk2utf8(char* in, size_t inlen, char* out, size_t outlen) {
#if defined(_ICONV_H) || defined(_LIBICONV_H)
    iconv_t _cd = iconv_open("utf-8", "gbk");
    if (_cd < 0) {
        PR_WARN("无法从 iconv 获取编码描述符，服务器消息可能会出现乱码");
        goto legacy;
    } else {
        iconv(_cd, &in, &inlen, &out, &outlen);
        iconv_close(_cd);
        return;
    }
legacy:
#endif
    memmove(out, in, inlen);
}

void pr_info_gbk(char* in, size_t inlen) {
    size_t _utf8_size = inlen << 2;
    char* _utf8_buf = (char*)malloc(_utf8_size);
    memset(_utf8_buf, 0, _utf8_size);
    if (_utf8_buf > 0) {
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
