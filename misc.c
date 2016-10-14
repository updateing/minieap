#include <malloc.h>
#include <ctype.h>
#include <stdint.h>

void chk_free(void** pptr) {
    if (pptr == NULL || *pptr == NULL)
        return;
        
    free(*pptr);
    *pptr = NULL;
}

uint8_t char2hex(const char* str) {
    const char digit0 = tolower(str[0]);
    const char digit1 = tolower(str[1]);
    
    if (digit1 == 0) {
        return digit0 >= 'a' ? 10 + (digit0 - 'a') : digit0 - '0';
    }
    
    return 16 * (digit0 >= 'a' ? 10 + (digit0 - 'a') : digit0 - '0') +
            digit1 >= 'a' ? 10 + (digit1 - 'a') : digit1 - '0';
}
