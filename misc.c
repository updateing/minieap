#include <malloc.h>

void chk_free(void** pptr) {
    if (pptr == NULL || *pptr == NULL)
        return;
        
    free(*pptr);
    *pptr = NULL;
}
