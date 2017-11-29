/* rjencode.h */
#ifndef RJENCODE_HIDER
#define RJENCODE_HIDER
#include "ustd.h"

#ifdef __cplusplus
extern "C" {
#endif

/* encode functions */

void rj_encode(uint8_t *buf, int len);
void rj_decode(uint8_t *buf, int len);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* RJENCODE_HIDER */
