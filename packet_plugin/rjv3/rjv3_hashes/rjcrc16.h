/* crc16.h */
#ifndef CRC16_HIDER
#define CRC16_HIDER
#include "ustd.h"

#ifdef __cplusplus
extern "C" {
#endif

/* hash functions */

uint16_t crc16(const uint8_t *buf, int len);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* CRC16_HIDER */
