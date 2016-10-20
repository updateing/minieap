#ifndef _MINIEAP_PACKET_UTIL_H
#define _MINIEAP_PACKET_UTIL_H

#include "minieap_common.h"
#include "eth_frame.h"
#include <stdint.h>

/*
 * These functions do not require a "context"
 */

/*
 * Append content to a frame
 *
 * Return: if the operation was successful
 */
RESULT append_to_frame(ETH_EAP_FRAME* frame, const uint8_t* data, int len);

/*
 * Stringify
 */
char* str_eapol_type(EAPOL_TYPE type);
#endif
