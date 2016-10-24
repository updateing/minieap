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
 * Duplicate a frame and its content
 */
ETH_EAP_FRAME* frame_duplicate(const ETH_EAP_FRAME* frame);

/*
 * Free a frame created by frame_duplicate
 */
void free_frame(ETH_EAP_FRAME** frame);

/*
 * Stringify
 */
char* str_eapol_type(EAPOL_TYPE type);
#endif
