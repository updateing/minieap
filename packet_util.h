#ifndef _MINIEAP_PACKET_UTIL_H
#define _MINIEAP_PACKET_UTIL_H

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
int append_to_frame(ETH_EAP_FRAME* frame, uint8_t* data, int len);

/*
 * Stringify
 */
char* str_eapol_type(EAPOL_TYPE type);
#endif
