#ifndef _MINIEAP_PACKET_PLUGIN_RJV3_KEEPALIVE_H
#define _MINIEAP_PACKET_PLUGIN_RJV3_KEEPALIVE_H

#include <stdint.h>

void rjv3_set_keepalive_echokey(uint32_t key);
void rjv3_set_keepalive_echono(uint32_t no);
void rjv3_set_keepalive_dest_mac(uint8_t* mac);
void rjv3_keepalive_reset();

RESULT rjv3_send_new_keepalive_frame(struct _packet_plugin* this);
void rjv3_send_keepalive_timed(void* vthis);
#endif
