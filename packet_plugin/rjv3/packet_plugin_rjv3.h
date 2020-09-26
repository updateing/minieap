#ifndef _MINIEAP_PACKET_PLUGIN_RJV3_H
#define _MINIEAP_PACKET_PLUGIN_RJV3_H

#include "packet_plugin.h"

#define PACKET_PLUGIN_RJV3_VER_STR  "0.93"

#define DEFAULT_HEARTBEAT_INTERVAL  60
#define DEFAULT_MAX_DHCP_COUNT      3
#define DEFAULT_SERVICE_NAME        "internet"
#define DEFAULT_VER_STR             "RG-SU For Linux V1.0"
#define DEFAULT_DHCP_SCRIPT         ""
#define DEFAULT_EAP_BCAST_ADDR      BROADCAST_STANDARD
#define DEFAULT_DHCP_TYPE           DHCP_AFTER_AUTH

PACKET_PLUGIN* packet_plugin_rjv3_new();
#endif
