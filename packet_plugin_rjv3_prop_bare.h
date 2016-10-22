#ifndef _MINIEAP_PACKET_PLUGIN_RJV3_PROP_BARE
#define _MINIEAP_PACKET_PLUGIN_RJV3_PROP_BARE

/*
 * Bare props: props without RJ_PROP_HEADER1
 *
 * In order to re-use code from packet_plugin_rjv3,
 * we initialize RJ_PROP_HEADER1 as {0xba, 0xfe}.
 */
#define IS_BARE_PROP(ptr) (ptr->header1.header_type == 0xba && ptr->header1.header_len == 0xfe)

#endif _MINIEAP_PACKET_PLUGIN_RJV3_PROP_BARE
