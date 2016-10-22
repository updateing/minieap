#ifndef _MINIEAP_PACKET_PLUGIN_RJV3_PROP_H
#define _MINIEAP_PACKET_PLUGIN_RJV3_PROP_H

#include "packet_plugin_rjv3_priv.h"
#include "linkedlist.h"
#include "minieap_common.h"

#include <stdint.h>

#define MAX_PROP_LEN 200 // Assumed

/*
 * CRUD methods for lists
 *
 * All `header_type` can be set to 0xFF to ignore, except `insert_rjv3_prop`.
 *
 * All `int` returning value means how many bytes the prop consists of.
 */

/*
 * `append_rjv3_prop` does not check if there is an existing field with same type/header_type,
 * thus may lead to duplicated entries.
 *
 * `append_rjv3_prop` will create a new buffer of content. This buffer should be freed
 * by destroying the list.
 *
 * `modify_rjv3_prop[_list]` returns the difference in sizes of the field (new - old)
 *
 * All these methods assume header_type == 0x1a
 */
int append_rjv3_prop(LIST_ELEMENT** list, uint8_t type, uint8_t* content, int len);
int modify_rjv3_prop(LIST_ELEMENT* list, uint8_t type, uint8_t* content, int len);
int modify_rjv3_prop_list(LIST_ELEMENT* org, LIST_ELEMENT* mods);
void remove_rjv3_prop(LIST_ELEMENT** list, uint8_t type);

/*
 * Find prop by type
 *
 * NULL if not found
 */
RJ_PROP* find_rjv3_prop(LIST_ELEMENT* list, uint8_t type);
/*
 * Default header_type = 0x1a
 */
RJ_PROP* new_rjv3_prop();

/*
 * Appending
 *
 * `append_rjv3_prop_[list_]to_buffer` returns the number of actual bytes written
 * `append_rjv3_prop_to_frame` can be used in list_traverse so it has two void* params.
 */
int append_rjv3_prop_to_buffer(RJ_PROP* prop, uint8_t* buf, int buflen);
int append_rjv3_prop_list_to_buffer(LIST_ELEMENT* list, uint8_t* buf, int buflen);
void append_rjv3_prop_to_frame(RJ_PROP* prop, ETH_EAP_FRAME* frame);
void destroy_rjv3_prop_list(LIST_ELEMENT** list);

/*
 * Read all props in buffer and form a list of the props.
 *
 * Make sure buf starts with xx xx 00 00 13 11 (normal) or 00 00 13 11 (bare)
 */
RESULT parse_rjv3_buf_to_prop_list(LIST_ELEMENT** list, uint8_t* buf, int buflen, int bare);
#endif
