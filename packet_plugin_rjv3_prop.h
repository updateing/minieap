#ifndef _MINIEAP_PACKET_PLUGIN_RJV3_PROP_H
#define _MINIEAP_PACKET_PLUGIN_RJV3_PROP_H

#include "packet_plugin_rjv3_priv.h"
#include <stdint.h>

/*
 * CRUD methods
 *
 * All `header_type` can be set to 0xFF to ignore, except `insert_rjv3_prop`.
 *
 * All `int` returning value means how many bytes the prop consists of.
 */

/*
 * `insert_rjv3_prop` does not check if there is an existing field with same type/header_type,
 * thus may lead to duplicated entries.
 */
int append_rjv3_prop(LIST_ELEMENT** list, uint8_t type, uint8_t* content, int len);
int modify_rjv3_prop(LIST_ELEMENT* list, uint8_t type, uint8_t* content, int len);
void remove_rjv3_prop(LIST_ELEMENT* list, uint8_t type);

/*
 * Find prop by type
 *
 * NULL if not found
 */
RJ_PROP* find_rjv3_prop(LIST_ELEMENT* list, uint8_t type);
RJ_PROP* new_rjv3_prop();
#endif
