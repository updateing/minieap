#include "linkedlist.h"
#include "minieap_common.h"
#include "packet_plugin_rjv3_priv.h"
#include "misc.h"
#include "logging.h"
#include "eth_frame.h"
#include "packet_util.h"

#include <stdint.h>
#include <malloc.h>
#include <limits.h>

RJ_PROP* new_rjv3_prop() {
    RJ_PROP* _prop = (RJ_PROP*)malloc(sizeof(RJ_PROP));
    if (_prop < 0) {
        PR_ERRNO("RJv3 字段结构内存分配失败");
        return NULL;
    }

    /* REAL MAGIC! */
    _prop->header1.header_type = 0x1a;
    _prop->header2.magic[0] = 0x00;
    _prop->header2.magic[1] = 0x00;
    _prop->header2.magic[2] = 0x13;
    _prop->header2.magic[3] = 0x11;
    return _prop;
}

int append_rjv3_prop(LIST_ELEMENT** list, uint8_t type, uint8_t* content, int len) {
    RJ_PROP* _prop = new_rjv3_prop();
    if (_prop == NULL) return -1;

    uint8_t* buf;
    if (len > 0) {
        buf = (uint8_t*)malloc(len);
        if (buf < 0) {
            free(_prop);
            return -1;
        }
        memmove(buf, content, len);
    } else {
        buf = NULL;
    }

    _prop->header1.header_len = len + sizeof(RJ_PROP_HEADER1) + sizeof(RJ_PROP_HEADER2);
    _prop->header2.type = type;
    _prop->header2.len = len + sizeof(RJ_PROP_HEADER2) - sizeof(_prop->header2.magic);
    _prop->content = buf;
    insert_data(list, _prop);
    return _prop->header1.header_len;
}

/* Risky. Normally to_match and src should be the same type. */
static int rjv3_type_prop_compare(void* to_match, void* src) {
    if (((RJ_PROP*)src)->header2.type == *(uint8_t*)to_match)
        return 0;
    return 1;
}

int modify_rjv3_prop(LIST_ELEMENT* list, uint8_t type, uint8_t* content, int len) {
    RJ_PROP* _prop = (RJ_PROP*)lookup_data(list, &type, rjv3_type_prop_compare);
    if (_prop == NULL) return 0; // Nothing modified

    int _org_header2_len = _prop->header2.len;
    chk_free((void**)&_prop->content);
    _prop->content = content;
    _prop->header2.len = len + sizeof(RJ_PROP_HEADER2) - sizeof(_prop->header2.magic);
    _prop->header1.header_len = len + sizeof(RJ_PROP_HEADER1) + sizeof(RJ_PROP_HEADER2);
    return _prop->header2.len - _org_header2_len;
}

int modify_rjv3_prop_list(LIST_ELEMENT* org, LIST_ELEMENT* mods) {
    LIST_ELEMENT* _curr;
    int _delta = 0;
    for (_curr = mods; _curr; _curr = _curr->next) {
#define CURR ((RJ_PROP*)_curr->content)
        _delta += modify_rjv3_prop(org,
                                  CURR->header2.type,
                                  CURR->content,
                                  CURR->header2.len - sizeof(RJ_PROP_HEADER2)
                                                    + sizeof(CURR->header2.magic));
    }
    return _delta;
}

void remove_rjv3_prop(LIST_ELEMENT** list, uint8_t type) {
    remove_data(list, &type, rjv3_type_prop_compare, TRUE);
}

int append_rjv3_prop_to_buffer(RJ_PROP* prop, uint8_t* buf, int buflen) {
    int _content_len = prop->header2.len - sizeof(RJ_PROP_HEADER2) + sizeof(prop->header2.magic);
    int _full_len = sizeof(RJ_PROP_HEADER1)+ sizeof(RJ_PROP_HEADER2) + _content_len;

    if (buflen < _full_len) {
        PR_ERR("缓冲空间不足，无法追加字段");
        return -1;
    }

    if (prop->header1.header_type != 0x1a) {
        PR_WARN("不支持写入 header_type 为 %zu 的字段", prop->header1.header_type);
        return 0;
    }
    memmove(buf, &prop->header1, sizeof(RJ_PROP_HEADER1));
    memmove(buf + sizeof(RJ_PROP_HEADER1), &prop->header2, sizeof(RJ_PROP_HEADER2));
    memmove(buf + sizeof(RJ_PROP_HEADER1) + sizeof(RJ_PROP_HEADER2),
                prop->content, _content_len);
    return _full_len;
}

int append_rjv3_prop_list_to_buffer(LIST_ELEMENT* list, uint8_t* buf, int buflen) {
    size_t _props_len = 0, _single_len = 0;
    LIST_ELEMENT* _curr;

    for (_curr = list; _curr; _curr = _curr->next) {
        _single_len = append_rjv3_prop_to_buffer((RJ_PROP*)_curr->content,
                                                 buf + _props_len,
                                                 buflen - _props_len);
        if (_single_len > 0) {
            _props_len += _single_len;
        } else {
            return -1;
        }
    }

    return _props_len;
}

/* This one utilizes packet_util, thus no need to mess with pointer arithmetics */
void append_rjv3_prop_to_frame(RJ_PROP* prop, ETH_EAP_FRAME* frame) {
    int _content_len = 0;
    if (prop->header1.header_type == 0x1a) {
        _content_len = prop->header2.len - sizeof(RJ_PROP_HEADER2) + sizeof(prop->header2.magic);
    } else if (prop->header1.header_type == 0x02) {
        /* Container prop, see `rjv3_prepare_frame` */
        _content_len = prop->header2.len + (prop->header2.type << 8);
    } else {
        PR_WARN("不支持写入 header_type 为 %zu 的字段", prop->header1.header_type);
        return;
    }

    append_to_frame(frame, (uint8_t*)&prop->header1, sizeof(RJ_PROP_HEADER1));
    append_to_frame(frame, (uint8_t*)&prop->header2, sizeof(RJ_PROP_HEADER2));
    append_to_frame(frame, prop->content, _content_len);
}

