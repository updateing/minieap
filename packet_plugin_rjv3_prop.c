#include "linkedlist.h"
#include "minieap_common.h"
#include "packet_plugin_rjv3_priv.h"
#include "misc.h"
#include "logging.h"

#include <stdint.h>
#include <malloc.h>

RJ_PROP* new_rjv3_prop() {
    RJ_PROP* _prop = (RJ_PROP*)malloc(sizeof(RJ_PROP));
    if (_prop < 0) {
        PR_ERRNO("RJv3 字段结构内存分配失败");
        return NULL;
    }
    
    _prop->header1.header_type = 0x1a;
    _prop->header1.magic_2[0] = 0x00;
    _prop->header1.magic_2[1] = 0x00;
    _prop->header1.magic_2[2] = 0x13;
    _prop->header1.magic_2[3] = 0x11;
    return _prop;
}

int append_rjv3_prop(LIST_ELEMENT** list, uint8_t type, uint8_t* content, int len) {
    RJ_PROP* _prop = new_rjv3_prop();
    if (_prop == NULL) return -1;
    
    _prop->header1.header_len = len + sizeof(RJ_PROP_HEADER1) + sizeof(RJ_PROP_HEADER2);
    _prop->header2.type = type;
    _prop->header2.len = len + sizeof(RJ_PROP_HEADER2);
    _prop->content = content;
    insert_data(list, _prop);
    return _prop->header1.header_len;
}

static int rjv3_prop_compare(void* src, void* to_match) {
    if (((RJ_PROP*)src)->header2.type == ((RJ_PROP*)to_match)->header2.type)
        return 0;
    return 1;
}

RESULT modify_rjv3_prop(LIST_ELEMENT* list, uint8_t type, uint8_t* content, int len) {
    RJ_PROP _exp = { .header2 = { .type = type } };
    RJ_PROP* _prop = (RJ_PROP*)lookup_data(list, &_exp, rjv3_prop_compare);
    
    if (_prop < 0) return FAILURE;
    chk_free((void**)&_prop->content);
    _prop->content = content;
    _prop->header2.len = len + sizeof(RJ_PROP_HEADER2);
    _prop->header1.header_len = len + sizeof(RJ_PROP_HEADER1) + sizeof(RJ_PROP_HEADER2);
    return _prop->header1.header_len;
}

void remove_rjv3_prop(LIST_ELEMENT* list, uint8_t type) {
    RJ_PROP _exp = { .header2 = { .type = type }};
    remove_data(list, &_exp, rjv3_prop_compare);
}
