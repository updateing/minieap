#include "linkedlist.h"
#include "minieap_common.h"
#include "packet_plugin.h"
#include "misc.h"
#include "logging.h"
#include "packet_plugin_rjv3_priv.h"
#include "packet_plugin_rjv3_prop.h"

#include <stdint.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct _packet_plugin_rjv3_priv {
    int heartbeat_interval;
    int echo_key; // Used in Keep-Alive packets
    int packet_id; // Corresponding to request
    char* dhcp_script; // Remember to free this
    char* service_name;
    uint8_t fake_ver[2];
    DOT1X_BCAST_ADDR bcast_addr;
    DHCP_TYPE dhcp_type;
    LIST_ELEMENT* cmd_prop_list; // Free!
} rjv3_priv;

#define PRIV ((rjv3_priv*)(this->priv))

#define MAX_PATH 260 // TODO move to common
#define MAX_PROP_LEN 200 // Assumed

/*
 * Headers before the fields
 */
static const uint8_t pkt_start_priv_header[] = {
                0xff, 0xff, 0x37, 0x77, 0x7f, 0xff, /*   ..7w.. */ /* Would be different in second auth */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* ........ */
    0xff, 0xff, 0xff, 0xac, 0xb1, 0xff, 0xb0, 0xb0, /* ........ */
    0x2d, 0x00, 0x00, 0x13, 0x11, 0x38, 0x30, 0x32, /* -....802 */
    0x31, 0x78, 0x2e, 0x65, 0x78, 0x65, 0x00, 0x00, /* 1x.exe.. */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, /* ........ */
//    0x02, 0x00, 0x00, 0x00, 0x13, 0x11, 0x01, 0xb1, /* ........ */
};

static const uint8_t pkt_identity_priv_header[] = {
                0xff, 0xff, 0x37, 0x77, 0x7f, 0xff, /*   ..7w.. */ /* Would be different in second auth */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* ........ */
    0xff, 0xff, 0xff, 0xac, 0xb1, 0xff, 0xb0, 0xb0, /* ........ */
    0x2d, 0x00, 0x00, 0x13, 0x11, 0x38, 0x30, 0x32, /* -....802 */
    0x31, 0x78, 0x2e, 0x65, 0x78, 0x65, 0x00, 0x00, /* 1x.exe.. */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, /* ........ */
//    0x02, 0x00, 0x00, 0x00, 0x13, 0x11, 0x01, 0xb1, /* ........ */
};

static const uint8_t pkt_md5_priv_header[] = {
                0xff, 0xff, 0x37, 0x77, 0x7f, 0xff, /*   ..7w.. */ /* Would be different in second auth */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* ........ */
    0xff, 0xff, 0xff, 0xac, 0xb1, 0xff, 0xb0, 0xb0, /* ........ */
    0x2d, 0x00, 0x00, 0x13, 0x11, 0x38, 0x30, 0x32, /* -....802 */
    0x31, 0x78, 0x2e, 0x65, 0x78, 0x65, 0x00, 0x00, /* 1x.exe.. */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, /* ........ */
//    0x02, 0x00, 0x00, 0x00, 0x13, 0x11, 0x01, 0xc1, /* ........ */
};

static RESULT append_rj_cmdline_opt(struct _packet_plugin* this, const char* opt) {
    // e.g. 6f:52472d535520466f72204c696e75782056312e3000
    //      type:content
    // sets client version string to "RG-SU For Linux V1.0"
    int _content_len, _curr_pos;
    uint8_t _type;
    uint8_t* _content_buf;
    char* _arg = strdup(opt);
    char* _split;
   
    if (_arg == NULL) {
        PR_ERRNO("无法为命令行的 --rj-option 参数分配内存空间");
        return FAILURE;
    }
    
    _split = strtok(_arg, ":");
    if (_split == NULL)
        goto malformat;
    _type = char2hex(_split);
    
    _split = strtok(NULL, ":");
    if (_split == NULL)
        goto malformat;
        
    _content_len = strnlen(_split, MAX_PROP_LEN);
    if ((_content_len & 1) == 1) _content_len += 1;
    _content_buf = (uint8_t*)malloc(_content_len >> 1); // divide by 2
    
    for (_curr_pos = 0; _curr_pos < (_content_len >> 1); ++_curr_pos) {
        _content_buf[_curr_pos] = char2hex(_split + (_curr_pos << 1));
    }
    
    append_rjv3_prop(&PRIV->cmd_prop_list, _type, _content_buf, _content_len);

    free(_arg);
    return SUCCESS;

malformat:
    free(_arg);
    PR_WARN("--rj-option 的参数格式错误");
    return FAILURE;
}

void rjv3_print_cmdline_help(struct _packet_plugin* this) {
}

RESULT rjv3_process_cmdline_opts(struct _packet_plugin* this, int argc, char* argv[]) {
    int opt = 0;
    int longIndex = 0;
    int _arglen = 0; /* 当前参数长度 */
    unsigned int ver[2]; /* -v 版本号 */
    static const char* shortOpts = "e:a:d:v:f:c:q:";
    static const struct option longOpts[] = {
	    { "heartbeat", required_argument, NULL, 'e' },
	    { "eap-bcast-addr", required_argument, NULL, 'a' },
	    { "dhcp-type", required_argument, NULL, 'd' },
	    { "fake-version", required_argument, NULL, 'v' },
	    { "dhcp-script", required_argument, NULL, 'c' }, // An EAP client should not do this
	    { "decode-config", required_argument, NULL, 'q' },
	    { "rj-option", required_argument, NULL, 0 },
	    { NULL, no_argument, NULL, 0 }
    };

    opt = getopt_long(argc, argv, shortOpts, longOpts, &longIndex);
#define COPY_N_ARG_TO(buf, maxlen) \
        _arglen = strnlen(optarg, maxlen); \
        chk_free((void**)&buf); \
        buf = (char*)malloc(_arglen); \
        strncpy(buf, optarg, _arglen);
    while (opt != -1) {
        switch (opt) {
            case 'e':
                PRIV->heartbeat_interval = atoi(optarg);
                break;
            case 'a':
                PRIV->bcast_addr = atoi(optarg) % 3; /* 一共三个选项 */
                break;
            case 'd':
                PRIV->dhcp_type = atoi(optarg) % 4;
                break;
            case 'v':
                if (sscanf(optarg, "%u.%u", ver, ver + 1) != EOF) {
                    PRIV->fake_ver[0] = ver[0];
                    PRIV->fake_ver[1] = ver[1];
                }
                break;
            case 'c':
                COPY_N_ARG_TO(PRIV->dhcp_script, MAX_PATH);
                break;
            case 'q':
                // printSuConfig(optarg); TODO
                //exit(EXIT_SUCCESS);
                break;
            case 0:
#define IF_ARG(arg_name) (strcmp(longOpts[longIndex].name, arg_name) == 0)
                if (IF_ARG("rj-option")) {
                    /* Allow mulitple rj-options */
                    append_rj_cmdline_opt(this, optarg);
                }
                break;
            default:
                break;
        }
        opt = getopt_long(argc, argv, shortOpts, longOpts, &longIndex);
    }
    
    return SUCCESS;
}

static int rjv3_append_common_fields(LIST_ELEMENT* list, ETH_EAP_FRAME* frame) {
    int _len = 0, _this_len = -1;
    uint8_t _dhcp_en[RJV3_SIZE_DHCP] = {0x00, 0x00, 0x00, 0x01};
    uint8_t _local_mac[RJV3_SIZE_MAC];
    /* misc 1 */
    char* _local_ip;
    uint8_t _misc_2[RJV3_SIZE_MISC_2] = {0x01};
    uint8_t _misc_3[RJV3_SIZE_MISC_3] = {0};
    uint8_t _ll_ipv6[RJV3_SIZE_LL_IPV6] = {0};
    uint8_t _glb_ipv6[RJV3_SIZE_GLB_IPV6] = {0};
    uint8_t _v3_hash[RJV3_SIZE_V3_HASH] = {0};
    char* _service = "internet";
    uint8_t _hdd_ser[RJV3_SIZE_HDD_SER] = {0};
    /* misc 6 */
    uint8_t _misc_7[RJV3_SIZE_MISC_7] = {0};
    uint8_t _misc_8[RJV3_SIZE_MISC_8] = {0x40};
    char* _ver_str = "RG-SU For Linux V1.0";
    
    // TODO Customize!
#define CHK_ADD(x) \
    _this_len = x; \
    if (_this_len < 0) { \
        return -1; \
    } else { \
        _len += _this_len; \
    }
    
    CHK_ADD(append_rjv3_prop(&list, RJV3_TYPE_DHCP,     _dhcp_en,               sizeof(_dhcp_en)));
    CHK_ADD(append_rjv3_prop(&list, RJV3_TYPE_MAC,      _local_mac,             sizeof(_local_mac)));
    CHK_ADD(append_rjv3_prop(&list, RJV3_TYPE_MISC_1,   NULL,                   0));
    CHK_ADD(append_rjv3_prop(&list, RJV3_TYPE_IP,       (uint8_t*)_local_ip,   strlen(_local_ip)));
    CHK_ADD(append_rjv3_prop(&list, RJV3_TYPE_MISC_2,   _misc_2,                sizeof(_misc_2)));
    CHK_ADD(append_rjv3_prop(&list, RJV3_TYPE_MISC_3,   _misc_3,                sizeof(_misc_3)));
    CHK_ADD(append_rjv3_prop(&list, RJV3_TYPE_LL_IPV6,  _ll_ipv6,               sizeof(_ll_ipv6)));
    CHK_ADD(append_rjv3_prop(&list, RJV3_TYPE_GLB_IPV6, _glb_ipv6,              sizeof(_glb_ipv6)));
    CHK_ADD(append_rjv3_prop(&list, RJV3_TYPE_V3_HASH,  _v3_hash,               sizeof(_v3_hash)));
    CHK_ADD(append_rjv3_prop(&list, RJV3_TYPE_SERVICE,  (uint8_t*)_service,    sizeof(_service)));
    CHK_ADD(append_rjv3_prop(&list, RJV3_TYPE_HDD_SER,  _hdd_ser,               sizeof(_hdd_ser)));
    CHK_ADD(append_rjv3_prop(&list, RJV3_TYPE_MISC_6,   NULL,                   0));
    CHK_ADD(append_rjv3_prop(&list, RJV3_TYPE_MISC_7,   _misc_7,                sizeof(_misc_7)));
    CHK_ADD(append_rjv3_prop(&list, RJV3_TYPE_MISC_8,   _misc_8,                sizeof(_misc_8)));
    CHK_ADD(append_rjv3_prop(&list, RJV3_TYPE_VER_STR,  (uint8_t*)_ver_str,    sizeof(_ver_str)));
    
    return _len;
}

RESULT rjv3_prepare_frame(struct _packet_plugin* this, ETH_EAP_FRAME* frame) {
    /*
     * Size field, its format is NOT the same as those header1.magic == 0x1a ones.
     * Thus do not use the prop APIs.
     */
    /*
        struct _size_field {
            RJ_PROP_HEADER1 header1; // TODO Different in 2nd packet
            uint8_t whole_trailer_len[2]; // First 0x1a prop to end
        }
     */
    int _props_len;
    LIST_ELEMENT* _prop_list = (LIST_ELEMENT*)malloc(sizeof(LIST_ELEMENT));
    if (_prop_list < 0) return FAILURE;
    
    RJ_PROP* _size_prop = new_rjv3_prop();
    if (_size_prop < 0) {
        free(_prop_list);
        return FAILURE;
    }
    
    _size_prop->header1.header_type = 0x02;
    _size_prop->header1.header_len = 0x00;
    /* Change size by pointer later */
    insert_data(&_prop_list, _size_prop);
    
    /* Let's do the huge project! */
    _props_len = rjv3_append_common_fields(_prop_list, frame);

    /* Now correct the size, note the format is different */
    _size_prop->header2.type = (_props_len >> 4 & 0xf);
    _size_prop->header2.len = (_props_len & 0xf);
    
    /* Actually read from sparse nodes into a unite buffer */
    list_traverse(_prop_list, append_rjv3_prop_to_frame, (void*)frame);
    
    /* And those from cmdline */
    list_traverse(PRIV->cmd_prop_list, append_rjv3_prop_to_frame, (void*)frame);

    list_destroy(_prop_list);
    return SUCCESS;
}

RESULT rjv3_on_frame_received(struct _packet_plugin* this, ETH_EAP_FRAME* frame) {
    return SUCCESS; // TODO
}

PACKET_PLUGIN* packet_plugin_rjv3_new() {
    PACKET_PLUGIN* this = (PACKET_PLUGIN*)malloc(sizeof(PACKET_PLUGIN));
    if (this < 0) {
        PR_ERRNO("RJv3 插件主结构内存分配失败");
        return NULL;
    }
    memset(this, 0, sizeof(PACKET_PLUGIN));
    
    this->priv = (rjv3_priv*)malloc(sizeof(rjv3_priv));
    if (this->priv < 0) {
        PR_ERRNO("RJv3 插件私有结构内存分配失败");
        free(this);
        return NULL;
    }
    memset(this->priv, 0, sizeof(rjv3_priv));
    
    this->process_cmdline_opts = rjv3_process_cmdline_opts;
    this->print_cmdline_help = rjv3_print_cmdline_help;
    this->prepare_frame = rjv3_prepare_frame;
    this->on_frame_received = rjv3_on_frame_received;
    return this;
}

