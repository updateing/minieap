#include "linkedlist.h"
#include "minieap_common.h"
#include "packet_plugin.h"
#include "misc.h"
#include "logging.h"
#include "packet_plugin_rjv3_priv.h"
#include "packet_plugin_rjv3_prop.h"
#include "packet_util.h"
#include "eth_frame.h"
#include "packet_plugin_rjv3.h"
#include "if_impl.h"

#include <stdint.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>

typedef struct _packet_plugin_rjv3_priv {
    struct { // Cmdline options
        int heartbeat_interval;
        char* service_name; // All pointers can be freed since they are created by COPY_N_ARG_TO
        char* ver_str;
        char* fake_dns;
        char* fake_serial;
        uint8_t fake_ver[2];
        DOT1X_BCAST_ADDR bcast_addr;
        DHCP_TYPE dhcp_type;
        LIST_ELEMENT* cmd_prop_list; // Destroy!
    };
    // Internal state variables
    int auth_round;
    ETH_EAP_FRAME* last_recv_packet;
} rjv3_priv;

#define PRIV ((rjv3_priv*)(this->priv))

#define MAX_PATH 260 // TODO move to common

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

static const uint8_t pkt_challenge_priv_header[] = {
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

void rjv3_destroy(struct _packet_plugin* this) {
    chk_free((void**)&PRIV->service_name);
    chk_free((void**)&PRIV->ver_str);
    chk_free((void**)&PRIV->fake_dns);
    chk_free((void**)&PRIV->fake_serial);
    list_destroy(&PRIV->cmd_prop_list);
    chk_free((void**)&this->priv);
    chk_free((void**)&this);
}

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
    free(_content_buf);
    return SUCCESS;

malformat:
    free(_arg);
    PR_WARN("--rj-option 的参数格式错误");
    return FAILURE;
}

void rjv3_print_cmdline_help(struct _packet_plugin* this) {
}

void rjv3_load_default_params(struct _packet_plugin* this) {
    PRIV->heartbeat_interval = DEFAULT_HEARTBEAT_INTERVAL;
    PRIV->service_name = strdup(DEFAULT_SERVICE_NAME);
    PRIV->ver_str = strdup(DEFAULT_SERVICE_NAME);
    PRIV->bcast_addr = DEFAULT_EAP_BCAST_ADDR;
    PRIV->dhcp_type = DEFAULT_DHCP_TYPE;
}

RESULT rjv3_process_cmdline_opts(struct _packet_plugin* this, int argc, char* argv[]) {
    int opt = 0;
    int longIndex = 0;
    int _arglen = 0; /* 当前参数长度 */
    unsigned int ver[2]; /* -v 版本号 */
    static const char* shortOpts = ":e:a:d:v:f:c:q:";
    static const struct option longOpts[] = {
	    { "heartbeat", required_argument, NULL, 'e' },
	    { "eap-bcast-addr", required_argument, NULL, 'a' },
	    { "dhcp-type", required_argument, NULL, 'd' },
	    { "fake-version", required_argument, NULL, 'v' },
	    { "decode-config", required_argument, NULL, 'q' },
	    { "rj-option", required_argument, NULL, 0 },
	    { "service", required_argument, NULL, 0 },
	    { "version-str", required_argument, NULL, 0 },
	    { "fake-dns", required_argument, NULL, 0 },
	    { "fake-serial", required_argument, NULL, 0 },
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
                PRIV->bcast_addr = atoi(optarg) % 3; /* 一共三个选项 */ // TODO actually apply
                break;
            case 'd':
                PRIV->dhcp_type = atoi(optarg) % 4; // TODO actually apply
                break;
            case 'v':
                if (sscanf(optarg, "%u.%u", ver, ver + 1) != EOF) {
                    PRIV->fake_ver[0] = ver[0];
                    PRIV->fake_ver[1] = ver[1];
                }
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
                } else if (IF_ARG("service")) {
                    COPY_N_ARG_TO(PRIV->service_name, RJV3_SIZE_SERVICE);
                } else if (IF_ARG("version-str")) {
                    COPY_N_ARG_TO(PRIV->ver_str, MAX_PROP_LEN);
                } else if (IF_ARG("fake-dns")) {
                    COPY_N_ARG_TO(PRIV->fake_dns, INET6_ADDRSTRLEN);
                } else if (IF_ARG("fake-serial")) {
                    COPY_N_ARG_TO(PRIV->fake_serial, MAX_PROP_LEN);
                }
                break;
            case ':':
                PR_ERR("缺少参数：%s", argv[optind - 1]);
                return FAILURE;
            default:
                break;
        }
        opt = getopt_long(argc, argv, shortOpts, longOpts, &longIndex);
    }
    
    return SUCCESS;
}

/*
 * Calculate values for commonly seen fields, and add them to a list
 *
 * Returns how much space it would take to "serialize" all the fields in the list
 */
static int rjv3_append_common_fields(PACKET_PLUGIN* this, LIST_ELEMENT** list, int append_pwd_hash) {
    int _len = 0, _this_len = -1;
    uint8_t _dhcp_en[RJV3_SIZE_DHCP] = {0x00, 0x00, 0x00, 0x01};
    uint8_t _local_mac[RJV3_SIZE_MAC];
    uint8_t _pwd_hash[RJV3_SIZE_PWD_HASH] = {0};
    char _sec_dns[INET_ADDRSTRLEN] = {0};
    uint8_t _misc_2[RJV3_SIZE_MISC_2] = {0x01};
    uint8_t _ll_ipv6[RJV3_SIZE_LL_IPV6] = {0};
    uint8_t _ll_ipv6_tmp[RJV3_SIZE_LL_IPV6_T] = {0};
    uint8_t _glb_ipv6[RJV3_SIZE_GLB_IPV6] = {0};
    uint8_t _v3_hash[RJV3_SIZE_V3_HASH] = {0};
    uint8_t _service[RJV3_SIZE_SERVICE] = {0};
    uint8_t _hdd_ser[RJV3_SIZE_HDD_SER] = {0};
    /* misc 6 */
    uint8_t _misc_7[RJV3_SIZE_MISC_7] = {0};
    uint8_t _misc_8[RJV3_SIZE_MISC_8] = {0x40};
    char* _ver_str = PRIV->ver_str;

    rjv3_set_dhcp_en(_dhcp_en, PRIV->dhcp_type);

    rjv3_set_local_mac(_local_mac);

    rjv3_set_pwd_hash(_pwd_hash, PRIV->last_recv_packet);
    
    rjv3_set_secondary_dns(_sec_dns, PRIV->fake_dns);

    rjv3_set_ipv6_addr(_ll_ipv6, _ll_ipv6_tmp, _glb_ipv6);

    rjv3_set_v3_hash(_v3_hash, PRIV->last_recv_packet);

    rjv3_set_service_name(_service, PRIV->service_name);
    
    rjv3_set_hdd_serial(_hdd_ser, PRIV->fake_serial);
    
#define CHK_ADD(x) \
    _this_len = x; \
    if (_this_len < 0) { \
        return -1; \
    } else { \
        _len += _this_len; \
    }
    
    CHK_ADD(append_rjv3_prop(list, RJV3_TYPE_DHCP,     _dhcp_en,               sizeof(_dhcp_en)));
    CHK_ADD(append_rjv3_prop(list, RJV3_TYPE_MAC,      _local_mac,             sizeof(_local_mac)));
    
    //if (frame->header->eapol_hdr.type[0] == EAP_PACKET && frame->header->eap_hdr.type[0] == MD5_CHALLENGE) {
    if (append_pwd_hash) {
        CHK_ADD(append_rjv3_prop(list, RJV3_TYPE_PWD_HASH, _pwd_hash,          sizeof(_pwd_hash)));
    } else {
        CHK_ADD(append_rjv3_prop(list, RJV3_TYPE_PWD_HASH, NULL,               0));
    }
    
    CHK_ADD(append_rjv3_prop(list, RJV3_TYPE_SEC_DNS,  (uint8_t*)_sec_dns,    strlen(_sec_dns)));
    CHK_ADD(append_rjv3_prop(list, RJV3_TYPE_MISC_2,   _misc_2,                sizeof(_misc_2)));
    CHK_ADD(append_rjv3_prop(list, RJV3_TYPE_LL_IPV6,  _ll_ipv6,               sizeof(_ll_ipv6)));
    CHK_ADD(append_rjv3_prop(list, RJV3_TYPE_LL_IPV6_T,_ll_ipv6_tmp,           sizeof(_ll_ipv6_tmp)));
    CHK_ADD(append_rjv3_prop(list, RJV3_TYPE_GLB_IPV6, _glb_ipv6,              sizeof(_glb_ipv6)));
    CHK_ADD(append_rjv3_prop(list, RJV3_TYPE_V3_HASH,  _v3_hash,               sizeof(_v3_hash)));
    CHK_ADD(append_rjv3_prop(list, RJV3_TYPE_SERVICE,  _service,               sizeof(_service)));
    CHK_ADD(append_rjv3_prop(list, RJV3_TYPE_HDD_SER,  _hdd_ser,               sizeof(_hdd_ser)));
    CHK_ADD(append_rjv3_prop(list, RJV3_TYPE_MISC_6,   NULL,                   0));
    CHK_ADD(append_rjv3_prop(list, RJV3_TYPE_MISC_7,   _misc_7,                sizeof(_misc_7)));
    CHK_ADD(append_rjv3_prop(list, RJV3_TYPE_MISC_8,   _misc_8,                sizeof(_misc_8)));
    CHK_ADD(append_rjv3_prop(list, RJV3_TYPE_VER_STR,  (uint8_t*)_ver_str,    strlen(_ver_str)));
    
    return _len;
}

static void rjv3_append_priv_header(struct _packet_plugin* this, ETH_EAP_FRAME* frame) {
    EAPOL_TYPE _eapol_type = frame->header->eapol_hdr.type[0];
    switch (_eapol_type) {
        case EAPOL_START:
            append_to_frame(frame, pkt_start_priv_header, sizeof(pkt_start_priv_header));
            break;
        case EAP_PACKET:
            if (frame->header->eap_hdr.code[0] == EAP_REQUEST) {
                switch (frame->header->eap_hdr.type[0]) {
                    case IDENTITY:
                        append_to_frame(frame, pkt_identity_priv_header,
                                            sizeof(pkt_identity_priv_header));
                        break;
                    case MD5_CHALLENGE:
                        append_to_frame(frame, pkt_challenge_priv_header,
                                            sizeof(pkt_challenge_priv_header));
                        break;
                }
            }
            break;
        default:
            break;
    }
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
            <other 0x1a fields follow>
        }
     */
    size_t _props_len = 0;
    uint8_t _std_prop_buf[FRAME_BUF_SIZE] = {0}; // Buffer for 0x1a props
    LIST_ELEMENT* _prop_list = NULL;
    
    rjv3_append_priv_header(this, frame);
    
    /* Let's make the big news! */
    rjv3_append_common_fields(this, &_prop_list, frame->header->eapol_hdr.type[0] == EAP_PACKET &&
                                                frame->header->eap_hdr.code[0] == MD5_CHALLENGE);
    
    /* Actually read from sparse nodes into a unite buffer */
    _props_len = append_rjv3_prop_list_to_buffer(_prop_list, _std_prop_buf, FRAME_BUF_SIZE);
    
    /* And those from cmdline */
    _props_len += append_rjv3_prop_list_to_buffer(PRIV->cmd_prop_list,
                                                  _std_prop_buf + _props_len,
                                                  FRAME_BUF_SIZE - _props_len);

    /* The outside */
    RJ_PROP* _container_prop = new_rjv3_prop();
    if (_container_prop < 0) {
        list_destroy(&_prop_list);
        return FAILURE;
    }
    
    _container_prop->header1.header_type = 0x02;
    _container_prop->header1.header_len = 0x00;
    _container_prop->header2.type = (_props_len >> 8 & 0xff);
    _container_prop->header2.len = (_props_len & 0xff);
    _container_prop->content = _std_prop_buf;

    append_rjv3_prop_to_frame(_container_prop, frame);

    list_destroy(&_prop_list);
    return SUCCESS;
}

RESULT rjv3_on_frame_received(struct _packet_plugin* this, ETH_EAP_FRAME* frame) {
    PRIV->last_recv_packet = frame;
    return SUCCESS; // TODO
}

void rjv3_set_auth_round(struct _packet_plugin* this, int round) {
    PRIV->auth_round = round;
}

RESULT rjv3_process_config_file(struct _packet_plugin* this, const char* filepath) {
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
        
    this->name = "rjv3";
    this->description = "来自 hyrathb@GitHub 的 Ruijie V3 验证算法";
    this->destroy = rjv3_destroy;
    this->set_auth_round = rjv3_set_auth_round;
    this->process_cmdline_opts = rjv3_process_cmdline_opts;
    this->load_default_params = rjv3_load_default_params;
    this->print_cmdline_help = rjv3_print_cmdline_help;
    this->prepare_frame = rjv3_prepare_frame;
    this->on_frame_received = rjv3_on_frame_received;
    this->process_config_file = rjv3_process_config_file;
    return this;
}

