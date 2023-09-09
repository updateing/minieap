#include "packet_plugin_rjv3_priv.h"
#include "packet_plugin_rjv3_prop.h"
#include "packet_plugin_rjv3_keepalive.h"
#include "eth_frame.h"
#include "if_impl.h"
#include "checkV4.h"
#include "config.h"
#include "linkedlist.h"
#include "logging.h"
#include "net_util.h"
#include "packet_util.h"
#include "misc.h"
#include "eap_state_machine.h"
#include "sched_alarm.h"
#include "rjcrc16.h"
#include "rjencode.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <arpa/inet.h>

#ifdef __linux__
#include <linux/hdreg.h>
#endif

#define IS_MD5_FRAME(frame) \
    (frame != NULL && frame->header->eapol_hdr.type[0] == EAP_PACKET \
        && frame->header->eap_hdr.type[0] == MD5_CHALLENGE)

static void rjv3_set_dhcp_en(uint8_t* dhcp_en_arr, DHCP_TYPE dhcp_type) {
    dhcp_en_arr[3] = (dhcp_type != DHCP_NONE);
}

static void rjv3_set_local_mac(uint8_t* mac_buf) {
    IF_IMPL* _if_impl = get_if_impl();
    if (_if_impl == NULL) return;

    char ifname[IFNAMSIZ] = {0};
    _if_impl->get_ifname(_if_impl, ifname, IFNAMSIZ);

    obtain_iface_mac(ifname, mac_buf);
}

static void rjv3_set_pwd_hash(uint8_t* hash_buf, ETH_EAP_FRAME* request) {
    if (IS_MD5_FRAME(request)) {
        uint8_t* _hash_buf;
        EAP_CONFIG* _eap_config = get_eap_config();

        _hash_buf = (uint8_t*)computePwd(request->content + sizeof(FRAME_HEADER) + 1,
                                          _eap_config->username, _eap_config->password);
        memmove(hash_buf, _hash_buf, 16);
        /* 1 = sizeof(MD5-Value-Size), this is where MD5-Value starts */
    }
}

static void rjv3_set_ipv6_addr(uint8_t* ll_slaac, uint8_t* ll_temp, uint8_t* global) {
    LIST_ELEMENT *_ip_list = NULL, *_ip_curr;
    IF_IMPL* _if_impl = get_if_impl();
    if (_if_impl == NULL) return;

    char ifname[IFNAMSIZ] = {0};
    _if_impl->get_ifname(_if_impl, ifname, IFNAMSIZ);

    obtain_iface_ip_mask(ifname, &_ip_list);
    _ip_curr = _ip_list;

#define IP_ELEM ((IP_ADDR*)(_ip_curr->content))
    do {
        if (IP_ELEM->family == AF_INET6) {
            if ((IP_ELEM->ip[0] & 0xf0) == 0x20) { // 2xxx:: Global scope (ROUGH)
                memmove(global, IP_ELEM->ip, 16);
            } else if (IP_ELEM->ip[0] == 0xfe && IP_ELEM->ip[1] == 0x80) { // fe80:: Link local
                if (IP_ELEM->ip[11] == 0xff && IP_ELEM->ip[12] == 0xfe) {
                    /* ::xxff:fexx:: is the symbol of SLAAC */
                    memmove(ll_slaac, IP_ELEM->ip, 16);
                } else {
                    /* Privacy extension, will be used to form an global address also */
                    memmove(ll_temp, IP_ELEM->ip, 16);
                }
            }
        }
    } while ((_ip_curr = _ip_curr->next));
    list_destroy(&_ip_list, TRUE);
}

static void rjv3_set_v3_hash(uint8_t* hash_buf, ETH_EAP_FRAME* request) {
    uint8_t* _v3_buf;

    /* computeV4 returns its internal buffer, which can not be freed */
    if (IS_MD5_FRAME(request)) {
        _v3_buf = computeV4(request->content + sizeof(FRAME_HEADER) + 1, /* position of MD5-Value */
                            *(request->content + sizeof(FRAME_HEADER))); /* position of MD5-Value-Size */
    } else {
        uint8_t _v3_pad[RJV3_PAD_SIZE] = {0};
        _v3_buf = computeV4(_v3_pad, RJV3_PAD_SIZE);
    }
    memmove(hash_buf, _v3_buf, 0x80);
}

static void rjv3_set_service_name(uint8_t* name_buf, char* cmd_opt) {
    memmove(name_buf, cmd_opt, strlen(cmd_opt));
}

static void rjv3_set_secondary_dns(char* dns_ascii_buf, char* fake_dns) {
    if (fake_dns != NULL) {
        memmove(dns_ascii_buf, fake_dns, strnlen(fake_dns, INET6_ADDRSTRLEN));
        return;
    }

    LIST_ELEMENT* dns_list = NULL;

    obtain_dns_list(&dns_list);

    /* Only care about 2nd one */
    if (dns_list && dns_list->next) {
        strncpy(dns_ascii_buf, dns_list->next->content, INET6_ADDRSTRLEN);
    } else {
        PR_WARN("第二 DNS 地址获取错误。若认证失败，请用 --fake-dns2 指定第二 DNS 地址")
    }
    free_dns_list(&dns_list);
    return;
}

static void rjv3_set_hdd_serial(uint8_t* serial_buf, char* fake_serial) {
    if (fake_serial != NULL) {
        memmove(serial_buf, fake_serial, strnlen(fake_serial, MAX_PROP_LEN));
        return;
    }
#ifdef __linux__
    FILE* _fp = fopen("/etc/mtab", "r");
    char _line_buf[MAX_LINE_LEN] = {0};
    char* _line_buf_dev, *_line_buf_mountpoint;
    char* _root_dev = NULL;
    char* _ret;

    if (_fp == NULL) {
        goto info_err;
    }

    /* Find the root device */
    while ((_ret = fgets(_line_buf, MAX_LINE_LEN, _fp))) {
        _line_buf_dev = strtok(_line_buf, " ");
        if (_line_buf_dev == NULL) continue;
        _line_buf_mountpoint = strtok(NULL, " ");
        if (_line_buf_mountpoint != NULL &&
                _line_buf_mountpoint[0] == '/' && _line_buf_mountpoint[1] == 0) {
            if (_root_dev) free(_root_dev); /* Multiple mounts */
            _root_dev = strdup(_line_buf_dev);
        }
    }

    /* Query the serial no */
    if (_root_dev != NULL) {
        int devfd;
        struct hd_driveid hd;
        if ((devfd = open(_root_dev, O_RDONLY|O_NONBLOCK)) < 0) {
            goto info_err;
        }

        if (!ioctl(devfd, HDIO_GET_IDENTITY, &hd)) {
            unsigned char* _pos = &hd.serial_no[sizeof(hd.serial_no) - 1];
            for (; *_pos == ' '; _pos--);
            *(++_pos) = 0; /* Trim spaces */
            memmove(serial_buf, hd.serial_no, strlen((char*)hd.serial_no));
            goto close_return;
        } else {
            goto info_err;
        }
    }

info_err:
    PR_ERRNO("无法从 /etc/mtab 获取根分区挂载设备信息，请使用 --fake-serial 选项手动指定硬盘序列号");
close_return:
    if (_fp != NULL) fclose(_fp);
    if (_root_dev) free(_root_dev);
#endif // TODO macOS ioreg?
    return;
}

#define PRIV ((rjv3_priv*)(this->priv))

static RESULT rjv3_get_dhcp_lease(struct _packet_plugin* this, DHCP_LEASE* lease) {
    IF_IMPL* _if = get_if_impl();
    if (_if == NULL) return FAILURE;
    char _ifname[IFNAMSIZ] = {0};
    if (IS_FAIL(_if->get_ifname(_if, _ifname, IFNAMSIZ))) {
        PR_ERR("网络界面尚未配置");
        return FAILURE;
    }

    LIST_ELEMENT* _dns_list = NULL;
    LIST_ELEMENT* _ip_list = NULL;
    IP_ADDR* _ipv4 = NULL;
    if (IS_FAIL(obtain_iface_ip_mask(_ifname, &_ip_list))
            || (_ipv4 = find_ip_with_family(_ip_list, AF_INET)) == NULL) {

        PR_ERR("IPv4 地址获取错误");
        goto fail;
    }

    IP_ADDR _gw;
    _gw.family = AF_INET;
    if (IS_FAIL(obtain_iface_ipv4_gateway(_ifname, _gw.ip))) {
        PR_ERR("IPv4 网关获取错误");
        goto fail;
    }

    char* _dns1_str;
    IP_ADDR _dns1;
    _dns1.family = AF_INET;
    if (!PRIV->fake_dns1) {
        if (IS_FAIL(obtain_dns_list(&_dns_list))) {
            PR_ERR("主 DNS 地址获取错误，请使用 --fake-dns1 选项手动指定主 DNS 地址");
            goto fail;
        }
        _dns1_str = _dns_list->content;
    } else {
        _dns1_str = PRIV->fake_dns1;
    }
    if (inet_pton(AF_INET, _dns1_str, &_dns1.ip) == 0) {
            PR_ERR("主 DNS 地址格式错误，要求 IPv4 地址。请使用 --fake-dns1 选项手动指定主 DNS 地址");
            goto fail;
    }

    *(uint32_t*)&lease->ip = *(uint32_t*)&_ipv4->ip;
    *(uint32_t*)&lease->netmask = *(uint32_t*)&_ipv4->mask;
    *(uint32_t*)&lease->gateway = *(uint32_t*)&_gw.ip;
    *(uint32_t*)&lease->dns = *(uint32_t*)&_dns1.ip;

    free_ip_list(&_ip_list);
    free_dns_list(&_dns_list);

    return SUCCESS;
fail:
    free_ip_list(&_ip_list);
    free_dns_list(&_dns_list);

    return FAILURE;
}

static void rjv3_apply_bcast_addr(PACKET_PLUGIN* this, ETH_EAP_FRAME* frame) {
    static const uint8_t _rj_bcast[6] = {0x01,0xd0,0xf8,0x00,0x00,0x03};
    switch (PRIV->bcast_addr) {
        case BROADCAST_RJ:
            if (frame->header->eapol_hdr.type[0] == EAPOL_START) {
                /* Main program will take care of the MAC address when it's not START */
                memmove(frame->header->eth_hdr.dest_mac, _rj_bcast, sizeof(_rj_bcast));
            }
            break;
        case BROADCAST_CER:
        case BROADCAST_STANDARD:
        default:
            break;
    }
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
    char _sec_dns[INET6_ADDRSTRLEN] = {0};
    uint8_t _misc_2[RJV3_SIZE_MISC_2] = {0x01};
    uint8_t _ll_ipv6[RJV3_SIZE_LL_IPV6] = {0};
    uint8_t _ll_ipv6_tmp[RJV3_SIZE_LL_IPV6_T] = {0};
    uint8_t _glb_ipv6[RJV3_SIZE_GLB_IPV6] = {0};
    uint8_t _v3_hash[RJV3_SIZE_V3_HASH] = {0};
    uint8_t _service[RJV3_SIZE_SERVICE] = {0};
    uint8_t _hdd_ser[RJV3_SIZE_HDD_SER] = {0};
    /* misc 6 */
    uint8_t _misc_7[RJV3_SIZE_MISC_7] = {0};
    uint8_t _os_bits[RJV3_SIZE_OS_BITS] = {0x40};
    char* _ver_str = PRIV->ver_str;

    rjv3_set_dhcp_en(_dhcp_en, PRIV->dhcp_type);

    rjv3_set_local_mac(_local_mac);

    rjv3_set_pwd_hash(_pwd_hash, PRIV->last_recv_packet);

    rjv3_set_secondary_dns(_sec_dns, PRIV->fake_dns2);

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
    CHK_ADD(append_rjv3_prop(list, RJV3_TYPE_OS_BITS,  _os_bits,               sizeof(_os_bits)));
    CHK_ADD(append_rjv3_prop(list, RJV3_TYPE_VER_STR,  (uint8_t*)_ver_str,    strlen(_ver_str) + 1)); // Zero terminated

    return _len;
}

static int rjv3_should_fill_dhcp_prop(struct _packet_plugin* this) {
    return (PRIV->dhcp_type == DHCP_BEFORE_AUTH) ||
            (PRIV->dhcp_type == DHCP_DOUBLE_AUTH && PRIV->succ_count >= 2);
}

/* The bytes containing twisted IPv4 addresses */
static void rjv3_append_priv_header(struct _packet_plugin* this, ETH_EAP_FRAME* frame) {
    DHCP_INFO_PROP _dhcp_prop = {0};

    _dhcp_prop.magic[0] = 0x00;
    _dhcp_prop.magic[1] = 0x00;
    _dhcp_prop.magic[2] = 0x13;
    _dhcp_prop.magic[3] = 0x11;

    _dhcp_prop.dhcp_enabled = (PRIV->dhcp_type != DHCP_NONE);

    if (rjv3_should_fill_dhcp_prop(this)) {
        rjv3_get_dhcp_lease(this, &_dhcp_prop.lease);
    }

    *(uint16_t*)&_dhcp_prop.crc16_hash = htons(crc16((uint8_t*)&_dhcp_prop, 21));

    rj_encode((uint8_t*)&_dhcp_prop, sizeof(_dhcp_prop));
    append_to_frame(frame, (uint8_t*)&_dhcp_prop, sizeof(_dhcp_prop));

    uint8_t _magic[4] = {0x00, 0x00, 0x13, 0x11};
    append_to_frame(frame, _magic, sizeof(_magic));

    uint8_t _prog_name[RJV3_SIZE_PROG_NAME] = RJV3_PROG_NAME;
    append_to_frame(frame, _prog_name, sizeof(_prog_name));

    uint8_t _version[4] = {0x01, 0x1f, 0x01, 0x02}; /* May be different */
    append_to_frame(frame, _version, sizeof(_version));
}

/* Append everything proprietary */
RESULT rjv3_append_priv(struct _packet_plugin* this, ETH_EAP_FRAME* frame) {
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
    int _props_len = 0, _single_len = 0;
    uint8_t _std_prop_buf[FRAME_BUF_SIZE] = {0}; // Buffer for 0x1a props
    LIST_ELEMENT* _prop_list = NULL;

    rjv3_apply_bcast_addr(this, frame);
    rjv3_append_priv_header(this, frame);

    /* Let's make the big news! */
    _single_len = rjv3_append_common_fields(this, &_prop_list, IS_MD5_FRAME(frame));
    if (_single_len < 0) {
        return FAILURE;
    }

    /* The Mods! */
    _props_len += modify_rjv3_prop_list(_prop_list, PRIV->cmd_prop_mod_list);

    /* Actually read from sparse nodes into a unite buffer */
    _single_len = append_rjv3_prop_list_to_buffer(_prop_list, _std_prop_buf, FRAME_BUF_SIZE);

    if (_single_len > 0) {
        _props_len += _single_len;
    } else {
        return FAILURE;
    }

    /* And those from cmdline */
    _single_len = append_rjv3_prop_list_to_buffer(PRIV->cmd_prop_list,
                                                  _std_prop_buf + _props_len,
                                                  FRAME_BUF_SIZE - _props_len);
    if (_single_len >= 0) { // This time with '='
        _props_len += _single_len;
    } else {
        return FAILURE;
    }

    /* The outside */
    /* logoffReason(1) magic(4) length(2) */
    uint8_t _header[7] = {0x00, 0x00, 0x00, 0x13, 0x11, 0x00, 0x00};
    _header[5] = (_props_len >> 8 & 0xff);
    _header[6] = (_props_len & 0xff);

    append_to_frame(frame, _header, sizeof(_header));

    append_to_frame(frame, _std_prop_buf, _props_len);

    destroy_rjv3_prop_list(&_prop_list);
    return SUCCESS;
}

static int rjv3_is_echokey_prop(void* unused, void* prop) {
    RJ_PROP* _prop = (RJ_PROP*)prop;

    if (_prop->header2.type == 0x1 && PROP_TO_CONTENT_SIZE(_prop) != 0) {
        return 0;
    }
    return 1;
}

RESULT rjv3_process_result_prop(ETH_EAP_FRAME* frame) {
    LIST_ELEMENT* _srv_msg = NULL;
    RJ_PROP* _msg = NULL;

    /* Success frames does not have EAP_HEADER.type,
     * and do not use EAP_HEADER.len since it once betrayed us
     */
    parse_rjv3_buf_to_prop_list(&_srv_msg,
                                frame->content + sizeof(FRAME_HEADER)
                                    - sizeof(frame->header->eap_hdr.type),
                                frame->actual_len - sizeof(FRAME_HEADER)
                                    + sizeof(frame->header->eap_hdr.type),
                                TRUE);

    /* Assume this server message is the first property */
    if (_srv_msg != NULL) {
        _msg = (RJ_PROP*)_srv_msg->content;
        int _content_len = _msg->header2.len - HEADER2_SIZE_NO_MAGIC(_msg);

        if (_content_len != 0) {
            PR_INFO("服务器通知：\n");
            pr_info_gbk((char*)_msg->content, _content_len);
        }
    }
    if (frame->header->eapol_hdr.type[0] == EAP_PACKET &&
            frame->header->eap_hdr.code[0] == EAP_SUCCESS) {
        _msg = find_rjv3_prop(_srv_msg, RJV3_TYPE_ACCOUNTING_MSG);
        if (_msg != NULL) {
            int _content_len = _msg->header2.len - HEADER2_SIZE_NO_MAGIC(_msg);

            if (_content_len != 0) {
                PR_INFO("计费通知：\n");
                pr_info_gbk((char*)_msg->content, _content_len);
            }
        }

        _msg = NULL;
        _msg = (RJ_PROP*)lookup_data(_srv_msg, NULL, rjv3_is_echokey_prop);
        if (_msg == NULL) {
            PR_ERR("无法找到 echo key 的位置，将不能进行心跳");
            return FAILURE;
        } else {
            uint32_t _echokey = 0;
            _echokey |= bit_reverse(~*(_msg->content + 6)) << 24;
            _echokey |= bit_reverse(~*(_msg->content + 7)) << 16;
            _echokey |= bit_reverse(~*(_msg->content + 8)) << 8;
            _echokey |= bit_reverse(~*(_msg->content + 9));
            rjv3_set_keepalive_echokey(_echokey);
            rjv3_set_keepalive_echono(rand() & 0xffff);
            rjv3_set_keepalive_dest_mac(frame->header->eth_hdr.src_mac);
        }
    }
    destroy_rjv3_prop_list(&_srv_msg);
    return SUCCESS;
}

void rjv3_start_secondary_auth(void* vthis) {
    PACKET_PLUGIN* this = (PACKET_PLUGIN*)vthis;
    DHCP_LEASE _tmp_dhcp_lease = {0};

    /* Try to fill out lease info to determine whether DHCP finished.
     * The addresses in lease info are not used here.
     */
    if (IS_FAIL(rjv3_get_dhcp_lease(this, &_tmp_dhcp_lease))) {
        PRIV->dhcp_count++;
        if (PRIV->dhcp_count > PRIV->max_dhcp_count) {
            rjv3_process_result_prop(PRIV->duplicated_packet); // Loads of texts
            free_frame(&PRIV->duplicated_packet); // Duplicated in process_success
            schedule_alarm(1, rjv3_send_keepalive_timed, this);
            PR_ERR("无法获取 IPv4 地址等信息，将不会进行第二次认证而直接开始心跳");
        } else {
            PR_WARN("DHCP 可能尚未完成，将继续等待……");
            schedule_alarm(5, rjv3_start_secondary_auth, this);
        }
        return;
    } else {
        PR_INFO("DHCP 完成，正在开始第二次认证");
        free_frame(&PRIV->duplicated_packet); // Duplicated in process_success
        switch_to_state(EAP_STATE_START_SENT, NULL);
        return;
    }
}
