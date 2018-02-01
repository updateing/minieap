#include "if_impl.h"
#include "packet_builder.h"
#include "logging.h"
#include "net_util.h"
#include "packet_plugin_rjv3_priv.h"
#include "sched_alarm.h"
#include "misc.h"
#include "packet_util.h"

#include <stdlib.h>

static int g_keepalive_alarm_id;
static uint32_t g_echokey;
static uint32_t g_echono;
static uint8_t g_dest_mac[6];

#define PRIV ((rjv3_priv*)(this->priv))
void rjv3_set_keepalive_echokey(uint32_t key) {
    g_echokey = key;
}

void rjv3_set_keepalive_echono(uint32_t no) {
    g_echono = no;
}

void rjv3_set_keepalive_dest_mac(uint8_t* mac) {
    memmove(g_dest_mac, mac, 6);
}

void rjv3_keepalive_reset() {
    unschedule_alarm(g_keepalive_alarm_id);
    g_echokey = 0;
    g_echono = 0;
}

static RESULT send_echo_frame(struct _packet_plugin* this, uint8_t* content, int len) {
    PACKET_BUILDER* _builder = packet_builder_get();
    if (_builder == NULL) {
        PR_ERR("包生成器未初始化");
        goto fail;
    }

    IF_IMPL* _if = get_if_impl();
    uint8_t _src[6] = {0};
    char _ifname[IFNAMSIZ] = {0};
    if (_if == NULL) {
        PR_ERR("网络界面未初始化");
        goto fail;
    }

    if (IS_FAIL(_if->get_ifname(_if, _ifname, IFNAMSIZ)) || IS_FAIL(obtain_iface_mac(_ifname, _src))) {
        PR_ERR("无法获取源 MAC");
        goto fail;
    }

    uint8_t _proto[] = {0x88, 0x8e};

    _builder->set_eth_field(_builder, FIELD_DST_MAC, g_dest_mac);
    _builder->set_eth_field(_builder, FIELD_SRC_MAC, _src);
    _builder->set_eth_field(_builder, FIELD_ETH_PROTO, _proto);
    _builder->set_eap_fields(_builder, EAPOL_RJ_PROPRIETARY_KEEPALIVE, 0, 0, 0, NULL);

    ETH_EAP_FRAME frame;
    if ((frame.content = (uint8_t*)malloc(100)) == NULL) {
        PR_ERR("无法为 Keep-Alive 报文分配内存空间");
        goto fail;
    }
    memset(frame.content, 0, 100);
    frame.buffer_len = 100;
    frame.actual_len = _builder->build_packet(_builder, frame.content);

    frame.header->eapol_hdr.len[0] = 0;
    frame.header->eapol_hdr.len[1] = 30; // Why? It's 27...
    memmove(frame.content + sizeof(ETHERNET_HEADER) + sizeof(EAPOL_HEADER), content, len);
    frame.actual_len += len;

    if (IS_FAIL(_if->send_frame(_if, &frame))) {
        goto fail;
    }

    free(frame.content);
    return SUCCESS;
fail:
    PR_ERR("无法发送 Keep-Alive 报文");
    free(frame.content);
    return FAILURE;
}

RESULT rjv3_send_new_keepalive_frame(struct _packet_plugin* this) {
    uint32_t _num1 = g_echokey + g_echono;
    uint32_t _num2 = g_echono++;

    uint8_t _template[] = {
		/*0x00,0x1E,*/ /* EAP-Size */
		0xFF,0xFF,0x37,0x77,0x7F,0x9F,0xFF,0xFF,0xD9,0x13,0xFF,0xFF,0x37,0x77,
		0x7F,0x9F,0xFF,0xFF,0xF7,0x2B,0xFF,0xFF,0x37,0x77,0x7F,0x3F,0xFF
    };
    _template[6] = ~bit_reverse((_num1 >> 24) & 0xff);
    _template[7] = ~bit_reverse((_num1 >> 16) & 0xff);
    _template[8] = ~bit_reverse((_num1 >> 8 ) & 0xff);
    _template[9] = ~bit_reverse( _num1        & 0xff);

    _template[16] = ~bit_reverse((_num2 >> 24) & 0xff);
    _template[17] = ~bit_reverse((_num2 >> 16) & 0xff);
    _template[18] = ~bit_reverse((_num2 >> 8 ) & 0xff);
    _template[19] = ~bit_reverse( _num2        & 0xff);

    return send_echo_frame(this, _template, sizeof(_template));
}

void rjv3_send_keepalive_timed(void* vthis) {
    PACKET_PLUGIN* this = (PACKET_PLUGIN*)vthis;
    if (IS_FAIL(rjv3_send_new_keepalive_frame(this))) {
        PR_ERR("心跳包发送失败");
    }
    g_keepalive_alarm_id = schedule_alarm(PRIV->heartbeat_interval, rjv3_send_keepalive_timed, vthis);
}
