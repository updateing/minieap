#include "if_impl.h"
#include "packet_builder.h"
#include "logging.h"
#include "net_util.h"
#include "packet_plugin_rjv3_priv.h"
#include "sched_alarm.h"
#include "misc.h"

#include <malloc.h>

static uint32_t g_echokey;
static uint32_t g_echono;

#define PRIV ((rjv3_priv*)(this->priv))
void rjv3_set_keepalive_echokey(uint32_t key) {
    g_echokey = key;
}

void rjv3_set_keepalive_echono(uint32_t no) {
    g_echono = no;
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

    uint8_t _std_bcast[] = {0x01,0x80,0xc2,0x00,0x00,0x03};
    uint8_t _rj_bcast[] = {0x01,0xd0,0xf8,0x00,0x00,0x03};
    uint8_t _proto[] = {0x88, 0x8e};
    uint8_t* _dst = PRIV->bcast_addr == BROADCAST_RJ ? _rj_bcast : _std_bcast;
    _builder->set_eth_field(_builder, FIELD_DST_MAC, _dst);
    _builder->set_eth_field(_builder, FIELD_SRC_MAC, _src);
    _builder->set_eth_field(_builder, FIELD_ETH_PROTO, _proto);
    _builder->set_eap_fields(_builder, EAPOL_RJ_PROPRIETARY_KEEPALIVE, 0, 0, 0, NULL);

    ETH_EAP_FRAME frame;
    if ((frame.content = (uint8_t*)malloc(100)) < 0) {
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

    return _if->send_frame(_if, &frame);
fail:
    PR_ERR("无法发送 Keep-Alive 报文");
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
    schedule_alarm(PRIV->heartbeat_interval, rjv3_send_keepalive_timed, vthis);
}
