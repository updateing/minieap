/*
 * Implement packet sending/receiving by libpcap.
 * It's portable but the program size (+ libpcap)
 * is considerably larger.
 */
#include "if_impl.h"
#include "minieap_common.h"
#include "logging.h"

#include <pcap.h>
#include <net/if.h>
#include <stdlib.h>

typedef struct _if_impl_libpcap_priv {
    int promisc;
    char ifname[IFNAMSIZ];
    short proto;
    pcap_t* pcapdev;
    void (*handler)(ETH_EAP_FRAME* frame); /* Packet handler */
} libpcap_priv;

#define PRIV ((libpcap_priv*)(this->priv))

static void libpcap_packet_handler(uint8_t* vthis, const struct pcap_pkthdr* pkthdr, const uint8_t* packet) {
    ETH_EAP_FRAME _frame;
    IF_IMPL* this = (IF_IMPL*)vthis;

    _frame.buffer_len = _frame.actual_len = pkthdr->caplen;
    _frame.content = (uint8_t*)packet;
    PRIV->handler(&_frame);
}

RESULT libpcap_set_ifname(struct _if_impl* this, const char* ifname) {
    strncpy(PRIV->ifname, ifname, IFNAMSIZ);
    return SUCCESS;
}

RESULT libpcap_get_ifname(struct _if_impl* this, char* buf, int buflen) {
    if (buflen < strnlen(PRIV->ifname, IFNAMSIZ)) {
        return FAILURE;
    }
    strncpy(buf, PRIV->ifname, buflen);
    return SUCCESS;
}

RESULT libpcap_setup_capture_params(struct _if_impl* this, unsigned short eth_protocol, int promisc) {
    PRIV->proto = eth_protocol;
    PRIV->promisc = promisc;
    return SUCCESS;
}

RESULT libpcap_prepare_interface(struct _if_impl* this) {
    char _err_buf[PCAP_ERRBUF_SIZE] = {0};
    PRIV->pcapdev = pcap_open_live(PRIV->ifname, FRAME_BUF_SIZE, PRIV->promisc, 100, _err_buf);
    if (PRIV->pcapdev == NULL) {
        PR_ERR("libpcap 打开设备失败： %s", _err_buf);
        return FAILURE;
    }

    char _filter_str[30] = {0};
    struct bpf_program _bpf;
    sprintf(_filter_str, "ether proto 0x%hx", PRIV->proto);
    if (pcap_compile(PRIV->pcapdev, &_bpf, _filter_str, 0, 0) < 0) {
        PR_ERR("libpcap 过滤器编译失败");
        return FAILURE;
    }

    if (pcap_setfilter(PRIV->pcapdev, &_bpf) < 0) {
        PR_ERR("libpcap 过滤器设置失败");
        return FAILURE;
    }
    return SUCCESS;
}

RESULT libpcap_start_capture(struct _if_impl* this) {
    pcap_loop(PRIV->pcapdev, -1, libpcap_packet_handler, (uint8_t*)this);
    return SUCCESS; /* No use if it's blocking... */
}

RESULT libpcap_stop_capture(struct _if_impl* this) {
    if (PRIV->pcapdev) {
        pcap_breakloop(PRIV->pcapdev);
        return SUCCESS;
    } else {
        return FAILURE;
    }
}

RESULT libpcap_send_frame(struct _if_impl* this, ETH_EAP_FRAME* frame) {
    if (!PRIV->pcapdev || pcap_sendpacket(PRIV->pcapdev, frame->content, frame->actual_len) < 0) {
        return FAILURE;
    }
    return SUCCESS;
}

void libpcap_set_frame_handler(struct _if_impl* this, void (*handler)(ETH_EAP_FRAME* frame)) {
    PRIV->handler = handler;
}

void libpcap_destroy(IF_IMPL* this) {
    if (PRIV->pcapdev) pcap_close(PRIV->pcapdev);
    free(PRIV);
    free(this);
}

IF_IMPL* libpcap_new() {
    IF_IMPL* this = (IF_IMPL*)malloc(sizeof(IF_IMPL));
    if (this == NULL) {
        PR_ERRNO("libpcap 主结构内存分配失败");
        return NULL;
    }
    memset(this, 0, sizeof(IF_IMPL));

    /* The priv pointer in if_impl.h is a libpcap_priv* here */
    this->priv = (libpcap_priv*)malloc(sizeof(libpcap_priv));
    if (this->priv == NULL) {
        PR_ERRNO("libpcap 私有结构内存分配失败");
        free(this);
        return NULL;
    }
    memset(this->priv, 0, sizeof(libpcap_priv));

    this->set_ifname = libpcap_set_ifname;
    this->get_ifname = libpcap_get_ifname;
    this->destroy = libpcap_destroy;
    this->setup_capture_params = libpcap_setup_capture_params;
    this->prepare_interface = libpcap_prepare_interface;
    this->start_capture = libpcap_start_capture;
    this->stop_capture = libpcap_stop_capture;
    this->send_frame = libpcap_send_frame;
    this->set_frame_handler = libpcap_set_frame_handler;
    this->name = "libpcap";
    this->description = "采用 libpcap 进行通信的可移植网络接口模块";
    return this;
}
IF_IMPL_INIT(libpcap_new);
