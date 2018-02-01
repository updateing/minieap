/*
 * Implement packet sending/receiving by BPF,
 * so libpcap could be left out in the build.
 */
#include "if_impl.h"
#include "minieap_common.h"
#include "logging.h"
#include "misc.h"

#include <net/if.h>
#include <net/ethernet.h> // ETHERTYPE_PAE
#include <net/bpf.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>

#define BPF_BUFFER_SIZE 1600 /* I'm lazy */

typedef struct _if_impl_bpf_priv {
    int bpffd; /* Internal use */
    int stop_flag; /* Set to break out of recv loop */
    int promisc;
    char ifname[IFNAMSIZ];
    short proto; /* Stored as host byte order */
    void (*handler)(ETH_EAP_FRAME* frame); /* Packet handler */
} bpf_priv;

#define PRIV ((bpf_priv*)(this->priv))

static RESULT bpf_open(struct _if_impl* this) {
    int no;
    char pathbuf[12]; /* /dev/bpf255\0 */
    for (no = 0; no < 256; no++) {
        sprintf(pathbuf, "/dev/bpf%d", no);
        if ((PRIV->bpffd = open(pathbuf, O_RDWR)) > 0) {
            return SUCCESS;
        }
    }
    return FAILURE;
}

static struct bpf_program* bpf_generate_proto_filter(short proto) {
    static struct bpf_insn bpf_proto_filter_insns[] = {
        BPF_STMT(BPF_LD|BPF_H|BPF_ABS, 12),                     /* 000 acc_lo = packet[12] */
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, ETHERTYPE_PAE, 0, 1),   /* 001 if (acc_lo == PAE) goto PC+0(002) else goto PC+1(003) */
        BPF_STMT(BPF_RET|BPF_K, 1500),                          /* 002 return 1500 (capture all bytes) */
        BPF_STMT(BPF_RET|BPF_K, 0),                             /* 003 return 0 */
    };
    static struct bpf_program bpf_proto_filter = {
        .bf_len = sizeof(bpf_proto_filter_insns) / sizeof(struct bpf_insn),
        .bf_insns = bpf_proto_filter_insns,
    };

    bpf_proto_filter_insns[1].k = (unsigned short)proto; /* Change the proto value, this will be expanded to 32bits */
    return &bpf_proto_filter;
}

RESULT bpf_set_ifname(struct _if_impl* this, const char* ifname) {
    strncpy(PRIV->ifname, ifname, IFNAMSIZ);
    return SUCCESS;
}

RESULT bpf_get_ifname(struct _if_impl* this, char* buf, int buflen) {
    if (buflen < strnlen(PRIV->ifname, IFNAMSIZ)) {
        return FAILURE;
    }
    strncpy(buf, PRIV->ifname, IFNAMSIZ);
    return SUCCESS;
}

RESULT bpf_setup_capture_params(struct _if_impl* this, unsigned short eth_protocol, int promisc) {
    PRIV->proto = eth_protocol;
    PRIV->promisc = promisc;
    return SUCCESS;
}

RESULT bpf_prepare_interface(struct _if_impl* this) {
    struct ifreq ifreq;
    int tmp = 0;

    if (IS_FAIL(bpf_open(this))) {
        PR_ERRNO("BPF 设备打开失败");
        return FAILURE;
    }

    tmp = 1;
    if (ioctl(PRIV->bpffd, BIOCIMMEDIATE, &tmp) < 0) {
        PR_ERRNO("BPF 设置立即模式失败，认证可能有延迟或出现丢包");
    }

    tmp = BPF_BUFFER_SIZE;
    if (ioctl(PRIV->bpffd, BIOCSBLEN, &tmp) < 0) {
        PR_ERRNO("BPF 缓冲区大小设置失败");
        return FAILURE;
    }

    if (ioctl(PRIV->bpffd, BIOCSETF, bpf_generate_proto_filter(PRIV->proto)) < 0) {
        PR_ERRNO("BPF 过滤器设置失败");
        return FAILURE;
    }

    tmp = 1;
    if (ioctl(PRIV->bpffd, BIOCSHDRCMPLT, &tmp) < 0) {
        PR_ERRNO("BPF 设置不更改链路源层地址失败");
        /* Do we really need this? */
    }

    if (PRIV->promisc) {
        if (ioctl(PRIV->bpffd, BIOCPROMISC, NULL) < 0) {
            PR_ERRNO("BPF 设置混杂模式失败，可能无法接收数据包");
        }
    }

    memset(&ifreq, 0 , sizeof(ifreq));
    strncpy(ifreq.ifr_name, PRIV->ifname, IFNAMSIZ);
    if (ioctl(PRIV->bpffd, BIOCSETIF, &ifreq) < 0) {
        PR_ERRNO("BPF 设置接口名称失败");
        return FAILURE;
    }

    return SUCCESS;
}

RESULT bpf_start_capture(struct _if_impl* this) {
    unsigned char* bpfbuf;
    ETH_EAP_FRAME frame;

    if ((bpfbuf = (unsigned char*)malloc(BPF_BUFFER_SIZE)) == NULL) {
        PR_ERRNO("BPF 分配接收缓冲区失败");
        return FAILURE;
    }

    memset(bpfbuf, 0, BPF_BUFFER_SIZE);
    frame.actual_len = 0;
    frame.buffer_len = FRAME_BUF_SIZE;

    while (read(PRIV->bpffd, (void*)bpfbuf, BPF_BUFFER_SIZE) > 0 && PRIV->stop_flag == 0) {
        frame.actual_len = ((struct bpf_hdr*)bpfbuf)->bh_caplen;
        frame.content = bpfbuf + ((struct bpf_hdr*)bpfbuf)->bh_hdrlen;
        PRIV->handler(&frame);
    }

    free(bpfbuf);
    PRIV->stop_flag = 0;
    return SUCCESS; /* No use if it's blocking... */
}

RESULT bpf_stop_capture(struct _if_impl* this) {
    PRIV->stop_flag = 1;
    return SUCCESS;
}

RESULT bpf_send_frame(struct _if_impl* this, ETH_EAP_FRAME* frame) {
    return write(PRIV->bpffd, frame->content, frame->actual_len) > 0 ? SUCCESS : FAILURE;
}

void bpf_set_frame_handler(struct _if_impl* this, void (*handler)(ETH_EAP_FRAME* frame)) {
    PRIV->handler = handler;
}

void bpf_destroy(IF_IMPL* this) {
    if (PRIV->bpffd > 0)
        close(PRIV->bpffd);
    chk_free((void**)&this->priv);
    chk_free((void**)&this);
}

IF_IMPL* bpf_new() {
    IF_IMPL* this = (IF_IMPL*)malloc(sizeof(IF_IMPL));
    if (this == NULL) {
        PR_ERRNO("BPF 主结构内存分配失败");
        return NULL;
    }
    memset(this, 0, sizeof(IF_IMPL));

    /* The priv pointer in if_impl.h is a bpf_priv* here */
    this->priv = (bpf_priv*)malloc(sizeof(bpf_priv));
    if (this->priv == NULL) {
        PR_ERRNO("BPF 私有结构内存分配失败");
        free(this);
        return NULL;
    }
    memset(this->priv, 0, sizeof(bpf_priv));

    this->set_ifname = bpf_set_ifname;
    this->get_ifname = bpf_get_ifname;
    this->destroy = bpf_destroy;
    this->setup_capture_params = bpf_setup_capture_params;
    this->prepare_interface = bpf_prepare_interface;
    this->start_capture = bpf_start_capture;
    this->stop_capture = bpf_stop_capture;
    this->send_frame = bpf_send_frame;
    this->set_frame_handler = bpf_set_frame_handler;
    this->name = "bpf";
    this->description = "采用 BPF (Berkeley Packet Filter) 进行通信的轻量网络接口模块";
    return this;
}
IF_IMPL_INIT(bpf_new);
