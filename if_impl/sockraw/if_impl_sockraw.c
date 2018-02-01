/*
 * Implement packet sending/receiving by native socket,
 * so libpcap could be left out in the build.
 */
#include "if_impl.h"
#include "minieap_common.h"
#include "logging.h"
#include "misc.h"

#include <netinet/in.h>
#include <linux/if_ether.h> // ETH_ALEN
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdlib.h>

typedef struct _if_impl_sockraw_priv {
    char ifname[IFNAMSIZ];
    int sockfd; /* Internal use */
    int if_index; /* Index of this interface */
    int stop_flag; /* Set to break out of recv loop */
    int promisc;
    short proto; /* Stored as host byte order */
    void (*handler)(ETH_EAP_FRAME* frame); /* Packet handler */
} sockraw_priv;

#define PRIV ((sockraw_priv*)(this->priv))

static void sockraw_bind_to_if(struct _if_impl* this, short protocol) {
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = PRIV->if_index;
    sll.sll_protocol = htons(protocol);
    bind(PRIV->sockfd, (struct sockaddr*)&sll, sizeof(sll));
}

RESULT sockraw_set_ifname(struct _if_impl* this, const char* ifname) {
    struct ifreq ifreq;
    int _tmpsockfd = 0;

    if ((_tmpsockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        PR_ERRNO("套接字打开失败");
        return FAILURE;
    }

    memset(&ifreq, 0, sizeof(struct ifreq));
    strncpy(ifreq.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(_tmpsockfd, SIOCGIFINDEX, &ifreq) < 0) {
        PR_ERRNO("网络界面 ID 获取失败");
        return FAILURE;
    }
    PRIV->if_index = ifreq.ifr_ifindex;

    strncpy(PRIV->ifname, ifname, IFNAMSIZ);
    close(_tmpsockfd);
    return SUCCESS;
}

RESULT sockraw_get_ifname(struct _if_impl* this, char* buf, int buflen) {
    if (buflen < strnlen(PRIV->ifname, IFNAMSIZ)) {
        return FAILURE;
    }
    strncpy(buf, PRIV->ifname, IFNAMSIZ);
    return SUCCESS;
}

RESULT sockraw_setup_capture_params(struct _if_impl* this, unsigned short eth_protocol, int promisc) {
    PRIV->proto = eth_protocol;
    PRIV->promisc = promisc;

    return SUCCESS;
}

RESULT sockraw_prepare_interface(struct _if_impl* this) {
    struct ifreq ifreq;

    if ((PRIV->sockfd = socket(AF_PACKET, SOCK_RAW, htons(PRIV->proto))) < 0) {
        PR_ERRNO("套接字打开失败");
        return FAILURE;
    }
    sockraw_bind_to_if(this, PRIV->proto);

    /* Handle promisc */
    memset(&ifreq, 0, sizeof(struct ifreq));
    strncpy(ifreq.ifr_name, PRIV->ifname, IFNAMSIZ);

    if (ioctl(PRIV->sockfd, SIOCGIFFLAGS, &ifreq) < 0) {
        PR_ERRNO("获取网络界面标志信息失败");
        return FAILURE;
    }

    if (PRIV->promisc)
        ifreq.ifr_flags |= IFF_PROMISC;
    else
        ifreq.ifr_flags &= ~IFF_PROMISC;

    if (ioctl(PRIV->sockfd, SIOCSIFFLAGS, &ifreq) < 0) {
        PR_ERRNO("混杂模式设置失败");
        return FAILURE;
    }
    return SUCCESS;
}

RESULT sockraw_start_capture(struct _if_impl* this) {
    uint8_t buf[FRAME_BUF_SIZE]; /* Max length of ethernet packet */
    int recvlen = 0;
    ETH_EAP_FRAME frame;

    memset(buf, 0, FRAME_BUF_SIZE);
    frame.actual_len = 0;
    frame.buffer_len = FRAME_BUF_SIZE;
    frame.content = buf;
    // TODO will ctrl-c break recv first or call signal handler first?
    while ((recvlen = recv(PRIV->sockfd, (void*)buf, 1512, 0)) > 0
                && PRIV->stop_flag == 0) {
        frame.actual_len = recvlen;
        PRIV->handler(&frame);
        memset(buf, 0, 1512);
    }

    PRIV->stop_flag = 0;
    return SUCCESS; /* No use if it's blocking... */
}

RESULT sockraw_stop_capture(struct _if_impl* this) {
    PRIV->stop_flag = 1;
    return SUCCESS;
}

RESULT sockraw_send_frame(struct _if_impl* this, ETH_EAP_FRAME* frame) {
    struct sockaddr_ll socket_address;
    if (frame == NULL || frame->content == NULL)
        return FAILURE;

    /* Send via this interface */
    memset(&socket_address, 0, sizeof(struct sockaddr_ll));
    socket_address.sll_ifindex = PRIV->if_index;
    socket_address.sll_halen = ETH_ALEN;
    memmove(socket_address.sll_addr, frame->header->eth_hdr.dest_mac, 6);

    int ret = sendto(PRIV->sockfd, frame->content, frame->actual_len, 0,
                (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll));
    if (ret < 0) {
        PR_ERRNO("sendto 调用失败");
        return FAILURE;
    } else {
        return SUCCESS;
    }
}

void sockraw_set_frame_handler(struct _if_impl* this, void (*handler)(ETH_EAP_FRAME* frame)) {
    PRIV->handler = handler;
}

void sockraw_destroy(IF_IMPL* this) {
    if (PRIV->sockfd > 0)
        close(PRIV->sockfd);
    chk_free((void**)&this->priv);
    chk_free((void**)&this);
}

IF_IMPL* sockraw_new() {
    IF_IMPL* this = (IF_IMPL*)malloc(sizeof(IF_IMPL));
    if (this == NULL) {
        PR_ERRNO("SOCK_RAW 主结构内存分配失败");
        return NULL;
    }
    memset(this, 0, sizeof(IF_IMPL));

    /* The priv pointer in if_impl.h is a sockraw_priv* here */
    this->priv = (sockraw_priv*)malloc(sizeof(sockraw_priv));
    if (this->priv == NULL) {
        PR_ERRNO("SOCK_RAW 私有结构内存分配失败");
        free(this);
        return NULL;
    }
    memset(this->priv, 0, sizeof(sockraw_priv));

    this->set_ifname = sockraw_set_ifname;
    this->get_ifname = sockraw_get_ifname;
    this->destroy = sockraw_destroy;
    this->setup_capture_params = sockraw_setup_capture_params;
    this->prepare_interface = sockraw_prepare_interface;
    this->start_capture = sockraw_start_capture;
    this->stop_capture = sockraw_stop_capture;
    this->send_frame = sockraw_send_frame;
    this->set_frame_handler = sockraw_set_frame_handler;
    this->name = "sockraw";
    this->description = "采用RAW Socket进行通信的轻量网络接口模块";
    return this;
}
IF_IMPL_INIT(sockraw_new)
