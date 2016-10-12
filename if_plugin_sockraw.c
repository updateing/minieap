/*
 * Implement packet sending/receiving by native socket,
 * so libpcap could be left out in the build.
 */
#include "if_plugin.h"
#include "minieap_common.h"
#include "logging.h"
#include "misc.h"

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <malloc.h>

typedef struct _if_plugin_sockraw_priv {
    int sockfd; /* Internal use */
    char ifname[IFNAMSIZ];
    int stop_flag; /* Set to break out of recv loop */
    void (*handler)(ETH_EAP_FRAME* frame); /* Packet handler */
} sockraw_priv;

#define PRIV ((sockraw_priv*)(this->priv))

RESULT sockraw_init(struct _if_plugin* this, const char* ifname) {
    if (ifname == NULL) {
        PR_ERR("网卡名未指定，请检查 -n 的设置！");
        return FAILURE;
    }
    
    strncpy(PRIV->ifname, ifname, IFNAMSIZ);
    
    /* Default protocol is ETH_P_PAE (0x888e) */
    if ((PRIV->sockfd = socket(PF_PACKET, SOCK_RAW, ETH_P_PAE)) < 0) {
        PR_ERRNO("套接字打开失败");
        return FAILURE;
    }
    
    return SUCCESS;
}

RESULT sockraw_obtain_mac(struct _if_plugin* this, uint8_t* adr_buf) {
    struct ifreq ifreq;

    strncpy(ifreq.ifr_name, PRIV->ifname, IFNAMSIZ);
    
    if (ioctl(PRIV->sockfd, SIOCGIFHWADDR, &ifreq) < 0) {
        PR_ERRNO("通过 ioctl 获取 MAC 地址失败");
        return FAILURE;
    }

    memcpy(adr_buf, ifreq.ifr_hwaddr.sa_data, 6);
    return SUCCESS;
}

RESULT sockraw_setup_capture_params(struct _if_plugin* this, short eth_protocol, int promisc) {
    struct ifreq ifreq;
    int _curr_proto;
    unsigned int _opt_len = sizeof(int);
    
    /* Handle protocol */
    if (getsockopt(PRIV->sockfd, SOL_SOCKET, SO_PROTOCOL, &_curr_proto, &_opt_len) < 0) {
        PR_ERRNO("获取套接字参数失败");
        return FAILURE;
    }
    
    if (_curr_proto != eth_protocol) {
        /* Socket protocol is not what we want. Reopen it. */
        close(PRIV->sockfd);
        
        if ((PRIV->sockfd = socket(PF_PACKET, SOCK_RAW, eth_protocol)) < 0) {
            PR_ERRNO("套接字打开失败");
            return FAILURE;
        }
    }
    
    /* Handle promisc */    
    strncpy(ifreq.ifr_name, PRIV->ifname, IFNAMSIZ);
            
    if (ioctl(PRIV->sockfd, SIOCGIFFLAGS, &ifreq) < 0) {
        PR_ERRNO("获取网络界面参数失败");
        return FAILURE;
    }
    
    if (promisc)
        ifreq.ifr_flags |= IFF_PROMISC;
    else
        ifreq.ifr_flags &= ~IFF_PROMISC;
    
    if (ioctl(PRIV->sockfd, SIOCSIFFLAGS, &ifreq) < 0) {
        PR_ERRNO("开启混杂模式失败");
        return FAILURE;
    }
    return SUCCESS;
}

RESULT sockraw_start_capture(struct _if_plugin* this) {
    uint8_t buf[1512]; /* Max length of ethernet packet */
    int recvlen = 0;
    ETH_EAP_FRAME frame;
    
    memset(buf, 0, 1512);
    frame.len = 0;
    frame.content = buf;
    // TODO will ctrl-c break recv first or call signal handler first?
    while ((recvlen = recv(PRIV->sockfd, (void*)buf, 1512, 0)) > 0
                && PRIV->stop_flag == 0) {
        frame.len = recvlen;
        PRIV->handler(&frame);
        memset(buf, 0, 1512);
    }
    
    PRIV->stop_flag = 0;
    return SUCCESS; /* No use if it's blocking... */
}

RESULT sockraw_stop_capture(struct _if_plugin* this) {
    PRIV->stop_flag = 1;
    return SUCCESS;
}

RESULT sockraw_send_frame(struct _if_plugin* this, ETH_EAP_FRAME* frame) {
    if (frame == NULL || frame->content == NULL)
        return FAILURE;
    return send(PRIV->sockfd, frame->content, frame->len, 0) > 0;
}

void sockraw_set_frame_handler(struct _if_plugin* this, void (*handler)(ETH_EAP_FRAME* frame)) {
    PRIV->handler = handler;
}

void sockraw_shutdown(if_plugin* this) {
    chk_free((void**)&this->priv);
    chk_free((void**)&this);
}

if_plugin* sockraw_new() {
    if_plugin* this = (if_plugin*)malloc(sizeof(if_plugin));
    if (this->priv < 0) {
        PR_ERRNO("SOCK_RAW 主结构内存分配失败");
        return NULL;
    }
    memset(this, 0, sizeof(if_plugin));
    
    /* The priv pointer in if_plugin.h is a sockraw_priv* here */
    this->priv = (sockraw_priv*)malloc(sizeof(sockraw_priv));
    if (this->priv < 0) {
        PR_ERRNO("SOCK_RAW 私有结构内存分配失败");
        return NULL;
    }
    memset(this->priv, 0, sizeof(sockraw_priv));
    
    this->init = sockraw_init;
    this->shutdown = sockraw_shutdown;
    this->obtain_mac = sockraw_obtain_mac;
    this->setup_capture_params = sockraw_setup_capture_params;
    this->start_capture = sockraw_start_capture;
    this->stop_capture = sockraw_stop_capture;
    this->send_frame = sockraw_send_frame;
    this->set_frame_handler = sockraw_set_frame_handler;
    this->name = "sockraw";
    this->description = "采用RAW Socket进行通信的轻量网络接口模块";
    return this;
}
