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
    /* The `priv` pointer in `if_plugin.h` is a sockraw_priv* here */
    this->priv = (sockraw_priv*)malloc(sizeof(sockraw_priv));
    memset(PRIV, 0, sizeof(sockraw_priv));
    
    if (this->priv < 0) {
        print_log("ERROR: %s: cannot allocate memory for file descriptor (%d)", __func__, errno);
        return FAILURE;
    }
    
    if (ifname == NULL) {
        print_log("ERROR: %s: ifname is null!", __func__);
        return FAILURE;
    }
    
    strncpy(PRIV->ifname, ifname, IFNAMSIZ);
    
    /* Default protocol is ETH_P_PAE (0x888e) */
    if ((PRIV->sockfd = socket(PF_PACKET, SOCK_RAW, ETH_P_PAE)) < 0) {
        print_log("ERROR: %s: socket open failed with %d", __func__, errno);
        return FAILURE;
    }
    
    return SUCCESS;
}

RESULT sockraw_obtain_mac(struct _if_plugin* this, uint8_t* adr_buf) {
    struct ifreq ifreq;

    strncpy(ifreq.ifr_name, PRIV->ifname, IFNAMSIZ);
    
    if (ioctl(PRIV->sockfd, SIOCGIFHWADDR, &ifreq) < 0) {
        print_log("ERROR: %s: ioctl failed with %d", __func__, errno);
        return FAILURE;
    }

    memcpy(adr_buf, ifreq.ifr_hwaddr.sa_data, 6);
    return SUCCESS;
}

RESULT sockraw_set_capture_params(struct _if_plugin* this, short eth_protocol, int promisc) {
    struct ifreq ifreq;
    int _curr_proto;
    unsigned int _opt_len = sizeof(int);
    
    /* Handle protocol */
    if (getsockopt(PRIV->sockfd, SOL_SOCKET, SO_PROTOCOL, &_curr_proto, &_opt_len) < 0) {
        print_log("ERROR: %s: getsockopt failed with %d", __func__, errno);
        return FAILURE;
    }
    
    if (_curr_proto != eth_protocol) {
        /* Socket protocol is not what we want. Reopen it. */
        close(PRIV->sockfd);
        
        if ((PRIV->sockfd = socket(PF_PACKET, SOCK_RAW, eth_protocol)) < 0) {
            print_log("ERROR: %s: socket open failed with %d", __func__, errno);
            return FAILURE;
        }
    }
    
    /* Handle promisc */    
    strncpy(ifreq.ifr_name, PRIV->ifname, IFNAMSIZ);
            
    if (ioctl(PRIV->sockfd, SIOCGIFFLAGS, &ifreq) < 0) {
        print_log("ERROR: %s: ioctl SIOCGIFFLAGS failed with %d", __func__, errno);
        return FAILURE;
    }
    
    if (promisc)
        ifreq.ifr_flags |= IFF_PROMISC;
    else
        ifreq.ifr_flags &= ~IFF_PROMISC;
    
    if (ioctl(PRIV->sockfd, SIOCSIFFLAGS, &ifreq) < 0) {
        print_log("ERROR: %s: ioctl SIOCSIFFLAGS failed with %d", __func__, errno);
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
