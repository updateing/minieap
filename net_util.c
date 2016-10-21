#include "net_util.h"
#include "logging.h"
#include "misc.h"
#include "minieap_common.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>
#include <string.h>
#include <net/if.h>
#include <malloc.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

RESULT obtain_iface_mac(const char* ifname, uint8_t* adr_buf) {
    struct ifreq ifreq;
    int sockfd = -1;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) {
        PR_ERRNO("套接字打开失败");
        return FAILURE;
    }

    memset(&ifreq, 0, sizeof(struct ifreq));
    strncpy(ifreq.ifr_name, ifname, IFNAMSIZ);

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifreq) < 0) {
        PR_ERRNO("通过 ioctl 获取 MAC 地址失败");
        close(sockfd);
        return FAILURE;
    }

    memcpy(adr_buf, ifreq.ifr_hwaddr.sa_data, 6);
    close(sockfd);
    return SUCCESS;
}

RESULT obtain_iface_ip(const char* ifname, LIST_ELEMENT** list) {
    struct ifaddrs *ifaddrs, *if_curr;
    IP_ADDR *addr;
    if (getifaddrs(&ifaddrs) < 0) {
        PR_ERRNO("通过 getifaddrs 获取 IP 地址失败");
        return FAILURE;
    }

    if_curr = ifaddrs;
    do {
        if (strcmp(if_curr->ifa_name, ifname) == 0) {
            addr = (IP_ADDR*)malloc(sizeof(IP_ADDR));
            memset(addr, 0, sizeof(IP_ADDR));
            addr->family = if_curr->ifa_addr->sa_family;
            if (addr->family == AF_INET) {
                memmove(addr->ip, &((struct sockaddr_in*)if_curr->ifa_addr)->sin_addr, 4);
            } else if (addr->family == AF_INET6) {
                memmove(addr->ip, &((struct sockaddr_in6*)if_curr->ifa_addr)->sin6_addr, 16);
            }
            insert_data(list, addr);
        }
    } while ((if_curr = if_curr->ifa_next));
    return SUCCESS;
}

void free_ip_list(LIST_ELEMENT** list) {
    list_destroy(list, TRUE);
}

RESULT obtain_dns_list(LIST_ELEMENT** list) {
    FILE* _fp = fopen("/etc/resolv.conf", "r");
    char _line_buf[MAX_LINE_LEN] = {0};
    char* _line_buf_1;

    if (_fp <= 0) {
        PR_ERR("无法从 /etc/resolv.conf 获取 DNS 信息，请使用 --fake-dns 选项手动指定 DNS 地址: %s", ferror(_fp));
        return FAILURE;
    }

    while (fgets(_line_buf, MAX_LINE_LEN, _fp)) {
        if (_line_buf[0] != '#') {
            _line_buf_1 = strtok(_line_buf, " ");
            if (_line_buf == NULL || strcmp(_line_buf, "nameserver") != 0) continue;
            _line_buf_1 = strtok(NULL, " ");
            if (_line_buf != NULL) {
                int _len = strnlen(_line_buf_1, INET6_ADDRSTRLEN);
                if (_line_buf_1[_len - 1] == '\n') {
                    _line_buf_1[_len - 1] = 0;
                    _len--;
                }
                insert_data(list, strndup(_line_buf_1, _len));
            }
        }
    }

    return SUCCESS;
}

void free_dns_list(LIST_ELEMENT** list) {
    list_destroy(list, TRUE);
}

/* http://stackoverflow.com/a/3288983/5701966 */
#define NL_BUFSIZE 8192
static int read_from_netlink_socket(int sockfd, uint8_t *buf, int seq, int pid) {
    struct nlmsghdr *nlHdr;
    int readLen = 0, msgLen = 0;

    do {
        /* Recieve response from the kernel */
        if ((readLen = recv(sockfd, buf, NL_BUFSIZE - msgLen, 0)) < 0) {
            PR_ERRNO("无法从 NETLINK 接收数据");
            return -1;
        }

        nlHdr = (struct nlmsghdr *) buf;

        /* Check if the header is valid */
        if ((NLMSG_OK(nlHdr, readLen) == 0)
            || (nlHdr->nlmsg_type == NLMSG_ERROR)) {
            PR_ERRNO("NETLINK 报告了一个错误");
            return -1;
        }

         /* Check if the its the last message */
        if (nlHdr->nlmsg_type == NLMSG_DONE) {
            break;
        } else {
            /* Else move the pointer to buffer appropriately */
            buf += readLen;
            msgLen += readLen;
        }

        /* Check if its a multi part message */
        if ((nlHdr->nlmsg_flags & NLM_F_MULTI) == 0) {
            /* return if its not */
            break;
        }
    } while ((nlHdr->nlmsg_seq != seq) || (nlHdr->nlmsg_pid != pid));
    return msgLen;
}

static RESULT retrive_if_gateway(const char* ifname, struct nlmsghdr* nl_hdr, struct in_addr* gateway) {
    struct rtmsg *rtMsg;
    struct rtattr *rtAttr;
    struct in_addr dst_addr, this_gateway;
    int rtLen;
    char this_ifname[IFNAMSIZ];

    rtMsg = (struct rtmsg *) NLMSG_DATA(nl_hdr);

    /* If the route is not for AF_INET or does not belong to main routing table
       then return. Do not care about IPv6 for now. */
    if ((rtMsg->rtm_family != AF_INET) || (rtMsg->rtm_table != RT_TABLE_MAIN))
        return FAILURE;

    /* get the rtattr field */
    rtAttr = (struct rtattr *) RTM_RTA(rtMsg);
    rtLen = RTM_PAYLOAD(nl_hdr);
    for (; RTA_OK(rtAttr, rtLen); rtAttr = RTA_NEXT(rtAttr, rtLen)) {
        switch (rtAttr->rta_type) {
        case RTA_OIF:
            if_indextoname(*(int *) RTA_DATA(rtAttr), this_ifname);
            break;
        case RTA_GATEWAY:
            this_gateway.s_addr= *(u_int *) RTA_DATA(rtAttr);
            break;
        case RTA_DST:
            dst_addr.s_addr= *(u_int *) RTA_DATA(rtAttr);
            break;
        }
    }

    if (dst_addr.s_addr == 0 && strncmp(this_ifname, ifname, IFNAMSIZ)) {
        gateway->s_addr = this_gateway.s_addr;
        return SUCCESS;
    }
    return FAILURE;
}

RESULT obtain_iface_ipv4_gateway(const char* ifname, uint8_t* buf) {
    struct nlmsghdr *nl_msg;
    uint8_t msg_buf[NL_BUFSIZE];

    int sockfd, len, msg_seq = 0;

    if ((sockfd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0) {
        PR_ERRNO("NETLINK 套接字打开失败");
        return FAILURE;
    }

    /* Point the header and the msg structure pointers into the buffer */
    nl_msg = (struct nlmsghdr *) msg_buf;

    /* Fill in the nlmsg header*/
    nl_msg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));  // Length of message.
    nl_msg->nlmsg_type = RTM_GETROUTE;   // Get the routes from kernel routing table.

    nl_msg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;    // The message is a request for dump.
    nl_msg->nlmsg_seq = msg_seq++;    // Sequence of the message packet.
    nl_msg->nlmsg_pid = getpid();    // PID of process sending the request.

    /* Send the request */
    if (send(sockfd, nl_msg, nl_msg->nlmsg_len, 0) < 0) {
        PR_ERRNO("无法向 NETLINK 发送请求");
        return FAILURE;
    }

    /* Read the response */
    if ((len = read_from_netlink_socket(sockfd, msg_buf, msg_seq, getpid())) < 0) {
        return FAILURE;
    }

    /* Parse and print the response */
    for (; NLMSG_OK(nl_msg, len); nl_msg = NLMSG_NEXT(nl_msg, len)) {
        struct in_addr addr;
        memset(&addr, 0, sizeof(struct in_addr));
        if (!IS_FAIL(retrive_if_gateway(ifname, nl_msg, &addr))) {
            /* IPv4 Only */
            memmove(buf, &addr.s_addr, 4);
            break;
        }
    }
    close(sockfd);

    return SUCCESS;
}
