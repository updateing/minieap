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
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#ifdef __linux__
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_packet.h>
#endif

#ifdef __APPLE__
#include <net/if_dl.h>
#include <net/if.h>
#include <net/route.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <netinet/in.h>
#endif

static int ip_addr_family_cmpfunc(void* family, void* ip_addr) {
    if (*(short*)family == ((IP_ADDR*)ip_addr)->family) {
        return 0;
    }
    return 1;
}

IP_ADDR* find_ip_with_family(LIST_ELEMENT* list, short family) {
    return (IP_ADDR*)lookup_data(list, &family, ip_addr_family_cmpfunc);
}

RESULT obtain_iface_mac(const char* ifname, uint8_t* adr_buf) {
    struct ifaddrs *ifaddrs, *if_curr;
    if (getifaddrs(&ifaddrs) < 0) {
        PR_ERRNO("通过 getifaddrs 获取 MAC 地址失败");
        return FAILURE;
    }

    if_curr = ifaddrs;
    do {
        if (strcmp(if_curr->ifa_name, ifname) == 0) {
#ifdef __linux__
            if (if_curr->ifa_addr->sa_family == AF_PACKET) {
                memmove(adr_buf, ((struct sockaddr_ll*)if_curr->ifa_addr)->sll_addr, 6);
            }
#else
            if (if_curr->ifa_addr->sa_family == AF_LINK) {
                memmove(adr_buf, LLADDR((struct sockaddr_dl*)if_curr->ifa_addr), 6);
            }
#endif
        }
    } while ((if_curr = if_curr->ifa_next));
    freeifaddrs(ifaddrs);
    return SUCCESS;
}

RESULT obtain_iface_ip_mask(const char* ifname, LIST_ELEMENT** list) {
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
                if (if_curr->ifa_netmask) {
                    memmove(addr->mask, &((struct sockaddr_in*)if_curr->ifa_netmask)->sin_addr, 4);
                }
            } else if (addr->family == AF_INET6) {
                memmove(addr->ip, &((struct sockaddr_in6*)if_curr->ifa_addr)->sin6_addr, 16);
                if (if_curr->ifa_netmask) {
                    memmove(addr->mask, &((struct sockaddr_in6*)if_curr->ifa_netmask)->sin6_addr, 16);
                }
            }
            insert_data(list, addr);
        }
    } while ((if_curr = if_curr->ifa_next));
    freeifaddrs(ifaddrs);
    return SUCCESS;
}

void free_ip_list(LIST_ELEMENT** list) {
    list_destroy(list, TRUE);
}

RESULT obtain_dns_list(LIST_ELEMENT** list) {
    FILE* _fp = fopen("/etc/resolv.conf", "r");
    char _line_buf[MAX_LINE_LEN] = {0};
    char* _line_buf_1;

    if (_fp == NULL) {
        PR_ERRNO("无法从 /etc/resolv.conf 获取 DNS 信息");
        return FAILURE;
    }

    while (fgets(_line_buf, MAX_LINE_LEN, _fp)) {
        if (_line_buf[0] != '#') {
            _line_buf_1 = strtok(_line_buf, " ");
            if (_line_buf_1 == NULL || strcmp(_line_buf_1, "nameserver") != 0) continue;
            _line_buf_1 = strtok(NULL, " ");
            if (_line_buf_1 != NULL) {
                int _len = strnlen(_line_buf_1, INET6_ADDRSTRLEN);
                if (_line_buf_1[_len - 1] == '\n') {
                    _line_buf_1[_len - 1] = 0;
                    _len--;
                }
                insert_data(list, strndup(_line_buf_1, _len));
            }
        }
    }
    fclose(_fp);
    return SUCCESS;
}

void free_dns_list(LIST_ELEMENT** list) {
    list_destroy(list, TRUE);
}

#ifdef __linux__
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
            struct nlmsgerr* _err = (struct nlmsgerr*) NLMSG_DATA(nlHdr);
            if (_err->error != 0) {
                PR_WARN("NETLINK 报告了一个错误 (%x)", _err->error);
                return msgLen - readLen;
            }
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
    struct in_addr dst_addr = {0}, this_gateway = {0};
    int rtLen = 0;
    char this_ifname[IFNAMSIZ] = {0};

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
            if_indextoname(*(uint32_t *) RTA_DATA(rtAttr), this_ifname);
            break;
        case RTA_GATEWAY:
            this_gateway.s_addr = *(uint32_t *) RTA_DATA(rtAttr);
            break;
        case RTA_DST:
            dst_addr.s_addr = *(uint32_t *) RTA_DATA(rtAttr);
            break;
        }
    }

#ifdef DEBUG
    PR_DBG("%08X %08X %s", dst_addr.s_addr, this_gateway.s_addr, this_ifname);
#endif
    if (dst_addr.s_addr == 0 && strncmp(this_ifname, ifname, IFNAMSIZ) == 0) {
        gateway->s_addr = this_gateway.s_addr;
        return SUCCESS;
    }
    return FAILURE;
}

RESULT obtain_iface_ipv4_gateway(const char* ifname, uint8_t* buf) {
    struct nlmsghdr *nl_msg;
    uint8_t msg_buf[NL_BUFSIZE];

    int sockfd, len, msg_seq = 0, rand_pid = rand() % 65536;

    if ((sockfd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0) {
        PR_ERRNO("NETLINK 套接字打开失败");
        return FAILURE;
    }
    struct sockaddr_nl nl_addr;
    nl_addr.nl_family = AF_NETLINK;
    nl_addr.nl_pid = rand_pid;
    bind(sockfd, (struct sockaddr*)&nl_addr, sizeof(nl_addr));

    memset(msg_buf, 0, sizeof(msg_buf));

    /* Point the header and the msg structure pointers into the buffer */
    nl_msg = (struct nlmsghdr *) msg_buf;

    /* Fill in the nlmsg header*/
    nl_msg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));  // Length of message.
    nl_msg->nlmsg_type = RTM_GETROUTE;   // Get the routes from kernel routing table.
    nl_msg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;    // The message is a request for dump.
    nl_msg->nlmsg_seq = msg_seq++;    // Sequence of the message packet.
    nl_msg->nlmsg_pid = rand_pid;    // PID of process sending the request.

    struct rtmsg *rtMsg;
    rtMsg = (struct rtmsg *) NLMSG_DATA(nl_msg);
    rtMsg->rtm_table = RT_TABLE_MAIN;
    rtMsg->rtm_family = AF_INET;

    /* Send the request */
    if (send(sockfd, nl_msg, nl_msg->nlmsg_len, 0) < 0) {
        PR_ERRNO("无法向 NETLINK 发送请求");
        goto err;
    }

    /* Read the response */
    if ((len = read_from_netlink_socket(sockfd, msg_buf, msg_seq, rand_pid)) < 0) {
        goto err;
    }

    /* Parse and print the response */
    for (; NLMSG_OK(nl_msg, len); nl_msg = NLMSG_NEXT(nl_msg, len)) {
        struct in_addr addr;
        memset(&addr, 0, sizeof(struct in_addr));
        if (!IS_FAIL(retrive_if_gateway(ifname, nl_msg, &addr))) {
            /* IPv4 Only */
            memmove(buf, &addr.s_addr, 4);
            close(sockfd);
            return SUCCESS;
        }
    }
err:
    close(sockfd);
    return FAILURE;
}
#elif defined __APPLE__
/* alignment constraint for routing socket */
#define ROUNDUP(a) \
       ((a) > 0 ? (1 + (((a) - 1) | (sizeof(uint32_t) - 1))) : sizeof(uint32_t))

static void get_rtaddrs(int addrs, struct sockaddr *sa, struct sockaddr **rti_info) {
    int i;

    for (i = 0; i < RTAX_MAX; i++) {
        if (addrs & (1 << i)) {
            rti_info[i] = sa;
            sa = (struct sockaddr *)(ROUNDUP(sa->sa_len) + (char *)sa);
        } else {
            rti_info[i] = NULL;
        }
    }
}

RESULT obtain_iface_ipv4_gateway(const char* ifname, uint8_t* _buf) {
    size_t needed;
    int mib[6];
    char *buf, *next, *lim;
    struct rt_msghdr2 *rtm;

    mib[0] = CTL_NET;
    mib[1] = PF_ROUTE;
    mib[2] = 0;
    mib[3] = 0;
    mib[4] = NET_RT_DUMP2;
    mib[5] = 0;
    if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0) {
        PR_ERR("sysctl: net.route.0.0.dump estimate");
        return FAILURE;
    }

    if ((buf = malloc(needed)) == 0) {
        PR_ERR("malloc(%lu)", (unsigned long)needed);
        return FAILURE;
    }
    if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0) {
        PR_ERR("sysctl: net.route.0.0.dump");
        free(buf);
        return FAILURE;
    }

    lim  = buf + needed;
    for (next = buf; next < lim; next += rtm->rtm_msglen) {
        struct sockaddr *sa, *rti_info[RTAX_MAX];
        char this_ifname[IFNAMSIZ + 1];

        rtm = (struct rt_msghdr2 *)next;
        sa = (struct sockaddr *)(rtm + 1);

        /*
        * Skip protocol-cloned routes.
        */
        if ((rtm->rtm_flags & RTF_WASCLONED) &&
            (rtm->rtm_parentflags & RTF_PRCLONING)) {
                continue;
        }

        if (sa->sa_family != AF_INET)
            continue;

        get_rtaddrs(rtm->rtm_addrs, sa, rti_info);
        if ((rtm->rtm_addrs & RTA_DST)) {
            struct sockaddr_in *dst_addr = (struct sockaddr_in *)rti_info[RTAX_DST],
            *this_gateway = (struct sockaddr_in *)rti_info[RTAX_GATEWAY];

            if_indextoname(rtm->rtm_index, this_ifname);

            if (dst_addr->sin_addr.s_addr == 0 && strncmp(this_ifname, ifname, IFNAMSIZ) == 0) {
                *(in_addr_t *)_buf = this_gateway->sin_addr.s_addr;
                free(buf);
                return SUCCESS;
            }
        }
    }

    free(buf);
    return FAILURE;
}
#endif
