#ifndef _MINIEAP_NET_UTIL_H
#define _MINIEAP_NET_UTIL_H

#include "minieap_common.h"
#include "linkedlist.h"
#include <stdint.h>

typedef struct _ip_addr {
    unsigned short family;
    uint8_t ip[16]; /* IPv4 and IPv6. IPv4 takes first 4 bytes */
} IP_ADDR;

/*
 * Retrieves MAC address for a specific network interface into address_buf.
 *
 * Return: if the MAC address was successfully retrived
 */
RESULT obtain_iface_mac(const char* ifname, uint8_t* address_buf);

/*
 * Get all IPv4v6 address on the interface. List content would be
 * struct IP_ADDR.
 *
 * Remember to free the list after usage.
 *
 * Return: if the operation was successful
 */
RESULT obtain_iface_ip(const char* ifname, LIST_ELEMENT** list);
void free_ip_list(LIST_ELEMENT** list);

/*
 * Obtain a list of DNS servers in /etc/resolv.conf
 *
 * Remember to free the list after usage.
 *
 * Return: if the operation was successful
 */
RESULT obtain_dns_list(LIST_ELEMENT** list);
void free_dns_list(LIST_ELEMENT** list);
#endif
