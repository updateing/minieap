#ifndef _MINIEAP_IF_IMPL_H
#define _MINIEAP_IF_IMPL_H

#include <stdint.h>
#include "minieap_common.h"
#include "eth_frame.h"
#include "linkedlist.h"

typedef struct _ip_addr {
    unsigned short family;
    uint8_t ip[16]; /* IPv4 and IPv6. IPv4 takes first 4 bytes */
} IP_ADDR;

/*
 * Representing an interface driver plugin.
 * Main program should exit after any FAILURE returning value
 */
typedef struct _if_impl {
    /*
     * Called by main program when it's starting.
     * Can be used to open the interface.
     *
     * Return: if the initialization succeeds
     */
    RESULT (*set_ifname)(struct _if_impl* this, const char* ifname);
    
    /*
     * Called by main program when it's exiting.
     * Can be used to free memory.
     */
    void (*destroy)(struct _if_impl* this);
    
    /*
     * Called by main program when it wants MAC address
     * for a specific network interface into address_buf.
     *
     * Return: if the MAC address was successfully retrived
     */
    RESULT (*obtain_mac)(struct _if_impl* this, uint8_t* address_buf);
    
    /*
     * Get all IPv4v6 address on the interface. List content would be
     * struct IP_ADDR.
     *
     * Return: if the operation was successful
     */
    RESULT (*obtain_ip)(struct _if_impl* this, LIST_ELEMENT** list);
     
     /*
      * Called by main program when capturing parameters are ready.
      * (Ethernet protocol number and promiscuous mode request)
      * Can be used to set up packet filter or promiscuous mode.
      *
      * Return: if the setup was successful
      */
    RESULT (*setup_capture_params)(struct _if_impl* this, short eth_protocol, int promisc);

    /*
     * Called by main program when the capturing start/stop.
     * Can be used to launch/terminate the actual capturing process.
     * Note: `start_capture` could be blocking.
     *
     * Return: if capturing started/stopped successfully
     */
    RESULT (*start_capture)(struct _if_impl* this);
    RESULT (*stop_capture)(struct _if_impl* this);
    
    /*
     * Send a frame per request.
     *
     * Return: if the frame was successfully sent
     */
    RESULT (*send_frame)(struct _if_impl* this, ETH_EAP_FRAME* frame);
        
    /*
     * Called by main program when there is a frame handler.
     * A frame handler is a function called when the filter receives
     * a network frame.
     * Can be used to obtain the callback function (and call it when
     * a frame arrives)
     */
    void (*set_frame_handler)(struct _if_impl* this, void (*handler)(ETH_EAP_FRAME* frame));
    
    /*
     * Implementation name, to be selected by user
     */
    char* name;
    
    /*
     * Description, displayed to user
     */
    char* description;
    
    /*
     * For plugin private use, a plugin can malloc and save data here.
     * Main program should not touch this pointer.
     */
    void* priv;
} IF_IMPL;

/*
 * Initialize the network interface plugin/driver list.
 *
 * Return: number of plugins loaded
 */
int init_if_impl_list();

/*
 * Select one implementation with given name for usage.
 *
 * Return: if the specific implementation was found.
 */
RESULT select_if_impl(const char* name);
/*
 * Get selected implementation
 */
IF_IMPL* get_if_impl();
#endif
