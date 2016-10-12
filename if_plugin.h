#ifndef _MINIEAP_IF_PLUGIN_H
#define _MINIEAP_IF_PLUGIN_H

#include <stdint.h>
#include "minieap_common.h"
#include "eth_frame.h"

/*
 * Representing an interface driver plugin.
 * Main program should exit after any FAILURE returning value
 */
typedef struct _if_plugin {
    /*
     * Called by main program when it's starting.
     * Can be used to open the interface, initialize
     * the `priv` pointer and set function pointers in `this`.
     *
     * Return: if the initialization succeeds
     */
    RESULT (*init)(struct _if_plugin* this, const char* ifname);
    
    /*
     * Called by main program when it wants MAC address
     * for a specific network interface into address_buf.
     *
     * Return: if the MAC address was successfully retrived
     */
    RESULT (*obtain_mac)(struct _if_plugin* this, uint8_t* address_buf);
     
     /*
      * Called by main program when capturing parameters are ready.
      * (Ethernet protocol number and promiscuous mode request)
      * Can be used to set up packet filter or promiscuous mode.
      *
      * Return: if the setup was successful
      */
    RESULT (*setup_capture_params)(struct _if_plugin* this, short eth_protocol, int promisc);

    /*
     * Called by main program when the capturing start/stop.
     * Can be used to launch/terminate the actual capturing process.
     * Note: `start_capture` could be blocking.
     *
     * Return: if capturing started/stopped successfully
     */
    RESULT (*start_capture)(struct _if_plugin* this);
    RESULT (*stop_capture)(struct _if_plugin* this);
    
    /*
     * Send a frame per request.
     *
     * Return: if the frame was successfully sent
     */
    RESULT (*send_frame)(struct _if_plugin* this, ETH_EAP_FRAME* frame);
        
    /*
     * Called by main program when there is a frame handler.
     * A frame handler is a function called when the filter receives
     * a network frame.
     * Can be used to obtain the callback function (and call it when
     * a frame arrives)
     */
    void (*set_frame_handler)(struct _if_plugin* this, void (*handler)(ETH_EAP_FRAME* frame));
    
    /*
     * For plugin private use, a plugin can malloc and save data here.
     * Main program should not touch this pointer.
     */
    void* priv;
} if_plugin;

#endif
