#ifndef _MINIEAP_IF_PLUGIN_H
#define _MINIEAP_IF_PLUGIN_H

typedef struct _if_plugin_ops {
    /*
     * Called by main program when it's starting.
     * Can be used to initialize some plugin-specific vars.
     *
     * Return: if the initialization succeeds
     */
    RESULT (*init)();
    
    /*
     * Called by main program when it wants MAC address
     * for a specific network interface into address_buf.
     *
     * Return: if the MAC address was successfully retrived
     */
    RESULT (*obtain_mac)(const char* ifname, uint8_t* address_buf);
     
     /*
      * Called by main program when capturing parameters are ready.
      * (Ethernet protocol number and promiscuous mode request)
      * Can be used to set up packet filter or promiscuous mode.
      *
      * Return: if the setup was successful
      */
    RESULT (*setup_capture_params)(short eth_protocol, int promisc);
    
    /*
     * Called by main program when there is a frame handler.
     * A frame handler is a function called when the filter receives
     * a network frame.
     * Can be used to obtain the callback function (and call it when
     * a frame arrives)
     */
    void (*set_frame_handler)((void)(*handler)(ETH_EAP_FRAME* frame));
    
    /*
     * Called by main program when the capturing start.
     * Can be used to launch the actual capturing process.
     *
     * Return: if capturing started successfully
     */
    RESULT (*start_capture)();
    
    /*
     * Send a frame per request.
     *
     * Return: if the frame was successfully sent
     */
    RESULT (*send_frame)(ETH_EAP_FRAME* frame);
} if_plugin_ops;

