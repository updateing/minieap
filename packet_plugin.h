#ifndef _MINIEAP_PACKET_PLUGIN_H
#define _MINIEAP_PACKET_PLUGIN_H

#include "minieap_common.h"
#include "eth_frame.h"

typedef struct _packet_plugin {
    /*
     * Called by main program when it's exiting.
     * Can be used to free memory.
     */
    void (*destroy)(struct _packet_plugin* this);
    
    /*
     * Called by main program when command line options are available.
     * Can be used to initialize custom options.
     *
     * Return: if there is any error during the process (malformed value, etc)
     */
    RESULT (*process_cmdline_opts)(struct _packet_plugin* this, int argc, char* argv[]);
    
    /*
     * Called by main program when printing help for command line options.
     */
    void (*print_cmdline_help)(struct _packet_plugin* this);
    
    /*
     * Called by main program when the main program finishes filling
     * the standard ethernet and EAP(OL) fields in a ready-to-send frame.
     * Can be used to append custom padding or alter standard fields.
     *
     * Return: if the maniputation completed successfully
     */
    RESULT (*prepare_frame)(struct _packet_plugin* this, ETH_EAP_FRAME* frame);

    /*
     * Called by main program when we received a packet.
     * Can be used to process proprietary field.
     *
     * Return: if the frame is processed successfully
     */
    RESULT (*on_frame_received)(struct _packet_plugin* this, ETH_EAP_FRAME* frame);
    
    /*
     * Plugin name, to be selected by user
     */
    char* name;
    
    /*
     * Description, displayed to user
     */
    char* description;
    
    /*
     * Packet plugin internal use
     */
    void* priv;
} PACKET_PLUGIN;

#endif
