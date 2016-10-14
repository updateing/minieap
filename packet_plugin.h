#ifndef _MINIEAP_PACKET_PLUGIN_H
#define _MINIEAP_PACKET_PLUGIN_H

#include "minieap_common.h"
#include "eth_frame.h"

typedef struct _packet_plugin {
    /*
     * Called by main program when command line options are available.
     * Can be used to initialize custom options.
     *
     * Return: if there is any error during the process (malformed value, etc)
     */
    RESULT (*process_cmdline_opts)(int argc, char* argv[]);
    
    /*
     * Called by main program when printing help for command line options.
     */
    void (*print_cmdline_opts_help)();
    
    /*
     * Called by main program when the main program finishes filling
     * the standard ethernet and EAP(OL) fields in a ready-to-send frame.
     * Can be used to append custom padding or alter standard fields.
     */
    RESULT (*prepare_frame)(ETH_EAP_FRAME* frame);

    /*
     * Packet plugin internal use
     */
    void* priv;
} PACKET_PLUGIN;

#endif
