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
     * Called by main program when it knows the config file path.
     * Can be used to read from config file.
     * The file is the same as main program's config file. Better use a prefix
     * for plugin-specific options.
     *
     * Note: this file may not exist at the moment.
     *
     * Return: if there is any error during the process (malformed value, etc)
     */
    RESULT (*process_config_file)(struct _packet_plugin* this, const char* filepath);
    
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
     * Sets the round number we are currently in.
     * This is useful in double authentication, where frames in round 1 and round 2
     * require different fields.
     */
    void (*set_auth_round)(struct _packet_plugin* this, int round);
    
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

/* Call the right start of program */
int init_packet_plugin_list();
/* Add this plugin to the active plugin list. May add one plugin twice */
RESULT select_packet_plugin(const char* name);
/*
 * The event dispatchers! They will notify all active plugins about these events
 */
void packet_plugin_destroy();
RESULT packet_plugin_process_cmdline_opts(int argc, char* argv[]);
RESULT packet_plugin_process_config_file(char* filepath);
void packet_plugin_print_cmdline_help();
RESULT packet_plugin_prepare_frame(ETH_EAP_FRAME* frame);
RESULT packet_plugin_on_frame_received(ETH_EAP_FRAME* frame);
void packet_plugin_set_auth_round(int round);
#endif
