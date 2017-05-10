/*
 * MiniEAP Packet Modifiers / Plugins
 *
 * The packet plugins modify standard EAP packets before sending them, in order to
 * authenticate with servers running proprietary protocol extensions.
 *
 * Every plugin must implement ALL of the following functions except noted,
 * as well as a `new()` function which constructs its _packet_plugin structure (produce a new instance).
 * The `new()` function must be registered by PACKET_PLUGIN_INIT() macro.
 *
 * Each member function takes the pointer to the structure/instance as first parameter.
 *
 * Take a look at packet_plugin/printer/packet_plugin_printer.c for example.
 */
#ifndef _MINIEAP_PACKET_PLUGIN_H
#define _MINIEAP_PACKET_PLUGIN_H

#include "minieap_common.h"
#include "eth_frame.h"
#include "module_init.h"

#ifdef __linux__
#define PACKET_PLUGIN_INIT(func) __define_in_section(func, ".pktplugininit")
#else
#define PACKET_PLUGIN_INIT(func) __define_in_section(func, "__DATA,__pktplugininit")
#endif

typedef struct _packet_plugin {
    /*
     * Free `this`, `this->priv` and everything allocated dynamically.
     */
    void (*destroy)(struct _packet_plugin* this);

    /*
     * Parse command line options.
     *
     * The `argc` and `argv` is the same as what `main()` receives.
     * So be careful that there may be options for other plugins or main program.
     * Ignore unrecognized options nicely!
     *
     * Return: if there is any error during the process (malformed value, etc)
     */
    RESULT (*process_cmdline_opts)(struct _packet_plugin* this, int argc, char* argv[]);

    /*
     * Parse config from file.
     *
     * The file is the same as main program's config file. Better use a prefix
     * for plugin-specific options, and skip everything unrecognized.
     *
     * Note: this file may not exist at the moment.
     *
     * conf_parser_traverse is preferred for better safety and performance. (Ignore
     * `filepath` in this case, and do not open/parse here since main program handles this)
     *
     * Return: if there is any error during the process (malformed value, etc)
     */
    RESULT (*process_config_file)(struct _packet_plugin* this, const char* filepath);

    /*
     * Validate the parameters (from config file or overriden by cmdline)
     *
     * Return: if all mandatory params are valid/not null
     */
    RESULT (*validate_params)(struct _packet_plugin* this);

    /*
     * Print credit / version info
     */
    void  (*print_banner)(struct _packet_plugin* this);

    /*
     * Load the defaults
     */
    void (*load_default_params)(struct _packet_plugin* this);

    /*
     * Print help for command line options provided by this plugin.
     * Indent by a tab before each line.
     */
    void (*print_cmdline_help)(struct _packet_plugin* this);

    /*
     * Called by main program when the a standard EAP(oL) frame is ready
     * to be sent.
     * The frame will be sent immediately when this function returns.
     * Can be used to append proprietary fields or change destination address, etc.
     * This is where all the magic happens!
     *
     * You may need to check if we are in proxy mode and go different routines.
     *
     * Return: if the operation completed successfully
     */
    RESULT (*prepare_frame)(struct _packet_plugin* this, ETH_EAP_FRAME* frame);

    /*
     * Called by main program on arrival of new frames.
     * Can be used to read proprietary fields and update internal state.
     *
     * You may need to check if we are in proxy mode and go different routines.
     *
     * Return: if the frame is processed successfully
     */
    RESULT (*on_frame_received)(struct _packet_plugin* this, ETH_EAP_FRAME* frame);

    /*
     * Do not set this function since double authentication should be handled by RJv3
     * plugin internally. EAP standard does not define this behavior.
     * TODO This should be removed in the future.
     *
     * Old comment:
     * Sets the round number we are currently in.
     * This is useful in double authentication, where frames in round 1 and round 2
     * require different fields.
     */
    void (*set_auth_round)(struct _packet_plugin* this, int round);

    /*
     * Save parameters to config file.
     * conf_parser_add_value() is preferred.
     * No need to save here since main program will handle saving itself.
     */
    void (*save_config)(struct _packet_plugin* this);

    /*
     * Plugin name, to be shown to and selected by user
     */
    char* name;

    /*
     * Description, shown to user
     */
    char* description;

    /*
     * Version string, shown to user
     */
    char* version;

    /*
     * Plugin internal use. Other parts of the program should not access this field.
     */
    void* priv;
} PACKET_PLUGIN;

/* Initialize list of available plugins */
int init_packet_plugin_list();
/* Add this plugin to the active plugin list. May add the same plugin twice */
RESULT select_packet_plugin(const char* name);
/* Save all active plugins' name to file */
void save_active_packet_plugin_list();
/*
 * The event dispatchers!
 * Normally they will notify all active plugins about these events,
 * but a few of them work a bit differently. Take a look at `packet_plugin/packet_plugin.c`
 * for details.
 */
void packet_plugin_destroy();
RESULT packet_plugin_process_cmdline_opts(int argc, char* argv[]);
RESULT packet_plugin_validate_params();
void packet_plugin_print_banner();
void packet_plugin_load_default_params();
RESULT packet_plugin_process_config_file(const char* filepath);
void packet_plugin_print_cmdline_help();
RESULT packet_plugin_prepare_frame(ETH_EAP_FRAME* frame);
RESULT packet_plugin_on_frame_received(ETH_EAP_FRAME* frame);
void packet_plugin_set_auth_round(int round);
void packet_plugin_save_config();
#endif
