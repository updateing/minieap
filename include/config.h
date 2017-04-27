#ifndef _MINIEAP_CONFIG_H
#define _MINIEAP_CONFIG_H

#include "minieap_common.h"
#include "linkedlist.h"
#include "if_impl.h"

#include <net/if.h>

#define USERNAME_MAX_LEN 64
#define PASSWORD_MAX_LEN 64

/*
 * EAP credentials
 */
typedef struct _eap_config {
    char* username;
    char* password;
} EAP_CONFIG;

/*
 * Proxy mode config
 */
typedef struct _proxy_config {
    int proxy_on;
    char* lan_ifname;
    IF_IMPL* if_impl;
} PROXY_CONFIG;

/*
 * Behavior of `-k`
 */
typedef enum _kill_type {
    /* Do not kill anyone */
    KILL_NONE,
    /* Kill other instances and exit */
    KILL_ONLY,
    /* Kill others and start */
    KILL_AND_START
} KILL_TYPE;

typedef enum _daemon_type {
    /* Run in foreground and log to console */
    DAEMON_FOREGROUND,
    /* Run in background and disable logging */
    DAEMON_NO_LOG,
    /* Run in background and log to console */
    DAEMON_CONSOLE_LOG,
    /* Run in background and log to file (PROG_CONFIG.logfile) */
    DAEMON_FILE_LOG
} DAEMON_TYPE;

/*
 * General program config
 */
typedef struct _prog_config {
    /*
     * Interface to operate on.
     * WAN interface when proxy mode on.
     */
    char* ifname;
    //#define DEFAULT_IFNAME NULL

    /*
     * PID file, avoid multiple instances.
     * "none" to disable.
     */
    char* pidfile;
    #define DEFAULT_PIDFILE "/var/run/minieap.pid"

    /*
     * Config file path
     * Will read everything from the file,
     * but cmdline opts may override it.
     */
    char* conffile;
    #define DEFAULT_CONFFILE "/etc/minieap.conf"

    /*
     * Config file path
     * Will read everything from the file,
     * but cmdline opts may override it.
     */
    char* logfile;
    #define DEFAULT_LOGFILE "/var/log/minieap.log"

    /*
     * Selected interface implementation: how to drive network adapters?
     */
    char* if_impl;
    //define DEFAULT_IF_IMPL "sockraw"

    /*
     * Selected packet plugins: how you want to alter the packets?
     */
    LIST_ELEMENT* packet_plugin_list;

    /*
     * Whether to restart after being forced offline by server.
     * Mostly due to same account being used elsewhere (classroom)
     * and timed access control.
     */
    int restart_on_logoff;
    #define DEFAULT_RESTART_ON_LOGOFF TRUE

    /*
     * Wait seconds after failure before next try.
     */
    int wait_after_fail_secs;
    #define DEFAULT_WAIT_AFTER_FAIL_SECS 30

    /*
     * Whether to daemonize and how to deal with logs
     */
    DAEMON_TYPE daemon_type;
    #define DEFAULT_DAEMON_TYPE DAEMON_FOREGROUND

    /*
     * Max number of retries(timeouts) before we have a result, success or failure.
     */
    int max_retries;
    #define DEFAULT_MAX_RETRIES 3

    /*
     * Max number of CONTINOUS failures before we exit.
     */
    int max_failures;
    #define DEFAULT_MAX_FAILURES 3

    /*
     * Timeout (seconds) waiting for server reply in each stage
     */
    int stage_timeout;
    #define DEFAULT_STAGE_TIMEOUT 5

    /*
     * Whether to save parameters to file
     */
    int save_now;
    #define DEFAULT_SAVE_NOW FALSE

    /*
     * How many auths it takes to finish the actual authentication process.
     * This is non-standard (mainly for proxy) - but you can leave it alone.
     */
    int auth_round;
    #define DEFAULT_AUTH_ROUND 1

    /*
     * How to kill other instances
     */
    KILL_TYPE kill_type;
    #define DEFAULT_KILL_TYPE KILL_NONE
} PROG_CONFIG;

/*
 * Default settings
 */
void load_default_params();

/*
 * Fill in the PROG_CONFIG->conffile field only.
 * Used to implement cmdline option overriding.
 */
RESULT parse_cmdline_conf_file(int argc, char* argv[]);

/*
 * Parse command line parameters
 */
RESULT parse_cmdline_opts(int argc, char* argv[]);

/*
 * Read from config file
 */
RESULT parse_config_file(const char* filename);

/*
 * If everything is given
 */
RESULT validate_params();

/*
 * Atexit
 */
void free_config();

/*
 * Save to file
 */
RESULT save_config_file();

PROG_CONFIG* get_program_config();
EAP_CONFIG* get_eap_config();
PROXY_CONFIG* get_proxy_config();

#endif
