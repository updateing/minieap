#ifndef _MINIEAP_CONFIG_H
#define _MINIEAP_CONFIG_H

#include "minieap_common.h"

#define USERNAME_MAX_LEN 64
#define PASSWORD_MAX_LEN 64
#define IFNAME_MAX_LEN 16
#define MAX_PATH 260

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
    /*
     * Turn off proxy after this number of success'es
     * Official RJ supplicant needs 2 success'es to enter
     * correct state.
     */
    int require_successes;
} PROXY_CONFIG;

/*
 * Behavior of `-k`
 */
typedef enum _kill_type {
    /* Kill other instances and exit */
    KILL_ONLY,
    /* Kill others and start */
    KILL_AND_START
} KILL_TYPE;

/*
 * General program config
 */
typedef struct _prog_config {
    /*
     * Interface to operate on.
     * WAN interface when proxy mode on.
     */
    char* ifname;
    
    /*
     * PID file, avoid multiple instances.
     * "none" to disable.
     */
    char* pidfile;
    
    /*
     * Logging config is applied in logging.c
     */
    // char* logfile;
    
    /*
     * Whether to restart after being forced offline by server.
     * Mostly due to same account being used elsewhere (classroom)
     * and timed access control.
     */
    int restart_on_logoff;
    
    /*
     * Wait seconds after failure before next try.
     */
    int wait_after_fail_secs;
    
    /*
     * Whether to daemonize.
     */
    int run_in_background;
    
    /*
     * Max number of retries(timeouts) before we have a result, success or failure.
     */
    int max_retries;
    
    /*
     * Max number of CONTINOUS failures before we exit.
     */
    int max_failures;
    
    /*
     * Timeout waiting for server reply in each stage
     */
    int stage_timeout;
    
    /*
     * Whether to save parameters to file
     */
    int save_now;
    
    /*
     * How to kill other instances
     */
    KILL_TYPE kill_type;
} PROG_CONFIG;

RESULT parse_cmdline_opts(int argc, char* argv[]);
RESULT parse_config_file(const char* filename);
#endif
