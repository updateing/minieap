/*
 * General EAP config center
 */

#include <getopt.h>
#include <string.h>
#include <stdlib.h>

#include "config.h"
#include "logging.h"
#include "misc.h"

static EAP_CONFIG g_eap_config;
static PROXY_CONFIG g_proxy_config;
static PROG_CONFIG g_prog_config;

static void configure_daemon_param(int daemon_mode) {
    switch (daemon_mode) {
        case 0:
            g_prog_config.run_in_background = 0;
            set_log_destination(LOG_TO_CONSOLE);
            break;
        case 1:
        case 2:
            g_prog_config.run_in_background = 1;
            set_log_destination(LOG_TO_CONSOLE);
            break;
        case 3:
            g_prog_config.run_in_background = 1;
            set_log_destination(LOG_TO_FILE);
    }
}
     
RESULT parse_cmdline_opts(int argc, char* argv[]) {
    int opt = 0;
    int longIndex = 0;
    int _arglen = 0; /* 当前参数长度 */
    int _daemon_mode = 0; /* 稍后处理 */
    static const char* shortOpts = "hk::wu:p:n:i:m:g:s:o:t:e:r:l:x:a:d:b:"
        "v:f:c:z:j:q:";
    static const struct option longOpts[] = {
	    { "help", no_argument, NULL, 'h' },
	    { "kill", optional_argument, NULL, 'k' },
	    { "save", no_argument, NULL, 'w' }, // --save, -w
	    { "username", required_argument, NULL, 'u' },
	    { "password", required_argument, NULL, 'p' },
	    { "nic", required_argument, NULL, 'n' },
	    /*{ "ip", required_argument, NULL, 'i' },
	    { "mask", required_argument, NULL, 'm' },
	    { "gateway", required_argument, NULL, 'g' },
	    { "dns", required_argument, NULL, 's' },
	    { "ping-host", required_argument, NULL, 'o' },*/
	    { "auth-timeout", required_argument, NULL, 't' },
	    { "wait-after-fail", required_argument, NULL, 'r' },
	    { "max-fail", required_argument, NULL, 'l' },
	    { "no-auto-reauth", required_argument, NULL, 'x' },
	    { "dhcp-type", required_argument, NULL, 'd' },
	    { "daemonize", required_argument, NULL, 'b' },
	    { "run-on-success", required_argument, NULL, 'c' }, /* They are */
	    { "dhcp-script", required_argument, NULL, 'c' },    /* both 'c' */
	    { "proxy-lan-iface", required_argument, NULL, 'z' },
	    { "require-success", required_argument, NULL, 'j' },
	    { "decode-config", required_argument, NULL, 'q' },
	    { "max-retries", required_argument, NULL, 0},
	    { "pid-file", required_argument, NULL, 0},
	    { NULL, no_argument, NULL, 0 }
    };

    opt = getopt_long(argc, argv, shortOpts, longOpts, &longIndex);
#define COPY_N_ARG_TO(buf, maxlen) \
        _arglen = strnlen(optarg, maxlen); \
        chk_free((void**)&buf); \
        buf = (char*)malloc(_arglen); \
        strncpy(buf, optarg, _arglen);
    while (opt != -1) {
        switch (opt) {
            case 'h':
                //print_help(argv[0]); /* 调用本函数将退出程序 */
            case 'k':
                if (optarg == NULL)
                    g_prog_config.kill_type = KILL_ONLY; /* 结束其他实例并退出 */
                else
                    g_prog_config.kill_type = KILL_AND_START; /* 结束其他实例，本实例继续运行 */
                break;
            case 'w':
                g_prog_config.save_now = 1;
                break;
            case 'u':
                COPY_N_ARG_TO(g_eap_config.username, USERNAME_MAX_LEN);
                break;
            case 'p':
                COPY_N_ARG_TO(g_eap_config.password, PASSWORD_MAX_LEN);
                break;
            case 'n':
                COPY_N_ARG_TO(g_prog_config.ifname, IFNAME_MAX_LEN);
                break;
            /*case 'i':
                ip = inet_addr(optarg);
                break;
            case 'm':
                mask = inet_addr(optarg);
                break;
            case 'g':
                gateway = inet_addr(optarg);
                break;
            case 's':
                dns = inet_addr(optarg);
                break;
            case 'o':
                pingHost = inet_addr(optarg);
                break; TODO why is this needed*/
            case 't':
                g_prog_config.stage_timeout = atoi(optarg); /* 此处不设置限制，但原始的代码中有最大99秒的限制 */
                break;
            case 'r':
                g_prog_config.wait_after_fail_secs = atoi(optarg); /* 同上 */
                break;
            case 'l':
                g_prog_config.max_failures = atoi(optarg);
                break;
            case 'x':
                g_prog_config.restart_on_logoff = atoi(optarg);
                break;
            case 'b':
                _daemon_mode = atoi(optarg); /* 在循环结束后处理 */
                break;
            case 'c':
                COPY_N_ARG_TO(g_prog_config.run_on_success, MAX_PATH);
                break;
            case 'z':
                g_proxy_config.proxy_on = 1;
                COPY_N_ARG_TO(g_proxy_config.lan_ifname, IFNAME_MAX_LEN);
                break;
            case 'j':
                g_prog_config.require_successes = atoi(optarg);
                break;
            case 0: /* 超出26个字母的选项，没有短选项与其对应 */
#define IF_ARG(arg_name) (strcmp(longOpts[longIndex].name, arg_name) == 0)
                if (IF_ARG("max-retries")) {
                    g_prog_config.max_retries = atoi(optarg);
                } else if (IF_ARG("pid-file")) {
                    COPY_N_ARG_TO(g_prog_config.pidfile, MAX_PATH);
                }
                break;
            default:
                break;
        }
        opt = getopt_long(argc, argv, shortOpts, longOpts, &longIndex);
    }
    
    configure_daemon_param(_daemon_mode);
    return SUCCESS;
}

PROG_CONFIG* get_program_config() {
    return &g_prog_config;
}

EAP_CONFIG* get_eap_config() {
    return &g_eap_config;
}

PROXY_CONFIG* get_proxy_config() {
    return &g_proxy_config;
}
