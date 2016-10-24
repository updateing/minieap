/*
 * General EAP config center
 */

#include <getopt.h>
#include <string.h>
#include <stdlib.h>
#include <net/if.h>

#include "config.h"
#include "logging.h"
#include "misc.h"
#include "if_impl.h"
#include "packet_plugin.h"

static EAP_CONFIG g_eap_config;
static PROXY_CONFIG g_proxy_config;
static PROG_CONFIG g_prog_config;

/*
 * We don't have a "daemon_mode" parameter, so translate
 * it to what we have.
 */
static void configure_daemon_log_param(int daemon_mode) {
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
            set_log_file_path(g_prog_config.logfile);
            set_log_destination(LOG_TO_FILE);
            break;
    }
}

void load_default_params() {
#define PCFG g_prog_config
    PCFG.pidfile = strdup(DEFAULT_PIDFILE);
    PCFG.if_impl = strdup(DEFAULT_IF_IMPL);
    PCFG.logfile = strdup(DEFAULT_LOGFILE);
    PCFG.restart_on_logoff = DEFAULT_RESTART_ON_LOGOFF;
    PCFG.wait_after_fail_secs = DEFAULT_WAIT_AFTER_FAIL_SECS;
    PCFG.run_in_background = DEFAULT_RUN_IN_BACKGROUND;
    PCFG.max_retries = DEFAULT_MAX_RETRIES;
    PCFG.max_failures = DEFAULT_MAX_FAILURES;
    PCFG.stage_timeout = DEFAULT_STAGE_TIMEOUT;
    PCFG.save_now = DEFAULT_STAGE_TIMEOUT;
    PCFG.auth_round = DEFAULT_AUTH_ROUND;
    PCFG.kill_type = DEFAULT_KILL_TYPE;

    configure_daemon_log_param(0); // No run in bg + log to console
}

RESULT parse_cmdline_conf_file(int argc, char* argv[]) {
    int i = 1;
    for (; i < argc; ++i) {
        if (strcmp(argv[i], "--conf-file") == 0) {
            if (i + 1 >= argc) {
                PR_ERR("--conf-file必须有一个参数");
                return FAILURE;
            } else {
                int _len = strnlen(argv[i + 1], MAX_PATH);
                g_prog_config.conffile = (char*)malloc(_len);
                strncpy(g_prog_config.conffile, argv[i + 1], _len);
            }
        }
    }

    if (g_prog_config.conffile == NULL)
        g_prog_config.conffile = strdup(DEFAULT_CONFFILE);

    return SUCCESS;
}

RESULT parse_cmdline_opts(int argc, char* argv[]) {
    int opt = 0;
    int longIndex = 0;
    int daemon_mode = 0; /* 涉及日志文件路径设定，稍后处理 */
    static const char* shortOpts = "-:hk::wu:p:n:t:e:r:l:x:a:d:b:"
        "v:f:c:z:j:q:";
    static const struct option longOpts[] = {
	    { "help", no_argument, NULL, 'h' },
	    { "kill", optional_argument, NULL, 'k' },
	    { "save", no_argument, NULL, 'w' }, // --save, -w
	    { "username", required_argument, NULL, 'u' },
	    { "password", required_argument, NULL, 'p' },
	    { "nic", required_argument, NULL, 'n' },
	    { "auth-timeout", required_argument, NULL, 't' },
	    { "wait-after-fail", required_argument, NULL, 'r' },
	    { "max-fail", required_argument, NULL, 'l' },
	    { "no-auto-reauth", required_argument, NULL, 'x' },
	    { "daemonize", required_argument, NULL, 'b' },
	    { "run-on-success", required_argument, NULL, 'c' }, /* They are */
	    { "dhcp-script", required_argument, NULL, 'c' },    /* both 'c' */
	    { "proxy-lan-iface", required_argument, NULL, 'z' },
	    { "auth-round", required_argument, NULL, 'j' },
	    { "decode-config", required_argument, NULL, 'q' },
	    { "max-retries", required_argument, NULL, 0},
	    { "pid-file", required_argument, NULL, 0},
	    { "if-impl", required_argument, NULL, 0},
	    { "pkt-plugin", required_argument, NULL, 0},
	    { "module", required_argument, NULL, 0},
	    { "log-file", required_argument, NULL, 0},
	    { NULL, no_argument, NULL, 0 }
    };

    opt = getopt_long(argc, argv, shortOpts, longOpts, &longIndex);
#define COPY_N_ARG_TO(buf, maxlen) \
        chk_free((void**)&buf); \
        buf = strndup(optarg, maxlen);
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
                COPY_N_ARG_TO(g_prog_config.ifname, IFNAMSIZ);
                break;
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
                daemon_mode = atoi(optarg) % 4;
                break;
            case 'c':
                COPY_N_ARG_TO(g_prog_config.run_on_success, MAX_PATH);
                break;
            case 'z':
                g_proxy_config.proxy_on = 1;
                COPY_N_ARG_TO(g_proxy_config.lan_ifname, IFNAMSIZ);
                break;
            case 'j':
                g_prog_config.auth_round = atoi(optarg);
                break;
            case 0: /* 超出26个字母的选项，没有短选项与其对应 */
#define IF_ARG(arg_name) (strcmp(longOpts[longIndex].name, arg_name) == 0)
                if (IF_ARG("max-retries")) {
                    g_prog_config.max_retries = atoi(optarg);
                } else if (IF_ARG("pid-file")) {
                    COPY_N_ARG_TO(g_prog_config.pidfile, MAX_PATH);
                } else if (IF_ARG("if-impl")) {
                    COPY_N_ARG_TO(g_prog_config.if_impl, IFNAMSIZ);
                } else if (IF_ARG("pkt-plugin") || IF_ARG("module")) {
                    insert_data(&g_prog_config.packet_plugin_list, optarg);
                } else if (IF_ARG("log-file")) {
                    COPY_N_ARG_TO(g_prog_config.logfile, MAX_PATH);
                }
                break;
            case ':':
                PR_ERR("缺少参数：%s", argv[optind - 1]);
                return FAILURE;
                break;
            default:
                break;
        }
        opt = getopt_long(argc, argv, shortOpts, longOpts, &longIndex);
    }

    configure_daemon_log_param(daemon_mode);
    return SUCCESS;
}

RESULT parse_config_file(const char* filepath) {
    return SUCCESS; // TODO
}

RESULT validate_params() {
#define ASSERT_NOTIFY(x, msg) \
    if (x) { \
        PR_ERR(msg); \
        return FAILURE; \
    }

    ASSERT_NOTIFY(!g_proxy_config.proxy_on && !g_eap_config.username, "用户名不能为空");
    ASSERT_NOTIFY(!g_proxy_config.proxy_on && !g_eap_config.password, "密码不能为空");
    ASSERT_NOTIFY(g_proxy_config.proxy_on && !g_proxy_config.lan_ifname,
                        "代理认证开启时，LAN 侧网卡名不能为空");
    ASSERT_NOTIFY(!g_prog_config.ifname, "网卡名不能为空");
    return SUCCESS;
}

void free_config() {
    chk_free((void**)&g_prog_config.run_on_success);
    chk_free((void**)&g_prog_config.ifname);
    chk_free((void**)&g_prog_config.pidfile);
    chk_free((void**)&g_prog_config.conffile);
    chk_free((void**)&g_prog_config.if_impl);
    list_destroy(&g_prog_config.packet_plugin_list, FALSE);

    chk_free((void**)&g_eap_config.username);
    chk_free((void**)&g_eap_config.password);

    chk_free((void**)&g_proxy_config.lan_ifname);
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
