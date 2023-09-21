/*
 * General EAP config center
 */

#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>
#include <net/if.h>

#include "config.h"
#include "logging.h"
#include "misc.h"
#include "if_impl.h"
#include "packet_plugin.h"
#include "conf_parser.h"

static EAP_CONFIG g_eap_config;
static PROXY_CONFIG g_proxy_config;
static PROG_CONFIG g_prog_config;

static void configure_log_by_daemon_type(DAEMON_TYPE daemon_type) {
    switch (daemon_type) {
        case DAEMON_FOREGROUND:
            set_log_destination(LOG_TO_CONSOLE);
            break;
        case DAEMON_NO_LOG:
            set_log_file_path("/dev/null");
            set_log_destination(LOG_TO_FILE);
            break;
        case DAEMON_CONSOLE_LOG:
            set_log_destination(LOG_TO_CONSOLE);
            break;
        case DAEMON_FILE_LOG:
            set_log_file_path(g_prog_config.logfile);
            set_log_destination(LOG_TO_FILE);
            break;
    }
}

void load_default_params() {
#define PCFG g_prog_config
    PCFG.pidfile = strdup(DEFAULT_PIDFILE);
    PCFG.logfile = strdup(DEFAULT_LOGFILE);
    PCFG.restart_on_logoff = DEFAULT_RESTART_ON_LOGOFF;
    PCFG.wait_after_fail_secs = DEFAULT_WAIT_AFTER_FAIL_SECS;
    PCFG.daemon_type = DEFAULT_DAEMON_TYPE;
    PCFG.max_retries = DEFAULT_MAX_RETRIES;
    PCFG.max_failures = DEFAULT_MAX_FAILURES;
    PCFG.stage_timeout = DEFAULT_STAGE_TIMEOUT;
    PCFG.save_now = DEFAULT_SAVE_NOW;
    PCFG.auth_round = DEFAULT_AUTH_ROUND;
    PCFG.kill_type = DEFAULT_KILL_TYPE;

    configure_log_by_daemon_type(DEFAULT_DAEMON_TYPE);
}

/*
 * Loop on argv to find "--conf-file"
 */
RESULT parse_cmdline_conf_file(int argc, char* argv[]) {
    int i = 1;
    for (; i < argc; ++i) {
        if (strcmp(argv[i], "--conf-file") == 0) {
            if (i + 1 >= argc) {
                PR_ERR("--conf-file必须有一个参数");
                return FAILURE;
            } else {
                int _len = strnlen(argv[i + 1], MAX_PATH);
                g_prog_config.conffile = (char*)malloc(_len + 1);
                strncpy(g_prog_config.conffile, argv[i + 1], _len);
                g_prog_config.conffile[_len] = '\0';
            }
        }
    }

    if (g_prog_config.conffile == NULL)
        g_prog_config.conffile = strdup(DEFAULT_CONFFILE);

    return SUCCESS;
}

#define _STR(x) #x
#define STR(x) _STR(x)
static void print_cmdline_help() {
    PR_RAW("这是一个允许私有扩展的 802.1x 客户端，可通过插件实现私有部分的认证。\n");
    PR_RAW("\n以下选项中，[]表示可选参数，<>表示必选参数。\n\n");
    PR_RAW(
        "\t--help, -h\t显示本帮助\n"
        "\t--kill, -k [1]\t终止其他实例并退出。加任意非 0 参数表示终止其他实例后继续进行认证\n"
        "\t--save, -w\t保存本次认证所用参数\n"
        "\t--username, -u <...>\t用户名\n"
        "\t--password, -p <...>\t密码\n"
        "\t--nic, -n <...>\t\t要使用的网络界面名\n"
        "\t--stage-timeout, -t <num>\t单个认证阶段的超时时间 [默认" STR(DEFAULT_STAGE_TIMEOUT) "]\n"
        "\t--wait-after-fail, -r <num>\t认证失败后重新认证前的等待时间（但当服务器要求重新认证时将直接开始认证）[默认" STR(DEFAULT_WAIT_AFTER_FAIL_SECS) "]\n"
        "\t--max-fail, -l <num>\t最大允许认证失败次数 [默认" STR(DEFAULT_MAX_FAILURES) "]\n"
        "\t--no-auto-reauth, -x\t认证掉线后不允许自动重连 [默认" STR(DEFAULT_RESTART_ON_LOGOFF) "]\n"
        "\t--daemonize, -b <0-3>\t后台运行方式： [默认0]\n"
            "\t\t\t\t0 = 不后台\n"
            "\t\t\t\t1 = 后台运行，关闭输出\n"
            "\t\t\t\t2 = 后台运行，输出到当前控制台\n"
            "\t\t\t\t3 = 后台运行，输出到日志文件\n"
        "\t--proxy-lan-iface, -z <...>\t代理认证时的 LAN 网络界面名 [默认无]\n"
        "\t--auth-round, -j <num>\t需要认证的次数 [默认1]\n"
        "\t--max-retries <num>\t最大超时重试的次数 [默认3]\n"
        "\t--pid-file <...>\tPID 文件路径，设为none可禁用 [默认" DEFAULT_PIDFILE "]\n"
        "\t--conf-file <...>\t配置文件路径 [默认" DEFAULT_CONFFILE "]\n"
        "\t--if-impl <...>\t\t选择此网络操作模块，仅允许选择一次 [默认为第一个可用的模块]\n"
        "\t--pkt-plugin <...>\t启用此名称的数据包修改器，可启用多次、多个 [默认无]\n"
        "\t--module <...>\t\t同上\n"
            "\t\t\t\t当命令行选项中存在 --module 或 --pkt-plugin 时，配置文件中的所有 module= 行都将被忽略\n"
    );

    print_if_impl_list();
    packet_plugin_print_cmdline_help();

    PR_RAW("\n\033[1m注意：选项与参数之间必须用空格分开！\033[0m\n");

    _exit(EXIT_SUCCESS);
}

static void parse_one_opt(const char* option, const char* argument) {
#define ISOPT(x) (strcmp(option, x) == 0)

#define COPY_N_ARG_TO(buf, maxlen) \
        chk_free((void**)&buf); \
        buf = strndup(argument, maxlen);

    /* Sort by frequency of usage */
    if (ISOPT("username")) {
        COPY_N_ARG_TO(g_eap_config.username, USERNAME_MAX_LEN);
    } else if (ISOPT("password")) {
        COPY_N_ARG_TO(g_eap_config.password, PASSWORD_MAX_LEN);
    } else if (ISOPT("nic")) {
        COPY_N_ARG_TO(g_prog_config.ifname, IFNAMSIZ);
    } else if (ISOPT("daemonize")) {
        g_prog_config.daemon_type = atoi(argument) % 4;
    } else if (ISOPT("pkt-plugin") || ISOPT("module")) {
        insert_data(&g_prog_config.packet_plugin_list, (void*)argument);
    } else if (ISOPT("if-impl")) {
        COPY_N_ARG_TO(g_prog_config.if_impl, IFNAMSIZ);
    } else if (ISOPT("save")) {
        g_prog_config.save_now = 1;
    } else if (ISOPT("help")) {
        print_cmdline_help(); /* 调用本函数将退出程序 */
    } else if (ISOPT("max-fail")) {
        g_prog_config.max_failures = atoi(argument);
    } else if (ISOPT("max-retries")) {
        g_prog_config.max_retries = atoi(argument);
    } else if (ISOPT("no-auto-reauth")) {
        g_prog_config.restart_on_logoff = 0;
    } else if (ISOPT("wait-after-fail")) {
        g_prog_config.wait_after_fail_secs = atoi(argument);
    } else if (ISOPT("stage-timeout")) {
        g_prog_config.stage_timeout = atoi(argument);
    } else if (ISOPT("kill")) {
        if (argument == NULL)
            g_prog_config.kill_type = KILL_ONLY; /* 结束其他实例并退出 */
        else
            g_prog_config.kill_type = KILL_AND_START; /* 结束其他实例，本实例继续运行 */
    } else if (ISOPT("proxy-lan-iface")) {
        g_proxy_config.proxy_on = 1;
        COPY_N_ARG_TO(g_proxy_config.lan_ifname, IFNAMSIZ);
    } else if (ISOPT("auth-round")) {
        g_prog_config.auth_round = atoi(argument);
    } else if (ISOPT("pid-file")) {
        COPY_N_ARG_TO(g_prog_config.pidfile, MAX_PATH);
    } else if (ISOPT("log-file")) {
        COPY_N_ARG_TO(g_prog_config.logfile, MAX_PATH);
    }
}

RESULT parse_cmdline_opts(int argc, char* argv[]) {
    int opt = 0;
    int longIndex = 0;
    int cmd_module_list_reset = FALSE;
    static const char* shortOpts = "-:hk::wu:p:n:t:r:l:x:b:c:z:j:";
    static const struct option longOpts[] = {
	    { "help", no_argument, NULL, 'h' },
	    { "kill", optional_argument, NULL, 'k' },
	    { "save", no_argument, NULL, 'w' }, // --save, -w
	    { "username", required_argument, NULL, 'u' },
	    { "password", required_argument, NULL, 'p' },
	    { "nic", required_argument, NULL, 'n' },
	    { "stage-timeout", required_argument, NULL, 't' },
	    { "wait-after-fail", required_argument, NULL, 'r' },
	    { "max-fail", required_argument, NULL, 'l' },
	    { "no-auto-reauth", no_argument, NULL, 'x' },
	    { "daemonize", required_argument, NULL, 'b' },
	    { "proxy-lan-iface", required_argument, NULL, 'z' },
	    { "auth-round", required_argument, NULL, 'j' },
	    { "max-retries", required_argument, NULL, 0},
	    { "pid-file", required_argument, NULL, 0},
	    { "if-impl", required_argument, NULL, 0},
	    { "pkt-plugin", required_argument, NULL, 0},
	    { "module", required_argument, NULL, 0},
	    { "log-file", required_argument, NULL, 0},
	    { NULL, no_argument, NULL, 0 }
    };

    opt = getopt_long(argc, argv, shortOpts, longOpts, &longIndex);
    while (opt != -1) {
        switch (opt) {
            case ':':
                PR_ERR("缺少参数：%s", argv[optind - 1]);
                return FAILURE;
                break;
            case 0:
                if ((strcmp(longOpts[longIndex].name, "module") == 0 ||
                    strcmp(longOpts[longIndex].name, "pkt-plugin") == 0)
                    && cmd_module_list_reset == FALSE) {
                    /* When there is at least one "--module" provided on the cmdline,
                       give up all the plugins read from config file.
                       Otherwise this would cause confusion / duplication.
                       Do not free content here. This should be done in conf_parser_free()
                     */
                    list_destroy(&g_prog_config.packet_plugin_list, FALSE);
                    cmd_module_list_reset = TRUE;
                }
                // fall thru
            default:
                if (opt > 0) {
                    // Short options here. longIndex = 0 in this case.
                    longIndex = shortopt2longindex(opt, longOpts, sizeof(longOpts) / sizeof(struct option));
                }
                if (longIndex >= 0) {
                    parse_one_opt(longOpts[longIndex].name, optarg);
                }
                break;
        }
        opt = getopt_long(argc, argv, shortOpts, longOpts, &longIndex);
    }
    configure_log_by_daemon_type(g_prog_config.daemon_type);
    return SUCCESS;
}

static void parser_traverser(CONFIG_PAIR* pair, void* unused) {
    if (pair->value[0] == 0) {
        return; /* Refuse options without value. At least there should be no-auto-reauth=1 */
    }
    parse_one_opt(pair->key, pair->value);
}

RESULT parse_config_file(const char* filepath) {
    conf_parser_set_file_path(filepath);
    if (IS_FAIL(conf_parser_parse_now())) {
        return FAILURE;
    }
    conf_parser_traverse(parser_traverser, NULL);
    return SUCCESS;
}

RESULT save_config_file() {
    char itoa_buf[12]; /* -2147483647\0 */
    conf_parser_free(); /* Save some meaningless lookup / free */
    conf_parser_add_value("username", g_eap_config.username);
    conf_parser_add_value("password", g_eap_config.password);
    conf_parser_add_value("nic", g_prog_config.ifname);
    save_active_packet_plugin_list();
    conf_parser_add_value("daemonize", my_itoa(g_prog_config.daemon_type, itoa_buf, 10));
    conf_parser_add_value("if-impl", get_if_impl()->name);
    conf_parser_add_value("max-fail", my_itoa(g_prog_config.max_failures, itoa_buf, 10));
    conf_parser_add_value("max-retries", my_itoa(g_prog_config.max_retries, itoa_buf, 10));
    conf_parser_add_value("no-auto-reauth", g_prog_config.restart_on_logoff ? "0" : "1");
    conf_parser_add_value("wait-after-fail", my_itoa(g_prog_config.wait_after_fail_secs, itoa_buf, 10));
    conf_parser_add_value("stage-timeout", my_itoa(g_prog_config.stage_timeout, itoa_buf, 10));
    conf_parser_add_value("proxy-lan-iface", g_proxy_config.lan_ifname);
    conf_parser_add_value("auth-round", my_itoa(g_prog_config.auth_round, itoa_buf, 10));
    conf_parser_add_value("pid-file", g_prog_config.pidfile);
    conf_parser_add_value("log-file", g_prog_config.logfile);
    packet_plugin_save_config();
    return conf_parser_save_file();
}
/*
 * Validate basic parameters (username, password, network interface).
 * If more than one of them is missing, refuse to proceed.
 */
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

/*
 * Free everything we created for options,
 * for e.g. char* produced by strdup() and lists by --module
 */
void free_config() {
    chk_free((void**)&g_prog_config.ifname);
    chk_free((void**)&g_prog_config.pidfile);
    chk_free((void**)&g_prog_config.logfile);
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
