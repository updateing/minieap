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
        case 2:
            g_prog_config.run_in_background = 1;
            set_log_destination(LOG_TO_CONSOLE);
            break;
        case 1:
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

#define _STR(x) #x
#define STR(x) _STR(x)
static void print_cmdline_help() {
    PR_RAW(
        "\t--help, -h\t显示本帮助\n"
        "\t--kill, -k [1]\t终止其他实例并退出。加任意非 0 参数表示终止其他实例后继续进行认证\n"
        "\t--save, -w\t保存本次认证所用参数\n"
        "\t--username, -u <...>\t用户名\n"
        "\t--password, -p <...>\t密码\n"
        "\t--nic, -n <...>\t\t要使用的网络界面名\n"
        "\t--stage-timeout, -t <num>\t单个认证阶段的超时时间 [默认" STR(DEFAULT_STAGE_TIMEOUT) "]\n"
        "\t--wait-after-fail, -r <num>\t认证失败后重新认证前的等待时间（注意当服务器要求重新认证时将直接开始认证）[默认" STR(DEFAULT_WAIT_AFTER_FAIL_SECS) "]\n"
        "\t--max-fail, -l <num>\t最大允许认证失败次数 [默认" STR(DEFAULT_MAX_FAILURES) "]\n"
        "\t--no-auto-reauth, -x\t认证掉线后不允许自动重连 [默认" STR(DEFAULT_RESTART_ON_LOGOFF) "]\n"
        "\t--daemonize, -b <0-3>\t后台运行方式： [默认0]\n"
            "\t\t\t\t0 = 不后台\n"
            "\t\t\t\t1 = 后台运行，输出到当前控制台\n"
            "\t\t\t\t2 = 同3，为保持兼容性而设\n"
            "\t\t\t\t3 = 后台运行，输出到日志文件\n"
        "\t--run-on-success, -c <...>\t认证完成后运行此命令 [默认无]\n"
        "\t--dhcp-script <...>\t\t同上\n"
        "\t--proxy-lan-iface, -z <...>\t代理认证时的 LAN 网络界面名 [默认无]\n"
        "\t--auth-round, -j <num>\t需要认证的次数 [默认1]\n"
        "\t--max-retries <num>\t最大超时重试的次数 [默认3]\n"
        "\t--pid-file <...>\tPID 文件路径，设为none可禁用 [默认" DEFAULT_PIDFILE "]\n"
        "\t--conf-file <...>\t配置文件路径 [默认" DEFAULT_CONFFILE "]\n"
        "\t--if-impl <...>\t\t选择此网络操作抽象模块，仅允许选择一次 [默认" DEFAULT_IF_IMPL "]\n"
        "\t--pkt-plugin <...>\t启用此名称的数据包修改器，可启用多次、多个 [默认无]\n"
        "\t--module <...>\t\t同上\n"
    );

    packet_plugin_print_cmdline_help();

    PR_RAW("注意：选项与参数之间必须用空格分开！");

    _exit(EXIT_SUCCESS);
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
	    { "stage-timeout", required_argument, NULL, 't' },
	    { "wait-after-fail", required_argument, NULL, 'r' },
	    { "max-fail", required_argument, NULL, 'l' },
	    { "no-auto-reauth", no_argument, NULL, 'x' },
	    { "daemonize", required_argument, NULL, 'b' },
	    { "run-on-success", required_argument, NULL, 'c' }, /* They are */
	    { "dhcp-script", required_argument, NULL, 'c' },    /* both 'c' */
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
#define COPY_N_ARG_TO(buf, maxlen) \
        chk_free((void**)&buf); \
        buf = strndup(optarg, maxlen);
    while (opt != -1) {
        switch (opt) {
            case 'h':
                print_cmdline_help(); /* 调用本函数将退出程序 */
                break;
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
                g_prog_config.stage_timeout = atoi(optarg); /* 此处不设置限制，但原始的代码中有最大99秒的限制 */ //TODO
                break;
            case 'r':
                g_prog_config.wait_after_fail_secs = atoi(optarg); /* 同上 */
                break;
            case 'l':
                g_prog_config.max_failures = atoi(optarg);
                break;
            case 'x':
                g_prog_config.restart_on_logoff = 1;
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
