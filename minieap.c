#include "config.h"
#include "if_impl.h"
#include "linkedlist.h"
#include "packet_plugin.h"
#include "packet_builder.h"
#include "logging.h"
#include "eap_state_machine.h"
#include "sched_alarm.h"

#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <signal.h>
#include <time.h>

/*
 * Initialize the settings.
 * Note: Override values in config file with cmdline.
 */
static int init_program_config(int argc, char* argv[]) {
    PROG_CONFIG* cfg;
    if (IS_FAIL(parse_cmdline_conf_file(argc, argv))) {
        PR_ERR("配置文件路径解析出错");
        goto err;
    }

    cfg = get_program_config();
    if (IS_FAIL(parse_config_file(cfg->conffile))) {
        PR_ERR("配置文件内容解析出错");
        goto err;
    }
    if (IS_FAIL(parse_cmdline_opts(argc, argv))) {
        PR_ERR("命令行参数解析出错");
        goto err;
    }

    return validate_params();
err:
    return FAILURE;
}

/*
 * Initialize the settings. Called after plugins being selected.
 * Note: Override values in config file with cmdline.
 */
static int init_plugin_config(int argc, char* argv[]) {
    PROG_CONFIG *cfg = get_program_config();
    if (IS_FAIL(packet_plugin_process_config_file(cfg->conffile))) {
        PR_ERR("插件配置文件内容解析出错");
        goto err;
    }
    if (IS_FAIL(packet_plugin_process_cmdline_opts(argc, argv))) {
        PR_ERR("插件命令行参数解析出错");
        goto err;
    }
    return packet_plugin_validate_params();
err:
    return FAILURE;
}

static void packet_plugin_list_select(void* name, void* unused) {
    select_packet_plugin((const char* )name);
}

/*
 * Do all the initialization tasks
 */
static int init_cfg(int argc, char* argv[]) {
    PROG_CONFIG* cfg = get_program_config();

    set_log_destination(LOG_TO_CONSOLE);

    init_if_impl_list();
    init_packet_plugin_list();

    load_default_params();
    if (IS_FAIL(init_program_config(argc, argv))) {
        PR_ERR("参数初始化错误");
        return FAILURE;
    }

    list_traverse(cfg->packet_plugin_list, packet_plugin_list_select, NULL);

    if (IS_FAIL(select_if_impl(cfg->if_impl))) {
        PR_ERR("网络驱动插件启用失败，请检查插件名称是否拼写正确");
        return FAILURE;
    }

    packet_plugin_load_default_params();
    if (IS_FAIL(init_plugin_config(argc, argv))) {
        PR_ERR("插件初始化错误");
        return FAILURE;
    }

    return SUCCESS;
}

static int init_if() {
    PROG_CONFIG* cfg = get_program_config();
    IF_IMPL* if_impl;

    if_impl = get_if_impl();
    if (IS_FAIL(if_impl->set_ifname(if_impl,cfg->ifname))) {
        PR_ERR("设置接口名称失败");
        return FAILURE;
    }

    if (IS_FAIL(if_impl->setup_capture_params(if_impl, htons(ETH_P_PAE), FALSE))) {
        PR_ERR("设置捕获参数失败");
        return FAILURE;
    }

    if_impl->set_frame_handler(if_impl, eap_state_machine_recv_handler);

    return SUCCESS;
}

static void exit_handler() {
    free_config();
    free_if_impl();
    packet_plugin_destroy();
    eap_state_machine_destroy();
    sched_alarm_destroy();
    PR_INFO("MiniEAP 已退出");
    close_log();
};

static void signal_handler(int signal) {
    exit(0);
}

/*
 * Detailed errors are printed where they happen, not here ...
 */
int main(int argc, char* argv[]) {
    srand(time(0));
    atexit(exit_handler);
	signal(SIGHUP, signal_handler);
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

    if (IS_FAIL(init_cfg(argc, argv))) {
        return FAILURE;
    }

    if (IS_FAIL(init_if())) {
        return FAILURE;
    }

    if (IS_FAIL(eap_state_machine_init())) {
        return FAILURE;
    }

    if (IS_FAIL(sched_alarm_init())) {
        return FAILURE;
    }

    switch_to_state(EAP_STATE_PREPARING, NULL);

    return 0;
}
