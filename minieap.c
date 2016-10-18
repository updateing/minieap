#include "config.h"
#include "if_impl.h"
#include "linkedlist.h"
#include "packet_plugin.h"
#include "packet_builder.h"
#include "logging.h"
#include <stdlib.h>

/*
 * Initialize the settings.
 * Note: Override values in config file with cmdline.
 */
int init_program_config(int argc, char* argv[]) {
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

    return SUCCESS;
err:
    return FAILURE;
}

/*
 * Initialize the settings. Called after plugins being selected.
 * Note: Override values in config file with cmdline.
 */
int init_plugin_config(int argc, char* argv[]) {
    PROG_CONFIG *cfg = get_program_config();
    if (IS_FAIL(packet_plugin_process_config_file(cfg->conffile))) {
        PR_ERR("插件配置文件内容解析出错");
        goto err;
    }
    if (IS_FAIL(packet_plugin_process_cmdline_opts(argc, argv))) {
        PR_ERR("插件配置文件内容解析出错");
        goto err;
    }
    return SUCCESS;
err:
    return FAILURE;
}

void exit_handler() {
    free_config();
    (get_if_impl())->destroy(get_if_impl());
    packet_builder_destroy(packet_builder_get());
    packet_plugin_destroy();
    PR_INFO("MiniEAP 已退出");
};

int main(int argc, char* argv[]) {
    PROG_CONFIG* cfg = get_program_config();
    unsigned char mac[6];
    IF_IMPL* if_impl;
    
    atexit(exit_handler);
    
    /* Do these two first */
    init_if_impl_list();
    init_packet_plugin_list();
    if (IS_FAIL(init_program_config(argc, argv))) {}
        
    
    select_if_impl("sockraw");
    select_packet_plugin("rjv3");
    
    if_impl = get_if_impl();
    if_impl->set_ifname(if_impl,cfg->ifname);
    if_impl->obtain_mac(if_impl, mac);
    printf("%02x%02x%02x%02x%02x%02x\n", mac[0], mac[1],mac[2],mac[3],mac[4],mac[5]);

    return 0;
}

