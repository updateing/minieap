#include "linkedlist.h"
#include "minieap_common.h"
#include "packet_plugin.h"
#include "misc.h"
#include "logging.h"
#include "packet_plugin_rjv3_priv.h"
#include "packet_plugin_rjv3_prop.h"
#include "packet_plugin_rjv3_keepalive.h"
#include "packet_plugin_rjv3.h"
#include "sched_alarm.h"
#include "config.h"

#include <arpa/inet.h>
#include <getopt.h>
#include <stdlib.h>

#define PRIV ((rjv3_priv*)(this->priv))

void rjv3_destroy(struct _packet_plugin* this) {
    chk_free((void**)&PRIV->service_name);
    chk_free((void**)&PRIV->ver_str);
    chk_free((void**)&PRIV->fake_dns1);
    chk_free((void**)&PRIV->fake_dns2);
    chk_free((void**)&PRIV->fake_serial);
    list_destroy(&PRIV->cmd_prop_list, TRUE);
    list_destroy(&PRIV->cmd_prop_mod_list, TRUE);
    chk_free((void**)&this->priv);
    chk_free((void**)&this);
}

static void rjv3_reset_state(PACKET_PLUGIN* this) {
    PRIV->dhcp_count = 0;
    PRIV->succ_count = 0;
    if (PRIV->dhcp_type == DHCP_DOUBLE_AUTH) {
        rjv3_reset_priv_header();
    }
}

static RESULT append_rj_cmdline_opt(struct _packet_plugin* this, const char* opt) {
    // e.g. 6f:52472d535520466f72204c696e75782056312e3000
    //      type:content
    // sets client version string to "RG-SU For Linux V1.0"
    int _content_len, _curr_pos;
    uint8_t _type;
    uint8_t* _content_buf;
    char* _arg = strdup(opt);
    char* _split;

    if (_arg == NULL) {
        PR_ERRNO("无法为命令行的 --rj-option 参数分配内存空间");
        return FAILURE;
    }

    _split = strtok(_arg, ":");
    if (_split == NULL)
        goto malformat;
    _type = char2hex(_split);

    _split = strtok(NULL, ":");
    if (_split == NULL)
        goto malformat;

    _content_len = strnlen(_split, MAX_PROP_LEN);
    if ((_content_len & 1) == 1) _content_len += 1;
    _content_len >>= 1;
    _content_buf = (uint8_t*)malloc(_content_len); // divide by 2

    for (_curr_pos = 0; _curr_pos < _content_len; ++_curr_pos) {
        _content_buf[_curr_pos] = char2hex(_split + (_curr_pos << 1));
    }

    _split = strtok(NULL, ":");
    if (_split != NULL && _split[0] == 'r') {
        if (append_rjv3_prop(&PRIV->cmd_prop_mod_list, _type, _content_buf, _content_len) < 0) {
            goto fail;
        }
    } else {
        if (append_rjv3_prop(&PRIV->cmd_prop_list, _type, _content_buf, _content_len) < 0) {
            goto fail;
        }
    }

    free(_arg);
    free(_content_buf);
    return SUCCESS;

malformat:
    PR_ERR("--rj-option 的参数格式错误：%s", opt);
fail:
    free(_arg);
    return FAILURE;
}

void rjv3_print_cmdline_help(struct _packet_plugin* this) {
}

void rjv3_load_default_params(struct _packet_plugin* this) {
    PRIV->heartbeat_interval = DEFAULT_HEARTBEAT_INTERVAL;
    PRIV->service_name = strdup(DEFAULT_SERVICE_NAME);
    PRIV->ver_str = strdup(DEFAULT_VER_STR);
    PRIV->bcast_addr = DEFAULT_EAP_BCAST_ADDR;
    PRIV->dhcp_type = DEFAULT_DHCP_TYPE;
}

RESULT rjv3_process_cmdline_opts(struct _packet_plugin* this, int argc, char* argv[]) {
    int opt = 0;
    int longIndex = 0;
    static const char* shortOpts = "-:e:a:d:v:f:c:q:";
    static const struct option longOpts[] = {
	    { "heartbeat", required_argument, NULL, 'e' },
	    { "eap-bcast-addr", required_argument, NULL, 'a' },
	    { "dhcp-type", required_argument, NULL, 'd' },
	    { "decode-config", required_argument, NULL, 'q' },
	    { "rj-option", required_argument, NULL, 0 },
	    { "service", required_argument, NULL, 0 },
	    { "version-str", required_argument, NULL, 0 },
	    { "fake-dns1", required_argument, NULL, 0 },
	    { "fake-dns2", required_argument, NULL, 0 },
	    { "fake-serial", required_argument, NULL, 0 },
	    { NULL, no_argument, NULL, 0 }
    };

    opt = getopt_long(argc, argv, shortOpts, longOpts, &longIndex);
#define COPY_N_ARG_TO(buf, maxlen) \
        chk_free((void**)&buf); \
        buf = strndup(optarg, maxlen);
    while (opt != -1) {
        switch (opt) {
            case 'e':
                PRIV->heartbeat_interval = atoi(optarg);
                break;
            case 'a':
                PRIV->bcast_addr = atoi(optarg) % 2; /* 一共2个选项 */ // Do not allow CER
                break;
            case 'd':
                PRIV->dhcp_type = atoi(optarg) % 4;
                break;
            case 'q':
                // printSuConfig(optarg); TODO
                //exit(EXIT_SUCCESS);
                break;
            case 0:
#define IF_ARG(arg_name) (strcmp(longOpts[longIndex].name, arg_name) == 0)
                if (IF_ARG("rj-option")) {
                    /* Allow mulitple rj-options */
                    if (IS_FAIL(append_rj_cmdline_opt(this, optarg))) {
                        return FAILURE;
                    }
                } else if (IF_ARG("service")) {
                    COPY_N_ARG_TO(PRIV->service_name, RJV3_SIZE_SERVICE);
                } else if (IF_ARG("version-str")) {
                    COPY_N_ARG_TO(PRIV->ver_str, MAX_PROP_LEN);
                } else if (IF_ARG("fake-dns1")) {
                    COPY_N_ARG_TO(PRIV->fake_dns1, INET6_ADDRSTRLEN);
                } else if (IF_ARG("fake-dns2")) {
                    COPY_N_ARG_TO(PRIV->fake_dns2, INET6_ADDRSTRLEN);
                } else if (IF_ARG("fake-serial")) {
                    COPY_N_ARG_TO(PRIV->fake_serial, MAX_PROP_LEN);
                }
                break;
            case ':':
                PR_ERR("缺少参数：%s", argv[optind - 1]);
                return FAILURE;
            default:
                break;
        }
        opt = getopt_long(argc, argv, shortOpts, longOpts, &longIndex);
    }

    return SUCCESS;
}

RESULT rjv3_prepare_frame(struct _packet_plugin* this, ETH_EAP_FRAME* frame) {
    return rjv3_append_priv(this, frame);
}

static RESULT rjv3_process_success(struct _packet_plugin* this, ETH_EAP_FRAME* frame) {
    PRIV->succ_count++;
    if (IS_FAIL(rjv3_process_result_prop(frame))) {
        return FAILURE;
    }
    if (PRIV->dhcp_type == DHCP_DOUBLE_AUTH) {
        if (PRIV->succ_count < 2) {
            PR_INFO("正在执行 DHCP 脚本以准备第二次认证");
            system((get_program_config())->run_on_success); // TODO move this to plugin

            /* Try right after the script ends */
            rjv3_start_secondary_auth(this);

            return SUCCESS;
        } else {
            /* Double success */
            rjv3_reset_state(this);
            PR_INFO("二次认证成功");
        }
    }
    PR_INFO("正定时发送 Keep-Alive 报文以保持在线……");
    schedule_alarm(1, rjv3_send_keepalive_timed, this);
    return SUCCESS;
}

static RESULT rjv3_process_failure(PACKET_PLUGIN* this, ETH_EAP_FRAME* frame) {
    rjv3_process_result_prop(frame);
    rjv3_reset_state(this);
    return SUCCESS;
}

RESULT rjv3_on_frame_received(struct _packet_plugin* this, ETH_EAP_FRAME* frame) {
    PRIV->last_recv_packet = frame;

    if (frame->header->eapol_hdr.type[0] == EAP_PACKET) {
        if (frame->header->eap_hdr.code[0] == EAP_SUCCESS) {
            return rjv3_process_success(this, frame);
        } else if (frame->header->eap_hdr.code[0] == EAP_FAILURE) {
            return rjv3_process_failure(this, frame);
        }
    }
    return SUCCESS;
}

RESULT rjv3_process_config_file(struct _packet_plugin* this, const char* filepath) {
    return SUCCESS; // TODO
}

PACKET_PLUGIN* packet_plugin_rjv3_new() {
    PACKET_PLUGIN* this = (PACKET_PLUGIN*)malloc(sizeof(PACKET_PLUGIN));
    if (this < 0) {
        PR_ERRNO("RJv3 插件主结构内存分配失败");
        return NULL;
    }
    memset(this, 0, sizeof(PACKET_PLUGIN));

    this->priv = (rjv3_priv*)malloc(sizeof(rjv3_priv));
    if (this->priv < 0) {
        PR_ERRNO("RJv3 插件私有结构内存分配失败");
        free(this);
        return NULL;
    }
    memset(this->priv, 0, sizeof(rjv3_priv));

    this->name = "rjv3";
    this->description = "来自 hyrathb@GitHub 的 Ruijie V3 验证算法";
    this->destroy = rjv3_destroy;
    this->process_cmdline_opts = rjv3_process_cmdline_opts;
    this->load_default_params = rjv3_load_default_params;
    this->print_cmdline_help = rjv3_print_cmdline_help;
    this->prepare_frame = rjv3_prepare_frame;
    this->on_frame_received = rjv3_on_frame_received;
    this->process_config_file = rjv3_process_config_file;
    return this;
}
