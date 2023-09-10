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
#include "conf_parser.h"
#include "packet_util.h"

#include <arpa/inet.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#define PRIV ((rjv3_priv*)(this->priv))

void rjv3_destroy(struct _packet_plugin* this) {
    chk_free((void**)&PRIV->service_name);
    chk_free((void**)&PRIV->ver_str);
    chk_free((void**)&PRIV->dhcp_script);
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
    PRIV->last_recv_packet = NULL;
    rjv3_keepalive_reset();
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

#define _STR(x) #x
#define STR(x) _STR(x)
void rjv3_print_cmdline_help(struct _packet_plugin* this) {
    PR_RAW(
        "\t--heartbeat, -e <num>\t\t心跳间隔秒数 [默认" STR(DEFAULT_HEARTBEAT_INTERVAL) "]\n"
        "\t--eap-bcast-addr, -a <0-1>\tStart 包广播地址： [默认" STR(DEFAULT_EAP_BCAST_ADDR) "]\n"
            "\t\t\t\t\t0 = 标准地址\n"
            "\t\t\t\t\t1 = 锐捷私有地址\n"
        "\t--dhcp-type, -d <0-3>\t\tDHCP 方式： [默认" STR(DEFAULT_DHCP_TYPE) "]\n"
            "\t\t\t\t\t0 = 不使用 DHCP\n"
            "\t\t\t\t\t1 = 二次认证\n"
            "\t\t\t\t\t2 = 认证后 DHCP\n"
            "\t\t\t\t\t3 = 认证前 DHCP\n"
        "\t--dhcp-script, -c <...>\t\t二次认证之间及认证完成后运行此命令 [默认无]\n"
        "\t--rj-option <type>:<value>[:r]\t自定义认证字段，其中 type 和 value 必须为十六进制串\n"
            "\t\t\t\t\t如 --rj-option 6a:000102 表示新增一条类型为 0x6a、内容为 0x00 0x01 0x02的字段\n"
            "\t\t\t\t\t:r 表示替换内置生成的字段，如 --rj-option 6f:000102:r 表示将内置算法生成的类型为 0x6f 的字段内容替换为 0x00 0x12 0x02\n"
            "\t\t\t\t\t当命令行与配置文件中同时存在此选项时，两处的选项都将发挥作用。若认证失败，请检查配置文件中是否有错误的参数\n"
        "\t--service <str>\t\t\t自定义服务名 [默认" DEFAULT_SERVICE_NAME "]\n"
        "\t--version-str <str>\t\t自定义版本字符串 [默认" DEFAULT_VER_STR "]\n"
        "\t--fake-dns1 <str>\t\t自定义主 DNS 地址（点分十进制 IPv4 格式） [默认自动获取]\n"
        "\t--fake-dns2 <str>\t\t自定义次 DNS 地址（IPv4 / IPv6 不限） [默认自动获取]\n"
        "\t--fake-serial <str>\t\t自定义硬盘序列号 [默认自动获取]\n"
        "\t--max-dhcp-count <num>\t\t二次认证时等待 DHCP 结果的允许超时次数 [默认" STR(DEFAULT_MAX_DHCP_COUNT) "]\n"
        "\t从 --service 到 --fake-serial（除 --fake-dns1）都是对应的 --rj-option 的简单形式，可直接使用 ASCII 字符串作为参数，不需转化为十六进制表示\n"
        );
}

void rjv3_load_default_params(struct _packet_plugin* this) {
    PRIV->heartbeat_interval = DEFAULT_HEARTBEAT_INTERVAL;
    PRIV->max_dhcp_count = DEFAULT_MAX_DHCP_COUNT;
    PRIV->service_name = strdup(DEFAULT_SERVICE_NAME);
    PRIV->ver_str = strdup(DEFAULT_VER_STR);
    PRIV->dhcp_script = strdup(DEFAULT_DHCP_SCRIPT);
    PRIV->bcast_addr = DEFAULT_EAP_BCAST_ADDR;
    PRIV->dhcp_type = DEFAULT_DHCP_TYPE;
}

static RESULT rjv3_parse_one_opt(struct _packet_plugin* this, const char* option, const char* argument) {
#define COPY_N_ARG_TO(buf, maxlen) \
    chk_free((void**)&buf); \
    buf = strndup(argument, maxlen);

#define ISOPT(arg_name) (strcmp(option, arg_name) == 0)
    if (ISOPT("heartbeat")) {
        PRIV->heartbeat_interval = atoi(argument);
        if (PRIV->heartbeat_interval == 0) {
            PR_WARN("心跳间隔指定为 0，这将会禁止心跳！请确认参数格式正确。");
        }
    } else if (ISOPT("eap-bcast-addr")) {
        PRIV->bcast_addr = atoi(argument) % 2; /* 一共2个选项 */ // Do not allow CER
    } else if (ISOPT("dhcp-type")) {
        PRIV->dhcp_type = atoi(argument) % 4;
    } else if (ISOPT("dhcp-script")) {
        COPY_N_ARG_TO(PRIV->dhcp_script, MAX_PATH);
    } else if (ISOPT("rj-option")) {
        /* Allow mulitple rj-options */
        if (IS_FAIL(append_rj_cmdline_opt(this, argument))) {
            return FAILURE;
        }
    } else if (ISOPT("service")) {
        COPY_N_ARG_TO(PRIV->service_name, RJV3_SIZE_SERVICE);
    } else if (ISOPT("version-str")) {
        COPY_N_ARG_TO(PRIV->ver_str, MAX_PROP_LEN);
    } else if (ISOPT("fake-dns1")) {
        COPY_N_ARG_TO(PRIV->fake_dns1, INET6_ADDRSTRLEN);
    } else if (ISOPT("fake-dns2")) {
        COPY_N_ARG_TO(PRIV->fake_dns2, INET6_ADDRSTRLEN);
    } else if (ISOPT("fake-serial")) {
        COPY_N_ARG_TO(PRIV->fake_serial, MAX_PROP_LEN);
    } else if (ISOPT("max-dhcp-count")) {
        PRIV->max_dhcp_count = atoi(argument);
    }
    return SUCCESS;
}

RESULT rjv3_process_cmdline_opts(struct _packet_plugin* this, int argc, char* argv[]) {
    int opt = 0;
    int longIndex = 0;
    static const char* shortOpts = "-:e:a:d:v:f:c:q:";
    static const struct option longOpts[] = {
	    { "heartbeat", required_argument, NULL, 'e' },
	    { "eap-bcast-addr", required_argument, NULL, 'a' },
	    { "dhcp-type", required_argument, NULL, 'd' },
	    { "dhcp-script", required_argument, NULL, 'c' },
	    { "rj-option", required_argument, NULL, 0 },
	    { "service", required_argument, NULL, 0 },
	    { "version-str", required_argument, NULL, 0 },
	    { "fake-dns1", required_argument, NULL, 0 },
	    { "fake-dns2", required_argument, NULL, 0 },
	    { "fake-serial", required_argument, NULL, 0 },
	    { "max-dhcp-count", required_argument, NULL, 0 },
	    { NULL, no_argument, NULL, 0 }
    };

    opt = getopt_long(argc, argv, shortOpts, longOpts, &longIndex);
    while (opt != -1) {
        switch (opt) {
            case ':':
                PR_ERR("缺少参数：%s", argv[optind - 1]);
                return FAILURE;
            default:
                if (opt > 0) {
                    // Short options here. longIndex = 0 in this case.
                    longIndex = shortopt2longindex(opt, longOpts, sizeof(longOpts) / sizeof(struct option));
                }
                if (longIndex >= 0 && IS_FAIL(rjv3_parse_one_opt(this, longOpts[longIndex].name, optarg))) {
                    return FAILURE;
                }
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

    if (PRIV->dhcp_type == DHCP_DOUBLE_AUTH) {
        if (PRIV->succ_count < 2) {
            /* This requires fine-grained control of authentication progress,
             * so we can not use the logic of --auth-round.
             */
            PR_INFO("首次认证成功，正在执行 DHCP 脚本以准备第二次认证");

            /*
             * PRIV->last_recv_packet == `frame`, but `frame` will be freed
             * once the state transition is finished. We need to keep it
             * in case DHCP fails and we need to start heartbeating.
             */
            if (PRIV->duplicated_packet != NULL) {
                free_frame(&PRIV->duplicated_packet);
            }
            PRIV->duplicated_packet = frame_duplicate(frame);
            system(PRIV->dhcp_script);

            /* Try right after the script ends */
            rjv3_start_secondary_auth(this);

            /* Do not try to parse the server messages in this packet.
             * It's meaningless and spamming.
             */
            return SUCCESS;
        } else {
            /* Double success */
            rjv3_reset_state(this);
            PR_INFO("二次认证成功");
        }
    } else if (PRIV->dhcp_type == DHCP_AFTER_AUTH) {
        /* Run script after one-pass authentication finishes */
        system(PRIV->dhcp_script);
    }

    if (IS_FAIL(rjv3_process_result_prop(frame))) {
        return FAILURE;
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

static void rjv3_parser_traverser(CONFIG_PAIR* pair, void* this) {
    if (pair->value[0] == 0) {
        return; /* Refuse options without value. At least there should be no-auto-reauth=1 */
    }
    rjv3_parse_one_opt((struct _packet_plugin*)this, pair->key, pair->value);
}

RESULT rjv3_process_config_file(struct _packet_plugin* this, const char* filepath) {
    conf_parser_traverse(rjv3_parser_traverser, (void*)this);
    return SUCCESS;
}

static void rjv3_save_one_prop(void* prop, void* is_mod) {
#define TO_RJ_PROP(x) ((RJ_PROP*)x)
                       /*                                      6f   : */
    int prop_str_len = sizeof(TO_RJ_PROP(prop)->header2.type) * 2 + 1
                       /* 000102aabbcc */
                        + TO_RJ_PROP(prop)->header2.len * 2
                       /*           :r      \0 */
                        + (is_mod ? 2 : 0) + 1;
    char* prop_str = (char*)malloc(prop_str_len);
    if (prop_str == NULL) {
        PR_ERRNO("无法保存 --rj-option 选项");
        return;
    }

    char* curr_pos = prop_str;
    hex2char(TO_RJ_PROP(prop)->header2.type, curr_pos);
    curr_pos += 2;
    *curr_pos++ = ':';

    int i;
    for (i = 0; i < PROP_TO_CONTENT_SIZE(TO_RJ_PROP(prop)); i++) {
        hex2char(TO_RJ_PROP(prop)->content[i], curr_pos);
        curr_pos += 2;
    }

    if (is_mod) {
        *curr_pos++ = ':';
        *curr_pos++ = 'r';
    }

    *curr_pos = 0;

    conf_parser_add_value("rj-option", prop_str);
    free(prop_str);
}

void rjv3_save_config(struct _packet_plugin* this) {
    char itoa_buf[10];
    conf_parser_add_value("heartbeat", my_itoa(PRIV->heartbeat_interval, itoa_buf, 10));
    conf_parser_add_value("eap-bcast-addr", my_itoa(PRIV->bcast_addr, itoa_buf, 10));
    conf_parser_add_value("dhcp-type", my_itoa(PRIV->dhcp_type, itoa_buf, 10));
    list_traverse(PRIV->cmd_prop_list, rjv3_save_one_prop, FALSE);
    list_traverse(PRIV->cmd_prop_mod_list, rjv3_save_one_prop, (void*)TRUE); /* No warning! */
    conf_parser_add_value("service", PRIV->service_name);
    conf_parser_add_value("version-str", PRIV->ver_str);
    conf_parser_add_value("dhcp-script", PRIV->dhcp_script);
    conf_parser_add_value("fake-dns1", PRIV->fake_dns1);
    conf_parser_add_value("fake-dns2", PRIV->fake_dns2);
    conf_parser_add_value("fake-serial", PRIV->fake_serial);
    conf_parser_add_value("max-dhcp-count", my_itoa(PRIV->max_dhcp_count, itoa_buf, 10));
}

static void packet_plugin_rjv3_print_banner() {
    PR_INFO("\nRJv3 for MiniEAP " VERSION "\n"
            "V3 校验算法来自 hyrathb@GitHub\n"
            "Hamster Tian, 2016\n\n");
}

PACKET_PLUGIN* packet_plugin_rjv3_new() {
    PACKET_PLUGIN* this = (PACKET_PLUGIN*)malloc(sizeof(PACKET_PLUGIN));
    if (this == NULL) {
        PR_ERRNO("RJv3 插件主结构内存分配失败");
        return NULL;
    }
    memset(this, 0, sizeof(PACKET_PLUGIN));

    this->priv = (rjv3_priv*)malloc(sizeof(rjv3_priv));
    if (this->priv == NULL) {
        PR_ERRNO("RJv3 插件私有结构内存分配失败");
        free(this);
        return NULL;
    }
    memset(this->priv, 0, sizeof(rjv3_priv));

    this->name = "rjv3";
    this->description = "来自 hyrathb@GitHub 的 Ruijie V3 验证算法";
    this->version = PACKET_PLUGIN_RJV3_VER_STR;
    this->destroy = rjv3_destroy;
    this->process_cmdline_opts = rjv3_process_cmdline_opts;
    this->print_banner = packet_plugin_rjv3_print_banner;
    this->load_default_params = rjv3_load_default_params;
    this->print_cmdline_help = rjv3_print_cmdline_help;
    this->prepare_frame = rjv3_prepare_frame;
    this->on_frame_received = rjv3_on_frame_received;
    this->process_config_file = rjv3_process_config_file;
    this->save_config = rjv3_save_config;
    return this;
}
PACKET_PLUGIN_INIT(packet_plugin_rjv3_new)
