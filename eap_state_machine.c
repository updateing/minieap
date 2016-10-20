#include "eap_state_machine.h"
#include "packet_builder.h"
#include "packet_plugin.h"
#include "config.h"
#include "if_impl.h"
#include "logging.h"
#include "packet_util.h"
#include "minieap_common.h"
#include "eth_frame.h"

typedef struct _state_mach_priv {
    int state_last_count; // Number of timeouts occured in this state
    int state_max_count; // Number of timeouts allowed
    int auth_round; // Current authentication round
    int fail_count;
    uint8_t local_mac[6];
    uint8_t server_mac[6];
    EAP_STATE state;
    ETH_EAP_FRAME* last_recv_frame;
    PACKET_BUILDER* packet_builder;
} STATE_MACH_PRIV;

static STATE_MACH_PRIV g_priv;

typedef struct _state_trans {
    EAP_STATE state;
    RESULT (*trans_func)(ETH_EAP_FRAME* frame);
} STATE_TRANSITION;

static RESULT trans_to_preparing(ETH_EAP_FRAME* frame);
static RESULT trans_to_start_sent(ETH_EAP_FRAME* frame);
static RESULT trans_to_identity_sent(ETH_EAP_FRAME* frame);
static RESULT trans_to_challenge_sent(ETH_EAP_FRAME* frame);
static RESULT trans_to_success(ETH_EAP_FRAME* frame);
static RESULT trans_to_failure(ETH_EAP_FRAME* frame);

static STATE_TRANSITION g_transition_table[] = {
    {EAP_STATE_UNKNOWN, NULL},
    {EAP_STATE_PREPARING, trans_to_preparing},
    {EAP_STATE_WAITING_FOR_CLIENT_START, NULL},
    {EAP_STATE_START_SENT, trans_to_start_sent},
    {EAP_STATE_WAITING_FOR_CLIENT_IDENTITY, NULL},
    {EAP_STATE_IDENTITY_SENT, trans_to_identity_sent},
    {EAP_STATE_WAITING_FOR_CLILENT_CHALLENGE, NULL},
    {EAP_STATE_CHALLENGE_SENT, trans_to_challenge_sent},
    {EAP_STATE_SUCCESS, trans_to_success},
    {EAP_STATE_FAILURE, trans_to_failure},
};

static const uint8_t BCAST_ADDR[6] = {0x01,0x80,0xc2,0x00,0x00,0x03};
static const uint8_t ETH_P_PAE_BYTES[2] = {0x88, 0x8e};

#define PRIV (&g_priv) // I like pointers!

static void eap_state_machine_clear_state() {
    PROG_CONFIG* _cfg = get_program_config();
    
    PRIV->state_last_count = 0;
    PRIV->state_max_count = _cfg->max_retries;
    PRIV->state = EAP_STATE_UNKNOWN;
    PRIV->auth_round = 1;
    PRIV->fail_count = 0;
}

RESULT eap_state_machine_init() {
    IF_IMPL* _if_impl = get_if_impl();
    
    PRIV->packet_builder = packet_builder_get();
    eap_state_machine_clear_state();
    
    _if_impl->obtain_mac(_if_impl, PRIV->local_mac);

    memmove(PRIV->server_mac, BCAST_ADDR, sizeof(BCAST_ADDR));
    
    return PRIV->packet_builder == NULL ? FAILURE : SUCCESS;
}

void eap_state_machine_destroy() {
    packet_builder_destroy();
    PRIV->packet_builder = NULL;
}

static inline void set_outgoing_eth_fields(PACKET_BUILDER* builder, uint8_t* dst_mac) {
    builder->set_eth_field(builder, FIELD_DST_MAC, dst_mac);
    builder->set_eth_field(builder, FIELD_SRC_MAC, PRIV->local_mac);
    builder->set_eth_field(builder, FIELD_ETH_PROTO, ETH_P_PAE_BYTES);
}

static RESULT state_mach_send_identity_response(ETH_EAP_FRAME* request) {
    uint8_t _buf[FRAME_BUF_SIZE] = {0};
    ETH_EAP_FRAME _response;
    IF_IMPL* _if_impl = get_if_impl();
    
    set_outgoing_eth_fields(PRIV->packet_builder, PRIV->server_mac);
    PRIV->packet_builder->set_eap_fields(PRIV->packet_builder,
                                EAP_PACKET, EAP_RESPONSE,
                                IDENTITY, request->header->eap_hdr.id[0],
                                get_eap_config());
    _response.actual_len = PRIV->packet_builder->build_packet(PRIV->packet_builder, _buf);
    _response.buffer_len = FRAME_BUF_SIZE;
    _response.content = _buf;
    
    if (IS_FAIL(packet_plugin_prepare_frame(&_response))) {
        PR_ERR("插件在准备发送 Response-Identity 包时出现错误");
        return FAILURE;
    }
    if (IS_FAIL(_if_impl->send_frame(_if_impl, &_response))) {
        PR_ERR("发送 Response-Identity 包时出现错误");
        return FAILURE;
    }
    return SUCCESS;
}

static RESULT state_mach_send_challenge_response(ETH_EAP_FRAME* request) {
    uint8_t _buf[FRAME_BUF_SIZE] = {0};
    ETH_EAP_FRAME _response;
    IF_IMPL* _if_impl = get_if_impl();
    
    set_outgoing_eth_fields(PRIV->packet_builder, PRIV->server_mac);
    PRIV->packet_builder->set_eap_fields(PRIV->packet_builder,
                                EAP_PACKET, EAP_RESPONSE,
                                MD5_CHALLENGE, request->header->eap_hdr.id[0],
                                get_eap_config());
    PRIV->packet_builder->set_eap_md5_seed(PRIV->packet_builder,
                                request->content + sizeof(FRAME_HEADER) + 1, /* 1 = sizeof(MD5-Value-Size) */
                                MD5_CHALLENGE_DIGEST_SIZE);
    _response.actual_len = PRIV->packet_builder->build_packet(PRIV->packet_builder, _buf);
    _response.buffer_len = FRAME_BUF_SIZE;
    _response.content = _buf;
    
    if (IS_FAIL(packet_plugin_prepare_frame(&_response))) {
        PR_ERR("插件在准备发送 Response-MD5-Challenge 包时出现错误");
        return FAILURE;
    }
    if (IS_FAIL(_if_impl->send_frame(_if_impl, &_response))) {
        PR_ERR("发送 Response-MD5-Challenge 包时出现错误");
        return FAILURE;
    }
    return SUCCESS;
}

static RESULT state_mach_send_eapol_simple(EAPOL_TYPE eapol_type) {
    uint8_t _buf[FRAME_BUF_SIZE] = {0};
    ETH_EAP_FRAME _response;
    IF_IMPL* _if_impl = get_if_impl();
    
    set_outgoing_eth_fields(PRIV->packet_builder, PRIV->server_mac);
    PRIV->packet_builder->set_eap_fields(PRIV->packet_builder,
                                eapol_type, 0,
                                0, 0,
                                NULL);
    _response.actual_len = PRIV->packet_builder->build_packet(PRIV->packet_builder, _buf);
    _response.buffer_len = FRAME_BUF_SIZE;
    _response.content = _buf;
    
    if (IS_FAIL(packet_plugin_prepare_frame(&_response))) {
        PR_ERR("插件在准备发送 %s 包时出现错误", str_eapol_type(eapol_type));
        return FAILURE;
    }
    if (IS_FAIL(_if_impl->send_frame(_if_impl, &_response))) {
        PR_ERR("发送 %s 包时出现错误", str_eapol_type(eapol_type));
        return FAILURE;
    }
    return SUCCESS;
}

static RESULT state_mach_process_success(ETH_EAP_FRAME* frame) {
    // TODO show info, keepalive -> rjv3
    PROG_CONFIG* _cfg = get_program_config();
    PRIV->fail_count = 0;
    if (PRIV->auth_round == _cfg->auth_round) {
        PR_INFO("认证成功");
        return SUCCESS;
    } else {
        PR_INFO("第 %d 次认证成功，正在执行下一次认证", PRIV->auth_round);
        packet_plugin_set_auth_round(++PRIV->auth_round);
        switch_to_state(EAP_STATE_START_SENT, frame); // No need to prepare again
        return SUCCESS;
    }
}

static RESULT state_mach_process_failure(ETH_EAP_FRAME* frame) {
    // TODO show reason -> rjv3
    PROG_CONFIG* _cfg = get_program_config();
    if (++PRIV->fail_count == _cfg->max_failures) {
        PR_ERR("认证失败 %d 次，已达到指定次数，正在退出……", PRIV->fail_count);
        exit(FAILURE);
    } else {
        PR_ERR("认证失败 %d 次，将在 %d 秒后重试……", PRIV->fail_count, _cfg->wait_after_fail_secs);
        // TODO start alarm
        return SUCCESS;
    }
}

void eap_state_machine_recv_handler(ETH_EAP_FRAME* frame) {
    packet_plugin_on_frame_received(frame);
    EAPOL_TYPE _eapol_type = frame->header->eapol_hdr.type[0];
    if (_eapol_type == EAP_PACKET) {
        /* We don't want to handle other types here */
        EAP_TYPE _eap_type = frame->header->eap_hdr.type[0];
        EAP_CODE _eap_code = frame->header->eap_hdr.code[0];
        
        switch (_eap_code) {
            case EAP_REQUEST:
                /*
                 * Store server's MAC addr, do not use broadcast after.
                 */
                memmove(PRIV->server_mac, frame->header->eth_hdr.src_mac, 6);
                if (_eap_type == IDENTITY) {
                    switch_to_state(EAP_STATE_IDENTITY_SENT, frame);
                    return;
                } else if (_eap_type == MD5_CHALLENGE) {
                    switch_to_state(EAP_STATE_CHALLENGE_SENT, frame);
                    return;
                }
                break;
            case EAP_SUCCESS:
                switch_to_state(EAP_STATE_SUCCESS, frame);
                return;
                break;
            case EAP_FAILURE:
                switch_to_state(EAP_STATE_FAILURE, frame);
                return;
                break;
            default:
                break;
        }
    }
}

static RESULT trans_to_preparing(ETH_EAP_FRAME* frame) {
    IF_IMPL* _if_impl = get_if_impl();
    RESULT ret = switch_to_state(EAP_STATE_START_SENT, frame);
    _if_impl->start_capture(_if_impl); // Blocking...
    return ret;
}

static RESULT trans_to_start_sent(ETH_EAP_FRAME* frame) {
    return state_mach_send_eapol_simple(EAPOL_START);
}

static RESULT trans_to_identity_sent(ETH_EAP_FRAME* frame) {
    return state_mach_send_identity_response(frame);
}

static RESULT trans_to_challenge_sent(ETH_EAP_FRAME* frame) {
    return state_mach_send_challenge_response(frame);
}

static RESULT trans_to_success(ETH_EAP_FRAME* frame) {
    return state_mach_process_success(frame);
}

static RESULT trans_to_failure(ETH_EAP_FRAME* frame) {
    return state_mach_process_failure(frame);
}

RESULT switch_to_state(EAP_STATE state, ETH_EAP_FRAME* frame) {
    int i = 0;
    for (; i < sizeof(g_transition_table) / sizeof(STATE_TRANSITION); ++i) {
        if (state == g_transition_table[i].state) {
            if (IS_FAIL(g_transition_table[i].trans_func(frame))) {
                PR_ERR("从 %d 状态向 %d 状态的转化函数执行失败", PRIV->state, state);
                return FAILURE;
             }
             PRIV->state = state;
             return SUCCESS;
        }
    }
    PR_WARN("%d 状态未定义"); // TODO Is this possible?
    return SUCCESS;
}

