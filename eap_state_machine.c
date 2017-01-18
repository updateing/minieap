#include "eap_state_machine.h"
#include "packet_builder.h"
#include "packet_plugin.h"
#include "packet_util.h"
#include "config.h"
#include "if_impl.h"
#include "logging.h"
#include "packet_util.h"
#include "minieap_common.h"
#include "eth_frame.h"
#include "net_util.h"
#include "sched_alarm.h"

#include <stdlib.h>

typedef struct _state_mach_priv {
    int state_last_count; // Number of timeouts occured in this state
    int auth_round; // Current authentication round
    int fail_count;
    int state_alarm_id;
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

static void disable_state_watchdog();

static void eap_state_machine_reset() {
    disable_state_watchdog();
    free_frame(&PRIV->last_recv_frame);
    PRIV->state_last_count = 0;
    PRIV->state = EAP_STATE_UNKNOWN; // If called by a transition func, this won't take effect
    PRIV->auth_round = 1;
    PRIV->fail_count = 0;
    memmove(PRIV->server_mac, BCAST_ADDR, sizeof(BCAST_ADDR));
}

RESULT eap_state_machine_init() {
    IF_IMPL* _if_impl = get_if_impl();
    char buf[IFNAMSIZ] = {0};

    _if_impl->get_ifname(_if_impl, buf, IFNAMSIZ);
    obtain_iface_mac(buf, PRIV->local_mac);

    eap_state_machine_reset();

    PRIV->packet_builder = packet_builder_get();

    return PRIV->packet_builder == NULL ? FAILURE : SUCCESS;
}

void eap_state_machine_destroy() {
    packet_builder_destroy();
    PRIV->packet_builder = NULL;
    free_frame(&PRIV->last_recv_frame);
}

static inline void set_outgoing_eth_fields(PACKET_BUILDER* builder) {
    builder->set_eth_field(builder, FIELD_DST_MAC, PRIV->server_mac);
    builder->set_eth_field(builder, FIELD_SRC_MAC, PRIV->local_mac);
    builder->set_eth_field(builder, FIELD_ETH_PROTO, ETH_P_PAE_BYTES);
}

/*
 * Packet senders
 *
 * Build the general response, call plugins to modify it, and send it.
 */
static RESULT state_mach_send_identity_response(ETH_EAP_FRAME* request) {
    uint8_t _buf[FRAME_BUF_SIZE] = {0};
    ETH_EAP_FRAME _response;
    IF_IMPL* _if_impl = get_if_impl();

    set_outgoing_eth_fields(PRIV->packet_builder);
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

    set_outgoing_eth_fields(PRIV->packet_builder);
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

    set_outgoing_eth_fields(PRIV->packet_builder);
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
    PROG_CONFIG* _cfg = get_program_config();
    if (PRIV->auth_round == _cfg->auth_round) {
        PR_INFO("认证成功");
        eap_state_machine_reset(); // Prepare for further use (e.g. re-auth after offline)
        return SUCCESS;
    } else {
        PR_INFO("第 %d 次认证成功，正在执行下一次认证", PRIV->auth_round);
        PRIV->fail_count = 0;
        packet_plugin_set_auth_round(++PRIV->auth_round);
        switch_to_state(EAP_STATE_START_SENT, frame); // Do not restart_auth or reset to keep auth_round
        return SUCCESS;
    }
}

static void restart_auth(void* unused) {
    eap_state_machine_reset();
    switch_to_state(EAP_STATE_START_SENT, NULL);
}

static RESULT state_mach_process_failure(ETH_EAP_FRAME* frame) {
    PROG_CONFIG* _cfg = get_program_config();
    if (PRIV->state == EAP_STATE_SUCCESS) {
        /* Server forced us offline, not auth failing */
        if (_cfg->restart_on_logoff) {
            /* Wait for this state transition to FAILURE finish */
            PR_WARN("认证掉线，稍后将重新开始认证……");
            schedule_alarm(1, restart_auth, NULL);
        } else {
            PR_ERR("认证掉线，正在退出……");
            exit(EXIT_FAILURE);
        }
    } else {
        /* Fail during auth */
        if (++PRIV->fail_count == _cfg->max_failures) {
            PR_ERR("认证失败 %d 次，已达到指定次数，正在退出……", PRIV->fail_count);
            exit(EXIT_FAILURE);
        } else {
            PR_WARN("认证失败 %d 次，将在 %d 秒或服务器请求后重试……", PRIV->fail_count, _cfg->wait_after_fail_secs);
            schedule_alarm(_cfg->wait_after_fail_secs, restart_auth, NULL);
        }
    }
    return SUCCESS;
}

/*
 * This is the first function that will be notified on arrival of new frames.
 *
 * Dispatch the frame to plugins (to update their internal state,
 * preparing to modify the upcoming response frame)
 * and switch to next state (to send response)
 */
void eap_state_machine_recv_handler(ETH_EAP_FRAME* frame) {
    /* Keep a copy of the frame, since if_impl may not hold it */
    if (PRIV->last_recv_frame != NULL) {
        free_frame(&PRIV->last_recv_frame);
    }
    PRIV->last_recv_frame = frame_duplicate(frame);
    packet_plugin_on_frame_received(PRIV->last_recv_frame);

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
                } else if (_eap_type == MD5_CHALLENGE) {
                    switch_to_state(EAP_STATE_CHALLENGE_SENT, frame);
                }
                break;
            case EAP_SUCCESS:
                switch_to_state(EAP_STATE_SUCCESS, frame);
                break;
            case EAP_FAILURE:
                switch_to_state(EAP_STATE_FAILURE, frame);
                break;
            default:
                break;
        }
    }
}

#define CFG_STAGE_TIMEOUT ((get_program_config())->stage_timeout)
/*
 * Re-transmit the response to last frame, in case the authentication server
 * stops responding.
 */
static void reset_state_watchdog();
static void state_watchdog(void* unused) {
    switch_to_state(PRIV->state, PRIV->last_recv_frame);
    reset_state_watchdog();
}

/*
 * Set a new watchdog for current state
 */
static void reset_state_watchdog() {
    unschedule_alarm(PRIV->state_alarm_id);
    PRIV->state_alarm_id = schedule_alarm(CFG_STAGE_TIMEOUT, state_watchdog, NULL);
}

static void disable_state_watchdog() {
    unschedule_alarm(PRIV->state_alarm_id);
    PRIV->state_alarm_id = 0;
}

/*
 * The transition functions
 *
 * Send appropriate authentication frame for specific state.
 * Besides that, deal with watchdog as well.
 */
static RESULT trans_to_preparing(ETH_EAP_FRAME* frame) {
    PR_INFO("========================");
    PR_INFO("MiniEAP " VERSION "已启动");
    IF_IMPL* _if_impl = get_if_impl();
    RESULT ret = switch_to_state(EAP_STATE_START_SENT, frame);
    _if_impl->start_capture(_if_impl); // Blocking...
    return ret;
}

static RESULT trans_to_start_sent(ETH_EAP_FRAME* frame) {
    PR_INFO("正在查找认证服务器");
    return state_mach_send_eapol_simple(EAPOL_START);
}

static RESULT trans_to_identity_sent(ETH_EAP_FRAME* frame) {
    PR_INFO("正在回应用户名请求");
    return state_mach_send_identity_response(frame);
}

static RESULT trans_to_challenge_sent(ETH_EAP_FRAME* frame) {
    PR_INFO("正在回应密码请求");
    return state_mach_send_challenge_response(frame);
}

static RESULT trans_to_success(ETH_EAP_FRAME* frame) {
    disable_state_watchdog(); // Session finished,do not wait for new packets.
    return state_mach_process_success(frame);
}

static RESULT trans_to_failure(ETH_EAP_FRAME* frame) {
    disable_state_watchdog(); // Same as above.
    return state_mach_process_failure(frame);
}

/*
 * Look up the transition function for specific state, call it
 * and change the PRIV->state if it succeeds.
 *
 * Sets up watchdog when entering a new state (this watchdog will be
 * fed/reload when it barks, do not worry about that here). One can cancel
 * this watchdog in transition function if needed.
 */
RESULT switch_to_state(EAP_STATE state, ETH_EAP_FRAME* frame) {
    int i;

    if (PRIV->state == state) {
        PROG_CONFIG* _cfg = get_program_config();
        PRIV->state_last_count++;
        if (PRIV->state_last_count == _cfg->max_retries) {
            PR_ERR("在 %d 状态已经停留了 %d 次，达到指定次数，正在退出……", PRIV->state, _cfg->max_retries);
            exit(EXIT_FAILURE);
        }
    } else {
        /*
         * Reset watchdog before calling trans func
         * in case we need to cancel it there.
         * e.g. after success
         */
        PRIV->state_last_count = 0;
        reset_state_watchdog();
    }

    for (i = 0; i < sizeof(g_transition_table) / sizeof(STATE_TRANSITION); ++i) {
        if (state == g_transition_table[i].state) {
            if (IS_FAIL(g_transition_table[i].trans_func(frame))) {
                exit(EXIT_FAILURE);
            } else {
                PRIV->state = state;
            }
            return SUCCESS;
        }
    }
    PR_WARN("%d 状态未定义");
    return SUCCESS;
}
