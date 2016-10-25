#ifndef _MINIEAP_EAP_STATE_MACH_H
#define _MINIEAP_EAP_STATE_MACH_H

#include "minieap_common.h"
#include "eth_frame.h"

/*
 * Normal authentication procedure:
 *
 * Format:
 * Event                      -- Transition function ->      New state
 * "When ${event} happens, perform ${trans_func} and then go to ${new_state}"
 *
 * set PREPARING              ---open if, send EAPOL-Start-> START_SENT
 * received Request-Identity  ---send Response-Identity--->  IDENTITY_SENT
 * received Request-Challenge ---send Response-Challenge---> CHALLENGE_SENT
 * received SUCCESS           ---double auth?
 *                               Y -> auth_round >= required?
 *                                    Y ->                   SUCCESS
 *                                    N -> auth_round++ ->   START_SENT
 *                               N ->                        SUCCESS
 * received Keep-Alive        ---SUCCESS?
 *                               Y -> send Keep-Alive ->     SUCCESS
 *                               N ->                        Do nothing
 * timer event                ---SUCCESS?
 *                               Y -> send Keep-Alive ->     SUCCESS
 *                               N -> state_last_count++ >= required?
 *                                    Y -> show "Timeout" -> PREPARING
 *                                    N -> show "Wait" ->    Keep original
 * received FAILURE           ---fail_count >= required?
 *                               Y -> show "Max Err" ->      Exit
 *                               N -> show "Restart" ->      PREPARING
 *
 * Authentication relay procedure:
 * set PREPARING              --->                           WAITING_FOR_CLIENT_START
 * received Start from client ---> waiting for client start?
 *                                 Y -> mod & send to up ->  START_SENT
 *                                 N ->                      Do nothing
 * received Req-Id from upper ---> mod & send to client ---> WAITING_FOR_CLIENT_IDENTITY
 * received Rsp-Id from clnt  ---> waiting for client ID?
 *                                 Y -> mod & send to up ->  IDENTITY_SENT
 *                                 N ->                      Do nothing
 * received Req-Ch from upper ---> mod & send to client ---> WAITING_FOR_CLIENT_CHALLENGE
 * received Rsp-Ch from clnt  ---> waiting for client challenge?
 *                                 Y -> mod & send to up ->  CHALLENGE_SENT
 *                                 N ->                      Do nothing
 * received Succ from upper   ---> mod & send to client
 *                                 --->double auth?
 *                                     Y ->                  PREPARING
 *                                     N ->                  SUCCESS
 * received Fail from upper   ---> mod & send to client
 *                                 ---> max fail reached?
 *                                      Y ->                 Exit
 *                                      N ->                 PREPARING
 * (note: we send Keep-Alive ourselves)
 */

typedef enum _eap_state {
    EAP_STATE_UNKNOWN = -1,
    EAP_STATE_PREPARING = 0,
    EAP_STATE_WAITING_FOR_CLIENT_START = 1,
    EAP_STATE_START_SENT = 2,
    EAP_STATE_WAITING_FOR_CLIENT_IDENTITY = 3,
    EAP_STATE_IDENTITY_SENT = 4,
    EAP_STATE_WAITING_FOR_CLILENT_CHALLENGE = 5,
    EAP_STATE_CHALLENGE_SENT = 6,
    EAP_STATE_SUCCESS = 7,
    EAP_STATE_FAILURE = 8
} EAP_STATE;

/*
 * Initialize the "machine"
 */
RESULT eap_state_machine_init();

/*
 * Free!
 */
void eap_state_machine_destroy();

/*
 * Notify that we are waiting too long in intermediate states.
 * Can be called in alarm handler, and take actions to fix this (restart).
 */
void notify_state_timeout();

/*
 * Switch to specific state, and perform actions accordingly.
 * `frame` is the frame caused this transition.
 */
RESULT switch_to_state(EAP_STATE state, ETH_EAP_FRAME* frame);

/*
 * Handles the incoming frames
 */
void eap_state_machine_recv_handler(ETH_EAP_FRAME* frame);

#endif

