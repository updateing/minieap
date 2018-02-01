#include "eth_frame.h"
#include "minieap_common.h"

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

RESULT append_to_frame(ETH_EAP_FRAME* frame, const uint8_t* data, int len) {
    if (frame->actual_len + len > frame->buffer_len)
        return FAILURE;

    memmove(frame->content + frame->actual_len, data, len);
    frame->actual_len += len;
    return SUCCESS;
}

ETH_EAP_FRAME* frame_duplicate(const ETH_EAP_FRAME* frame) {
    ETH_EAP_FRAME* _frame = (ETH_EAP_FRAME*)malloc(sizeof(ETH_EAP_FRAME));
    _frame->actual_len = frame->actual_len;
    _frame->buffer_len = frame->buffer_len;
    _frame->content = (uint8_t*)malloc(_frame->actual_len);
    if (_frame->content == NULL) {
        return NULL;
    }
    memmove(_frame->content, frame->content, _frame->actual_len);
    return _frame;
}

void free_frame(ETH_EAP_FRAME** frame) {
    if (frame == NULL || *frame == NULL) return;
    free((*frame)->content);
    free(*frame);
    *frame = NULL;
}

char* str_eapol_type(EAPOL_TYPE type) {
    switch (type) {
        case EAP_PACKET:
            return "EAP Packet";
        case EAPOL_START:
            return "EAPoL-Start";
        case EAPOL_LOGOFF:
            return "EAPoL-Logoff";
        default:
            return "未知";
    }
}
