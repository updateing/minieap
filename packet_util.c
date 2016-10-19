#include "eth_frame.h"
#include "minieap_common.h"

#include <stdint.h>
#include <string.h>

int append_to_frame(ETH_EAP_FRAME* frame, uint8_t* data, int len) {
    if (frame->actual_len + len > frame->buffer_len)
        return FAILURE;
    
    memmove(frame->content + frame->actual_len, data, len);
    frame->actual_len += len;
    return SUCCESS;
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
            
