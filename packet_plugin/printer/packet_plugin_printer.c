#include "packet_plugin.h"
#include "eth_frame.h"
#include "logging.h"
#include "stdlib.h"
#include <stdio.h>

RESULT printer_prepare_frame(struct _packet_plugin* this, ETH_EAP_FRAME* frame) {
    PR_INFO("We send one! %d %d\n", frame->actual_len,frame->buffer_len);
    return SUCCESS;
}

RESULT printer_on_frame_received(struct _packet_plugin* this, ETH_EAP_FRAME* frame) {
    PR_INFO("We got one! %d %d\n", frame->actual_len,frame->buffer_len);
    return SUCCESS;
}

void printer_destroy(struct _packet_plugin* this) {
    free(this);
}

PACKET_PLUGIN* packet_plugin_printer_new() {
    PACKET_PLUGIN* this = (PACKET_PLUGIN*)malloc(sizeof(PACKET_PLUGIN));
    if (this == NULL) {
        PR_ERRNO("Printer 插件主结构内存分配失败");
        return NULL;
    }
    memset(this, 0, sizeof(PACKET_PLUGIN));

    this->priv = NULL;

    this->name = "printer";
    this->description = "将流经此插件的数据包内容打印出来";
    this->prepare_frame = printer_prepare_frame;
    this->on_frame_received = printer_on_frame_received;
    this->destroy = printer_destroy;
    return this;
}
PACKET_PLUGIN_INIT(packet_plugin_printer_new)
