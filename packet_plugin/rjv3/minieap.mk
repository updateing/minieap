# Makefile for packet plugin: RJv3 authentication

LOCAL_PATH := $(call my-dir)

LOCAL_SRC_FILES := \
    $(call all-c-files-under,) \
    $(call all-c-files-under,rjv3_hashes)
LOCAL_C_INCLUDES := rjv3_hashes
LOCAL_CFLAGS :=
LOCAL_LDFLAGS :=
LOCAL_MODULE := packet_plugin_rjv3

include $(APPEND)
