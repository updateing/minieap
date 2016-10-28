# Makefile for packet plugin

LOCAL_PATH := $(call my-dir)

LOCAL_SRC_FILES := $(call all-c-files-under,)
LOCAL_C_INCLUDES :=
LOCAL_CFLAGS :=
LOCAL_LDFLAGS :=
LOCAL_MODULE := packet_plugin_manager

include $(APPEND)
