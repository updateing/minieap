# Makefile for interface implementation: libpcap

LOCAL_PATH := $(call my-dir)

LOCAL_SRC_FILES := if_impl_libpcap.c
LOCAL_C_INCLUDES :=
LOCAL_CFLAGS :=
LOCAL_LDFLAGS := -lpcap
LOCAL_MODULE := if_impl_libpcap

include $(APPEND)
