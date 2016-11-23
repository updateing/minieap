# Makefile for interface implementation: raw socket interface

LOCAL_PATH := $(call my-dir)

LOCAL_SRC_FILES := if_impl_bpf.c
LOCAL_C_INCLUDES :=
LOCAL_CFLAGS :=
LOCAL_LDFLAGS :=
LOCAL_MODULE := if_impl_bpf

include $(APPEND)
