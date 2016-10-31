include config.mk

ifeq ($(ENABLE_ICONV),1)
COMMON_CFLAGS += -DENABLE_ICONV
endif

#### Common bits ####
COMMON_C_INCLUDES := include
COMMON_MODULES := \
	util \
	main \
	if_impl_manager \
	packet_plugin_manager

BUILD_MODULES := $(PLUGIN_MODULES) $(COMMON_MODULES)

minieap: $(BUILD_MODULES)
	$(CC) -o minieap \
        $(COMMON_LDFLAGS) \
        $(foreach objs,$(addsuffix _LDFLAGS,$(BUILD_MODULES)),$($(objs))) \
        $(foreach objs,$(addsuffix _PRIV_OBJS,$(BUILD_MODULES)),$($(objs))) \
        $(LIBS)

.PHONY: clean
clean: $(addsuffix _clean,$(BUILD_MODULES))

define my-dir
$(dir $(lastword $(MAKEFILE_LIST)))
endef

define all-c-files-under
$(subst $(LOCAL_PATH)/,,$(wildcard $(LOCAL_PATH)/$(1)/*.c))
endef

APPEND := $(shell pwd)/append.mk
MK_LIST := $(shell find . -name minieap.mk)
include $(MK_LIST)
