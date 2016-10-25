#### Choose/Add your modules here ####
PLUGIN_MODULES := \
	if_impl_libpcap \
	if_impl_sockraw \
	packet_plugin_printer \
	packet_plugin_rjv3

# If your platform does not provide ifaddrs, add your own implementation here
#PLUGIN_MODULES += ifaddrs

#### Common bits ####
# These two flags are inherited from environment
COMMON_CFLAGS := $(CFLAGS)
COMMON_LDFLAGS := $(LDFLAGS)
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
        $(foreach objs,$(addsuffix _PRIV_OBJS,$(BUILD_MODULES)),$($(objs)))

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
