include config.mk

#### Populate [C|LD]FLAGS ####
COMMON_CFLAGS := $(CUSTOM_CFLAGS) $(CFLAGS) -Wall -D_GNU_SOURCE
COMMON_LDFLAGS := $(CUSTOM_LDFLAGS) $(LDFLAGS) -T minieap_init_func.lds
LIBS += $(CUSTOM_LIBS)

ifeq ($(ENABLE_ICONV),true)
COMMON_CFLAGS += -DENABLE_ICONV
ifeq ($(LIBICONV_STANDALONE),true)
COMMON_LDFLAGS += -liconv
endif
endif

ifeq ($(ENABLE_DEBUG),true)
COMMON_CFLAGS += -DDEBUG
endif

ifeq ($(STATIC_BUILD),true)
COMMON_LDFLAGS += -static
COMMON_LDFLAGS := $(filter-out -l%,$(COMMON_LDFLAGS))
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
