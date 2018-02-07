include config.mk

#### Populate [C|LD]FLAGS ####
COMMON_CFLAGS := $(CUSTOM_CFLAGS) $(CFLAGS) -Wall -Wpedantic -D_GNU_SOURCE
COMMON_LDFLAGS := $(CUSTOM_LDFLAGS) $(LDFLAGS)
LIBS += $(CUSTOM_LIBS)

# You are not cross-compiling for macOS on Linux, I guess?
ifeq ($(shell uname -s),Linux)
COMMON_LDFLAGS += -T minieap_init_func.lds
endif

ifeq ($(ENABLE_ICONV),true)
COMMON_CFLAGS += -DENABLE_ICONV
ifeq ($(LIBICONV_STANDALONE),true)
COMMON_LDFLAGS += -liconv
endif
endif

ifeq ($(ENABLE_GBCONV),true)
COMMON_CFLAGS += -DENABLE_GBCONV
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
clean:
	rm -f minieap.service minieap.1.gz

define my-dir
$(dir $(lastword $(MAKEFILE_LIST)))
endef

define all-c-files-under
$(subst $(LOCAL_PATH)/,,$(wildcard $(LOCAL_PATH)/$(1)$(if $(1),/,)*.c))
endef

APPEND := $(shell pwd)/append.mk
MK_LIST := $(shell find . -name minieap.mk)
include $(MK_LIST)

#### Install ####

DESTDIR ?=
PREFIX ?= /usr/local
BINDIR ?= /sbin
SYSCONFDIR ?= /etc
SYSTEMDDIR ?= $(SYSCONFDIR)/systemd

minieap.%: minieap.%.in
	sed "s|:TARGET:|$(PREFIX)$(BINDIR)|g;s|:SYSCONFDIR:|$(SYSCONFDIR)|g" $< > $@

minieap.1.gz: minieap.1
	gzip -k $<

.PHONY: install
install: minieap minieap.1.gz minieap.service
	install -d $(DESTDIR)$(PREFIX)$(BINDIR)/
	install -m 755 minieap $(DESTDIR)$(PREFIX)$(BINDIR)/
	install -d $(DESTDIR)$(SYSCONFDIR)/
	install -m 644 minieap.conf $(DESTDIR)$(SYSCONFDIR)/
	install -d $(DESTDIR)$(PREFIX)/share/man/man1/
	install -m 644 minieap.1.gz $(DESTDIR)$(PREFIX)/share/man/man1/
	install -d $(DESTDIR)$(SYSTEMDDIR)/system/
	install -m 644 minieap.service $(DESTDIR)$(SYSTEMDDIR)/system/
	-systemctl enable minieap

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(PREFIX)$(BINDIR)/minieap
	rm -f $(DESTDIR)$(PREFIX)/share/man/man1/minieap.1.gz
	-systemctl disable minieap
	rm -f $(DESTDIR)$(SYSTEMDDIR)/system/minieap.service
