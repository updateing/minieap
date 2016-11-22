#### Choose/Add your modules here ####
PLUGIN_MODULES := \
	if_impl_sockraw \
	packet_plugin_printer \
	packet_plugin_rjv3

# PLUGIN_MODULES += if_impl_libpcap

# PLUGIN_MODULES += ifaddrs

ENABLE_ICONV := 1

COMMON_CFLAGS := $(CFLAGS) -Wall -D_GNU_SOURCE
COMMON_LDFLAGS := $(LDFLAGS) -static -T minieap_init_func.lds
LIBS := $(LIBS)

# Example for cross-compiling
# CC := arm-brcm-linux-uclibcgnueabi-gcc
# COMMON_CFLAGS += -I/home/me/libiconv-1.14/include
# LIBS += /home/me/arm/libiconv.a
# PLUGIN_MODULES += ifaddrs
