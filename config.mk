#### Choose/Add your modules here ####
PLUGIN_MODULES := \
	packet_plugin_printer \
	packet_plugin_rjv3

PLUGIN_MODULES += if_impl_sockraw
# PLUGIN_MODULES += if_impl_libpcap

# PLUGIN_MODULES += ifaddrs

ENABLE_DEBUG := false
ENABLE_ICONV := true
STATIC_BUILD := false

# If your platform has iconv_* integrated into libc, change to false
# Affects dynamic linking
LIBICONV_STANDALONE := false

CUSTOM_CFLAGS :=
CUSTOM_LDFLAGS :=
CUSTOM_LIBS :=

# Example for cross-compiling
# CC := arm-brcm-linux-uclibcgnueabi-gcc
# ENABLE_ICONV := true
# CUSTOM_CFLAGS += -I/home/me/libiconv-1.14/include
# CUSTOM_LIBS += /home/me/arm/libiconv.a
# PLUGIN_MODULES += ifaddrs
# STATIC_BUILD := true
