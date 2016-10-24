MINIEAP_COMMON_OBJS := config.o logging.o minieap.o misc.o linkedlist.o if_impl.o packet_builder.o \
    packet_util.o packet_plugin.o eap_state_machine.o net_util.o sched_alarm.o

# If your platform does not provide getifaddrs(), you can find some implemention and compile it here
#MINIEAP_COMMON_OBJS += ifaddrs.o

MINIEAP_PLUGIN_OBJS := if_impl_sockraw.o
MINIEAP_PLUGIN_OBJS += packet_plugin_rjv3.o packet_plugin_rjv3_prop.o packet_plugin_rjv3_priv.o packet_plugin_rjv3_keepalive.o \
    checkV4.o byte_order.o md5.o rjmd5.o rjripemd128.o rjsha1.o rjtiger.o rjtiger_sbox.o rjwhirlpool.o rjwhirlpool_sbox.o

MINIEAP_PLUGIN_OBJS += packet_plugin_printer.o

CC := clang -Wall -DDEBUG -g

minieap : $(MINIEAP_COMMON_OBJS) $(MINIEAP_PLUGIN_OBJS)

.PHONY: clean
clean:
	rm -f minieap $(MINIEAP_COMMON_OBJS) $(MINIEAP_PLUGIN_OBJS)
