MINIEAP_COMMON_OBJS := config.o logging.o minieap.o misc.o linkedlist.o if_impl.o packet_builder.o packet_util.o

MINIEAP_PLUGIN_OBJS := if_impl_sockraw.o
MINIEAP_PLUGIN_OBJS += packet_plugin_rjv3.o packet_plugin_rjv3_prop.o

CC := cc -Wall -DDEBUG

minieap : $(MINIEAP_COMMON_OBJS) $(MINIEAP_PLUGIN_OBJS)

.PHONY: clean
clean:
	rm -f minieap $(MINIEAP_COMMON_OBJS) $(MINIEAP_PLUGIN_OBJS)

