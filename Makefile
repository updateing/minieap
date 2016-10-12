MINIEAP_COMMON_OBJS := config.o logging.o minieap.o misc.o linkedlist.o if_plugin.o packet_builder.o

MINIEAP_PLUGIN_OBJS := if_plugin_sockraw.o

CC := cc -Wall -DDEBUG

minieap : $(MINIEAP_COMMON_OBJS) $(MINIEAP_PLUGIN_OBJS)

.PHONY: clean
clean:
	rm -f minieap $(MINIEAP_COMMON_OBJS) $(MINIEAP_PLUGIN_OBJS)

