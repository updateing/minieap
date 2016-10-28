$(LOCAL_MODULE)_PRIV_C_FLAGS := \
    $(addprefix -I$(LOCAL_PATH),$(LOCAL_C_INCLUDES)) \
    $(addprefix -I,$(LOCAL_PATH)) \
    $(addprefix -I,$(COMMON_C_INCLUDES)) \
    $(COMMON_CFLAGS) \
    $(LOCAL_CFLAGS)

$(LOCAL_MODULE)_LDFLAGS := $(LOCAL_LDFLAGS)
$(LOCAL_MODULE)_PRIV_OBJS := $(addprefix $(LOCAL_PATH),$(LOCAL_SRC_FILES:.c=.o))
$(LOCAL_MODULE)_PRIV_DEPS := $(addprefix $(LOCAL_PATH),$(LOCAL_SRC_FILES:.c=.d))

# Use := here!
# And $($(xxx)_suffix), not $(xxx)_suffix
.PHONY: $(LOCAL_MODULE)
$($(LOCAL_MODULE)_PRIV_OBJS) : CFLAGS := $($(LOCAL_MODULE)_PRIV_C_FLAGS)
$(LOCAL_MODULE) : $($(LOCAL_MODULE)_PRIV_OBJS)

# sed: change everything before ":" to "${@:.d=.o} $@"
$($(LOCAL_MODULE)_PRIV_DEPS) : CFLAGS := $($(LOCAL_MODULE)_PRIV_C_FLAGS)
$($(LOCAL_MODULE)_PRIV_DEPS) : ${@:.d=.c}
	@$(CC) -MM ${@:.d=.c} $(CFLAGS) > $@
	@sed -i 's,^.*:,${@:.d=.o} $@ : ,g' $@

# %.o %.d : *.c
-include $($(LOCAL_MODULE)_PRIV_DEPS)

.PHONY: $(LOCAL_MODULE)_clean
$(LOCAL_MODULE)_clean:
# Use patsubst to get correct filenames!
	rm -f $($(patsubst %_clean,%,$@)_PRIV_OBJS) $($(patsubst %_clean,%,$@)_PRIV_DEPS)
