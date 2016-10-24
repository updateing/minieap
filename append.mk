$(LOCAL_MODULE)_PRIV_C_FLAGS := \
    $(addprefix -I$(LOCAL_PATH),$(LOCAL_C_INCLUDES)) \
    $(addprefix -I,$(LOCAL_PATH)) \
    $(addprefix -I,$(COMMON_C_INCLUDES)) \
    $(COMMON_CFLAGS) \
    $(LOCAL_CFLAGS)

$(LOCAL_MODULE)_LDFLAGS := $(LOCAL_LDFLAGS)
$(LOCAL_MODULE)_PRIV_OBJS := $(addprefix $(LOCAL_PATH),$(LOCAL_SRC_FILES:.c=.o))

# Use := here!
.PHONY: $(LOCAL_MODULE)
$(LOCAL_MODULE) : CFLAGS := $($(LOCAL_MODULE)_PRIV_C_FLAGS)
$(LOCAL_MODULE) : $($(LOCAL_MODULE)_PRIV_OBJS)

.PHONY: $(LOCAL_MODULE)_clean
$(LOCAL_MODULE)_clean:
# Use patsubst to get correct filenames!
	rm -f $($(patsubst %_clean,%,$@)_PRIV_OBJS)
