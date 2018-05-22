$(LOCAL_MODULE)_PRIV_C_FLAGS := \
    $(addprefix -I$(LOCAL_PATH),$(LOCAL_C_INCLUDES)) \
    $(addprefix -I,$(LOCAL_PATH)) \
    $(addprefix -I,$(COMMON_C_INCLUDES)) \
    $(COMMON_CFLAGS) \
    $(LOCAL_CFLAGS)

ifeq ($(STATIC_BUILD),true)
$(LOCAL_MODULE)_LDFLAGS := $(filter-out -l%,$(LOCAL_LDFLAGS))
else
$(LOCAL_MODULE)_LDFLAGS := $(LOCAL_LDFLAGS)
endif

$(LOCAL_MODULE)_PRIV_OBJS := $(addprefix $(LOCAL_PATH),$(LOCAL_SRC_FILES:.c=.o))
$(LOCAL_MODULE)_PRIV_DEPS := $(addprefix $(LOCAL_PATH),$(LOCAL_SRC_FILES:.c=.d))

.PHONY: $(LOCAL_MODULE)
$(LOCAL_MODULE) : $($(LOCAL_MODULE)_PRIV_OBJS)

$($(LOCAL_MODULE)_PRIV_OBJS) : LCFLAGS := $($(LOCAL_MODULE)_PRIV_C_FLAGS)
$($(LOCAL_MODULE)_PRIV_OBJS) : ${@:.o=.c}
	$(CC) $(LCFLAGS) ${@:.o=.c} -c -o $@

# sed: change everything before ":" to "${@:.d=.o} $@"
$($(LOCAL_MODULE)_PRIV_DEPS) : LCFLAGS := $($(LOCAL_MODULE)_PRIV_C_FLAGS)
$($(LOCAL_MODULE)_PRIV_DEPS) : ${@:.d=.c}
	@$(CC) -MM ${@:.d=.c} $(LCFLAGS) > $@
	@sed -i -e 's|^.*:|${@:.d=.o} $@ : |g' $@

# %.o %.d : *.c
# This will cause regeneration of .d files and unselected targets.
# Only include deps when building for selected modules.
ifneq ("$(MAKECMDGOALS)","clean")
ifneq ($(filter $(LOCAL_MODULE),$(BUILD_MODULES)),)
-include $($(LOCAL_MODULE)_PRIV_DEPS)
endif
endif

.PHONY: $(LOCAL_MODULE)_clean
$(LOCAL_MODULE)_clean:
# Use patsubst to get correct filenames!
	rm -f $($(patsubst %_clean,%,$@)_PRIV_OBJS) $($(patsubst %_clean,%,$@)_PRIV_DEPS)

.PHONY: clean
clean: $(LOCAL_MODULE)_clean
