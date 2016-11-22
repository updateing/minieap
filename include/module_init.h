#ifndef _MINIEAP_MODULE_INIT
#define _MINIEAP_MODULE_INIT

#define __define_in_init(func, sect) \
    static void* __init_##func __attribute__((unused, __section__(sect))) = func;

#endif
