#ifndef _MINIEAP_MODULE_INIT
#define _MINIEAP_MODULE_INIT

#define __define_in_section(func, sect) \
    static void* (*__init_##func)() __attribute__((used, __section__(sect))) = (void*(*)())func;

#endif
