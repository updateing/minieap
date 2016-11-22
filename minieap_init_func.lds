SECTIONS {
    . = ALIGN(8); /* SIGBUS? */
    .rodata.ifimpllist : {
        __IF_IMPL_LIST_START__ = .;
        *(.ifimplinit);
        __IF_IMPL_LIST_END__ = .;
    }
    .rodata.pktpluginlist : {
        __PACKET_PLUGIN_LIST_START__ = .;
        *(.pktplugininit);
        __PACKET_PLUGIN_LIST_END__ = .;
    }
}
INSERT AFTER .rodata; /* Do not override default linker script */
