SECTIONS {
    . = ALIGN(8); /* SIGBUS? */
    .data.ifimpllist : {
        __IF_IMPL_LIST_START__ = .;
        *(.ifimplinit);
        __IF_IMPL_LIST_END__ = .;
    }
    .data.pktpluginlist : {
        __PACKET_PLUGIN_LIST_START__ = .;
        *(.pktplugininit);
        __PACKET_PLUGIN_LIST_END__ = .;
    }
}
INSERT AFTER .data; /* Do not override default linker script */
