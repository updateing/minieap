#include "config.h"
#include "if_impl.h"
#include "linkedlist.h"

int main(int argc, char* argv[]) {
    PROG_CONFIG* cfg = get_program_config();
    unsigned char mac[6];
    IF_IMPL* if_impl;
    parse_cmdline_opts(argc, argv);
    
    init_if_impl_list();
    select_if_impl("sockraw");
    
    if_impl = get_if_impl();
    if_impl->set_ifname(if_impl,cfg->ifname);
    if_impl->obtain_mac(if_impl, mac);
    printf("%02x%02x%02x%02x%02x%02x\n", mac[0], mac[1],mac[2],mac[3],mac[4],mac[5]);
    return 0;
}

