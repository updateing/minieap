#include "config.h"
#include "if_plugin.h"
int main(int argc, char* argv[]) {
    if_plugin test;
    PROG_CONFIG* cfg = get_program_config();
    unsigned char mac[6];
    parse_cmdline_opts(argc, argv);
    
    sockraw_init(&test,cfg->ifname);
    sockraw_obtain_mac(&test, mac);
    printf("%02x%02x%02x%02x%02x%02x\n", mac[0], mac[1],mac[2],mac[3],mac[4],mac[5]);
}
