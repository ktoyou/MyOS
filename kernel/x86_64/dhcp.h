#ifndef X86_64_DHCP_H
#define X86_64_DHCP_H

#include "net.h"

struct dhcp64_lease {
    struct net64_config network;
    u32 dns;
    u32 seconds;
};

bool dhcp64_start(u32 seed);
bool dhcp64_poll(u64 now, net64_receiver receive);
bool dhcp64_get_lease(struct dhcp64_lease *result);

#endif
