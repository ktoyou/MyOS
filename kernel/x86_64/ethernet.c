#include "ethernet.h"

static const struct ethernet64_driver *active;

bool ethernet64_attach(const struct ethernet64_driver *driver) {
    if (active) return active == driver;
    if (!driver || !driver->name || !driver->init || !driver->link || !driver->mac ||
        !driver->send || !driver->receive || !driver->init()) return false;
    active = driver;
    return true;
}

const char *ethernet64_name(void) {
    return active ? active->name : NULL;
}

bool ethernet64_link(void) {
    return active && active->link();
}

void ethernet64_mac(u8 out[6]) {
    if (active) active->mac(out);
    else for (unsigned i = 0; i < 6; ++i) out[i] = 0;
}

bool ethernet64_send(const void *frame, u32 size) {
    return active && active->send(frame, size);
}

u32 ethernet64_receive(void *frame, u32 capacity) {
    return active ? active->receive(frame, capacity) : 0;
}
