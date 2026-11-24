#ifndef MYOS_NETSURF_STDLIB_H
#define MYOS_NETSURF_STDLIB_H
#include_next <stdlib.h>
static inline double atof(const char *number)
{
    return strtod(number, NULL);
}
#endif
