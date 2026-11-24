#include "myos.h"
/* NetSurf использует open как имя метода. Файлы открывает функция libc. */
#undef open
#include <time.h>
#define M_PI 3.14159265358979323846
#define M_PI_2 1.57079632679489661923
#define SCNx32 "x"
static inline int isascii(int c) { return (unsigned)c < 128; }
static inline char *ctime(const time_t *value)
{
    static char buf[26];
    return ctime_r(value, buf);
}
