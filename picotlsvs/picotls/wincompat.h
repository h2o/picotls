#ifndef WINCOMPAT_H
#define WINCOMPAT_H

#include <stdint.h>
#define ssize_t int
#include <Winsock2.h>

#ifndef gettimeofday
#define gettimeofday wintimeofday

int wintimeofday(struct timeval* tv, struct timezone* tz);
#endif


#endif /* WINCOMPAT_H */