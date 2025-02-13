#ifndef FAKEDNS_DEBUG_H
#define FAKEDNS_DEBUG_H

#ifdef DEBUG

#include <stdio.h>
#include <unistd.h>

#define DEBUG_ABORT() abort()
#define DEBUG_PRINTF(msg, ...) do { printf("%s() [ %s:%d ]:", __FUNCTION__, __FILE__, __LINE__); printf(msg __VA_OPT__(,) __VA_ARGS__); } while(0)

#else

#define DEBUG_ABORT()
#define DEBUG_PRINTF(msg, ...)

#endif//DEBUG

#endif//FAKEDNS_DEBUG_H
