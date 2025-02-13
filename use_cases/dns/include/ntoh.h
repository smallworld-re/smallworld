#ifndef FAKEDNS_NTOH_H
#define FAKEDNS_NTOH_H

// I am not including absolutely crazy APIs to do an endian flip.
#ifdef __BYTE_ORDER__

// We have the __BYTE_ORDER__ macro
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__

// System is little-endian; flip the bytes
#define NTOHS(x) (\
    (((x) & 0x00ff) << 8) |\
    (((x) & 0xff00) >> 8)\
)
#define NTOHL(x) (\
    (((x) & 0x000000ff) << 24) |\
    (((x) & 0x0000ff00) << 8) |\
    (((x) & 0x00ff0000) >> 8) |\
    (((x) & 0xff000000) >> 24)\
)

#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__

// System is big-endian; keep unchanged
#define NTOHS(x) (x)
#define NTOHL(x) (x)

#else

// No idea what endianness you want
#error Unknown byte order
 
#endif//__BYTE_ORDER__ == ??

#else

// Macro doesn't exist.  Sad.
#error Byte order macro undefined

#endif//__BYTE_ORDER__

#endif//FAKEDNS_NTOH_H
