#ifndef DEFS_H
#define DEFS_H 1
#include <stdint.h>

// Only defines here, no typedefs
#define u64 unsigned long long int // because linux uint64_t is not same as on mac

// Imitate pythons %. -1 % 5 = 4, not -1
#define MOD(n, m) (((int)n % (int)m) + (int)m) % (int)m

// Lightcrypto
#define BLOCK 1024
#define LEN 4096

// Lighthash3
#define SHA3_BITS 1024 // SHA3-256 = 512, SHA3-512 = 1024 (default)
static char hex[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
#endif
