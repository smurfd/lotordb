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

// base64encode/decode
static char enc[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
  'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
  's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};

// utf8encode/decode
static u64 n1[] = {0x000003f, 0x0000fc0, 0x003f000, 0x01c0000, 0x0000800, 0x0000c080, 0x0010000, 0x00e08080, 0xf0808080};
static u64 n2[] = {0x00efbfbf, 0x000f0000, 0x003f0000, 0x07000000, 0x00003f00, 0x0000003f};
#endif
