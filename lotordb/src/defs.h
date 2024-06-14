#ifndef DEFS_H
#define DEFS_H 1

//int variable=666;

#include <stdint.h>

// Only defines here, no typedefs
#define u64 unsigned long long int // because linux uint64_t is not same as on mac

#define EVEN(p) (!(p[0] & 1))

// Imitate pythons %. -1 % 5 = 4, not -1
#define MOD(n, m) (((int)n % (int)m) + (int)m) % (int)m

// SSL
#define RAND64() (rand() & 0x7fffffffffffffff) << 48 ^ (rand() & 0x7fffffffffffffff) << 35 ^\
                 (rand() & 0x7fffffffffffffff) << 22 ^ (rand() & 0x7fffffffffffffff) << 9 ^\
                 (rand() & 0x7fffffffffffffff) >> 4

// Lightciphers
#define NB 4
#define NK 8
#define NR 14
#define NB4 NB * 4
#define NK4 NK * 4
#define NBR1 NB * (NR + 1)
#define BBL 4 * NB * sizeof(uint8_t)

// Lightcrypto
#define BLOCK 1024
#define LEN 4096

// Lighthash3
#define SHA3_BITS 1024 // SHA3-256 = 512, SHA3-512 = 1024 (default)

// Lightkeys
#define BYTES 48
#define DIGITS (BYTES / 8)

typedef struct pt {u64 x[DIGITS], y[DIGITS];} pt;
typedef struct prng_t {u64 a, b, c, d;} prng_t;

static u64 curve_p[DIGITS] = {0x00000000ffffffff, 0xffffffff00000000, 0xfffffffffffffffe, 0xffffffffffffffff,
  0xffffffffffffffff,0xffffffffffffffff}, curve_b[DIGITS] = {0x2a85c8edd3ec2aef, 0xc656398d8a2ed19d, 0x0314088f5013875a,
  0x181d9c6efe814112, 0x988e056be3f82d19, 0xb3312fa7e23ee7e4}, curve_n[DIGITS] = {0xecec196accc52973, 0x581a0db248b0a77a,
  0xc7634d81f4372ddf, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff};
static pt curve_g = {{0x3a545e3872760ab7, 0x5502f25dbf55296c, 0x59f741e082542a38, 0x6e1d3b628ba79b98, 0x8eb1c71ef320ad74,
  0xaa87ca22be8b0537},{0x7a431d7c90ea0e5f, 0x0a60b1ce1d7e819d,0xe9da3113b5f0b8c0, 0xf8f41dbd289a147c, 0x5d9e98bf9292dc29,
  0x3617de4a96262c6f}};
static prng_t prng_ctx;
static char hex[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
#endif
