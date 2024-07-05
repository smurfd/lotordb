// Auth: smurfd, 2023 More reading & Borrow/Stolen parts read at the bottom of the file; 2 spacs indent; 120 width    //
#ifndef KEYS_H
#define KEYS_H 1
#include <stdbool.h>

#define BYTES 48
#define DIGITS (BYTES / 8)
#define u64 unsigned long long int // because linux uint64_t is not same as on mac
// Imitate pythons %. -1 % 5 = 4, not -1
#define MOD(n, m) (((int)n % (int)m) + (int)m) % (int)m
#define EVEN(p) (!(p[0] & 1))
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

u64 keys_write(char *fn, uint8_t data[], int type);
int keys_make(uint8_t publ[], uint8_t priv[], u64 private[]);
int keys_secr(const uint8_t pub[], const uint8_t prv[], uint8_t scr[], u64 r[]);
int keys_sign(const uint8_t priv[], const uint8_t hash[], uint8_t sign[], u64 k[]);
int keys_vrfy(const uint8_t publ[], const uint8_t hash[], const uint8_t sign[]);
#endif
