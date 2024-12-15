// Auth: smurfd, 2024 More reading at the bottom of the file; 2 spacs indent; 150 width                                                             //
#ifndef AES_H
#define AES_H 1
#include <stdint.h>

typedef struct state_t {
  uint8_t state[4][4];
} state_t;

#define BIN(x) str_to_bin(#x) // TODO: maby not needed?
#define LONG2BIN(x, y) long_to_bin(x, y)
#define BIN2LONG(x) bin_to_long(x)
#define EOR(x, y) (y ^ x)
#define u64 unsigned long long int // because linux uint64_t is not same as on mac
#define NB 4
#define NK 8
#define NR 14
#define BBL 4 * NB * sizeof(uint8_t)
void multiply(u64 *R);
void modreduce(u64 *K);
void st(u64 Z);
uint32_t little_endian_uint32(uint8_t x);
uint8_t *right_pad_to_multiple_of_16_bytes(uint8_t *input, int len);

void EQINVCIPHER(state_t *state, uint8_t *in, uint8_t *w);
void INVCIPHER(state_t *state, uint8_t *in, uint8_t *w);
void CIPHER(state_t *state, uint8_t *in, uint8_t *w);
void KEYEXPANSION(uint8_t *w, const uint8_t *key);
void KEYEXPANSIONEIC(uint8_t *w, uint8_t *key);

//void ciph_crypt(uint8_t *out, const uint8_t *in, const uint8_t *key, const uint8_t *iv, const bool cbc, bool dec);
//void ciph_cryptcfb(uint8_t *out, const uint8_t *in, const uint8_t *key, const uint8_t *iv, bool dec);
void ciph_decryptcbc(uint8_t *out, const uint8_t *in, const uint8_t *key, const uint8_t *iv);
void ciph_encryptcbc(uint8_t *out, const uint8_t *in, const uint8_t *key, const uint8_t *iv);
#endif
// Code grabbed from https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf and massaged
