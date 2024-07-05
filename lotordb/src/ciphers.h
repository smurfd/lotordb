// Auth: smurfd, 2023 More reading & Borrow/Stolen parts read at the bottom of the file; 2 spacs indent; 120 width    //
#ifndef CIPHERS_H
#define CIPHERS_H 1
#include <stdint.h>

#define NB 4
#define NK 8
#define NR 14
#define NB4 NB * 4
#define NK4 NK * 4
#define NBR1 NB * (NR + 1)
#define BBL 4 * NB * sizeof(uint8_t)
#define u64 unsigned long long int // because linux uint64_t is not same as on mac

extern const uint8_t SBOXINV[16][16], GF[15][256], MIX[4][4], MIX[4][4], K[32], SBOX[16][16];
extern const u64 WW[8];

void cipher_decrypt_cfb(uint8_t out[], const uint8_t in[], const uint8_t k[], const uint8_t *iv);
void cipher_decrypt_cbc(uint8_t out[], const uint8_t in[], const uint8_t k[], const uint8_t *iv);
void cipher_encrypt_cfb(uint8_t out[], const uint8_t in[], const uint8_t k[], const uint8_t *iv);
void cipher_encrypt_cbc(uint8_t out[], const uint8_t in[], const uint8_t k[], const uint8_t *iv);
#endif
