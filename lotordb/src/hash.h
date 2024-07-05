// Auth: smurfd, 2023 More reading & Borrow/Stolen parts read at the bottom of the file; 2 spacs indent; 120 width    //
#ifndef LIGHTHASH_H
#define LIGHTHASH_H 1
#include <stdint.h>
// Imitate pythons %. -1 % 5 = 4, not -1
#define MOD(n, m) (((int)n % (int)m) + (int)m) % (int)m
#define SHA3_BITS 1024 // SHA3-256 = 512, SHA3-512 = 1024 (default)
#define u64 unsigned long long int // because linux uint64_t is not same as on mac

void hash_new(char s[], const uint8_t *n);
void hash_shake_new(uint8_t *out, uint32_t outlen, const uint8_t *in, uint32_t inlen);
#endif
// Code grabbed from https://www.rfc-editor.org/rfc/rfc6234 and massaged
