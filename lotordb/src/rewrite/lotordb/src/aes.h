// Auth: smurfd, 2023 More reading & Borrow/Stolen parts read at the bottom of the file; 2 spacs indent; 150 width                                  //
#ifndef AES_H
#define AES_H 1
#include <stdint.h>

typedef struct state_t {
  uint8_t **state;
  uint8_t Nk;
} state_t;

#define BIN(x) str_to_bin(#x) // TODO: maby not needed?
#define LONG2BIN(x, y) long_to_bin(x, y)
#define BIN2LONG(x) bin_to_long(x)
#define EOR(x, y) (y ^ x)
#define u64 unsigned long long int // because linux uint64_t is not same as on mac
void multiply(u64 R[]);
void modreduce(u64 K[]);
void st(u64 Z);
uint32_t little_endian_uint32(uint8_t x);
uint8_t *right_pad_to_multiple_of_16_bytes(uint8_t *input, int len);
#endif
