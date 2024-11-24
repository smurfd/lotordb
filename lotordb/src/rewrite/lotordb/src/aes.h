// Auth: smurfd, 2023 More reading & Borrow/Stolen parts read at the bottom of the file; 2 spacs indent; 150 width                                  //
#ifndef AES_H
#define AES_H 1
#include <stdint.h>

#define BIN(x) to_bin(#x)
#define EOR(x, y) (y ^ x)
#define u64 unsigned long long int // because linux uint64_t is not same as on mac
void multiply(u64 R[]);
void modreduce(u64 K[]);
void st(u64 Z);
#endif
