#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../hash.h"
#include "../aes.h"

static uint8_t plain[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
  iv[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
  aeskey[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
    0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

void printing(char str[], u64 r[]) {
  printf("%s ", str);
  for (int i = 0; i < 32; i++) printf("%llu ", r[i]);
  printf("\n");
}

void printing_1matrix(char var[], int start, int end, u64 r[]) {
  printf("%s: ", var);
  for (int i = start; i >= end; i--) printf("%llu ", r[i]);
  printf("\n");
}
/*
void test_aes0(void) {
  uint8_t out[BBL] = {0}, in[BBL] = {0};
  ciph_cryptcfb(out, plain, aeskey, iv, false);
  ciph_cryptcfb(in, out, aeskey, iv, true);
  assert(memcmp(plain, in, BBL * sizeof(uint8_t)) == 0);
}

void test_aes1(void) {
  uint8_t out[BBL] = {0}, in[BBL] = {0};
  ciph_cryptcfb(out, plain, aeskey, iv, false);
  ciph_cryptcfb(in, out, aeskey, iv, true);
  assert(memcmp(plain, in, BBL * sizeof(uint8_t)) == 0);
}
*/
void test_aes2(void) {
  uint8_t out[BBL] = {0}, in[BBL] = {0};
  ciph_encryptcbc(out, plain, aeskey, iv);
  ciph_decryptcbc(in, out, aeskey, iv);
  assert(memcmp(plain, in, BBL * sizeof(uint8_t)) == 0);
}

int main(void) {
/*
  u64 r[32];
  char hash[256];
  uint8_t *xxx = malloc(32);
  clock_t t = clock();
  hash_new(hash, (uint8_t*)"some string to hash");
  printf("hash: %s\n", hash);
  for (int i = 0; i < 32; i++) r[i] = i;
  printing_1matrix("A", 19, 16, r);
  printing_1matrix("B", 23, 20, r);
  printing("before multiply: ", r);
  multiply(r);
  printing("after multiply: ", r);
  printing_1matrix("C", 15, 9, r);
  modreduce(r);
  printing("after modreduce: ", r);
  for (int i = 0; i < 32; i++) {st(r[i]); xxx[i] = 1;}
  printing("after st: ", r);
  double time_taken = ((double)clock() - t) / CLOCKS_PER_SEC; // in seconds
  printf("took %f seconds to execute\n\n", time_taken);
  for (int i = 0; i < 32; i++) printf("before %d\n", xxx[i]);
  right_pad_to_multiple_of_16_bytes(xxx, 18);
  for (int i = 0; i < 32; i++) printf("after %d\n", xxx[i]);
  printf("OK\n");
  printf("::: %u\n", little_endian_uint32(32));
  free(xxx);
*/
  //test_aes0();
  //test_aes1();
  test_aes2();
  printf("OK\n");
}
