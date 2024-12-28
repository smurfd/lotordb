#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../hash.h"
#include "../aes.h"

void test_hash(void) {
  uint8_t hash[256];
  hash_new((char*)hash, (uint8_t*)"some string to hash");
  assert(memcmp(hash, "3bac5403ba8697d73eac50c2f8ccf688e04d785658c518d50ec8e664f6c71b1fa87394ee056a3cdadd615d9b0b4ad2cef222b9ae68e463eac9ed2aee62367f52", 128));
}

void test_aes(void) {
  uint32_t key[8] = {0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4};
  uint32_t plain[4] = {0xf69f2445, 0xdf4f9b17, 0xad2b417b, 0xe66c3710};
  uint32_t expect[4] = {0x23304b7a, 0x39f9f3ff, 0x067d8d8f, 0x9e24ecc7};
  uint32_t resultenc[64] = {0}, resultdec[64] = {0};
  cipher(resultenc, key, plain);
  inv_cipher(resultdec, key, resultenc);
  assert(memcmp(resultenc, expect, 4 * sizeof(uint32_t)) == 0 && memcmp(resultdec, plain, 4 * sizeof(uint32_t)) == 0);
}

void test_aesloop(void) {
  uint8_t res = 0;
  uint32_t key[8] = {0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4};
  uint32_t plain[4] = {0xf69f2445, 0xdf4f9b17, 0xad2b417b, 0xe66c3710};
  uint32_t expect[4] = {0x23304b7a, 0x39f9f3ff, 0x067d8d8f, 0x9e24ecc7};
  uint32_t resultenc[64] = {0}, resultdec[64] = {0};
  for (int i = 0; i < 1000000; i++) {
    cipher(resultenc, key, plain);
    inv_cipher(resultdec, key, resultenc);
    res += memcmp(resultenc, expect, 4 * sizeof(uint32_t));
    res += memcmp(resultdec, plain, 4 * sizeof(uint32_t));
  }
  assert(res == 0);
}

int main(void) {
  test_hash();
  test_aes();
  test_aesloop();
  printf("OK\n");
}
