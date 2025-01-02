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
  clock_t start = clock(), end;
  for (int i = 0; i < 1000000; i++) {
    cipher(resultenc, key, plain);
    inv_cipher(resultdec, key, resultenc);
    res += memcmp(resultenc, expect, 4 * sizeof(uint32_t));
    res += memcmp(resultdec, plain, 4 * sizeof(uint32_t));
  }
  assert(res == 0);
  end = clock() - start;
  int msec = end * 1000 / CLOCKS_PER_SEC;
  printf("Time taken %d seconds %d milliseconds\n", msec/1000, msec%1000);
}

/*
Taglen = 128
AADlen = 160
PTlen = 480
Encrypt-Generate
K is
FEFFE992 8665731C 6D6A8F94 67308308
FEFFE992 8665731C 6D6A8F94 67308308
IV is
CAFEBABE FACEDBAD DECAF888
A is
3AD77BB4 0D7A3660 A89ECAF3 2466EF97
F5D3D585
P is
D9313225 F88406E5 A55909C5 AFF5269A
86A7A953 1534F7DA 2E4C303D 8A318A72
1C3C0C95 95680953 2FCF0E24 49A6B525
B16AEDF5 AA0DE657 BA637B39
H is
ACBEF205 79B4B8EB CE889BAC 8732DAD7
-----------------------
-----------------------
--------------------------------------------------------------
-----------------------
J0 is
CAFEBABE FACEDBAD DECAF888 00000001
*/

void test_aesgcm(void) {
  uint8_t iv[32] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
  key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
  plain[32] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
  cipher[32] = {0}, tag[32] = {0}, tag2[32] = {0}, aad[32] = {0}, plain2[32] = {0};
  gcm_ciphertag(cipher, tag, key, iv, plain, aad,  32);
  gcm_inv_ciphertag(plain2, tag2, key, iv, cipher, aad, tag);
  for (int i = 0; i < 32; i++) {
    printf("aes new %d %d\n", plain[i], plain2[i]);
    assert(plain[i] == plain2[i]);
  }
}

void test_aesgcmloop(void) {
  uint8_t iv[32] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
  key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
  plain[32] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
  cipher[32] = {0}, tag[32] = {0}, tag2[32] = {0}, aad[32] = {0}, plain2[32] = {0};
  clock_t start = clock(), end;
  for (int i = 0; i < 1000000; i++) {
    gcm_ciphertag(cipher, tag, key, iv, plain, aad,  32);
    gcm_inv_ciphertag(plain2, tag2, key, iv, cipher, aad, tag);
    for (int j = 0; j < 32; j++) {
      assert(plain[j] == plain2[j]);
    }
  }
  end = clock() - start;
  int msec = end * 1000 / CLOCKS_PER_SEC;
  printf("Time taken %d seconds %d milliseconds\n", msec/1000, msec%1000);
}

void test_aesgcm32bit(void) {
  uint32_t iv[32] = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff},
  key[32] = {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f},
  plain[32] = {0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff, 0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff},
  cipher[32] = {0}, tag[32] = {0}, tag2[32] = {0}, aad[32] = {0}, plain2[32] = {0};
  gcm_ciphertag32bit(cipher, tag, key, iv, plain, aad,  32);
  gcm_inv_ciphertag32bit(plain2, tag2, key, iv, cipher, aad, tag);
  for (int i = 0; i < 8; i++) {
    printf("aes new %d %d\n", plain[i], plain2[i]);
    assert(plain[i] == plain2[i]);
  }
}

void test_aesgcm32bitloop(void) {
  uint32_t iv[32] = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff},
  key[32] = {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f},
  plain[32] = {0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff, 0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff},
  cipher[32] = {0}, tag[32] = {0}, tag2[32] = {0}, aad[32] = {0}, plain2[32] = {0};
  clock_t start = clock(), end;
  for (int i = 0; i < 1000000; i++) {
    gcm_ciphertag32bit(cipher, tag, key, iv, plain, aad, 8);
    gcm_inv_ciphertag32bit(plain2, tag2, key, iv, cipher, aad, tag);
    for (int j = 0; j < 8; j++) {
      //printf("aes new %d %d\n", plain[i], plain2[i]);
      assert(plain[j] == plain2[j]);
    }
  }
  end = clock() - start;
  int msec = end * 1000 / CLOCKS_PER_SEC;
  printf("Time taken %d seconds %d milliseconds\n", msec/1000, msec%1000);
}

int main(void) {
  test_hash();
  test_aes();
  test_aesloop();
  test_aesgcm();
  test_aesgcmloop();
  test_aesgcm32bit();
  test_aesgcm32bitloop();
  printf("OK\n");
}
