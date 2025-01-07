#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../hash.h"
#include "../ecc.h"

uint8_t test_hash(void) {
  uint8_t hash[256];
  hash_new((char*)hash, (uint8_t*)"some string to hash");
  assert(memcmp(hash, "0x3bac5403ba8697d73eac50c2f8ccf688e04d785658c518d50ec8e664f6c71b1fa87394ee056a3cdadd615d9b0b4ad2cef222b9ae68e463eac9ed2aee62367f52", 128) == 0);
  return 1;
}

uint8_t test_hashloop(void) {
  uint8_t res = 0;
  clock_t start = clock();
  for (int i = 0; i < 1000000; i++) {
    uint8_t hash[256] = {0}; 
    hash_new((char*)hash, (uint8_t*)"some string to hash");
    res += memcmp(hash, "0x3bac5403ba8697d73eac50c2f8ccf688e04d785658c518d50ec8e664f6c71b1fa87394ee056a3cdadd615d9b0b4ad2cef222b9ae68e463eac9ed2aee62367f52", 128);
  }
  assert(res == 0);
  printf("hashloop: Time %us %ums\n", (uint32_t)((clock() - start) * 1000 / CLOCKS_PER_SEC) / 1000, (uint32_t)((clock() - start) * 1000 / CLOCKS_PER_SEC) % 1000);
  return 1;
}

uint8_t test_hashshakeloop(void) {
  uint8_t res = 0;
  clock_t start = clock();
  for (int i = 0; i < 1000000; i++) {
    char hash[256] = {0};
    hash_shake_new(hash, 128, (uint8_t*)"some string to hash", 19);
    res += memcmp(hash, "0x117a821877bd84a56e3feefca36f4979f733177186b9e2df97c48e2c5045d7afb85252ba5fa57b666d39f43959f9566eaedad6b54b0e2e09fb1c309408da0f2b", 128);
  }
  assert(res == 0);
  printf("hashshakeloop: Time %us %ums\n", (uint32_t)((clock() - start) * 1000 / CLOCKS_PER_SEC) / 1000, (uint32_t)((clock() - start) * 1000 / CLOCKS_PER_SEC) % 1000);
  return 1;
}

uint8_t test_ecc(void) {
  ecc_sign_gen();
  return 1;
}

int main(int argc, char** argv) {
  uint8_t ret = 1;
  if (argc == 1) { // When run without arguments or in CI
    ret &= test_hash();
    ret &= test_ecc();
  } else {
    ret &= test_hash();
    ret &= test_hashloop();
    ret &= test_hashshakeloop();
    ret &= test_ecc();
  }
  if (ret) {
    printf("OK\n");
  } else {
    printf("Not OK\n");
  }
}
