#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../crypto_server.h"
#include "../crypto_client.h"
//#include "../aes.h"
#include "../keys.h"
//#include "../hash.h"
#include "../crypto.h"
#include "../db_tables.h"
#include "../db_keystore.h"
#include "../examples/tables_example_struct.h"
#include "../lotorssl/src/bmec.h"
#include "../lotorssl/src/hash.h"
#include "../lotorssl/src/ciph.h"


/*
uint8_t test_hash(void) {
  uint8_t hash[256];
  hash_new((char*)hash, (uint8_t*)"some string to hash");
  assert(memcmp(hash, "0x3bac5403ba8697d73eac50c2f8ccf688e04d785658c518d50ec8e664f6c71b1fa87394ee056a3cdadd615d9b0b4ad2cef222b9ae68e463eac9ed2aee62367f52", 128) == 0);
  return 1;
}

uint8_t test_hashshake(void) {
  char hash[256] = {0};
  hash_shake_new(hash, 128, (uint8_t*)"some string to hash", 19);
  assert(memcmp(hash, "0x117a821877bd84a56e3feefca36f4979f733177186b9e2df97c48e2c5045d7afb85252ba5fa57b666d39f43959f9566eaedad6b54b0e2e09fb1c309408da0f2b", 128) == 0);
  return 1;
}
*/

uint8_t civ[32] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, ckey[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
  0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}, cplain[32] = {0x00, 0x11,
  0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
  0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, ccipher[32] = {0}, ctag[32] = {0}, ctag2[32] = {0}, caad[32] = {0}, cplain2[32] = {0}, cres = 0,
 *cplain3 = (uint8_t*)"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.\
 Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit\
 in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt\
 mollit anim id est laborum.";

int8_t test_hash3(void) {
  uint8_t *smurfd = (uint8_t*)"smurfd";
  char s[256] = {0};
  hash_new(s, smurfd);
  assert(strcmp(s, "0x5c452b35648528cf3a00a42021489011dd455b78fc34190c7680173b2dcdcc7d61e73d4f2c51051e45d26215f9f7729b8\
986549e169dcee3280bed61cda25f20") == 0);
  assert(strcmp(s, "0x5c452b35648528cf3a00a42021489011dd455b78fc34190c7680173b2dcdcc7d61e73d4f2c51051e45d26215f9f7729b8\
986549e169dcee3280bed61cdffffff") != 0); // Assume failure
  return 1;
}

uint8_t test_hash3big(void) {
  char s[256] = {0};
  hash_new(s, cplain3);
  assert(strcmp(s, "0xf32a9423551351df0a07c0b8c20eb972367c398d61066038e16986448ebfbc3d15ede0ed3693e3905e9a8c601d9d002a0\
6853b9797ef9ab10cbde1009c7d0f09") == 0);
  assert(strcmp(s, "0xf32a9423551351df0a07c0b8c20eb972367c398d61066038e16986448ebfbc3d15ede0ed3693e3905e9a8c601d9d002a0\
6853b9797ef9ab10cbde1009c7d0fff") != 0); // Assume failure
  return 1;
}

uint8_t test_hash3bigloop(void) {
  uint8_t res = 0;
  clock_t start = clock();
  for (int i = 0; i < 1000000; i++) {
    char s[256] = {0};
    hash_new(s, cplain3);
    res += memcmp(s, "0xf32a9423551351df0a07c0b8c20eb972367c398d61066038e16986448ebfbc3d15ede0ed3693e3905e9a8c601d9d002a0\
6853b9797ef9ab10cbde1009c7d0f09", 130);
  }
  assert(res == 0);
  clock_t cs = clock() - start;
  printf("hash3bigloop: Time %us %ums\n", (uint32_t)((cs) * 1000 / CLOCKS_PER_SEC) / 1000, (uint32_t)((cs) * 1000 / CLOCKS_PER_SEC) % 1000);
  return 1;
}

uint8_t test_hash3shk(void) {
  uint8_t res[] = {0x0d, 0xcf, 0xbc, 0x11, 0xbd, 0xd2, 0x43, 0x82, 0x4b, 0x31, 0xe5, 0x13, 0x5b, 0x8f, 0x83, 0xfa, 0x1c,
       0x11, 0x8d, 0xd7, 0x6a, 0xc0, 0xea, 0xaf, 0xee, 0x19, 0x10, 0x17, 0x0b, 0xa5, 0x61, 0x89, 0xa5, 0x8d, 0x21, 0x2a,
       0xa2, 0xb4, 0x2d, 0xfe, 0xbd, 0x1b, 0x8c, 0xdd, 0x08, 0xa4, 0xc4, 0xd5, 0xae, 0xcb, 0xfa, 0x0c, 0x33, 0x60, 0x0f,
       0x39, 0x78, 0x8b, 0x75, 0x81, 0xb5, 0xbb, 0x4f, 0x42}, in1[1024] = {0}, out1[512] = {0};
  char s[] = "smurfd";
  memcpy(in1, s, 6 * sizeof(uint8_t));
  hash_shake_new(out1, 64, in1, 6);
  assert(memcmp(out1, res, 64 * sizeof(uint8_t)) == 0);
  return 1;
}

uint8_t test_hash3shkbig(void) {
  uint8_t res[] = {0x75, 0x74, 0x60, 0x89, 0x24, 0x0d, 0x9e, 0x39, 0xff, 0xf1, 0xb4, 0xba, 0x58, 0x13, 0x0a, 0xf5, 0xb9,
       0x74, 0x4f, 0x41, 0x2a, 0x9d, 0xff, 0x73, 0x84, 0x70, 0xd1, 0x24, 0x72, 0x53, 0xd3, 0x2c, 0xe7, 0xfe, 0x5a, 0xef,
       0x0d, 0x43, 0xda, 0x15, 0x5f, 0x29, 0x08, 0x58, 0xa4, 0x2e, 0xa0, 0x41, 0xd3, 0x9a, 0x6b, 0xfd, 0x04, 0x21, 0xd4,
       0x49, 0x8e, 0xa4, 0x95, 0xbd, 0x41, 0x3a, 0x9f, 0x58}, in1[1024], out1[512];
  char s[130] = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et\
 dolore magna aliqua. Ut eni";
  memcpy(in1, s, 130 * sizeof(uint8_t));
  hash_shake_new(out1, 64, in1, 130);
  assert(memcmp(out1, res, 64 * sizeof(uint8_t)) == 0);
  return 1;
}

uint8_t test_hash3shkref(void) {
  uint8_t res[] = {0xf6, 0x49, 0x68, 0x85, 0x8b, 0x5c, 0xd8, 0xa6, 0x4f, 0xfd, 0xd9, 0x2e, 0x8c, 0x72, 0xda, 0x03, 0x87,
       0xc5, 0x68, 0x9b, 0x56, 0x2e, 0x96, 0x28, 0x86, 0x04, 0xdf, 0x95, 0x31, 0x5f, 0xee, 0xfa, 0x5a, 0xe9, 0xf0, 0x59,
       0x6b, 0x0b, 0x3d, 0x47, 0xcd, 0x61, 0xac, 0x67, 0x6a, 0xd1, 0xfb, 0x20, 0xcf, 0x3d, 0x92, 0xab, 0x2b, 0x68, 0xda,
       0xa4, 0x89, 0x31, 0xcc, 0x58, 0xd6, 0xd7, 0x23, 0xc7}, in1[1024], out1[512];
  char s[] = "\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3";
  memcpy(in1, s, 20 * sizeof(uint8_t));
  hash_shake_new(out1, 64, in1, 20);
  assert(memcmp(out1, res, 64 * sizeof(uint8_t)) == 0);
  return 1;
}

uint8_t test_hash3shkrefloop(void) {
  uint8_t res[] = {0xf6, 0x49, 0x68, 0x85, 0x8b, 0x5c, 0xd8, 0xa6, 0x4f, 0xfd, 0xd9, 0x2e, 0x8c, 0x72, 0xda, 0x03, 0x87,
       0xc5, 0x68, 0x9b, 0x56, 0x2e, 0x96, 0x28, 0x86, 0x04, 0xdf, 0x95, 0x31, 0x5f, 0xee, 0xfa, 0x5a, 0xe9, 0xf0, 0x59,
       0x6b, 0x0b, 0x3d, 0x47, 0xcd, 0x61, 0xac, 0x67, 0x6a, 0xd1, 0xfb, 0x20, 0xcf, 0x3d, 0x92, 0xab, 0x2b, 0x68, 0xda,
       0xa4, 0x89, 0x31, 0xcc, 0x58, 0xd6, 0xd7, 0x23, 0xc7}, in1[1024], out1[512], ret = 0;
  char s[] = "\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3";
  clock_t start = clock();
  for (int i = 0; i < 1000000; i++) {
    memcpy(in1, s, 20 * sizeof(uint8_t));
    hash_shake_new(out1, 64, in1, 20);
    ret += memcmp(out1, res, 64 * sizeof(uint8_t));
  }
  assert(ret == 0);
  clock_t cs = clock() - start;
  printf("hash3shkrefloop: Time %us %ums\n", (uint32_t)((cs) * 1000 / CLOCKS_PER_SEC) / 1000, (uint32_t)((cs) * 1000 / CLOCKS_PER_SEC) % 1000);
  return 1;
}

uint8_t test_hash3shkrefloop2(void) {
  uint8_t res[] = {0xf6, 0x49, 0x68, 0x85, 0x8b, 0x5c, 0xd8, 0xa6, 0x4f, 0xfd, 0xd9, 0x2e, 0x8c, 0x72, 0xda, 0x03, 0x87,
       0xc5, 0x68, 0x9b, 0x56, 0x2e, 0x96, 0x28, 0x86, 0x04, 0xdf, 0x95, 0x31, 0x5f, 0xee, 0xfa, 0x5a, 0xe9, 0xf0, 0x59,
       0x6b, 0x0b, 0x3d, 0x47, 0xcd, 0x61, 0xac, 0x67, 0x6a, 0xd1, 0xfb, 0x20, 0xcf, 0x3d, 0x92, 0xab, 0x2b, 0x68, 0xda,
       0xa4, 0x89, 0x31, 0xcc, 0x58, 0xd6, 0xd7, 0x23, 0xc7}, in1[1024], out1[512], ret = 0;
  char s[] = "\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3";
  clock_t start = clock();
  for (int i = 0; i < 1000000; i++) {
    memcpy(in1, s, 20 * sizeof(uint8_t));
    hash_shake_new(out1, 64, in1, 20);
    ret += memcmp(out1, res, 64 * sizeof(uint8_t));
  }
  assert(ret == 0);
  clock_t cs = clock() - start;
  printf("hash3shkrefloop2: Time %us %ums\n", (uint32_t)((cs) * 1000 / CLOCKS_PER_SEC) / 1000, (uint32_t)((cs) * 1000 / CLOCKS_PER_SEC) % 1000);
  return 1;
}


uint8_t test_aes(void) {
  uint32_t key[8] = {0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4};
  uint32_t plain[4] = {0xf69f2445, 0xdf4f9b17, 0xad2b417b, 0xe66c3710};
  uint32_t expect[4] = {0x23304b7a, 0x39f9f3ff, 0x067d8d8f, 0x9e24ecc7};
  uint32_t resultenc[64] = {0}, resultdec[64] = {0};
  cipher(resultenc, key, plain);
  inv_cipher(resultdec, key, resultenc);
  assert(memcmp(resultenc, expect, 4 * sizeof(uint32_t)) == 0 && memcmp(resultdec, plain, 4 * sizeof(uint32_t)) == 0);
  return 1;
}

uint8_t test_aesloop(void) {
  uint8_t res = 0;
  uint32_t key[8] = {0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4};
  uint32_t plain[4] = {0xf69f2445, 0xdf4f9b17, 0xad2b417b, 0xe66c3710};
  uint32_t expect[4] = {0x23304b7a, 0x39f9f3ff, 0x067d8d8f, 0x9e24ecc7};
  uint32_t resultenc[64] = {0}, resultdec[64] = {0};
  clock_t start = clock();
  for (int i = 0; i < 1000000; i++) {
    cipher(resultenc, key, plain);
    inv_cipher(resultdec, key, resultenc);
    res += memcmp(resultenc, expect, 4 * sizeof(uint32_t));
    res += memcmp(resultdec, plain, 4 * sizeof(uint32_t));
  }
  assert(res == 0);
  clock_t cs = clock() - start;
  printf("aesloop: Time %us %ums\n", (uint32_t)((cs) * 1000 / CLOCKS_PER_SEC) / 1000, (uint32_t)((cs) * 1000 / CLOCKS_PER_SEC) % 1000);
  return 1;
}

uint8_t test_aesgcm(void) {
  gcm_ciphertag(ccipher, ctag, ckey, civ, cplain, caad,  32);
  gcm_inv_ciphertag(cplain2, ctag2, ckey, civ, ccipher, caad, ctag);
  cres += memcmp(cplain, cplain2, 32 * sizeof(uint8_t));
  assert(cres == 0);
  return 1;
}

uint8_t test_aesgcmloop(void) {
  clock_t start = clock();
  for (int i = 0; i < 1000000; i++) {
    gcm_ciphertag(ccipher, ctag, ckey, civ, cplain, caad,  32);
    gcm_inv_ciphertag(cplain2, ctag2, ckey, civ, ccipher, caad, ctag);
    cres += memcmp(cplain, cplain2, 32 * sizeof(uint8_t));
  }
  assert(cres == 0);
  clock_t cs = clock() - start;
  printf("aesgcmloop: Time %us %ums\n", (uint32_t)((cs) * 1000 / CLOCKS_PER_SEC) / 1000, (uint32_t)((cs) * 1000 / CLOCKS_PER_SEC) % 1000);
  return 1;
}

uint8_t test_aesgcm32bit(void) {
  uint32_t iv[32] = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff},
  key[32] = {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f},
  plain[32] = {0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff, 0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff},
  cipher[32] = {0}, tag[32] = {0}, tag2[32] = {0}, aad[32] = {0}, plain2[32] = {0}, res = 0;
  gcm_ciphertag32bit(cipher, tag, key, iv, plain, aad,  32);
  gcm_inv_ciphertag32bit(plain2, tag2, key, iv, cipher, aad, tag);
  res += memcmp(plain, plain2, 8 * sizeof(uint32_t));
  assert(res == 0);
  return 1;
}

uint8_t test_aesgcm32bitloop(void) {
  uint32_t iv[32] = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff},
  key[32] = {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f},
  plain[32] = {0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff, 0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff},
  cipher[32] = {0}, tag[32] = {0}, tag2[32] = {0}, aad[32] = {0}, plain2[32] = {0}, res = 0;
  clock_t start = clock();
  for (int i = 0; i < 1000000; i++) {
    gcm_ciphertag32bit(cipher, tag, key, iv, plain, aad, 8);
    gcm_inv_ciphertag32bit(plain2, tag2, key, iv, cipher, aad, tag);
    res += memcmp(plain, plain2, 8 * sizeof(uint32_t));
  }
  assert(res == 0);
  clock_t cs = clock() - start;
  printf("aesgcm32bitloop: Time %us %ums\n", (uint32_t)((cs) * 1000 / CLOCKS_PER_SEC) / 1000, (uint32_t)((cs) * 1000 / CLOCKS_PER_SEC) % 1000);
  return 1;
}



//
// Generate a keypair & shared key then print it (test / demo)
uint8_t test_genkeys(void) {
  head h1, h2;
  h1.g = u64rnd(); h1.p = u64rnd(); h2.g = u64rnd(); h2.p = u64rnd();
  u64 c = 123456, d = 1, e = 1;
  cryptokey k1 = generate_cryptokeys(&h1), k2 = generate_cryptokeys(&h2);
  generate_shared_cryptokey_client(&k1, &k2, &h1);
  generate_shared_cryptokey_server(&k1, &k2, &h1);
  printf("Alice public & private key: 0x%.20llx 0x%.20llx\n", k1.publ, k1.priv);
  printf("Bobs public & private key: 0x%.20llx 0x%.20llx\n", k2.publ, k2.priv);
  printf("Alice & Bobs shared key: 0x%.20llx 0x%.20llx\n", k1.shar, k2.shar);
  handler_cryptography(c, k1, &d);
  handler_cryptography(d, k2, &e);
  printf("Before:  0x%.20llx\nEncrypt: 0x%.20llx\nDecrypt: 0x%.20llx\n",c,d,e);
  assert(c == e);
  return 1;
}

uint8_t test_keys_verify(void) {
  uint8_t sig[BYTES * 2],  pubkey[BYTES + 1],  sec[BYTES], privkey[BYTES], h[BYTES] = {0};
  assert(keys_make(pubkey, privkey));
  assert(keys_secr(pubkey, privkey, sec));
  assert(keys_sign(privkey, h, sig));
  assert(keys_vrfy(pubkey, h, sig));
  assert(!keys_vrfy(privkey, h, sig)); // assert failure
  return 1;
}

static void table_filltestdata(ctx **c, binary **bin, FILE *write_ptr) {
  for (u64 i = 0; i < DBLENGTH; i++) {
    struct tabletest p = {i, 6.8, "testsmurfan", 666, 1};
    table_addctx(*c, i, 12345678901111 + i, &p, sizeof(p));
    table_writectx(*c, *bin, write_ptr);
  }
  if (write_ptr != NULL) fclose(write_ptr);
}

// Create a local database and search for the age 666
uint8_t test_db_table(void) {
  binary *bin, *dataall;
  u64 *header;
  ctx *c;
  // Open database file for writing
  FILE *write_ptr = fopen("/tmp/dbtest1.db", "ab");
  // Malloc memory for variables used
  table_malloc(&bin, &dataall, &header, &c, sizeof(struct tabletest));
  // Create context for database, write to file & close file
  table_filltestdata(&c, &bin, write_ptr);
  // Open database file for reading
  FILE *read_ptr = fopen("/tmp/dbtest1.db", "rb");
  for (u64 j = 0; j < table_getctxsize(read_ptr) / DBLENGTH; j++) { // Loop the whole database, in chunks of DBLENGTH
    // Read binary chunks DBLENGTH
    table_readctx(dataall, read_ptr, j);
    for (u64 i = 0; i < DBLENGTH; i++) {
      // For each chunk, copy data & decrypt. tabletest defined in ../examples/tables_example_struct.h
      table_getctx(c, header, bin, dataall + i, sizeof(struct tabletest));
      if (((struct tabletest*)((struct ctx*)c)->structure)->age == 666) { // Search for age == 666
        printf("Found\n");
        // Free memory & close filepointer
        table_free(&bin, &dataall, &header, &c, read_ptr);
        return 1;
      }
    }
  }
  // Free memory & close filepointer
  table_free(&bin, &dataall, &header, &c, read_ptr);
  return 0;
}
/*
uint8_t test_aes(void) {
  uint32_t key[8] = {0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4};
  uint32_t plain[4] = {0xf69f2445, 0xdf4f9b17, 0xad2b417b, 0xe66c3710};
  uint32_t expect[4] = {0x23304b7a, 0x39f9f3ff, 0x067d8d8f, 0x9e24ecc7};
  uint32_t resultenc[64] = {0}, resultdec[64] = {0};
  cipher(resultenc, key, plain);
  inv_cipher(resultdec, key, resultenc);
  assert(memcmp(resultenc, expect, 4 * sizeof(uint32_t)) == 0 && memcmp(resultdec, plain, 4 * sizeof(uint32_t)) == 0);
  return 1;
}

uint8_t test_aesloop(void) {
  uint8_t res = 0;
  uint32_t key[8] = {0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4};
  uint32_t plain[4] = {0xf69f2445, 0xdf4f9b17, 0xad2b417b, 0xe66c3710};
  uint32_t expect[4] = {0x23304b7a, 0x39f9f3ff, 0x067d8d8f, 0x9e24ecc7};
  uint32_t resultenc[64] = {0}, resultdec[64] = {0};
  clock_t start = clock();
  for (int i = 0; i < 1000000; i++) {
    cipher(resultenc, key, plain);
    inv_cipher(resultdec, key, resultenc);
    res += memcmp(resultenc, expect, 4 * sizeof(uint32_t));
    res += memcmp(resultdec, plain, 4 * sizeof(uint32_t));
  }
  assert(res == 0);
  printf("aesloop: Time %us %ums\n", (uint32_t)((clock() - start) * 1000 / CLOCKS_PER_SEC) / 1000, (uint32_t)((clock() - start) * 1000 / CLOCKS_PER_SEC) % 1000);
  return 1;
}

uint8_t test_aesgcm(void) {
  uint8_t iv[32] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
  key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
  plain[32] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
  cipher[32] = {0}, tag[32] = {0}, tag2[32] = {0}, aad[32] = {0}, plain2[32] = {0}, res = 0;
  gcm_ciphertag(cipher, tag, key, iv, plain, aad,  32);
  gcm_inv_ciphertag(plain2, tag2, key, iv, cipher, aad, tag);
  res += memcmp(plain, plain2, 32 * sizeof(uint8_t));
  assert(res == 0);
  return 1;
}

uint8_t test_aesgcmloop(void) {
  uint8_t iv[32] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
  key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
  plain[32] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
  cipher[32] = {0}, tag[32] = {0}, tag2[32] = {0}, aad[32] = {0}, plain2[32] = {0}, res = 0;
  clock_t start = clock();
  for (int i = 0; i < 1000000; i++) {
    gcm_ciphertag(cipher, tag, key, iv, plain, aad,  32);
    gcm_inv_ciphertag(plain2, tag2, key, iv, cipher, aad, tag);
    res += memcmp(plain, plain2, 32 * sizeof(uint8_t));
  }
  assert(res == 0);
  printf("aesgcmloop: Time %us %ums\n", (uint32_t)((clock() - start) * 1000 / CLOCKS_PER_SEC) / 1000, (uint32_t)((clock() - start) * 1000 / CLOCKS_PER_SEC) % 1000);
  return 1;
}

uint8_t test_aesgcm32bit(void) {
  uint32_t iv[32] = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff},
  key[32] = {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f},
  plain[32] = {0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff, 0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff},
  cipher[32] = {0}, tag[32] = {0}, tag2[32] = {0}, aad[32] = {0}, plain2[32] = {0}, res = 0;
  gcm_ciphertag32bit(cipher, tag, key, iv, plain, aad,  32);
  gcm_inv_ciphertag32bit(plain2, tag2, key, iv, cipher, aad, tag);
  res += memcmp(plain, plain2, 8 * sizeof(uint32_t));
  assert(res == 0);
  return 1;
}

uint8_t test_aesgcm32bitloop(void) {
  uint32_t iv[32] = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff},
  key[32] = {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f},
  plain[32] = {0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff, 0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff},
  cipher[32] = {0}, tag[32] = {0}, tag2[32] = {0}, aad[32] = {0}, plain2[32] = {0}, res = 0;
  clock_t start = clock();
  for (int i = 0; i < 1000000; i++) {
    gcm_ciphertag32bit(cipher, tag, key, iv, plain, aad, 8);
    gcm_inv_ciphertag32bit(plain2, tag2, key, iv, cipher, aad, tag);
    res += memcmp(plain, plain2, 8 * sizeof(uint32_t));
  }
  assert(res == 0);
  printf("aesgcm32bitloop: Time %us %ums\n", (uint32_t)((clock() - start) * 1000 / CLOCKS_PER_SEC) / 1000, (uint32_t)((clock() - start) * 1000 / CLOCKS_PER_SEC) % 1000);
  return 1;
}
*/
int main(int argc, char** argv) {
  int ret = 1;
  if (argc == 1) { // When run without arguments
    printf("\"[o.o]\" \t testing .... \t \"[o.o]\"\n\n");
    //ret &= test_hash();
    //ret &= test_hashshake();
    ret &= test_hash3();
    ret &= test_hash3big();
    ret &= test_hash3shk();
    ret &= test_hash3shkbig();
    ret &= test_hash3shkref();
    ret &= test_aes();
    ret &= test_aesgcm();
    ret &= test_aesgcm32bit();
    //ret &= test_aes();
    //ret &= test_aesgcm();
    //ret &= test_aesgcm32bit();
    ret &= test_genkeys();
    ret &= test_keys_verify();
    ret &= test_db_table();
    if (ret) printf("\nOK\n");
    else printf("\nNot OK\n");
  } else {
    if (strcmp(argv[1], "server") == 0) { // When run with server arguments and either keys or tables
      connection c = server_init("127.0.0.1", "9998", usage(argv[2], argc, "server"));
      server_handle(c);
      server_end(c);
    } else if (strcmp(argv[1], "client") == 0) { // When run with client arguments and either keys or tables
      connection c = client_init("127.0.0.1", "9998", usage(argv[2], argc, "client"));
      if (client_handle(c) < 0) {
        printf("Cant connect to server\n");
        exit(0);
      }
      client_end(c);
    } else if (strcmp(argv[1], "local") == 0) { // When run locally to measure speed
      printf("\"[o.o]\" \t testing locally.... \t \"[o.o]\"\n\n");
      //ret &= test_hash();
      //ret &= test_hashshake();
      ret &= test_hash3();
      ret &= test_hash3big();
      ret &= test_hash3bigloop();
      ret &= test_hash3shk();
      ret &= test_hash3shkbig();
      ret &= test_hash3shkref();
      ret &= test_hash3shkrefloop();
      ret &= test_hash3shkrefloop2();
      ret &= test_aes();
      ret &= test_aesloop();
      ret &= test_aesgcmloop();
      ret &= test_aesgcm();
      ret &= test_aesgcmloop();
      ret &= test_aesgcm32bit();
      ret &= test_aesgcm32bitloop();
      //ret &= test_aes();
      //ret &= test_aesloop();
      //ret &= test_aesgcm();
      //ret &= test_aesgcmloop();
      //ret &= test_aesgcm32bit();
      //ret &= test_aesgcm32bitloop();
      ret &= test_genkeys();
      ret &= test_keys_verify();
      ret &= test_db_table();
      if (ret) printf("\nOK\n");
      else printf("\nNot OK\n");
    }
  }
}
