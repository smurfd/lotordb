#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../crypto_server.h"
#include "../crypto_client.h"
#include "../aes.h"
#include "../keys.h"
#include "../hash.h"
#include "../crypto.h"
#include "../db_tables.h"
#include "../db_keystore.h"
#include "../examples/tables_example_struct.h"
#include "../lotorssl/src/bmec.h"

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

int main(int argc, char** argv) {
  int ret = 1;
  if (argc == 1) { // When run without arguments
    printf("\"[o.o]\" \t testing .... \t \"[o.o]\"\n\n");
    ret &= test_hash();
    ret &= test_hashshake();
    ret &= test_aes();
    ret &= test_aesgcm();
    ret &= test_aesgcm32bit();
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
      ret &= test_hash();
      ret &= test_hashshake();
      ret &= test_aes();
      ret &= test_aesloop();
      ret &= test_aesgcm();
      ret &= test_aesgcmloop();
      ret &= test_aesgcm32bit();
      ret &= test_aesgcm32bitloop();
      ret &= test_genkeys();
      ret &= test_keys_verify();
      ret &= test_db_table();
      if (ret) printf("\nOK\n");
      else printf("\nNot OK\n");
    }
  }
}
