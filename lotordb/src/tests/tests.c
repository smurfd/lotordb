#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../ciphers.h"
#include "../crypto_server.h"
#include "../crypto_client.h"
#include "../keys.h"
#include "../crypto.h"
#include "../db_tables.h"
#include "../db_keystore.h"

static uint8_t iv1[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static uint8_t key1[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
static uint8_t outdec[256] = {0}, outenc[256] = {0}, lain[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

uint8_t test_ciphers_aes_gcm_text32loop(void) {
  for (int i = 0; i < 10000; i++) {
    aes_gcm_encrypt(outenc, lain, 32, key1, 32, iv1, 32);
    aes_gcm_decrypt(outdec, outenc, sizeof(outenc), key1, 32, iv1, 32);
    for (int i = 0; i < 32; i++) assert(lain[i] == outdec[i]);
  }
  return 1;
}

uint8_t test_ciphers_aes_gcm_text32(void) {
  aes_gcm_encrypt(outenc, lain, 32, key1, 32, iv1, 32);
  aes_gcm_decrypt(outdec, outenc, sizeof(outenc), key1, 32, iv1, 32);
  for (int i = 0; i < 32; i++) assert(lain[i] == outdec[i]);
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

// TODO: this needs to be wayyy simpler. More helper functions
uint8_t test_db_table(void) {
  // Define database table structure
  struct prstest {
    u64 age;
    float height;
    char name[20];
    u64 nr;
    int test;
  };
  // Open database file for writing
  FILE *write_ptr = fopen("/tmp/dbtest1.db", "ab");
  // Allocate memory
  binary *bin = malloc(sizeof(binary)), *dataall = malloc(sizeof(binary) * DBLENGTH);
  u64 *header = malloc(sizeof(u64) * DBLENGTH);
  ctx *c = (void*)malloc(sizeof(ctx));
  c->structure = malloc(sizeof(struct prstest));
  // Create context for database & write to file
  for (u64 i = 0; i < DBLENGTH; i++) {
    struct prstest p = {i, 6.8, "testsmurfan", 666, 1};
    table_addctx(c, i, 12345678901111 + i, (struct prstest*)&p, sizeof(struct prstest));
    table_writectx(c, bin, write_ptr);
  }
  fclose(write_ptr);
  // Open database file for reading
  FILE *read_ptr = fopen("/tmp/dbtest1.db", "rb");
  for (u64 j = 0; j < table_getctxsize(read_ptr) / DBLENGTH; j++) {
    // Loop the whole database, in chunks of DBLENGTH
    // Read binary chunks DBLENGTH
    table_readctx(dataall, read_ptr, j);
    for (u64 i = 0; i < DBLENGTH; i++) {
      // For each chunk, copy data & decrypt
      table_getctx(c, header, bin, dataall + i, sizeof(struct prstest));
      // Search for age == 666
      if (((struct prstest*)((struct ctx*)c)->structure)->age == 666) {
        printf("found\n");
        // Free memory
        if (c->structure != NULL) free(c->structure);
        if (header != NULL) free(header);
        if (bin != NULL) free(bin);
        if (c != NULL) free(c);
        fclose(read_ptr);
        return 1;
      }
    }
  }
  // Free memory
  if (c->structure != NULL) free(c->structure);
  if (header != NULL) free(header);
  if (bin != NULL) free(bin);
  if (c != NULL) free(c);
  fclose(read_ptr);
  return 0;
}

int main(int argc, char** argv) {
  int ret = 1;
  if (argc == 1) {
    printf("\"[o.o]\"              testing ....              \"[o.o]\"\n\n");
    ret &= test_genkeys();
    ret &= test_keys_verify();
    ret &= test_ciphers_aes_gcm_text32();
    ret &= test_ciphers_aes_gcm_text32loop();
    ret &= test_db_table();
    if (ret) printf("\nOK\n");
    else printf("\nNot OK\n");
  } else {
    if (strcmp(argv[1], "server") == 0) {
      connection c = server_init("127.0.0.1", "9998", usage(argv[2], argc, "server"));
      server_handle(c);
      server_end(c);
    } else if (strcmp(argv[1], "client") == 0) {
      connection c = client_init("127.0.0.1", "9998", usage(argv[2], argc, "client"));
      if (client_handle(c) < 0) {
        printf("Cant connect to server\n");
        exit(0);
      }
      client_end(c);
    }
  }
}
