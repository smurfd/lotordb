#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../ciphers_aes_gcm.h"
#include "../crypto_server.h"
#include "../crypto_client.h"
#include "../keys.h"
#include "../crypto.h"
#include "../ciphers.h"
#include "../db_tables.h"
#include "../db_keystore.h"

void test_ciphers_aes_gcm(void) {
  const char *vf = "tests/gcm_test_vectors.bin";
  uint8_t *vd;
  aes_init_keygen_tables();
  if (load_file_into_ram(vf, &vd) < 0) {
    printf("Cant load the test vector file\n");
    exit(0);
  }
  if(verify_gcm(vd)) {
    printf("NIST AES-GCM validation test suite: FAILED!\n");
    free(vd);
    exit(0);
  }
  free(vd);
}

//
// Generate a keypair & shared key then print it (test / demo)
void test_genkeys(void) {
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
}

void test_ciphers_cfb(void) {
  uint8_t plain[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
  iv[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, key[] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
  0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}, out[sizeof(plain)] = {0}, in[sizeof(plain)];
  cipher_encrypt_cfb(out, plain, key, iv, sizeof(plain));
  cipher_decrypt_cfb(in, out, key, iv, sizeof(plain));
  assert(memcmp(plain, in, sizeof(plain) * sizeof(uint8_t)) == 0);
}

void test_ciphers_cbc(void) {
  uint8_t plain[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
  iv[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, key[] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
  0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}, out[sizeof(plain)] = {0}, in[sizeof(plain)];
  cipher_encrypt_cbc(out, plain, key, iv, sizeof(plain));
  cipher_decrypt_cbc(in, out, key, iv, sizeof(plain));
  assert(memcmp(plain, in, sizeof(plain) * sizeof(uint8_t)) == 0);
}

void test_ciphers_cbc_long(void) {
  uint8_t plain[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
  iv[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, key[] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
  0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}, out[sizeof(plain)] = {0}, in[sizeof(plain)];
  cipher_encrypt_cbc(out, plain, key, iv, sizeof(plain));
  cipher_decrypt_cbc(in, out, key, iv, sizeof(plain));
  assert(memcmp(plain, in, sizeof(plain) * sizeof(uint8_t)) == 0);
}

void test_ciphers_cfb_long(void) {
  uint8_t plain[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
  iv[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, key[] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
  0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}, out[sizeof(plain)] = {0}, in[sizeof(plain)];
  cipher_encrypt_cfb(out, plain, key, iv, sizeof(plain));
  cipher_decrypt_cfb(in, out, key, iv, sizeof(plain));
  assert(memcmp(plain, in, sizeof(plain) * sizeof(uint8_t)) == 0);
}

void test_ciphers_cbc_long_str(void) {
  char plain[] = "this is a very very long string, that we should be able to encrypt and decrypt without a problem, dont you think? it should be perfectly fine, just gotta convert it to uint8_t. really really really long, yeah";
  uint8_t iv[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, key[] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
  0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}, out[sizeof(plain)] = {0}, in[sizeof(plain)];
  cipher_encrypt_cbc(out, (uint8_t*)plain, key, iv, sizeof(plain));
  cipher_decrypt_cbc(in, out, key, iv, sizeof(plain));
  assert(memcmp(plain, in, sizeof(plain) * sizeof(uint8_t)) == 0);
}

void test_ciphers_cfb_long_str(void) {
  char plain[] = "this is a very very long string, that we should be able to encrypt and decrypt without a problem, dont you think? it should be perfectly fine, just gotta convert it to uint8_t. really really really long, yeah";
  uint8_t iv[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, key[] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
  0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}, out[sizeof(plain)] = {0}, in[sizeof(plain)];
  cipher_encrypt_cfb(out, (uint8_t*)plain, key, iv, sizeof(plain));
  cipher_decrypt_cfb(in, out, key, iv, sizeof(plain));
  assert(memcmp(plain, in, sizeof(plain) * sizeof(uint8_t)) == 0);
}

void test_keys_verify(void) {
  uint8_t sig[BYTES * 2],  pubkey[BYTES + 1],  sec[BYTES], privkey[BYTES], h[BYTES] = {0};
  assert(keys_make(pubkey, privkey));
  assert(keys_secr(pubkey, privkey, sec));
  assert(keys_sign(privkey, h, sig));
  assert(keys_vrfy(pubkey, h, sig));
  assert(!keys_vrfy(privkey, h, sig)); // assert failure
}

int main(void) {
  printf("\"[o.o]\"              testing ....              \"[o.o]\"\n\n");
  printf("lotordb test\n");
  test_genkeys();
  test_keys_verify();
  test_ciphers_cbc();
  test_ciphers_cfb();
  test_ciphers_cbc_long();
  test_ciphers_cfb_long();
  //test_ciphers_cbc_long_str();
  //test_ciphers_cfb_long_str();
  test_ciphers_aes_gcm();
  printf("OK\n");
}
