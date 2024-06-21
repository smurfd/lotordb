#include <stdio.h>
#include <assert.h>
#include "../crypto.h"

//
// Generate a keypair & shared key then print it (test / demo)
void test(void) {
  head h1, h2;
  h1.g = u64rnd(); h1.p = u64rnd(); h2.g = u64rnd(); h2.p = u64rnd();
  u64 c = 123456, d = 1, e = 1;
  cryptokey k1 = generate_cryptokeys(&h1), k2 = generate_cryptokeys(&h2);

  generate_shared_cryptokey_client(&k1, &k2, &h1);
  generate_shared_cryptokey_server(&k1, &k2, &h1);
  printf("Alice public & private key: 0x%.16llx 0x%.16llx\n", k1.publ, k1.priv);
  printf("Bobs public & private key: 0x%.16llx 0x%.16llx\n", k2.publ, k2.priv);
  printf("Alice & Bobs shared key: 0x%.16llx 0x%.16llx\n", k1.shar, k2.shar);
  handler_cryptography(c, k1, &d);
  handler_cryptography(d, k2, &e);
  printf("Before:  0x%.16llx\nEncrypt: 0x%.16llx\nDecrypt: 0x%.16llx\n",c,d,e);
  assert(c == e);
}

int main(void) {
  printf("\"[o.o]\"              testing ....              \"[o.o]\"\n\n");
  printf("lotordb test\n");
  test();
  printf("OK\n");
}
