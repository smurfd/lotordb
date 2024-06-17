#include <stdio.h>
#include <assert.h>
#include "../crypto.h"

void test() {
  head h1, h2;
  h1.g = u64rnd(); h1.p = u64rnd(); h2.g = u64rnd(); h2.p = u64rnd();
  u64 c = 123456, d = 1, e = 1;
  key k1 = generate_keys(&h1), k2 = generate_keys(&h2);

  generate_shared_key_client(&k1, &k2, &h1);
  generate_shared_key_server(&k1, &k2, &h1);
  printf("Alice public & private key: 0x%.16llx 0x%.16llx\n", k1.publ, k1.priv);
  printf("Bobs public & private key: 0x%.16llx 0x%.16llx\n", k2.publ, k2.priv);
  printf("Alice & Bobs shared key: 0x%.16llx 0x%.16llx\n", k1.shar, k2.shar);
  cryption(c, k1, &d);
  cryption(d, k2, &e);
  printf("Before:  0x%.16llx\nEncrypt: 0x%.16llx\nDecrypt: 0x%.16llx\n",c,d,e);
  assert(c == e);
}

int main() {
  printf("lotordb test\n");
  test();
}
