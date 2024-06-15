#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "crypto.h"

int main(void) {
  int s = client_init("127.0.0.1", "9998");

  if (s >= 0) {
    u64 dat[BLOCK], cd[BLOCK];
    key k1, k2;
    head h;

    receive_key(s, &h, &k1);
    k2 = gen_keys(h.g, h.p);
    send_key(s, &h, &k2);
    cli_gen_shared_key(&k1, &k2, h.p);
    printf("share : 0x%.16llx\n", k1.shar);
    for (u64 i = 0; i < 12; i++) {
      dat[i] = (u64)i;
      cryption(dat[i], k1, &cd[i]);
    }
    send_data(s, cd, &h, 11);
    crypto_end(s);
  }
  // locally generate two keypairs
  srand(time(0));
  gen_keys_local();
  printf("OK\n");
}
