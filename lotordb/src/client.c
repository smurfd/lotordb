#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "crypto.h"
#include "keys.h"

int main(void) {
  int s = client_init("127.0.0.1", "9998");

  if (s >= 0) {
    u64 dat[BLOCK], cd[BLOCK];
    cryptokey k1, k2;
    head h;

    receive_cryptokey(s, &h, &k1);
    k2 = generate_cryptokeys(&h);
    send_cryptokey(s, &h, &k2);
    generate_shared_cryptokey_client(&k1, &k2, &h);
    printf("share : 0x%.16llx\n", k1.shar);
    for (u64 i = 0; i < 12; i++) {
      dat[i] = (u64)i;
      cryption(dat[i], k1, &cd[i]);
    }
    send_data(s, cd, &h, 11);
    printf("\n\n");
    kvsh k;
    set_key_value_store(&k, "0002", "testvalue", "/tmp");
    key_write(&k);
    key_del(&k);
    key_send(s, &k);


    char *mem = malloc(1000);
    char *ptr =(char*)(&k);
    memcpy(mem, ptr, sizeof(kvsh));


    client_end(s);
  }
  // locally generate two keypairs
  generate_cryptokeys_local();
  printf("OK\n");
}
