#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "../db_keystore.h"

void key_client(int sock) {
  kvsh *k = (kvsh*)malloc(sizeof(struct kvsh));
  set_key_value_store(k, "0002", "testvalue", "/tmp");
  key_write(k);
  key_del(k);
  key_send(sock, k);
  if (k != NULL) free(k);
}
