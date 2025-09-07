#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../db_keystore.h"

void key_client(int sock) {
  char key[256] = {""}, value[256] = {""}, store[256] = {""};
  kvsh *k = (kvsh*)malloc(sizeof(struct kvsh));
  memcpy(key, "0002", 4);
  memcpy(value, "testvalue", 9);
  memcpy(store, "/tmp", 4);
  key_set(k, key, value, store);
  key_write(k);
  key_del(k);
  key_send(sock, k);
  if (k != NULL) free(k);
}
