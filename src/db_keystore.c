#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include "db_keystore.h"
#include "lotorssl/src/hash.h"

void key_set(kvsh *k, char key[256], char value[256], char store[256]) {
  strncpy((*k).key, key, 255);
  strncpy((*k).value, value, 255);
  strncpy((*k).store, store, 255);
  hash_new((*k).hash, (uint8_t *)value);
  printf("KVSH: %s %s %s %s\n", key, value, store, (*k).hash);
}

void key_del(kvsh *k) {
  char s[512];
  strncpy(s, (*k).store, 512);
  strncat(s, "/", 2);
  strncat(s, (*k).key, 512 - strlen((*k).store) - 1);
  unlink(s);
}

void key_write(kvsh *k) {
  struct stat st = {0};
  if (stat((*k).store, &st) == -1) {
    mkdir((*k).store, 0700);
  }
  char s[512];
  strncpy(s, (*k).store, 512);
  strncat(s, "/", 2);
  strncat(s, (*k).key, 512 - strlen((*k).store) - 1);
  FILE *f = fopen(s, "w");
  fprintf(f, "%s\n", (*k).value);
  fclose(f);
}

void key_send(const int s, kvsh *k) {
  send(s, k, sizeof(struct kvsh), 0);
  printf("sent: %s %s %s %s\n", (*k).key, (*k).value, (*k).store, (*k).hash);
}

void key_recv(const int s, kvsh *k) {
  char tmphash[131];
  recv(s, k, sizeof(struct kvsh), 0);
  (*k).hash[130] = '\0';
  hash_new(tmphash, (uint8_t *)(*k).value);
  assert(strcmp(tmphash, (*k).hash) == 0);  // assert received hash and generated hash is the same
  printf("recv: %s %s %s %s\n", (*k).key, (*k).value, (*k).store, (*k).hash);
}
