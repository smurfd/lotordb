#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include "keys.h"
#include "hash.h"
#include "defs.h"

void set_key_value_store(kvsh *k, char key[256], char value[256], char store[256]) {
  strncpy((*k).key, key, strlen(key)+1);
  strncpy((*k).value, value, strlen(value)+1);
  strncpy((*k).store, store, strlen(store)+1);
  hash_new((*k).hash, (uint8_t *)value);
  printf("KVSH: %s %s %s %s\n", key, value, store, (*k).hash);
}

void get_key_value_store() {

}

void key_del(kvsh *k) {
  char s[512];
  strncpy(s, (*k).store, strlen((*k).store) + 1);
  strncat(s, "/", 1);
  strncat(s, (*k).key, strlen((*k).key) + 1);
  unlink(s);
}

void key_set_store() {

}

void key_write(kvsh *k) {
  struct stat st = {0};
  FILE *f;

  if (stat((*k).store, &st) == -1) {
    mkdir((*k).store, 0700);
  }
  char s[512];
  strncpy(s, (*k).store, strlen((*k).store) + 1);
  strncat(s, "/", 1);
  strncat(s, (*k).key, strlen((*k).key) + 1);
  f = fopen(s, "w");
  fprintf(f, "%s\n", (*k).value);
  fclose(f);
}

void key_send(const int s, kvsh *k) {
  send(s, k, sizeof(struct kvsh), 0);
  printf("sent: %s %s %s %s\n", (*k).key, (*k).value, (*k).store, (*k).hash);
}

void key_recv(const int s, kvsh *k) {
  recv(s, k, sizeof(struct kvsh), 0);
  (*k).hash[130] = '\0';
  printf("recv: %s %s %s %s\n", (*k).key, (*k).value, (*k).store, (*k).hash);
}
