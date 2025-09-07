#ifndef DB_KEYSTORE_H
#define DB_KEYSTORE_H 1

typedef struct kvsh {
  char key[256];
  char value[256];
  char store[256];
  char hash[131];
} kvsh;

void key_set(kvsh *k, char key[256], char value[256], char store[256]);
void key_write(kvsh *k);
void key_del(kvsh *k);
void key_send(const int s, kvsh *k);
void key_recv(const int s, kvsh *k);
#endif
