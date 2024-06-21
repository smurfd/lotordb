#ifndef KEYS_H
#define KEYS_H 1
#include <stdio.h>
#include <stdbool.h>
#include <inttypes.h>
#include <netinet/in.h>
#include "defs.h"

typedef struct kvsh {char key[256]; char value[256]; char store[256]; char hash[131];} kvsh;

void set_key_value_store(kvsh *k, char key[256], char value[256], char store[256]);
void key_write(kvsh *k);
void key_del(kvsh *k);
void key_send(const int s, kvsh *k);
void key_recv(const int s, kvsh *k);
#endif
