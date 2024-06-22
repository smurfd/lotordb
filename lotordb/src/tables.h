#ifndef CRYPTO_H
#define CRYPTO_H 1
#include <stdbool.h>
#include "defs.h"

typedef struct index {
  u64 index;
  u64 dbindex;
  u64 database;
  u64 table;
  u64 row;
  u64 col;
  u64 segments;
  u64 seek;
} index;

typedef struct data {
  u64 index;
  u64 database;
  u64 table;
  u64 relative;
  u64 row;
  u64 col;
  char data[4048];
} data;


typedef struct tables {
  index i;
  data d;
} tables;

void tables_send(const int s, tables *t);
void tables_recv(const int s, tables *t);
#endif
