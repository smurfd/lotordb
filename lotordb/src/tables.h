#ifndef TABLES_H
#define TABLES_H 1
#include <stdbool.h>
#include "defs.h"

typedef struct dbindex {
  u64 index;
  u64 dbindex;
  u64 database;
  u64 table;
  u64 row;
  u64 col;
  u64 segments;
  u64 seek;
} dbindex;

typedef struct dbdata {
  u64 index;
  u64 database;
  u64 table;
  u64 relative;
  u64 row;
  u64 col;
  char data[4048];
} dbdata;

typedef struct tbls {
  dbindex i;
  dbdata d;
} tbls;

void table_send(const int s, tbls *t);
void table_recv(const int s, tbls *t);
#endif
