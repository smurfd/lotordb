#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include "tables.h"
#include "defs.h"

void table_write_index(dbindex *t, char path[256]) {
  FILE *f;
  f = fopen(path, "w");
  printf("writing index: %llu %s %llu %s\n", (*t).index, (*t).unique_id, (*t).length, (*t).path);
  fprintf(f, "%llu|%s|%llu|%s\n", (*t).index, (*t).unique_id, (*t).length, (*t).path);
  fclose(f);
}

void table_write_data(dbdata *t, dbindex *i) {
  FILE *f;
  f = fopen((*i).path, "w");
  fprintf(f, "%s|%s\n", (*t).unique_id, (*t).data);
  fclose(f);
}

void set_table_data(dbdata *k, char unique_id[256], char data[4096]) {
  strncpy((*k).unique_id, unique_id, strlen(unique_id)+1);
  strncpy((*k).data, data, strlen(data)+1);
}

void set_table_index(dbindex *k, u64 index, char unique_id[256], u64 length, char path[256]) {
  strncpy((*k).unique_id, unique_id, strlen(unique_id)+1);
  strncpy((*k).path, path, strlen(path)+1);
  (*k).index = index;
  (*k).length = length;
}

void table_send(const int s, tbls *d) {
  send(s, d, sizeof(struct tbls), 0);
}

void table_recv(const int s, tbls *k) {
  recv(s, k, sizeof(struct tbls), 0);
}
