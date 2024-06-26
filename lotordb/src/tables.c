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

void table_send2(const int s, dbdata *d) {
  send(s, d, sizeof(struct dbdata), 0);  
}

void table_send3(const int s, dbindex *d) {
  send(s, d, sizeof(struct dbindex), 0);  
}

void table_send4(const int s, tbls *d) {
  send(s, d, sizeof(struct tbls), 0);  
}

void set_table2(dbdata *k, char unique_id[256], char data[4096], u64 xxx) {
  strncpy((*k).unique_id, unique_id, strlen(unique_id)+1);
  strncpy((*k).data, data, strlen(data)+1);
  (*k).xxx = xxx;
}

void set_table3(dbindex *k, u64 index, char unique_id[256], u64 length, char path[256]) {
  strncpy((*k).unique_id, unique_id, strlen(unique_id)+1);
  strncpy((*k).path, path, strlen(path)+1);
  (*k).index = index;
  (*k).length = length;
}


void table_recv2(const int s, dbdata *k) {
  printf("key recv %d\n", recv(s, k, sizeof(struct dbdata), 0));
  printf("hsh %s %llu \n", (*k).unique_id, (*k).xxx);
}

void table_recv3(const int s, dbindex *k) {
  recv(s, k, sizeof(struct dbindex), 0);
  printf("hsh %s %llu \n", (*k).unique_id, (*k).index);
}

void table_recv4(const int s, tbls *k) {
  recv(s, k, sizeof(struct tbls), 0);
  printf("hsh %s %llu \n", (*k).d.unique_id, (*k).i.index);
}
