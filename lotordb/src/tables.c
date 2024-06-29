#include <sys/socket.h>
//#include <sys/types.h>
//#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
//#include <time.h>
//#include <unistd.h>
#include <stdio.h>
#include "tables.h"
#include "defs.h"

// TODO: add check that f is not NULL == couldnt open file
// TODO: this feels stupid. read the index file several times.
//       is worse to have whole indexfile in memory(probably, especially when it scales)
int static table_check_unique_index(char path[256], char unique_id[256]) {
  FILE *f = fopen(path, "r");
  size_t len = 512;
  char *line = NULL;
  ssize_t read;
  if (f == NULL) {printf("ROHRO\n");return 1;}
  while((read = getline(&line, &len, f)) >= 0)  {
    char **ap, *argv[4];
    for (ap = argv; (*ap = strsep(&line, "|")) != NULL;) {
      if (++ap >= &argv[4]) break;
    }
    if (strcmp(argv[1], unique_id) == 0) {
      printf("Not unique\n");
      fclose(f);
      return -1;
    }
  }
  fclose(f);
  return 0;
}

void table_read_index(tbls *t, char path[256], char unique_id[256]) {
  FILE *f = fopen(path, "r");
  size_t len = 512;
  char *line = NULL;
  ssize_t read;
  while((read = getline(&line, &len, f)) != -1)  {
    char **ap, *argv[4];
    for (ap = argv; (*ap = strsep(&line, "|")) != NULL;)
      if (++ap >= &argv[4]) break;
    if (strcmp(argv[1], unique_id) == 0) {
      printf("Not unique\n");
      break;
    } else {
      set_table_index(t, (u64)atoi(argv[0]), argv[1], (u64)atoi(argv[2]), argv[3]);
      printf("SEP index %s %s %s %s", argv[0], argv[1], argv[2], argv[3]);
      break;
    }
  }
  fclose(f);
}

int table_read_data(tbls *t) {
  FILE *f = fopen((*t).i.path, "r");
  size_t len = 512;
  char *line = NULL;
  ssize_t read;
  if (f == NULL) {printf("No data file\n"); return 1;}
  while((read = getline(&line, &len, f)) != -1)  {
    if (strstr(line, "smurfd1") != NULL) {
      char **ap, *argv[2];
      for (ap = argv; (*ap = strsep(&line, "|")) != NULL;)
        if (++ap >= &argv[2]) break;
      printf("SEP data %s %s", argv[0], argv[1]);
    }
  }
  fclose(f);
  return 0;
}

int table_write_index(tbls *t, char path[256]) {
  if (table_check_unique_index(path, (*t).i.unique_id) >= 0) {
    FILE *f = fopen(path, "a");
    printf("writing index: %llu %s %llu %s\n", (*t).i.index, (*t).i.unique_id, (*t).i.length, (*t).i.path);
    fprintf(f, "%llu|%s|%llu|%s\n", (*t).i.index, (*t).i.unique_id, (*t).i.length, (*t).i.path);
    fclose(f);
  } else {
    printf("unique_id is not unique, will not write to index file\n");
    return -1;
  }
  return 0;
}

int table_write_data(tbls *t) {
  FILE *f = fopen((*t).i.path, "a");
  fprintf(f, "%s|%s\n", (*t).d.unique_id, (*t).d.data);
  fclose(f);
  return 0;
}

void set_table_data(tbls *t, char unique_id[256], char data[4096]) {
  strncpy((*t).d.unique_id, unique_id, strlen(unique_id) + 1);
  strncpy((*t).d.data, data, strlen(data) + 1);
}

void set_table_index(tbls *t, u64 index, char unique_id[256], u64 length, char path[256]) {
  strncpy((*t).i.unique_id, unique_id, strlen(unique_id) + 1);
  strncpy((*t).i.path, path, strlen(path) + 1);
  (*t).i.index = index;
  (*t).i.length = length;
}

void table_send(const int s, tbls *t) {
  send(s, t, sizeof(struct tbls), 0);
}

void table_recv(const int s, tbls *t) {
  recv(s, t, sizeof(struct tbls), 0);
}
