#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include "../db_tables.h"

void table_client(int sock) {
  struct prs {
    u64 age;
    float height;
    char name[20];
  };
  struct prs pp = {33, 6.8, "smurfan"};
  ctx *c = (void*)malloc(sizeof(ctx));
  c->structure = malloc(sizeof(struct prs));
  c->packedheader = 123456;
  c->index = 2233;
  memcpy(c->structure, &pp, sizeof(struct prs));
  tbls *t = (tbls*)malloc(sizeof(struct tbls));
  table_setctx(t, *c, sizeof(struct prs));
  table_send(sock, t);
  if (c->structure != NULL) free(c->structure);
  if (c != NULL) free(c);
  if (t != NULL) free(t);
}
