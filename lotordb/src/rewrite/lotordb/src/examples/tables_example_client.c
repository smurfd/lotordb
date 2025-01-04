#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../db_tables.h"
#include "tables_example_struct.h"

void table_client(int sock) {
  struct tabletest pp = {0, 6.8, "testsmurfan", 666, 0};
  ctx *c = (void*)malloc(sizeof(ctx));
  c->structure = malloc(sizeof(struct tabletest));
  c->packedheader = 123456;
  c->index = 2233;
  memcpy(c->structure, &pp, sizeof(struct tabletest));
  tbls *t = (tbls*)malloc(sizeof(struct tbls));
  table_setctx(t, *c, sizeof(struct tabletest));
  table_send(sock, t);
  if (c->structure != NULL) free(c->structure);
  if (c != NULL) free(c);
  if (t != NULL) free(t);
}
