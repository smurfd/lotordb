#ifndef DB_TABLES_H
#define DB_TABLES_H 1
#include "lotorssl/src/ciph.h"

#define DBLENGTH 100

typedef struct binary {
  uint8_t encrypted[1024];
} binary;

typedef struct ctx {
  u64 packedheader;
  u64 index;
  void *structure;
  u64 structurelen;
} ctx;

typedef struct header {
  uint8_t h[8]; // header entrys
} header;

typedef struct tbls {
  ctx p;
} tbls;

int tables_find(u64 nr);
u64 tables_getctxsize(FILE *ptr);
void tables_send(const int s, tbls *t);
void tables_recv(const int s, tbls *t);
void tables_setctx(tbls *t, ctx c, u64 len);
void tables_getheader(header *h, binary *bin);
void tables_getheaders(u64 *head, binary *bin);
void tables_writectx(ctx *c, binary *bin, FILE *write_ptr);
void tables_readctx(binary *dataall, FILE *read_ptr, u64 j);
void tables_addctx(ctx *c, u64 index, u64 pkhdr, void *p, u64 ctxstructlen);
void tables_getctx(ctx *c, u64 *head, binary *bin, binary *dataall, u64 len);
void tables_malloc(binary **bin, binary **dataall, u64 **head, ctx **c, u64 len);
void tables_free(binary **bin, binary **dataall, u64 **head, ctx **c, FILE *read_ptr);
#endif
