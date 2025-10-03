#ifndef DB_TABLES_H
#define DB_TABLES_H 1
#include "lotorssl/src/ciph.h"

#define u64 unsigned long long int // because linux uint64_t is not same as on mac
#define DBLENGTH 100

// TODO: Randomize these to file for program to use
static uint8_t iv1[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,\
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, key1[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,\
  0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
typedef struct binary {
  uint8_t encrypted[512];
} binary;

typedef struct ctx {
  u64 packedheader;
  u64 index;
  void *structure;
  u64 structurelen;
} ctx;

typedef struct tbls {
  ctx p;
} tbls;

int tables_find(u64 nr);
u64 tables_getctxsize(FILE *ptr);
void tables_send(const int s, tbls *t);
void tables_recv(const int s, tbls *t);
void tables_setctx(tbls *t, ctx c, u64 len);
void tables_getheaders(u64 *header, binary *bin);
void tables_writectx(ctx *c, binary *bin, FILE *write_ptr);
void tables_readctx(binary *dataall, FILE *read_ptr, u64 j);
void tables_addctx(ctx *c, u64 index, u64 pkhdr, void *p, u64 ctxstructlen);
void tables_getctx(ctx *c, u64 *header, binary *bin, binary *dataall, u64 len);
void tables_malloc(binary **bin, binary **dataall, u64 **header, ctx **c, u64 len);
void tables_free(binary **bin, binary **dataall, u64 **header, ctx **c, FILE *read_ptr);
#endif
