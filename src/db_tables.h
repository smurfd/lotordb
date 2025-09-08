#ifndef DB_TABLES_H
#define DB_TABLES_H 1
#include "db_keystore.h"
#include "lotorssl/src/ciph.h"
//#include "aes.h"

#define u64 unsigned long long int // because linux uint64_t is not same as on mac
#define DBLENGTH 1000

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

int table_find(u64 nr);
u64 table_getctxsize(FILE *ptr);
void table_send(const int s, tbls *t);
void table_recv(const int s, tbls *t);
void table_setctx(tbls *t, ctx c, u64 len);
void table_getheaders(u64 *header, binary *bin);
void table_writectx(ctx *c, binary *bin, FILE *write_ptr);
void table_readctx(binary *dataall, FILE *read_ptr, u64 j);
void table_addctx(ctx *c, u64 index, u64 pkhdr, void *p, u64 ctxstructlen);
void table_getctx(ctx *c, u64 *header, binary *bin, binary *dataall, u64 len);
void table_malloc(binary **bin, binary **dataall, u64 **header, ctx **c, u64 len);
void table_free(binary **bin, binary **dataall, u64 **header, ctx **c, FILE *read_ptr);
#endif

/*
# get data
decrypt index file
read unique_id to get size of data and path to data file
open data path
decrypt data file
find unique id
read size
decrypt
use data

# write data
decrypt datafile
encrypt x=data+hash
append x to /pth/to/x.txt
add row to index file, with path, len of encrypted data and add a padded unique id like smurfd@gmail.com
*/
