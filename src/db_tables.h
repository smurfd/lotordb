#ifndef DB_TABLES_H
#define DB_TABLES_H 1
#include "lotorssl/src/ciph.h"

#define DBLENGTH 100

typedef struct binary {
  uint8_t encrypted[1024];
} *binary;

typedef struct ctx {
  u64 packedheader;   // packed header
  u64 tableindex;     // what table to insert data into
  void *structure;    // structure of the data
  u64 structurelen;   // length of the structure
} *ctx;

typedef struct header {
  uint8_t h[8];       // header entries
  u64 packed;         // packed header
} *header;

typedef struct tbls {
  header h;
  ctx c;
} *tbls;

int tables_find(u64 nr);
u64 tables_getctxsize(FILE *ptr);
void tables_send(const int s, tbls t);
void tables_recv(const int s, tbls t);
void tables_setctx(tbls t, ctx c, u64 len);
void tables_getheader(header h, binary bin);
void tables_writectx(tbls t, binary bin, FILE *write_ptr);
void tables_readctx(binary dataall, FILE *read_ptr, u64 j);
u64 tables_packheader(u64 head, const uint8_t *data);
void tables_unpackheader(uint8_t *data, const u64 head);
void tables_addctx(tbls t, u64 index, u64 pkhdr, void *p, u64 ctxstructlen);
void tables_getctx(tbls t, header head, binary bin, binary dataall, u64 len);
void tables_malloc(binary *bin, binary *dataall, tbls *t, header *head, u64 len);
void tables_free(binary *bin, binary *dataall, tbls *t, header *head, FILE *read_ptr);
#endif

//struct tabletest {
//  u64 age;
//  float height;
//  char name[20];
//  u64 nr;
//  int test;
//};
// [0, 1.2, 'smurf0', 4, 1]
// [1, 2.2, 'smurf1', 7, 1]
// [2, 3.5, 'smurf2', 2, 1]
// [3, 0.2, 'smurf3', 6, 1]
// [4, 2.1, 'smurf4', 5, 1]
// [5, 4.4, 'smurf5', 0, 1]
// [6, 0.0, 'smurf6', 8, 1]
// [7, 1.1, 'smurf7', 9, 1]
// [8, 0.5, 'smurf8', 1, 1]


// tabletest stored in ctx.structure
// sizeof(tabletest) stored in ctx.structurelen


// TODO
// 4x packedheaders? 4*8 header uint8t?

// binary->encrypted first u64 contains the packed header. Rest is data to be entered into the row
// binary->encrypted data is sent from client to server when modifications is done(ie adding/modifying row, creating table)
//
