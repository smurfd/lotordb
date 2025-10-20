#include <sys/socket.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include "db_tables.h"
#include "lotorssl/src/ciph.h"


// encrypted = [Binary blob with some data in it 555]
// packedheader = [Binary bl]
// index = [ob with ]
// structure = [some data in it ]
// strlen = 555
static void tables_getctxfrombin(ctx *c, binary *bin, u64 ctxstructlen) {
  memcpy(&c->packedheader, bin->encrypted, sizeof(u64));
  memcpy(&c->index, (bin->encrypted) + sizeof(u64), sizeof(u64));
  memcpy(c->structure, bin->encrypted + sizeof(u64) + sizeof(u64), ctxstructlen);
  memcpy(&c->structurelen, bin->encrypted + sizeof(u64) + sizeof(u64) + ctxstructlen, sizeof(u64));
}

void tables_send(const int s, tbls *t) {
  send(s, t, sizeof(struct tbls), 0);
}

void tables_recv(const int s, tbls *t) {
  recv(s, t, sizeof(struct tbls), 0);
}

void tables_setctx(tbls *t, ctx c, u64 len) {
  memcpy(&(*t).p, &c, sizeof(u64) + sizeof(u64) + sizeof(u64) + len);
}

void tables_readctx(binary *dataall, FILE *read_ptr, u64 j) {
  fseek(read_ptr, j * (DBLENGTH * sizeof(binary) + 1), SEEK_SET);
  fread(dataall, sizeof(binary) * DBLENGTH, 1, read_ptr);
}

void tables_getctx(ctx *c, header *head, binary *bin, binary *dataall, u64 len) {
  uint8_t tag[1024] = {0}, aad[1024] = {0}, key[32] = {0}, iv0[32] = {0};
  memcpy(bin, dataall, sizeof(binary));
  gcm_read_key4file(key, iv0, "/tmp/ctxkeyiv.txt");
  gcm_inv_ciphertag(bin->encrypted, tag, key, iv0, bin->encrypted, aad, tag);
  tables_getheader(head, dataall);
  tables_getctxfrombin(c, bin, len);
}


u64 tables_packheader(u64 head, const uint8_t *data) {
  head =
  ((u64)(data[7]) << 56) |
  ((u64)(data[6]) << 48) |
  ((u64)(data[5]) << 40) |
  ((u64)(data[4]) << 32) |
  ((u64)(data[3]) << 24) |
  ((u64)(data[2]) << 16) |
  ((u64)(data[1]) << 8)  |
  ((u64)(data[0]) << 0);
  return head;
}

void tables_unpackheader(uint8_t *data, const u64 head) {
  for (uint8_t i = 0; i < 8; i++) {
    data[i] = (uint8_t)((head >> 8 * (7 - i)) & 0xff);
  }
}

void tables_getheader(header *head, binary *bin) {
  u64 h;
  memcpy(&h, bin->encrypted, sizeof(u64));
  tables_unpackheader(head->h, h);
}

u64 tables_getctxsize(FILE *ptr) {
  fseek(ptr, 0, SEEK_END);
  return ftell(ptr) / sizeof(binary);
}

// This can be slower than find
void tables_addctx(ctx *c, u64 index, u64 pkhdr, void *p, u64 ctxstructlen) {
  c->packedheader = pkhdr;
  c->index = index;
  memcpy(c->structure, p, ctxstructlen);
  c->structurelen = ctxstructlen; // ideally a part of packedheader in the future
}

void tables_writectx(ctx *c, binary *bin, FILE *write_ptr) {
  uint8_t tag[1024] = {0}, aad[1024] = {0}, key[32] = {0}, iv0[32] = {0};
  if (access("/tmp/ctxkeyiv.txt", F_OK) != 0) {
    FILE *f = fopen("/dev/urandom", "r");
    fread(key, sizeof(uint8_t), 32, f);
    fread(iv0, sizeof(uint8_t), 32, f);
    fclose(f);
    gcm_write_key2file("/tmp/ctxkeyiv.txt", key, iv0);
  } else {
    gcm_read_key4file(key, iv0, "/tmp/ctxkeyiv.txt");
  }
  memset(bin->encrypted, 0, 1024); // clear
  memcpy(bin->encrypted, (uint8_t*)c, sizeof(u64) + sizeof(u64)); // "convert" ctx to "binary" // TODO: replace u64 with 8 * uint8_t?
  memcpy(bin->encrypted + sizeof(u64) + sizeof(u64), (uint8_t*)c->structure, c->structurelen);
  memcpy(bin->encrypted + sizeof(u64) + sizeof(u64) + c->structurelen, &c->structurelen, sizeof(u64));
  gcm_ciphertag(bin->encrypted, tag, key, iv0, bin->encrypted, aad, 1024);
  fwrite(bin->encrypted, sizeof(binary), 1, write_ptr);
}

void tables_malloc(binary **bin, binary **dataall, header **head, ctx **c, u64 len) {
  (*bin) = malloc(sizeof(binary));
  (*dataall) = malloc(sizeof(binary) * DBLENGTH);
  (*head) = malloc(sizeof(header));
  (*c) = (void*)malloc(sizeof(ctx));
  (*c)->structure = malloc(len);
}

void tables_free(binary **bin, binary **dataall, header **head, ctx **c, FILE *read_ptr) {
  if ((*bin) != NULL) free((*bin));
  if ((*dataall) != NULL) free((*dataall));
  if ((*head) != NULL) free((*head));
  if ((*c) != NULL) free((*c));
  if ((*c)->structure != NULL) free((*c)->structure);
  if (read_ptr != NULL) fclose(read_ptr);
}
