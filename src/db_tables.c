#include <sys/socket.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include "db_tables.h"
#include "lotorssl/src/ciph.h"

// ctx
static void tables_getctxfrombin(tbls *t, const binary *bin, const u64 ctxstructlen) {
  memcpy(&(*t)->header->packed, (*bin)->encrypted, sizeof(u64));
  memcpy(&(*t)->ctx->tableindex, (*bin)->encrypted + sizeof(u64), sizeof(u64));
  memcpy((*t)->ctx->structure, (*bin)->encrypted + sizeof(u64) + sizeof(u64), ctxstructlen);
  memcpy(&(*t)->ctx->structurelen, (*bin)->encrypted + sizeof(u64) + sizeof(u64) + ctxstructlen, sizeof(u64));
}

u64 tables_getctxsize(FILE *ptr) {
  fseek(ptr, 0, SEEK_END);
  return ftell(ptr) / sizeof(struct binary);
}

void tables_addctx(tbls *t, u64 index, u64 pkhdr, void *p, u64 ctxstructlen) {
  (*t)->header->packed = pkhdr;
  (*t)->ctx->tableindex = index;
  memcpy((*t)->ctx->structure, p, ctxstructlen);
  (*t)->ctx->structurelen = ctxstructlen; // TODO: ideally a part of packedheader
}

void tables_setctx(tbls *t, const ctx *c, const u64 len) {
  memcpy(&(*t)->ctx, &(*c), sizeof(u64) + sizeof(u64) + sizeof(u64) + len);
}

void tables_getctx(tbls *t, header *head, binary *bin, const binary *dataall, const u64 len) {
  uint8_t tag[1024] = {0}, aad[1024] = {0}, key[32] = {0}, iv0[32] = {0};
  memcpy((*bin), (*dataall), sizeof(struct binary));
  gcm_read_key4file(key, iv0, "/tmp/ctxkeyiv.txt");
  gcm_inv_ciphertag((*bin)->encrypted, tag, key, iv0, (*bin)->encrypted, aad, tag);
  tables_getheader(head, &(*dataall));
  tables_getctxfrombin(&(*t), &(*bin), len);
}

void tables_readctx(binary *dataall, FILE *read_ptr, const u64 j) {
  fseek(read_ptr, j * (DBLENGTH * sizeof(struct binary) + 1), SEEK_SET);
  fread((*dataall), sizeof(struct binary) * DBLENGTH, 1, read_ptr);
}

void tables_writectx(tbls *t, binary *bin, FILE *write_ptr) {
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
  memset((*bin)->encrypted, 0, 1024); // clear
  memcpy((*bin)->encrypted, (uint8_t*)(*t)->ctx, sizeof(u64) + sizeof(u64)); // cast ctx to bytes // TODO: replace u64 with 8 * uint8_t?
  memcpy((*bin)->encrypted + sizeof(u64) + sizeof(u64), (uint8_t*)(*t)->ctx->structure, (*t)->ctx->structurelen);
  memcpy((*bin)->encrypted + sizeof(u64) + sizeof(u64) + (*t)->ctx->structurelen, &(*t)->ctx->structurelen, sizeof(u64));
  gcm_ciphertag((*bin)->encrypted, tag, key, iv0, (*bin)->encrypted, aad, 1024);
  fwrite((*bin)->encrypted, sizeof(struct binary), 1, write_ptr);
}

// header
void tables_getheader(header *head, const binary *bin) {
  u64 h;
  memcpy(&h, (*bin)->encrypted, sizeof(u64));
  tables_unpackheader((*head)->header, h);
}

u64 tables_packheader(u64 head, const uint8_t *data) {
  head =
  ((u64)(data[7]) << 56) | ((u64)(data[6]) << 48) |
  ((u64)(data[5]) << 40) | ((u64)(data[4]) << 32) |
  ((u64)(data[3]) << 24) | ((u64)(data[2]) << 16) |
  ((u64)(data[1]) << 8)  | ((u64)(data[0]) << 0);
  return head;
}

void tables_unpackheader(uint8_t *data, const u64 head) {
  for (uint8_t i = 0; i < 8; i++) {
    data[i] = (uint8_t)((head >> 8 * (7 - i)) & 0xff);
  }
}

// communicate
void tables_send(const tbls *t, const int s) {
  send(s, &(*t), sizeof(struct tbls), 0);
}

void tables_recv(tbls *t, const int s) {
  recv(s, &(*t), sizeof(struct tbls), 0);
}

// memory
void tables_malloc(binary *bin, binary *dataall, tbls *t, header *head, u64 len) {
  (*bin) = malloc(sizeof(struct binary));
  (*dataall) = malloc(sizeof(struct binary) * DBLENGTH);
  (*head) = malloc(sizeof(struct header));
  (*t) = malloc(sizeof(struct tbls));
  (*t)->ctx = malloc(sizeof(struct ctx));
  (*t)->header = malloc(sizeof(struct header));
  (*t)->ctx->structure = malloc(len);
}

void tables_free(binary *bin, binary *dataall, tbls *t, header *head, FILE *read_ptr) {
  if ((*bin) != NULL) free((*bin));
  if ((*dataall) != NULL) free((*dataall));
  if ((*head) != NULL) free((*head));
  if ((*t)->ctx->structure != NULL) free((*t)->ctx->structure);
  if ((*t)->header != NULL) free((*t)->header);
  if ((*t)->ctx != NULL) free((*t)->ctx);
  if ((*t) != NULL) free((*t));
  if (read_ptr != NULL) fclose(read_ptr);
}
