#include <sys/socket.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "db_tables.h"
//#include "ciphers.h"

// TODO: Randomize these to file for program to use
static uint8_t iv1[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,\
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, key1[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,\
  0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

static void table_getctxfrombin(ctx *c, binary *bin, u64 ctxstructlen) {
  memcpy(&c->packedheader, bin->encrypted, sizeof(u64));
  memcpy(&c->index, (bin->encrypted) + sizeof(u64), sizeof(u64));
  memcpy(c->structure, bin->encrypted + sizeof(u64) + sizeof(u64), ctxstructlen);
  memcpy(&c->structurelen, bin->encrypted + sizeof(u64) + sizeof(u64) + ctxstructlen, sizeof(u64));
}

void table_send(const int s, tbls *t) {
  send(s, t, sizeof(struct tbls), 0);
}

void table_recv(const int s, tbls *t) {
  recv(s, t, sizeof(struct tbls), 0);
}

void table_setctx(tbls *t, ctx c, u64 len) {
  memcpy(&(*t).p, &c, sizeof(u64) + sizeof(u64) + sizeof(u64) + len);
}

void table_readctx(binary *dataall, FILE *read_ptr, u64 j) {
  fseek(read_ptr, j * (DBLENGTH * sizeof(binary) + 1), SEEK_SET);
  fread(dataall, sizeof(binary) * DBLENGTH, 1, read_ptr);
}

void table_getctx(ctx *c, u64 *header, binary *bin, binary *dataall, u64 len) {
  memcpy(bin, dataall, sizeof(binary));
  //aes_gcm_decrypt(bin->encrypted, bin->encrypted, 512, key1, 32, iv1, 32);
  table_getheaders(header, dataall);
  table_getctxfrombin(c, bin, len);
}

void table_getheaders(u64 *header, binary *bin) {
  for (u64 i = 0; i < DBLENGTH; i++) {
    memcpy(&header[i], bin[i].encrypted, sizeof(u64));
  }
}

u64 table_getctxsize(FILE *ptr) {
  fseek(ptr, 0, SEEK_END);
  return ftell(ptr) / sizeof(binary);
}

// This can be slower than find
void table_addctx(ctx *c, u64 index, u64 pkhdr, void *p, u64 ctxstructlen) {
  c->packedheader = pkhdr;
  c->index = index;
  memcpy(c->structure, p, ctxstructlen);
  c->structurelen = ctxstructlen; // ideally arpart of packedheader in the future
}

void table_writectx(ctx *c, binary *bin, FILE *write_ptr) {
  // "convert" ctx to "binary"
  memset(bin->encrypted, (uint8_t)' ', 512); // "PAD" the ctx
  memcpy(bin->encrypted, (uint8_t*)c, sizeof(u64) + sizeof(u64));
  memcpy(bin->encrypted + sizeof(u64) + sizeof(u64), (uint8_t*)c->structure, c->structurelen);
  memcpy(bin->encrypted + sizeof(u64) + sizeof(u64) + c->structurelen, &c->structurelen, sizeof(u64));
  //aes_gcm_encrypt(bin->encrypted, bin->encrypted, 512, key1, 32, iv1, 32);
  fwrite(bin->encrypted, sizeof(binary), 1, write_ptr);
}

void table_malloc(binary **bin, binary **dataall, u64 **header, ctx **c, u64 len) {
  (*bin) = malloc(sizeof(binary));
  (*dataall) = malloc(sizeof(binary) * DBLENGTH);
  (*header) = malloc(sizeof(u64) * DBLENGTH);
  (*c) = (void*)malloc(sizeof(ctx));
  (*c)->structure = malloc(len);
}

void table_free(binary **bin, binary **dataall, u64 **header, ctx **c, FILE *read_ptr) {
  if ((*bin) != NULL) free((*bin));
  if ((*dataall) != NULL) free((*dataall));
  if ((*header) != NULL) free((*header));
  if ((*c) != NULL) free((*c));
  if ((*c)->structure != NULL) free((*c)->structure);
  if (read_ptr != NULL) fclose(read_ptr);
}
