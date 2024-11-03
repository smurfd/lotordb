#include <sys/socket.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "db_tables.h"
#include "ciphers.h"

struct prs {
  u64 age;
  float height;
  char name[20];
};

// TODO: Randomize these to file for program to use
static uint8_t iv1[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,\
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, key1[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,\
  0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

void table_send(const int s, tbls *t) {
  send(s, t, sizeof(struct tbls), 0);
}

void table_recv(const int s, tbls *t) {
  recv(s, t, sizeof(struct tbls), 0);
}

static void table_getperson(data *person, binary *datatmp, void *p) {
  memcpy(&person->packedheader, datatmp->encrypted, sizeof(u64));
  memcpy(&person->index, (datatmp->encrypted)+ sizeof(u64), sizeof(u64));
  memcpy(person->structure, datatmp->encrypted + sizeof(u64) + sizeof(u64), sizeof(struct prs));
}

static void table_getheaders(u64 *header, binary *data) {
  for (u64 i = 0; i < DBLENGTH; i++) {
    memcpy(&header[i], data[i].encrypted, sizeof(u64));
  }
}

static u64 table_getdatasize(FILE *ptr) {
  fseek(ptr, 0, SEEK_END);
  return ftell(ptr);
}

static u64 table_getlastindex(void) {
  FILE *ptr = fopen(".build/cbin.b", "rb");
  u64 size = (table_getdatasize(ptr) / sizeof(binary));
  fclose(ptr);
  return size;
}

// This can be slower than find
static void table_adddata(data *person, u64 index, u64 pkhdr, void *p) {
  person->packedheader = pkhdr;
  person->index = index;
  memcpy(((struct prs*)(person->structure)), ((struct prs*)p), sizeof(struct prs));
}

void table_writeperson(data *person, binary *datatmp, FILE *write_ptr) {
  // "convert" data to "binary" data
  memset(datatmp->encrypted, (uint8_t)' ', 512); // "PAD" the data
  memcpy(datatmp->encrypted, (uint8_t*)person, sizeof(u64) + sizeof(u64));
  memcpy(datatmp->encrypted + sizeof(u64) + sizeof(u64), (uint8_t*)person->structure, sizeof(struct prs));
  aes_gcm_encrypt(datatmp->encrypted, datatmp->encrypted, 512, key1, 32, iv1, 32);
  fwrite(datatmp->encrypted, sizeof(binary), 1, write_ptr);
}

static void table_createdata(char fn[], binary *datatmp) {
  FILE *write_ptr = fopen(fn, "ab");
  data person;
  person.structure = malloc(sizeof(struct prs));
  u64 index = table_getlastindex() + 1;
  for (u64 i = 0; i < DBLENGTH; i++) {
    struct prs p = {(int)(33+i), 6.8, "smurfan"};
    table_adddata(&person, index++, 1234567890 + i, (struct prs*)&p);
    table_writeperson(&person, datatmp, write_ptr);
  }
  free(person.structure);
  fclose(write_ptr);
}

// TODO: this is stupid now when we add everything in order
static bool table_search(char fn[], binary *datatmp, binary *dataall, u64 *header, u64 nr) {
  data *person = (void*)malloc(sizeof(data));
  struct prs *pp = (void*)malloc(sizeof(struct prs));
  person->structure = (void*)malloc(sizeof(struct prs));
  FILE *ptr = fopen(fn, "rb");
  for (u64 j = 0; j < (table_getdatasize(ptr) / sizeof(binary)) / DBLENGTH; j++) {
    fseek(ptr, j * (DBLENGTH * sizeof(binary) + 1), SEEK_SET);
    fread(dataall, sizeof(binary) * DBLENGTH, 1, ptr);
    for (u64 i = 0; i < DBLENGTH; i++) {
      memcpy(datatmp, dataall + i, sizeof(binary));
      aes_gcm_decrypt(datatmp->encrypted, datatmp->encrypted, 512, key1, 32, iv1, 32);
      table_getheaders(header, dataall + i);
      table_getperson(person, datatmp, &pp);
      if (((struct prs*)((struct data*)person)->structure)->age == nr) {
        printf("found\n");
        free(pp);
        fclose(ptr);
        return true;
      }
    }
  }
  free(pp);
  free(person);
  fclose(ptr);
  return false;
}

void table_setperson(tbls *t, data person) {
  memcpy(&(*t).p, &person, sizeof(u64) + sizeof(u64) + sizeof(struct prs));
}

//
// This needs to be fast
int table_find(u64 nr) {
  binary *datatmp = malloc(sizeof (binary)), *dataall = malloc(sizeof(binary) * DBLENGTH);
  u64 *header = malloc(sizeof(u64) * DBLENGTH);
  char fn[] = {".build/cbin.b"};
  table_createdata(fn, datatmp);
  bool found = table_search(fn, datatmp, dataall, header, nr);
  if (datatmp != NULL) free(datatmp);
  if (dataall != NULL) free(dataall);
  if (header != NULL) free(header);
  if (found) return 1;
  return 0;
}
