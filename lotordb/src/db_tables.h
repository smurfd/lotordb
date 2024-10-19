#ifndef DB_TABLES_H
#define DB_TABLES_H 1
#include "db_keystore.h"
#include "ciphers.h"

#define u64 unsigned long long int // because linux uint64_t is not same as on mac
#define DBLENGTH 1000000

struct Data {
  uint8_t encrypted[512];
};

struct Person {
  u64 packedheader;
  char name[20];
  int age;
  float height;
};

typedef struct dbindex {
  u64 index;
  char unique_id[256];
  u64 length;
  char path[256];
} dbindex;

typedef struct dbdata {
  char unique_id[256];
  char data[4096];
} dbdata;

typedef struct tbls {
  dbindex i;
  dbdata d;
} tbls;

// TODO: Randomize these to file for program to use
static uint8_t iv1[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
  key1[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

void table_read_index(tbls *t, char path[256], char unique_id[256]);
int table_read_data(tbls *t);
int table_write_index(tbls *t, char path[256]);
int table_write_data(tbls *t);
void set_table_index(tbls *t, u64 index, char unique_id[256], u64 length, char path[256]);
void set_table_data(tbls *t, char unique_id[256], char data[4096]);
void table_send(const int s, tbls *t);
void table_recv(const int s, tbls *t);
void table_decrypt_indexfile(tbls *t);
void table_encrypt_indexfile(tbls *t, uint8_t *index);
void table_decrypt_datafile(tbls *t);
void table_encrypt_datafile(tbls *t, uint8_t *data);
int table_tmp(void);
#endif

/*
index file: aes encrypted, can have millions of entries in it
index, unique_id,          size,  path
1      smurfd1             48     /pth/to/f1.txt
2      smurfd2             4090   /pth/to/f2.txt
3      smurfd3             10     /pth/to/f3.txt
4      foo                 100    /pth/to/f3.txt
5      baar                1000   /pth/to/f3.txt

data file: aes encrypted, can have millions of entries in it
unique_id,          data(encrypt)
smurfd1             stuff you care about
smurfd2             a ton of stuff u care about
smurfd3             stuff
foo                 foobaarfoofoofoo
baar                foofooofffoofofofooofff

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
