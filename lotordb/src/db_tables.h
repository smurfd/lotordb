#ifndef DB_TABLES_H
#define DB_TABLES_H 1
#include "db_keystore.h"
#include "ciphers.h"

#define u64 unsigned long long int // because linux uint64_t is not same as on mac
#define DBLENGTH 1000000

typedef struct Data {
  uint8_t encrypted[512];
} Data;

typedef struct Person {
  u64 packedheader;
  u64 index;
  char name[20];
  int age;
  float height;
} Person;

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
  Person p;
} tbls;

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
int table_find(u64 nr);
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
