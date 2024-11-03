#ifndef DB_TABLES_H
#define DB_TABLES_H 1
#include "db_keystore.h"
#include "ciphers.h"

#define u64 unsigned long long int // because linux uint64_t is not same as on mac
#define DBLENGTH 1000

typedef struct binary {
  uint8_t encrypted[512];
} binary;

typedef struct data {
  u64 packedheader;
  u64 index;
  void *structure;
} data;

typedef struct tbls {
  data p;
} tbls;

void table_send(const int s, tbls *t);
void table_recv(const int s, tbls *t);
int table_find(u64 nr);
void table_setperson(tbls *t, data person);
void table_writeperson(data *person, binary *datatmp, FILE *write_ptr);
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
