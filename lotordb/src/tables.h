#ifndef TABLES_H
#define TABLES_H 1
#include "keys.h"
#include "defs.h"

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

void table_read_index(tbls *t, char path[256], char unique_id[256]);
int table_read_data(tbls *t);
int table_write_index(tbls *t, char path[256]);
int table_write_data(tbls *t);
void set_table_index(tbls *t, u64 index, char unique_id[256], u64 length, char path[256]);
void set_table_data(tbls *t, char unique_id[256], char data[4096]);
void table_send(const int s, tbls *t);
void table_recv(const int s, tbls *t);
#endif

/*
index, unique_id(encrypt), size,  path
1      smurfd1             48     /pth/to/f1.txt
2      smurfd2             4090   /pth/to/f2.txt
3      smurfd3             10     /pth/to/f3.txt
4      foo                 100    /pth/to/f4.txt
5      baar                1000   /pth/to/f5.txt

unique_id(encrypt), data(encrypt)
smurfd1             stuff you care about
smurfd2             a ton of stuff u care about
smurfd3             stuff
foo                 foobaarfoofoofoo
baar                foofooofffoofofofooofff


# get data
read index file, decrypt unique ids until you found what we search for (this will be slow when it scales)
Get path for unique_id
Open path
Read size
decrypt
use data

# write data
encrypt x=data+hash
write x to /pth/to/x.txt
add row to index file, with path, len of encrypted data and encrypted, padded unique id like smurfd@gmail.com


len = getline(&line, &buffer_size, f)
if strstr(line, unique_id) != null

*/
