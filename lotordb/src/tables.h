#ifndef TABLES_H
#define TABLES_H 1
#include <stdio.h>
#include <stdbool.h>
#include <inttypes.h>
#include <netinet/in.h>
#include "keys.h"

#include <sys/socket.h>
#include <stdbool.h>
#include "defs.h"
/*
typedef struct dbindex {
  u64 index;
  u64 dbindex;
  u64 database;
  u64 table;
  u64 row;
  u64 col;
  u64 segments;
  u64 seek;
} dbindex;

typedef struct dbdata {
  u64 index;
  u64 database;
  u64 table;
  u64 relative;
  u64 row;
  u64 col;
  char data[4048];
} dbdata;
*/
typedef struct dbindex {
  u64 index;
  char unique_id[256];
  u64 length;
  char path[256];
} dbindex;

typedef struct dbdata {
  char unique_id[256];
  char data[4096];
  u64 xxx;
} dbdata;

typedef struct tbls {
  dbindex i;
  dbdata d;
} tbls;

//void table_send(const int s, dbindex *d);//tbls *t);
//void table_recv(const int s, dbindex *d);//tbls *t);
//void table_set_index(tbls *t, u64 index, char unique_id[256], u64 length, char path[256]);
void table_write_index(dbindex *t, char path[256]);
//void table_write_index(tbls *t, char path[256]);
//void table_set_data(tbls *t, char unique_id[256], char data[4096]);
//void table_write_data(tbls *t);//, char unique_id[256], char data[4096]);
void table_write_data(dbdata *t, dbindex *i);

/*
#include <stdio.h>
#include <stdbool.h>
#include <inttypes.h>
#include <netinet/in.h>
*/
void set_table3(dbindex *k, u64 index, char unique_id[256], u64 length, char path[256]);
void table_send3(const int s, dbindex *d);//tbls *t);
void table_recv3(const int s, dbindex *k);

void table_recv2(const int s, dbdata *k);
void set_table2(dbdata *k, char unique_id[256], char data[4096], u64 xxx);
void table_send2(const int s, dbdata *d);//tbls *t);
//void set_key_value_store1(kvsh *k, char key[256], char value[256], char store[256]);
//void key_write1(kvsh *k);
//void key_del1(kvsh *k);
//void key_send1(const int s, kvsh *k);
//void key_recv1(const int s, kvsh *k);


#endif

/*
dbindex:

index, unique_id(encrypt), size,  path
1      smurfd1             48     /pth/to/f1.txt
2      smurfd2             4090   /pth/to/f2.txt
3      smurfd3             10     /pth/to/f3.txt
4      foo                 100    /pth/to/f4.txt
5      baar                1000   /pth/to/f5.txt

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
