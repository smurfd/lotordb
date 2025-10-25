#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../db_tables.h"
#include "../db_keystore.h"
#include "../examples/tables_example_struct.h"

static void tables_filltestdata(tbls *t, binary *bin, FILE *write_ptr) {
  u64 head = 0;
  for (u64 i = 0; i < DBLENGTH; i++) {
    uint8_t pk[8] = {i + 0, i + 1, i + 2, i + 3, i + 4, i + 5, i + 6, i + 7};
    tables_packheader(head, pk);
    struct tabletest p = {i, 6.8, "testsmurfan", i, 1};
    tables_addctx(t, i, head, &p, sizeof(p));
    tables_writectx(t, bin, write_ptr);
  }
  if (write_ptr != NULL) fclose(write_ptr);
}

uint8_t test_db_tables(void) { // Create a local database and search for age 66
  binary *bin = NULL, *dataall = NULL;
  header *head = NULL;
  tbls *t = NULL;
  FILE *write_ptr = fopen("/tmp/dbtest1.db", "wb"); // Open database for writing // TODO: should be 'ab'
  tables_malloc(&bin, &dataall, &t, &head, sizeof(struct tabletest)); // Malloc for variables used
  tables_filltestdata(t, bin, write_ptr); // Create context for database, write to file
  FILE *read_ptr = fopen("/tmp/dbtest1.db", "rb"); // Open database for reading
  for (u64 j = 0; j < tables_getctxsize(read_ptr) / DBLENGTH; j++) { // Loop the whole database, in chunks of DBLENGTH
    tables_readctx(dataall, read_ptr, j); // Read binary chunks DBLENGTH
    for (u64 i = 0; i < DBLENGTH; i++) {
      tables_getctx(t, head, bin, dataall + i, sizeof(struct tabletest)); // For each chunk, copy & decrypt. Tabletest defined in tables_example_struct.h
      if (((struct tabletest*)((struct tbls*)t)->c->structure)->age == 66) { // Search for age == 66
        printf("Found\n");
        tables_free(bin, dataall, t, head, read_ptr); // Free memory & close filepointer
        return 1;
      }
    }
  }
  tables_free(bin, dataall, t, head, read_ptr); // Free memory & close filepointer
  return 0;
}

uint8_t test_db_keystore(void) {
  char key[256] = {' '}, value[256] = {' '}, store[256] = {' '};
  kvsh *k = (kvsh*)malloc(sizeof(struct kvsh));
  memcpy(key, "0001", 4);
  memcpy(value, "testvalue", 9);
  memcpy(store, "/tmp", 4);
  keystore_set(k, key, value, store);
  keystore_write(k);
  keystore_del(k);
  if (k != NULL) free(k);
  return 1;
}

int main(int argc, char** argv) {
  int ret = 1;
  if (argc == 1) { // When run without arguments
    printf("\"[o.o]\"  testing ...  \"[o.o]\"\n\n");
    ret &= test_db_tables();
    ret &= test_db_keystore();
  } else if (strcmp(argv[1], "local") == 0) { // When run locally to measure speed
    printf("\"[o.o]\"  testing locally...  \"[o.o]\"\n\n");
    ret &= test_db_tables();
    ret &= test_db_keystore();
  }
  if (!ret) {
    printf("Not ");
  }
  printf("OK\n");
}
