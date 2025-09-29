#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../db_tables.h"
#include "../db_keystore.h"
#include "../examples/tables_example_struct.h"

static void table_filltestdata(ctx **c, binary **bin, FILE *write_ptr) {
  for (u64 i = 0; i < DBLENGTH; i++) {
    struct tabletest p = {i, 6.8, "testsmurfan", 66, 1};
    table_addctx(*c, i, 12345678901111 + i, &p, sizeof(p));
    table_writectx(*c, *bin, write_ptr);
  }
  if (write_ptr != NULL) fclose(write_ptr);
}

uint8_t test_db_table(void) { // Create a local database and search for age 66
  binary *bin, *dataall;
  u64 *header;
  ctx *c;
  FILE *write_ptr = fopen("/tmp/dbtest1.db", "wb"); // Open database for writing // TODO: should be 'ab'
  table_malloc(&bin, &dataall, &header, &c, sizeof(struct tabletest)); // Malloc for variables used
  table_filltestdata(&c, &bin, write_ptr); // Create context for database, write to file
  FILE *read_ptr = fopen("/tmp/dbtest1.db", "rb"); // Open database for reading
  for (u64 j = 0; j < table_getctxsize(read_ptr) / DBLENGTH; j++) { // Loop the whole database, in chunks of DBLENGTH
    table_readctx(dataall, read_ptr, j); // Read binary chunks DBLENGTH
    for (u64 i = 0; i < DBLENGTH; i++) {
      table_getctx(c, header, bin, dataall + i, sizeof(struct tabletest)); // For each chunk, copy & decrypt. Tabletest defined in tables_example_struct.h
      if (((struct tabletest*)((struct ctx*)c)->structure)->age == 66) { // Search for age == 66
        printf("Found\n");
        table_free(&bin, &dataall, &header, &c, read_ptr); // Free memory & close filepointer
        return 1;
      }
    }
  }
  table_free(&bin, &dataall, &header, &c, read_ptr); // Free memory & close filepointer
  return 0;
}

int main(int argc, char** argv) {
  int ret = 1;
  if (argc == 1) { // When run without arguments
    printf("\"[o.o]\"  testing ...  \"[o.o]\"\n\n");
    ret &= test_db_table();
  } else if (strcmp(argv[1], "local") == 0) { // When run locally to measure speed
    printf("\"[o.o]\"  testing locally...  \"[o.o]\"\n\n");
    ret &= test_db_table();
  }
  if (ret) {
    printf("OK\n");
  } else {
    printf("Fail\n");
  }
}
