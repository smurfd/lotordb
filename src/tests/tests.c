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
    struct tabletest p = {i, 6.8, "testsmurfan", 666, 1};
    table_addctx(*c, i, 12345678901111 + i, &p, sizeof(p));
    table_writectx(*c, *bin, write_ptr);
  }
  if (write_ptr != NULL) fclose(write_ptr);
}

// Create a local database and search for the age 666
uint8_t test_db_table(void) {
  binary *bin, *dataall;
  u64 *header;
  ctx *c;
  // Open database file for writing
  FILE *write_ptr = fopen("/tmp/dbtest1.db", "ab");
  // Malloc memory for variables used
  table_malloc(&bin, &dataall, &header, &c, sizeof(struct tabletest));
  // Create context for database, write to file & close file
  table_filltestdata(&c, &bin, write_ptr);
  // Open database file for reading
  FILE *read_ptr = fopen("/tmp/dbtest1.db", "rb");
  for (u64 j = 0; j < table_getctxsize(read_ptr) / DBLENGTH; j++) { // Loop the whole database, in chunks of DBLENGTH
    // Read binary chunks DBLENGTH
    table_readctx(dataall, read_ptr, j);
    for (u64 i = 0; i < DBLENGTH; i++) {
      // For each chunk, copy data & decrypt. tabletest defined in ../examples/tables_example_struct.h
      table_getctx(c, header, bin, dataall + i, sizeof(struct tabletest));
      if (((struct tabletest*)((struct ctx*)c)->structure)->age == 666) { // Search for age == 666
        printf("Found\n");
        // Free memory & close filepointer
        table_free(&bin, &dataall, &header, &c, read_ptr);
        return 1;
      }
    }
  }
  // Free memory & close filepointer
  table_free(&bin, &dataall, &header, &c, read_ptr);
  return 0;
}

int main(int argc, char** argv) {
  int ret = 1;
  if (argc == 1) { // When run without arguments
    printf("\"[o.o]\"  testing ...  \"[o.o]\"\n\n");
    ret &= test_db_table();
    if (ret) printf("\nOK\n");
    else printf("\nNot OK\n");
  } else if (strcmp(argv[1], "local") == 0) { // When run locally to measure speed
    printf("\"[o.o]\"  testing locally...  \"[o.o]\"\n\n");
    ret &= test_db_table();
    if (ret) printf("\nOK\n");
    else printf("\nNot OK\n");
  }
}
