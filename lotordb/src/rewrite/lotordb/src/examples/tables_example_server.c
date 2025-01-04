#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "../db_tables.h"
#include "tables_example_struct.h"

void table_server(int sock) {
  tbls *t = (tbls*)malloc(sizeof(struct tbls));
  table_recv(sock, t);
  FILE *write_ptr = fopen("/tmp/dbsrv1.db", "ab");
  binary *datatmp = malloc(sizeof(binary));
  table_writectx(&(*t).p, datatmp, write_ptr);
  fclose(write_ptr);
  if (datatmp != NULL) free(datatmp);
  if (t != NULL) free(t);
}
