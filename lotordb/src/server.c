#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "crypto.h"

int main(int argc, char** argv) {
  /*
  if (argc != 2) {
    printf("Usage:\n");
    printf("  server keys   # for keyvaluestore server\n");
    printf("  server table  # for table database server\n");
    exit(0);
  }
  int type = 0;
  if (strcmp(argv[1], "keys")==0) {type = 1;}
  else if (strcmp(argv[1], "talbe")==0) {type = 2;}
  else {printf("wrong server type\n"); exit(0);}
  */
  int type = usage(argv[1], argc, "server");
  connection c = server_init("127.0.0.1", "9998", type);
  if (server_listen(c) < 0) {
    printf("Can't create a Thread\n");
    exit(0);
  }
  server_end(c);
  printf("OK\n");
}
