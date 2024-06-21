#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "crypto.h"
#include "keys.h"

int main(int argc, char** argv) {
  /*
  if (argc != 2) {
    printf("Usage:\n");
    printf("  client keys   # for keyvaluestore client\n");
    printf("  client table  # for table database client\n");
    exit(0);
  }
  int type = 0;
  if (strcmp(argv[1], "keys")==0) {type = 1;}
  else if (strcmp(argv[1], "talbe")==0) {type = 2;}
  else {printf("wrong client type\n"); exit(0);}
  */
  int type = usage(argv[1], argc, "client");
  connection c = client_init("127.0.0.1", "9998", type);
  if (client_connect(c) < 0) {
    printf("Cant connect to server\n");
    exit(0);
  }
  client_end(c);
  printf("OK\n");
}
