#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "crypto.h"

int main(int argc, char** argv) {
  int type = usage(argv[1], argc, "server");
  connection c = server_init("127.0.0.1", "9998", type);
  if (server_listen(c) < 0) {
    printf("Can't create a Thread\n");
    exit(0);
  }
  server_end(c);
  printf("OK\n");
}
