/*
#include <stdio.h>
#include <stdlib.h>
#include "crypto_server.h"
#include "crypto.h"

int main(int argc, char** argv) {
  int type = usage(argv[1], argc, "server");
  connection c = server_init("127.0.0.1", "9998", type);
  server_handle(c);
  server_end(c);
  printf("OK\n");
}
*/