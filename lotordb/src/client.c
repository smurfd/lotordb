#include <stdio.h>
#include <stdlib.h>
#include "crypto_client.h"
#include "crypto.h"
#include "db_keystore.h"

int main(int argc, char** argv) {
  int type = usage(argv[1], argc, "client");
  connection c = client_init("127.0.0.1", "9998", type);
  if (client_handle(c) < 0) {
    printf("Cant connect to server\n");
    exit(0);
  }
  client_end(c);
  printf("OK\n");
}
