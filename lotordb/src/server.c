#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "crypto.h"

int main(void) {
  int s = server_init("127.0.0.1", "9998");

  if (server_listen(s) < 0) {
    printf("Can't create a Thread\n");
    exit(0);
  }
  server_end(s);
  printf("OK\n");
}
