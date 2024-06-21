#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "crypto.h"
#include "keys.h"

int main(int argc, char** argv) {//void) {
  int s = client_init("127.0.0.1", "9998");

  if (client_connect(s) < 0) {
    printf("Cant connect to server\n");
    exit(0);
  }
  client_end(s);
  printf("OK\n");
}
