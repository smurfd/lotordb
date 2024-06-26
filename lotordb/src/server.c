#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "crypto.h"

int main(int argc, char** argv) {
  int type = usage(argv[1], argc, "server");
/*  connection c = server_init("127.0.0.1", "9998", type);
  if (server_listen(c) < 0) {
    printf("Can't create a Thread\n");
    exit(0);
  }
  server_end(c);
*/

/*
  int socket_desc = server_listener();
  puts("Waiting for incoming connections...");
  int srv = server_handle(socket_desc);

*/
  //int socket_desc = server_listener();
  connection c = server_init2("127.0.0.1", "9998", type);
  puts("Waiting for incoming connections...");
  //int srv = server_handle(c.socket);
  int srv = server_handle(c);
  //close(srv);
  printf("OK\n");
}
