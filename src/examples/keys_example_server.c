#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "../db_keystore.h"

void key_server(int sock) {
  kvsh k;
  key_recv(sock, &k);
}
