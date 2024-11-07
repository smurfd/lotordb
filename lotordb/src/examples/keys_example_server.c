#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include "../db_keystore.h"

void key_server(int sock) {
  kvsh k;
  key_recv(sock, &k);
}
