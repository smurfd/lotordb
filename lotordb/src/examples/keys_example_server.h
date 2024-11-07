#ifndef KEYS_SERVER_H
#define KEYS_SERVER_H 1
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include "../db_keystore.h"

void key_server(int sock);
#endif
