#ifndef TABLES_CLIENT_H
#define TABLES_CLIENT_H 1
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include "../db_keystore.h"

void table_client(int sock);
#endif
