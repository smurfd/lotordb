#ifndef TABLES_SERVER_H
#define TABLES_SERVER_H 1
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include "../db_tables.h"

void table_server(int sock);
#endif
