#ifndef CRYPTO_SERVER_H
#define CRYPTO_SERVER_H 1
#include "crypto.h"
#include "defs.h"

connection server_init(const char *host, const char *port, int type);
int server_handle(connection conn);
void server_end(connection c);
#endif
