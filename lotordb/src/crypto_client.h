#ifndef CRYPTO_CLIENT_H
#define CRYPTO_CLIENT_H 1
#include "crypto.h"
#include "defs.h"

connection client_init(const char *host, const char *port, int type);
int client_handle(connection conn);
void client_end(connection c);
#endif
