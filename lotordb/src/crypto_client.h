#ifndef CRYPTO_CLIENT_H
#define CRYPTO_CLIENT_H 1
#include "crypto.h"
#include "defs.h"

connection client_init(const char *host, const char *port, int type);
int client_handle(connection conn);
void client_end(connection c);
void generate_shared_cryptokey_client(cryptokey *k1, cryptokey *k2, head *h);
#endif
