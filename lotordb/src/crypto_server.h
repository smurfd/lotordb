#ifndef CRYPTO_SERVER_H
#define CRYPTO_SERVER_H 1
#include "crypto.h"

connection server_init(const char *host, const char *port, int type);
int server_handle(connection conn);
void server_end(connection c);
void generate_shared_cryptokey_server(cryptokey *k1, cryptokey *k2, head *h);
#endif
