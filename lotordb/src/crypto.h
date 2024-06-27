// Auth: smurfd, 2023 More reading & Borrow/Stolen parts read at the bottom of the file; 2 spacs indent; 120 width    //
#ifndef CRYPTO_H
#define CRYPTO_H 1
#include <stdbool.h>
#include <inttypes.h>
#include <netinet/in.h>
#include "defs.h"

typedef struct header {
  u64 len;                   // length
  u64 ver;                   // version
  u64 g;                     // global
  u64 p;                     // private
} head;

typedef struct cryptokeys {
  u64 publ;                  // public key
  u64 priv;                  // private key
  u64 shar;                  // shared key
} cryptokey;

typedef struct connection {
  int socket;                // socket used for connection
  int *clisocket;            // clientsocket
  int type;                  // what type of client/server: 1 = keyvaluestore, 2 = tablesdb
  int err;                   // error
} connection;

typedef struct sockets {
  int descriptor;            // socket descriptor
  struct sockaddr_in addr;   // socket addr
} sockets;

// Client/Server
connection client_init(const char *host, const char *port, int type);
connection server_init(const char *host, const char *port, int type);
int server_handle(connection conn);
int client_handle(connection conn);
void client_end(connection c);
void server_end(connection c);

// Send/Receive
int send_cryptodata(connection c, void* data, head *h, u64 len);
void send_cryptokey(connection c, head *h, cryptokey *k);
int receive_cryptodata(connection c, void* data, head *h, u64 len);
void receive_cryptokey(connection c, head *h, cryptokey *k);

// Generators
void generate_shared_cryptokey_client(cryptokey *k1, cryptokey *k2, head *h);
void generate_shared_cryptokey_server(cryptokey *k1, cryptokey *k2, head *h);
cryptokey generate_cryptokeys(head *h);
void handler_cryptography(u64 data, cryptokey k, u64 *enc);

// Tooling
u64 u64rnd(void);
int usage(char *arg, int count, char *clisrv);
uint32_t utf8enc(uint32_t c);
uint32_t utf8dec(uint32_t c);
int err(char *s);
int base64enc(char ed[], const uint8_t *data, int inl);
int base64dec(uint8_t dd[], const char *data, int inl);
void bit_pack(u64 big[], const uint8_t byte[]);
void bit_unpack(uint8_t byte[], const u64 big[]);
void bit_hex_str(char hs[], const uint8_t *d, const int len);
#endif

// Very simple handshake
/*
```
    |                                                     |                    .
 cli|                                                     |srv                 .
    |                                                     |                    .
                                                                               .
     _____________ [1] TCP HANDSHAKE _____________________                     .
                                                                               |
     ----- >>> --- [1.1] syn ------------------- >   ----v                     |
     v---- <   --- [1.2] syn ack --------------- <<< -----        handled by os|
     ----- >>> --- [1.3] ack ------------------- >   -----                     |
                              v                                                |
                                                                               .
     _____________ [2] TLS HANDSHAKE _____________________                     .
                                                                               .
     ----- >>> --- [2.1] client hi ------------- >   ----v                     .
     ----- <   --- [2.1] server hi ------------- <<< -----                     .
     v---- <   --- [2.2] verify server crt ----- <<< -----                     .
     ----- >>> --- [2.3] client crt ------------ >   -----                     .
     ----- >>> --- [2.4] key exchange ---------- >   -----                     .
     ----- >>> --- [2.5] change cipher spec ---- >   -----                     .
     ----- >>> --- [2.6] client finish --------- >   ----v                     .
     ----- <   --- [2.7] change cipher spec ---- <<< -----                     .
     v---- <   --- [2.8] server finished ------- <<< -----                     .
     =-=-= >>> -=- [2.9] encrypted traffic -=-=- <<< -=-=-                     .
                                                                               .
     ...                                                                       .
     ...                                                                       .
     ...                                                                       .
     ...                                                                       .
```
[1] https://www.khanacademy.org/computing/computers-and-internet/xcae6f4a7ff015e7d:the-internet/xcae6f4a7ff015e7d:transporting-packets/a/transmission-control-protocol--tcp
https://en.wikipedia.org/wiki/Handshaking#TCP_three-way_handshake

[2] https://www.khanacademy.org/computing/computers-and-internet/xcae6f4a7ff015e7d:online-data-security/xcae6f4a7ff015e7d:secure-internet-protocols/a/transport-layer-security-protocol-tls
https://en.wikipedia.org/wiki/Transport_Layer_Security#TLS_handshake

[2.1]
  prot ver : tls 1.3
  cipher suite : TLS_RSA_256_SHA
[2.2]
  prot ver : tls 1.3
  cipher suite : TLS_RSA_256_SHA
  cert : pubkey : 0x123456789abcdef
[2.3]
[2.4]
  cli send pre-master key,
  encrypted with servers public key
  cli calculate shared key from pre-master
  store preshared key locally
[2.5]
[2.6]
  send "finish" encrypted with calculated share key
[2.7]
[2.8]
  server calculate shared key & try to decrypt clients "finish
  if successful, send back "finish" encrypted
[2.9]
  cli send data using symmetric encryption and shared key
*/
