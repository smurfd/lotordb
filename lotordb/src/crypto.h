// Auth: smurfd, 2023 More reading & Borrow/Stolen parts read at the bottom of the file; 2 spacs indent; 120 width    //
#ifndef CRYPTO_H
#define CRYPTO_H 1
#include <stdbool.h>
#include <inttypes.h>
#include <netinet/in.h>
#include "defs.h"

typedef struct asn asn;
typedef struct keys key;
typedef struct header head;
typedef struct sockaddr sock;
typedef struct sockaddr_in sock_in;
typedef struct secure_socket {sock_in ssls; int ssl;} sock_ssl;

struct header {u64 len, ver, g, p;};
struct keys {u64 publ, priv, shar;};

static char enc[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
  'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
  's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};

static u64 n1[] = {0x000003f, 0x0000fc0, 0x003f000, 0x01c0000, 0x0000800, 0x0000c080, 0x0010000, 0x00e08080, 0xf0808080},
           n2[] = {0x00efbfbf, 0x000f0000, 0x003f0000, 0x07000000, 0x00003f00, 0x0000003f};

int client_init(const char *host, const char *port);
int server_init(const char *host, const char *port);

void send_data(const int s, void* data, head *h, u64 len);
void send_key(int s, head *h, key *k);
void receive_data(const int s, void* data, head *h, u64 len);
void receive_key(int s, head *h, key *k);
void generate_shared_key_client(key *k1, key *k2, u64 p);
void generate_shared_key_server(key *k1, key *k2, u64 p);
key generate_keys(u64 g, u64 p);
int generate_keys_local(void);
int server_listen(int s, sock *cli);
void cryption(u64 data, key k, u64 *enc);
void crypto_end(int s);

u64 crypto_handle_cert(char d[LEN], const char *cert);
u64 crypto_handle_asn(char c[LEN], const char *cert);

uint32_t utf8enc(uint32_t c);
uint32_t utf8dec(uint32_t c);
int err(char *s);
int lrand(uint8_t h[], u64 k[]);
int base64enc(char ed[], const uint8_t *data, int inl);
int base64dec(uint8_t dd[], const char *data, int inl);
void bit_pack(u64 big[], const uint8_t byte[]);
void bit_unpack(uint8_t byte[], const u64 big[]);
void bit_hex_str(char hs[], const uint8_t *d, const int len);
#endif

// Very simple handshake
// asn1 - stolen / inspired from https://gitlab.com/mtausig/tiny-asn1

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
