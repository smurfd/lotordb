// Auth: smurfd, 2023 More reading & Borrow/Stolen parts read at the bottom of the file; 2 spacs indent; 120 width    //
#include <math.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "db_keystore.h"
#include "db_tables.h"
#include "crypto.h"

// Public functions

//
// Communication init
sockets communication_init(const char *host, const char *port) {
  sockets sock;
  sock.descriptor = socket(AF_INET , SOCK_STREAM , 0);
  if (sock.descriptor == -1) {
    printf("Could not create socket\n");
  }
  memset(&(sock.addr), '\0', sizeof(sock.addr));
  sock.addr.sin_family = AF_INET;
  sock.addr.sin_port = atoi(port);
  sock.addr.sin_addr.s_addr = inet_addr(host);
  return sock;
}

connection connection_init(int8_t descriptor, int type) {
  connection c;
  c.socket = descriptor;
  c.type = type;
  if (descriptor >= 0) c.err = 0;
  else c.err = -1;
  return c;
}

//
// Print usage information
int usage(char *arg, int count, char *clisrv) {
  if (count != 2) {
    printf("Usage:\n");
    printf("  %s keys   # for keyvaluestore client\n", clisrv);
    printf("  %s tables # for table database client\n", clisrv);
    exit(0);
  }
  int type = 0;
  if (strcmp(arg, "keys")==0) type = 1;
  else if (strcmp(arg, "tables")==0) type = 2;
  else {
    printf("wrong %s type\n", clisrv);
    exit(0);
  }
  return type;
}

//
// Encrypt and decrypt data with shared key
void handler_cryptography(u64 data, cryptokey k, u64 *enc) {
  (*enc) = data ^ k.shar;
}

//
// Send data to client/server
int send_cryptodata(connection c, void* data, head *h, u64 len) {
  int sock = *((connection*)&c)->clisocket;
  send(sock, h, sizeof(head), 0);
  return send(sock, data, sizeof(u64) * len, 0);
}

//
// Receive data from client/server
int receive_cryptodata(connection c, void* data, head *h, u64 len) {
  int sock = *((connection*)&c)->clisocket;
  recv(sock, h, sizeof(head), 0);
  return recv(sock, data, sizeof(u64) * len, 0);
}

//
// Send key to client/server
void send_cryptokey(connection c, head *h, cryptokey *k) {
  int sock = *((connection*)&c)->clisocket;
  // Just send the public key
  send(sock, h, sizeof(head), 0);
  send(sock, &k->publ, sizeof(u64), 0);
}

//
// Receive key from client/server
void receive_cryptokey(connection c, head *h, cryptokey *k) {
  int sock = *((connection*)&c)->clisocket;

  // Just receive the public key
  recv(sock, h, sizeof(head), 0);
  recv(sock, &k->publ, sizeof(u64), 0);
}

//
// Generate a public and private keypair
cryptokey generate_cryptokeys(head *h) {
  cryptokey k;

  k.priv = u64rnd();
  k.publ = (int64_t)pow((*h).g, k.priv) % (*h).p;
  return k;
}

//
// urandom generate u64
u64 u64rnd(void) {
  u64 f7 = 0x7fffffffffffffff;
  int r[5], f = open("/dev/urandom", O_RDONLY);
  read(f, &r, sizeof r);
  close(f);
  return (r[0] & f7) << 48 ^ (r[1] & f7) << 35 ^ (r[2] & f7) << 22 ^ (r[3] & f7) << 9 ^ (r[4] & f7) >> 4;
}

// Very simple handshake
