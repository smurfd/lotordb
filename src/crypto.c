// Auth: smurfd, 2023 More reading & Borrow/Stolen parts read at the bottom of the file; 2 spacs indent; 120 width    //
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "db_keystore.h"
#include "db_tables.h"
#include "crypto.h"
#include "tooling.h"
// TODO: Add AES for encryption/decryption (lightssl)
// TODO: Add ECDSA for keyexchange (lightssl)

// Public functions

//
// Communication init
sockets communication_init(const char *host, const char *port) {
  sockets sock;
  sock.descriptor = socket(AF_INET , SOCK_STREAM , 0);
  if (sock.descriptor == -1) {
    perror("\"[o.o]\" \t Could not create a socket\n");
    exit(0);
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
  if (count != 3) {
    printf("\"[o.o]\" \t Usage:\n");
    printf("  %s keys   # for keyvaluestore %s\n", clisrv, clisrv);
    printf("  %s tables # for table database %s\n", clisrv, clisrv);
    exit(0);
  }
  int type = 0;
  if (strcmp(arg, "keys")==0) type = 1;
  else if (strcmp(arg, "tables")==0) type = 2;
  else {
    printf("\"[o.o]\" \t Wrong %s type\n", clisrv);
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
  k.publ = (long long int)pow((*h).g, k.priv) % (*h).p;
  return k;
}
// Very simple handshake
