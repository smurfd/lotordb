#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include "examples/tables_example_client.h"
#include "examples/keys_example_client.h"
#include "crypto_client.h"
#include "db_tables.h"
#include "crypto.h"

//
// See examples/*_example_client.c to modify the clients functionallity
// Recompile after change
static void *client_connection_handler_ssl(void *conn) {
  int sock = *((connection*)conn)->clisocket;
  if (((connection*)conn)->type == 1) {
    key_client(sock);
  } else if (((connection*)conn)->type == 2) {
    table_client(sock);
  }
  return 0;
}

static void *client_connection_handler(void *conn) {
  u64 cd[BLOCK]; // dat[BLOCK]
  cryptokey k1, k2;
  head h;
  receive_cryptokey(*(connection*)conn, &h, &k1);                               // Handshake vvv
  k2 = generate_cryptokeys(&h);                                                 //
  send_cryptokey(*(connection*)conn, &h, &k2);                                  //
  generate_shared_cryptokey_client(&k1, &k2, &h);                               //
  printf("share : 0x%.20llx\n", k1.shar);                                       //
  for (u64 i = 0; i < 12; i++) {                                                //
    //dat[i] = (u64)i;                                                          //
    //handler_cryptography(dat[i], k1, &cd[i]);                                 //
    handler_cryptography((u64)i, k1, &cd[i]);                                   //
  }                                                                             //
  if (send_cryptodata(*(connection*)conn, cd, &h, 12) > 0) {                    // Handshake ^^^
    // TODO: send less data
    // TODO: If we are not communicating using SSL, Abort!
    pthread_t ssl_thread;
    if (pthread_create(&ssl_thread, NULL, client_connection_handler_ssl, (void*)conn) < 0) {
      perror("\"[o.o]\" \t Could not create a thread");
      return (void*)1;
    }
    pthread_join(ssl_thread, NULL);
  }
  return 0;
}

static int client_run(const char *host, const char *port) {
  sockets sock = communication_init(host, port);
  if (connect(sock.descriptor , (struct sockaddr*)&(sock.addr) , sizeof(sock.addr)) < 0) {
    perror("\"[o.o]\" \t Connection error");
    return 1;
  }
  return sock.descriptor;
}

int client_handle(connection conn) {
  pthread_t thread;
  conn.clisocket = &(conn.socket);
  if (pthread_create(&thread, NULL, client_connection_handler, (void*)&conn) < 0) {
    perror("\"[o.o]\" \t Could not create a thread");
    return 1;
  }
  pthread_join(thread, NULL);
  return conn.socket;
}

//
// Initialize client
connection client_init(const char *host, const char *port, int type) {
  printf("\"[o.o]\" \t finding food...\n");
  int socket_desc = client_run(host, port);
  return connection_init(socket_desc, type);
}

//
// End connection
void client_end(connection c) {
  close(c.socket);
}

//
// Generate the client shared key
void generate_shared_cryptokey_client(cryptokey *k1, cryptokey *k2, head *h) {
  (*k1).shar = (*h).p % (long long int)pow((*k1).publ, (*k2).priv);
}
