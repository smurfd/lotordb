#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <sys/socket.h>
#include "crypto_server.h"
#include "db_tables.h"
#include "crypto.h"

static cryptokey *clear_cryptokey(cryptokey *k) {
  (*k).publ = 0;
  (*k).priv = 0;
  (*k).shar = 0;
  return k;
}

static head *set_header(head *h, u64 a, u64 b) {
  (*h).g = a;
  (*h).p = b;
  return h;
}

static void *server_connection_handler_ssl(void *conn) {
  int sock = *((connection*)conn)->clisocket;
  if (((connection*)conn)->type == 1) { // keystore
    kvsh k;
    key_recv(sock, &k);
  } else if (((connection*)conn)->type == 2) { // tables
    tbls *t = (tbls*)malloc(sizeof(struct tbls));
    table_recv(sock, t);
    FILE *write_ptr = fopen("/tmp/dbsrv1.db", "ab");
    binary *datatmp = malloc(sizeof (binary));
    table_writeperson(&(*t).p, datatmp, write_ptr);
    free(datatmp);
    fclose(write_ptr);
    free(t);
  }
  return 0;
}

static void *server_connection_handler(void *conn) {
  u64 cd[BLOCK], dat[BLOCK];                                                    // Handshake vvv
  if (((connection*)conn)->socket == -1) return (void*) - 1;                    //
  head h = *set_header(&h, u64rnd(), u64rnd());                                 //
  cryptokey k1 = generate_cryptokeys(&h), k2 = *clear_cryptokey(&k2);           //
  if (h.len > BLOCK) return (void*) - 1;                                        //
  send_cryptokey(*(connection*)conn, &h, &k1);                                  //
  receive_cryptokey(*(connection*)conn, &h, &k2);                               //
  generate_shared_cryptokey_server(&k1, &k2, &h);                               //
  printf("share : 0x%.20llx\n", k2.shar);                                       //
  if (receive_cryptodata(*(connection*)conn, cd, &h, 12) > 0) {                 // Handshake ^^^
    // TODO: receive less data
    // TODO: If we are not communicating using SSL, Abort!
    pthread_t ssl_thread;
    printf("cd: %llu %llu %llu %llu\n", cd[0], cd[1], cd[2], cd[3]);
    for (u64 i = 0; i < 12; i++) {
      handler_cryptography(cd[i], k2, &dat[i]);
      assert((u64)dat[i] == (u64)i);
    }
    if (pthread_create(&ssl_thread, NULL, server_connection_handler_ssl, (void*)conn) < 0) {
      perror("Could not create thread");
    }
    pthread_join(ssl_thread, NULL);
  }
  return 0;
}

static int server_run(const char *host, const char *port) {
  sockets sock = communication_init(host, port);
  if (bind(sock.descriptor, (struct sockaddr*)&(sock.addr), sizeof(sock.addr)) < 0) {
    perror("Bind error");
    return 1;
  }
  listen(sock.descriptor, 3);
  return sock.descriptor;
}

int server_handle(connection conn) {
  int client_sock, c = sizeof(struct sockaddr_in);
  struct sockaddr_in client;
  while ((client_sock = accept(conn.socket, (struct sockaddr *)&client, (socklen_t*)&c))) {
    pthread_t thread;
    conn.clisocket = &client_sock;
    if (pthread_create(&thread, NULL, server_connection_handler, (void*)&conn) < 0) {
      perror("Could not create thread");
      return 1;
    }
    pthread_join(thread, NULL);
  }
  if (client_sock < 0) {
    perror("No clients connected");
    return 1;
  }
  return client_sock;
}

//
// Initialize server
connection server_init(const char *host, const char *port, int type) {
  int socket_desc = server_run(host, port);
  printf("\"[o.o]\" eating food...\n");
  return connection_init(socket_desc, type);
}

//
// End connection
void server_end(connection c) {
  close(c.socket);
}

//
// Generate the server shared key
void generate_shared_cryptokey_server(cryptokey *k1, cryptokey *k2, head *h) {
  (*k2).shar = (*h).p % (int64_t)pow((*k2).publ, (*k1).priv);
}
