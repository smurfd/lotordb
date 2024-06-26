// Auth: smurfd, 2023 More reading & Borrow/Stolen parts read at the bottom of the file; 2 spacs indent; 120 width    //
#include <math.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "crypto.h"
#include "tables.h"
#include "keys.h"
#include "defs.h"

// Static functions

//
// Receive key (clears private key if we receive it for some reason)
static void recv_cryptokey(int s, head *h, cryptokey *k) {
  recv(s, h, sizeof(head), 0);
  recv(s, k, sizeof(cryptokey), 0);
  (*k).priv = 0;
}

//
// Send key
static void snd_cryptokey(int s, head *h, cryptokey *k) {
  // This to ensure not to send the private key
  cryptokey kk;

  kk.publ = (*k).publ;
  kk.shar = (*k).shar;
  kk.priv = 0;
  send(s, h, sizeof(head), 0);
  send(s, &kk, sizeof(cryptokey), 0);
}

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
/*
//
// SSL server handler
static void *handler_ssl_server(void *conn) {
  // Switch to SSL
  // Decrypt the data
  tbls t;
  kvsh k;
  u64 dat[BLOCK], cd[BLOCK];
  cryptokey k2 = *clear_cryptokey(&k2);
  head h = *set_header(&h, u64rnd(), u64rnd());
  receive_cryptodata(*(connection*)conn, &dat, &h, BLOCK - 1);
  for (u64 i = 0; i < 10; i++) handler_cryptography(dat[i], k2, &cd[i]);
  printf("ssl 0x%.16llx 0x%.16llx 0x%.16llx\n", dat[0], dat[1], dat[2]);
  int s = ((connection*)conn)->socket;
  if (((connection*)conn)->type == 1) {
    printf("recv sock %d\n", ((connection*)conn)->socket);
    key_recv(((connection*)conn)->socket, &k);
  } else if (((connection*)conn)->type == 2) {
    //tbls t;
    
    //dbdata k2;
    //dbindex k3;
    //table_recv2(((connection*)conn)->socket, &k2);
    //table_recv3(((connection*)conn)->socket, &k3);
    //printf("tbl recv %s %llu %llu\n", k2.unique_id, k2.xxx, k3.index);
    //table_write_index(&k3, "/tmp/dbindex1.db1");
    //table_write_data(&k2, &k3);
    table_recv4(((connection*)conn)->socket, &t);
    printf("tbl recv %s %llu\n", t.d.unique_id, t.i.index);
  }
  //pthread_exit(NULL);
  return 0;
}
*/
//
// Server handler
static void *handler_server(void *conn) {
  u64 g1 = u64rnd(), p1 = u64rnd();
  if (((connection*)conn)->socket == -1) return (void*) - 1;
  head h = *set_header(&h, g1, p1);
  cryptokey k1 = generate_cryptokeys(&h), k2 = *clear_cryptokey(&k2);
  // Send and receive stuff
  if (h.len > BLOCK) return (void*) - 1;
  send_cryptokey(*(connection*)conn, &h, &k1);
  receive_cryptokey(*(connection*)conn, &h, &k2);
  generate_shared_cryptokey_server(&k1, &k2, &h);
  printf("share : 0x%.16llx\n", k2.shar);





  tbls t;
  kvsh k;
  u64 dat[BLOCK], cd[BLOCK];
  cryptokey k3 = *clear_cryptokey(&k3);
  head h1 = *set_header(&h1, u64rnd(), u64rnd());
  receive_cryptodata(*(connection*)conn, &dat, &h1, BLOCK - 1);
  for (u64 i = 0; i < 10; i++) handler_cryptography(dat[i], k3, &cd[i]);
  printf("ssl 0x%.16llx 0x%.16llx 0x%.16llx\n", dat[0], dat[1], dat[2]);
  int s = ((connection*)conn)->socket;
  if (((connection*)conn)->type == 1) {
    printf("recv sock %d\n", ((connection*)conn)->socket);
    key_recv(((connection*)conn)->socket, &k);
  } else if (((connection*)conn)->type == 2) {
    //tbls t;
    /*
    dbdata k2;
    dbindex k3;
    table_recv2(((connection*)conn)->socket, &k2);
    table_recv3(((connection*)conn)->socket, &k3);
    printf("tbl recv %s %llu %llu\n", k2.unique_id, k2.xxx, k3.index);
    table_write_index(&k3, "/tmp/dbindex1.db1");
    table_write_data(&k2, &k3);*/
    table_recv4(((connection*)conn)->socket, &t);
    printf("tbl recv %s %llu\n", t.d.unique_id, t.i.index);
  }




  pthread_exit(NULL);
  return 0;
}

static void *handler_client(void *conn) {
  u64 dat[BLOCK], cd[BLOCK];
  cryptokey k1, k2;
  head h;
  receive_cryptokey(*(connection*)conn, &h, &k1);
  k2 = generate_cryptokeys(&h);
  send_cryptokey(*(connection*)conn, &h, &k2);
  generate_shared_cryptokey_client(&k1, &k2, &h);
  printf("share : 0x%.16llx\n", k1.shar);
  for (u64 i = 0; i < 12; i++) {
    dat[i] = (u64)i;
    handler_cryptography(dat[i], k1, &cd[i]);
  }
  send_cryptodata(*(connection*)conn, cd, &h, 11);




  int s = ((connection*)conn)->socket;
  tbls t;
  kvsh k;
  if (((connection*)conn)->type == 1) {
    set_key_value_store(&k, "0002", "testvalue", "/tmp");
    key_write(&k);
    key_del(&k);
    key_send(s, &k);
  } else if (((connection*)conn)->type == 2) {
    /*
    dbdata d;
    dbindex di;
    set_table2(&d, "stuff", "stuff * 2", 66699);
    sleep(1); // TODO: wtf no sleep til brooklyn
    table_send2(((connection*)conn)->socket, &d);
    set_table3(&di, 1234, "stuff", 1111, "/tmp/dbdata.d1");
    table_send3(((connection*)conn)->socket, &di);
    */
    //sleep(1);
    //pthread_join(NULL, NULL);
    set_table2(&t.d, "stuff", "stuff * 2", 66699);
    set_table3(&t.i, 1234, "stuff", 1111, "/tmp/dbdata.d1");
    table_send4(((connection*)conn)->socket, &t);
    //pthread_join(NULL, NULL);
    printf("tbl send %s %llu\n", t.d.unique_id, t.i.index);

  }
  //pthread_exit(NULL);
  client_end(*(connection*)conn);



  pthread_exit(NULL);
  return 0;
}
/*
static void *handler_client_ssl(void *conn) {
  int s = ((connection*)conn)->socket;
  tbls t;
  kvsh k;
  if (((connection*)conn)->type == 1) {
    set_key_value_store(&k, "0002", "testvalue", "/tmp");
    key_write(&k);
    key_del(&k);
    key_send(s, &k);
  } else if (((connection*)conn)->type == 2) {
    
    //dbdata d;
    //dbindex di;
    //set_table2(&d, "stuff", "stuff * 2", 66699);
    //sleep(1); // TODO: wtf no sleep til brooklyn
    //table_send2(((connection*)conn)->socket, &d);
    //set_table3(&di, 1234, "stuff", 1111, "/tmp/dbdata.d1");
    //table_send3(((connection*)conn)->socket, &di);
    
    //sleep(1);
    //pthread_join(NULL, NULL);
    set_table2(&t.d, "stuff", "stuff * 2", 66699);
    set_table3(&t.i, 1234, "stuff", 1111, "/tmp/dbdata.d1");
    table_send4(((connection*)conn)->socket, &t);
    //pthread_join(NULL, NULL);
    printf("tbl send %s %llu\n", t.d.unique_id, t.i.index);

  }
  //pthread_exit(NULL);
  client_end(*(connection*)conn);
  //pthread_exit(NULL);
  return 0;
}*/

//
// Communication init
static sock_in communication_init(const char *host, const char *port) {
  sock_in adr;

  memset(&adr, '\0', sizeof(adr));
  adr.sin_family = AF_INET;
  adr.sin_port = atoi(port);
  adr.sin_addr.s_addr = inet_addr(host);
  return adr;
}

///////////////////////////////////////////////////////////////////////////vvvvv

//void *client_connection_handler(void *socket_desc) {
static void *client_connection_handler(void *conn) {
  
  printf("cli handlrrr\n");
  u64 dat[BLOCK], cd[BLOCK];
  cryptokey k1, k2;
  head h;
  receive_cryptokey(*(connection*)conn, &h, &k1);
  k2 = generate_cryptokeys(&h);
  send_cryptokey(*(connection*)conn, &h, &k2);
  generate_shared_cryptokey_client(&k1, &k2, &h);
  printf("share : 0x%.16llx\n", k1.shar);
  for (u64 i = 0; i < 12; i++) {
    dat[i] = (u64)i;
    handler_cryptography(dat[i], k1, &cd[i]);
  }

  send_cryptodata(*(connection*)conn, cd, &h, 11);
  printf("CLI CRYPTO DONE\n");
  
  //int sock = *(int*)((connection*)conn)->clisocket;
  int sock = *((connection*)conn)->clisocket;
  //int sock = *(int*)socket_desc;
  printf("cli type: %d %d\n", ((connection*)conn)->type, sock);
  if (((connection*)conn)->type == 1) {
    kvsh *k = (kvsh*)malloc(sizeof(struct kvsh));
    set_key_value_store(k, "0002", "testvalue", "/tmp");
    key_write(k);
    key_del(k);
    key_send(sock, k);
    free(k);
/*
    set_key_value_store(&k, "0002", "testvalue", "/tmp");
    key_write(&k);
    key_del(&k);
    key_send(sock, &k);
*/
  } else if (((connection*)conn)->type == 2) {
    for (int i=0;i<20;i++) {
      tbls *t = (tbls*)malloc(sizeof(struct tbls));
      set_table2(&t->d, "stuff", "stuff * 2", 66699);
      set_table3(&t->i, 1234, "stuff", 1111, "/tmp/dbdata.d1");
      table_send4(sock, t);
      free(t);
    }
  }
  //free(socket_desc);
  //free(((connection*)conn)->clisocket);
  return 0;
}

//void *server_connection_handler(void *socket_desc) {
static void *server_connection_handler(void *conn) {//void *socket_desc) {
  //int sock = *(int*)socket_desc;
  
  u64 dat[BLOCK], cd[BLOCK];
  u64 g1 = u64rnd(), p1 = u64rnd();
  if (((connection*)conn)->socket == -1) return (void*) - 1;
  head h = *set_header(&h, g1, p1);
  cryptokey k1 = generate_cryptokeys(&h), k2 = *clear_cryptokey(&k2);
  // Send and receive stuff
  if (h.len > BLOCK) return (void*) - 1;
  send_cryptokey(*(connection*)conn, &h, &k1);
  receive_cryptokey(*(connection*)conn, &h, &k2);
  generate_shared_cryptokey_server(&k1, &k2, &h);
  printf("share : 0x%.16llx\n", k2.shar);
  receive_cryptodata(*(connection*)conn, cd, &h, 11);
  printf("SRV CRYPTO DONE\n");

  int sock = *((connection*)conn)->clisocket;
  int read_size;
  //tbls *t = (tbls*)malloc(sizeof(struct tbls));
  printf("srv type: %d\n", ((connection*)conn)->type);


  if (((connection*)conn)->type == 1) {
  kvsh k;// = (kvsh*)malloc(sizeof(struct kvsh));
    printf("recv sock %d\n", ((connection*)conn)->socket);
    key_recv(sock, &k);
    //free(k);
    //key_recv(((connection*)conn)->socket, k);
  } else if (((connection*)conn)->type == 2) {
  tbls *t = (tbls*)malloc(sizeof(struct tbls));
    printf("srv clisock %d\n", sock);
    //read_size = recv(sock, t, sizeof(struct tbls), 0);
    //printf("srv recv %llu %llu : %s\n", t->i.index, t->d.xxx, t->i.unique_id);
    while ((read_size = recv(sock, t, sizeof(struct tbls), 0)) > 0) {
      printf("srv recv %llu %llu : %s\n", t->i.index, t->d.xxx, t->i.unique_id);
    }
    if (read_size == 0) {
      puts("Client disconnected");
      fflush(stdout);
    } else if (read_size == -1) {
      perror("recv failed");
    }
    free(t);
  }
  //free(((connection*)conn)->clisocket);
  //free(socket_desc);
  return 0;
}

int server_listener() {
  int socket_desc, client_sock, c, *new_sock;
  struct sockaddr_in server , client;
  socket_desc = socket(AF_INET , SOCK_STREAM , 0);
  if (socket_desc == -1) {
    printf("Could not create socket");
  }
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = INADDR_ANY;
  server.sin_port = htons( 8888 );
  if (bind(socket_desc, (struct sockaddr *)&server, sizeof(server)) < 0) {
    perror("bind failed. Error");
    return 1;
  }
  listen(socket_desc, 3);
  return socket_desc;
}

int server_handle(connection conn) {//int socket_desc) {
  int client_sock, *new_sock, c = sizeof(struct sockaddr_in);
  struct sockaddr_in client;
  //while ((client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c))) {
  while ((client_sock = accept(conn.socket, (struct sockaddr *)&client, (socklen_t*)&c))) {
    pthread_t sniffer_thread;
    //new_sock = malloc(1);
    //*new_sock = client_sock;
    conn.clisocket = malloc(1);
    *conn.clisocket = client_sock;
    printf("srv clisock %d\n", client_sock);
    //if (pthread_create(&sniffer_thread, NULL, server_connection_handler, (void*)new_sock) < 0) {
    if (pthread_create(&sniffer_thread, NULL, server_connection_handler, (void*)&conn) < 0) {
      perror("could not create thread");
      return 1;
    }
    pthread_join(sniffer_thread, NULL);
    puts("Handler assigned");
  }
  if (client_sock < 0) {
    perror("accept failed");
    return 1;
  }
  return client_sock;
}

int client_connection() {
  struct sockaddr_in server;
  int sock = socket(AF_INET , SOCK_STREAM , 0);
  if (sock == -1) {
    printf("Could not create socket");
  }
  server.sin_addr.s_addr = inet_addr("127.0.0.1");
  server.sin_family = AF_INET;
  server.sin_port = htons( 8888 );
  //Connect to remote server
  if (connect(sock , (struct sockaddr *)&server , sizeof(server)) < 0) {
    perror("connect failed. Error");
    return 1;
  }
  return sock;
}

//int client_handle(int sock) {
int client_handle(connection conn) {
  printf("cli_had\n");
  int *new_sock = (int*)malloc(1),  client_sock = conn.socket;//sock;
  pthread_t sniffer_thread;
  printf("cli_had\n");
  //*new_sock = client_sock;
  *conn.clisocket = *(int*)malloc(1);
  printf("cli_had\n");
  conn.clisocket = &client_sock;
  printf("cli_had\n");
  if (pthread_create(&sniffer_thread, NULL, client_connection_handler, (void*)&conn) < 0) {
  //if (pthread_create(&sniffer_thread, NULL, client_connection_handler, (void*)new_sock) < 0) {
      perror("could not create thread");
      return 1;
  }
  printf("cli_had\n");
  pthread_join(sniffer_thread , NULL);
  printf("cli %d\n", conn.socket);
  return conn.socket;//sock;
}

//
// Initialize server
connection server_init2(const char *host, const char *port, int type) {
  //int sck = socket(AF_INET, SOCK_STREAM, 0), opt=1;
  //setsockopt(sck, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));
  //sock_in adr = communication_init(host, port);
  //bind(sck, (sock*)&adr, sizeof(adr));
  int socket_desc = server_listener();
  //puts("Waiting for incoming connections...");

  printf("\"[o.o]\" eating food...\n");
  connection c;
  c.socket = socket_desc;//sck;
  c.type = type;
  if (socket_desc >= 0)
    c.err = 0;
  else
    c.err = -1;

  //int srv = server_handle(socket_desc);

  return c;
}

//
// Initialize client
connection client_init2(const char *host, const char *port, int type) {
  //int sck = socket(AF_INET, SOCK_STREAM, 0);
  //sock_in adr = communication_init(host, port);
  //connection c;
  //if (connect(sck, (sock*)&adr, sizeof(adr)) < 0) {
  //  c.err = -1;
  //  return c;
  //}
  printf("\"[o.o]\" finding food...\n");
  int sck = client_connection(); 
  connection c;
  c.socket = sck;
  c.type = type;
  if (sck >= 0)
    c.err = 0;
  else
    c.err = -1;
  printf("cli err %d\n", c.err);
  return c;
}

////////////////////////////////////////////////////////////////////////^^^^^^^^

// Public functions

//
// Print usage information
int usage(char *arg, int count, char *clisrv) {
  if (count != 2) {
    printf("Usage:\n");
    printf("  %s keys   # for keyvaluestore client\n", clisrv);
    printf("  %s table  # for table database client\n", clisrv);
    exit(0);
  }
  int type = 0;
  if (strcmp(arg, "keys")==0) {type = 1;}
  else if (strcmp(arg, "table")==0) {type = 2;}
  else {printf("wrong %s type\n", clisrv); exit(0);}
  return type;
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

//
// Encrypt and decrypt data with shared key
void handler_cryptography(u64 data, cryptokey k, u64 *enc) {
  (*enc) = data ^ k.shar;
}

//
// Initialize server
connection server_init(const char *host, const char *port, int type) {
  int sck = socket(AF_INET, SOCK_STREAM, 0), opt=1;
  setsockopt(sck, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));
  sock_in adr = communication_init(host, port);
  bind(sck, (sock*)&adr, sizeof(adr));
  printf("\"[o.o]\" eating food...\n");
  connection c;
  c.socket = sck;
  c.type = type;
  if (sck >= 0)
    c.err = 0;
  else
    c.err = -1;
  return c;
}

//
// Initialize client
connection client_init(const char *host, const char *port, int type) {
  int sck = socket(AF_INET, SOCK_STREAM, 0);
  sock_in adr = communication_init(host, port);
  connection c;
  if (connect(sck, (sock*)&adr, sizeof(adr)) < 0) {
    c.err = -1;
    return c;
  }
  printf("\"[o.o]\" finding food...\n");
  c.socket = sck;
  c.type = type;
  if (sck >= 0)
    c.err = 0;
  else
    c.err = -1;
  return c;
}

//
// Send data to client/server
void send_cryptodata(connection c, void* data, head *h, u64 len) {
  int sock = *((connection*)&c)->clisocket;
  send(sock, h, sizeof(head), 0);
  //send(c.socket, h, sizeof(head), 0);
  //send(c.socket, data, sizeof(u64)*len, 0);
  send(sock, data, sizeof(u64)*len, 0);
}

//
// Receive data from client/server
void receive_cryptodata(connection c, void* data, head *h, u64 len) {
  int sock = *((connection*)&c)->clisocket;
  recv(sock, h, sizeof(head), 0);
  //recv(c.socket, h, sizeof(head), 0);
  //recv(c.socket, data, sizeof(u64) * len, 0);
  recv(sock, data, sizeof(u64) * len, 0);
}

//
// Send key to client/server
void send_cryptokey(connection c, head *h, cryptokey *k) {
  int sock = *((connection*)&c)->clisocket;
  //snd_cryptokey(c.socket, h, k);
  snd_cryptokey(sock, h, k);
}

//
// Receive key from client/server
void receive_cryptokey(connection c, head *h, cryptokey *k) {
  int sock = *((connection*)&c)->clisocket;
  cryptokey tmp;

  // This to ensure if we receive a private key we clear it
  //recv_cryptokey(c.socket, h, &tmp);
  recv_cryptokey(sock, h, &tmp);
  (*k).publ = tmp.publ; (*k).shar = tmp.shar; (*k).priv = 0;
}

//
// End connection
void client_end(connection c) {
  close(c.socket);
}

//
// End connection
void server_end(connection c) {
  close(c.socket);
}

//
// Server listener
int server_listen(connection c) {
  int cl = 1, len = sizeof(sock_in);
  sock *cli = NULL;

  listen(c.socket, 10);
  int tmpsock = c.socket;
  while (cl >= 1) {
    cl = accept(tmpsock, (sock*)&cli, (socklen_t*)&len);
    pthread_t thrd, thrd_ssl;
    c.socket = cl;
    if (pthread_create(&thrd, NULL, handler_server, (void*)&c) < 0) return -1;
    pthread_join(thrd, NULL);
    // TODO: Only if handshake OK, we create SSL thread
    //if (pthread_create(&thrd_ssl, NULL, handler_ssl_server, (void*)&c) < 0) return -1;
    ////pthread_join(thrd, NULL);
    //pthread_join(thrd_ssl, NULL);
  }
  return cl;
}

int client_connect(connection c) {
  //pthread_t thrd, thrd_ssl;
  //if (pthread_create(&thrd, NULL, handler_client, (void*)&c) < 0) return -1;
  //pthread_join(thrd, NULL);
  // TODO: Only if handshake OK, we create SSL thread
  //if (pthread_create(&thrd_ssl, NULL, handler_client_ssl, (void*)&c) < 0) return -1;
  //pthread_join(thrd_ssl, NULL);

  //pthread_join(thrd, NULL);



  u64 dat[BLOCK], cd[BLOCK];
  cryptokey k1, k2;
  head h;
  receive_cryptokey(c, &h, &k1);
  k2 = generate_cryptokeys(&h);
  send_cryptokey(c, &h, &k2);
  generate_shared_cryptokey_client(&k1, &k2, &h);
  printf("share : 0x%.16llx\n", k1.shar);
  for (u64 i = 0; i < 12; i++) {
    dat[i] = (u64)i;
    handler_cryptography(dat[i], k1, &cd[i]);
  }
  send_cryptodata(c, cd, &h, 11);




  int s = c.socket;
  tbls t;
  kvsh k;
  if (c.type == 1) {
    set_key_value_store(&k, "0002", "testvalue", "/tmp");
    key_write(&k);
    key_del(&k);
    key_send(s, &k);
  } else if (c.type == 2) {
    /*
    dbdata d;
    dbindex di;
    set_table2(&d, "stuff", "stuff * 2", 66699);
    sleep(1); // TODO: wtf no sleep til brooklyn
    table_send2(((connection*)conn)->socket, &d);
    set_table3(&di, 1234, "stuff", 1111, "/tmp/dbdata.d1");
    table_send3(((connection*)conn)->socket, &di);
    */
    //sleep(1);
    //pthread_join(NULL, NULL);
    set_table2(&t.d, "stuff", "stuff * 2", 66699);
    set_table3(&t.i, 1234, "stuff", 1111, "/tmp/dbdata.d1");
    table_send4(c.socket, &t);
    //pthread_join(NULL, NULL);
    printf("tbl send %s %llu\n", t.d.unique_id, t.i.index);

  }
  //pthread_exit(NULL);
  client_end(c);

  return 0;
}

//
// Generate the server shared key
void generate_shared_cryptokey_server(cryptokey *k1, cryptokey *k2, head *h) {
  (*k2).shar = (*h).p % (int64_t)pow((*k2).publ, (*k1).priv);
}

//
// Generate the client shared key
void generate_shared_cryptokey_client(cryptokey *k1, cryptokey *k2, head *h) {
  (*k1).shar = (*h).p % (int64_t)pow((*k1).publ, (*k2).priv);
}

//
// Generate a public and private keypair
cryptokey generate_cryptokeys(head *h) {
  cryptokey k;

  k.priv = u64rnd();
  k.publ = (int64_t)pow((*h).g, k.priv) % (*h).p;
  return k;
}

static uint32_t oct(int i, int inl, const uint8_t d[]) {
  if (i < inl) return d[i];
  return 0;
}

static uint32_t sex(const char d[], char c[], int i) {
  if (d[i] == '=') return (0 & i++);
  return c[(int)d[i]];
}

//
// Error "handler"
int err(char *s) {
  printf("ERR: %s\n", s);
  return 1;
}

// from UTF-8 encoding to Unicode Codepoint
uint32_t utf8dec(uint32_t c) {
  if (c > 0x7f) {
    uint32_t m = (c <= n2[0]) ? n2[1] : n2[2];
    c = ((c & n2[3]) >> 6) | ((c & m) >> 4) | ((c & n2[4]) >> 2) | (c & n2[5]);
  }
  return c;
}

// From Unicode Codepoint to UTF-8 encoding
uint32_t utf8enc(uint32_t c) {
  uint32_t m = c;

  if (c > 0x7f) {
    m = (c & n1[0]) | (c & n1[1]) << 2 | (c & n1[2]) << 4 | (c & n1[3]) << 6;
    if (c < n1[4]) m |= n1[5];
    else if (c < n1[6]) m |= n1[7];
    else m |= n1[8];
  }
  return m;
}

//
// Base64 encoder
int base64enc(char ed[], const uint8_t *data, int inl) {
  int tab[] = {0, 2, 1}, ol = 4 * ((inl + 2) / 3);

  for (int i = 0, j = 0; i < inl;) {
    uint32_t a = oct(i++, inl, data), b = oct(i++, inl, data), c = oct(i++, inl, data),tri = (a << 0x10)+(b << 0x08) + c;
    for (int k = 3; k >=0; k--)
      ed[j++] = enc[(tri >> k * 6) & 0x3f];
  }
  for (int i = 0; i < tab[inl % 3]; i++)
    ed[ol - 1 - i] = '=';
  ed[ol] = '\0';
  return ol;
}

//
// Base64 decoder
int base64dec(uint8_t dd[], const char *data, int inl) {
  static char dec[LEN] = {0};
  int ol = inl / 4 * 3;

  for (int i = 1; i <= 2; i++) {if (data[inl - i] == '=') ol--;}
  for (int i = 0; i < 64; i++) dec[(uint8_t)enc[i]] = i;
  for (int i = 0, j = 0; i < inl;) {
    uint32_t a = sex(data, dec, i++), b = sex(data, dec, i++), c = sex(data, dec, i++), d = sex(data, dec, i++);
    uint32_t tri = (a << 3 * 6) + (b << 2 * 6) + (c << 1 * 6) + (d << 0 * 6);
    if (j < ol)
      for (int k = 2; k >= 0; k--)
        dd[j++] = (tri >> k * 8) & 0xff;
  }
  return ol;
}

// big[i] =
// ((uint64_t)dig[0] << 56) |
// ((uint64_t)dig[1] << 48) |
// ((uint64_t)dig[2] << 40) |
// ((uint64_t)dig[3] << 32) |
// ((uint64_t)dig[4] << 24) |
// ((uint64_t)dig[5] << 16) |
// ((uint64_t)dig[6] << 8) |
// (uint64_t)dig[7];
//
// Bit packing function uint8 to uint64
void bit_pack(u64 big[], const uint8_t byte[]) {
  for(uint32_t i = 0; i < 6; ++i) {
    const uint8_t *dig = byte + 8 * (6 - 1 - i); big[i] = 0;
    for (int j = 7; j >= 0; j--)
      big[i] |= ((u64)dig[7 - j] << (j * 8));
  }
}

// dig[0] = big[i] >> 56;
// dig[1] = big[i] >> 48;
// dig[2] = big[i] >> 40;
// dig[3] = big[i] >> 32;
// dig[4] = big[i] >> 24;
// dig[5] = big[i] >> 16;
// dig[6] = big[i] >> 8;
// dig[7] = big[i];
//
// Bit unpack uint64 to uint8
void bit_unpack(uint8_t byte[], const u64 big[]) {
  for(uint32_t i = 0; i < 6; ++i) {
    uint8_t *dig = byte + 8 * (6 - 1 - i);
    for (int j = 7; j >= 0; j--)
      dig[7 - j] = big[i] >> (j * 8);
  }
}

//
// 0-255 to 0x0 to 0xff
static void to_hex(uint8_t h[], uint8_t d) {
  h[0] = d >> 4;
  h[1] = d & 0xf;
}

static void to_hex_chr(char hs[], uint8_t h[]) {
  hs[0] = hex[h[0]];
  hs[1] = hex[h[1]];
}

//
// Convert a hex bitstring to a string
void bit_hex_str(char hs[], const uint8_t *d, const int len) {
  int co = 2;

  hs[0] = '0';
  hs[1] = 'x';
  for (int i = 0 ; i < len; i++) {
    uint8_t h[2];
    char hc[2];

    to_hex(h, d[i]);
    to_hex_chr(hc, h);
    hs[co++] = hc[0];
    hs[co++] = hc[1];
  }
  hs[len*2+2] = '\0';
}

// https://stackoverflow.com/questions/66715611/check-for-valid-utf-8-encoding-in-c/66723102#66723102
// UTF8 encode/decode


// Very simple handshake

// What im looking for:
// https://github.com/gh2o/tls_mini
// asn1 stolen / inspired from https://gitlab.com/mtausig/tiny-asn1
