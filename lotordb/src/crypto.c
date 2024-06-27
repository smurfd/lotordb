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

//
// Communication init
static sockets communication_init(const char *host, const char *port) {
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

static void *client_connection_handler_ssl(void *conn) {
  int sock = *((connection*)conn)->clisocket;
  if (((connection*)conn)->type == 1) {
    kvsh *k = (kvsh*)malloc(sizeof(struct kvsh));
    set_key_value_store(k, "0002", "testvalue", "/tmp");
    key_write(k);
    key_del(k);
    key_send(sock, k);
    free(k);
  } else if (((connection*)conn)->type == 2) {
    for (int i=0;i<20;i++) {
      tbls *t = (tbls*)malloc(sizeof(struct tbls));
      set_table_data(&t->d, "stuff", "stuff * 2");
      set_table_index(&t->i, 1234, "stuff", 1111, "/tmp/dbdata.d1");
      table_send(sock, t);
      free(t);
    }
  }
  return 0;
}

static void *client_connection_handler(void *conn) {
  u64 dat[BLOCK], cd[BLOCK];
  cryptokey k1, k2;
  head h;
  receive_cryptokey(*(connection*)conn, &h, &k1);                               // Handshake vvv
  k2 = generate_cryptokeys(&h);                                                 //
  send_cryptokey(*(connection*)conn, &h, &k2);                                  //
  generate_shared_cryptokey_client(&k1, &k2, &h);                               //
  printf("share : 0x%.16llx\n", k1.shar);                                       //
  for (u64 i = 0; i < 12; i++) {                                                //
    dat[i] = (u64)i;                                                            //
    handler_cryptography(dat[i], k1, &cd[i]);                                   //
  }                                                                             //
  if (send_cryptodata(*(connection*)conn, cd, &h, 11) > 0) {                    // Handshake ^^^
    // TODO: send less data
    // TODO: If we are not communicating using SSL, Abort!
    pthread_t ssl_thread;
    if (pthread_create(&ssl_thread, NULL, client_connection_handler_ssl, (void*)conn) < 0) {
      perror("could not create thread");
    }
    pthread_join(ssl_thread, NULL);
  }
  //free(((connection*)conn)->clisocket);
  return 0;
}

static void *server_connection_handler_ssl(void *conn) {
  int sock = *((connection*)conn)->clisocket;
  if (((connection*)conn)->type == 1) {
    kvsh k;
    key_recv(sock, &k);
  } else if (((connection*)conn)->type == 2) {
    tbls *t = (tbls*)malloc(sizeof(struct tbls));
    table_recv(sock, t);
    table_write_index(&t->i, "/tmp/dbindex1.db1");
    table_write_data(&t->d, &t->i);
    free(t);
  }
  //free(((connection*)conn)->clisocket);
  return 0;
}

static void *server_connection_handler(void *conn) {
  u64 cd[BLOCK];                                                                // Handshake vvv
  if (((connection*)conn)->socket == -1) return (void*) - 1;                    //
  head h = *set_header(&h, u64rnd(), u64rnd());                                 //
  cryptokey k1 = generate_cryptokeys(&h), k2 = *clear_cryptokey(&k2);           //
  if (h.len > BLOCK) return (void*) - 1;                                        //
  send_cryptokey(*(connection*)conn, &h, &k1);                                  //
  receive_cryptokey(*(connection*)conn, &h, &k2);                               //
  generate_shared_cryptokey_server(&k1, &k2, &h);                               //
  printf("share : 0x%.16llx\n", k2.shar);                                       //
  if (receive_cryptodata(*(connection*)conn, cd, &h, 11) > 0) {                 // Handshake ^^^
    // TODO: receive less data
    // TODO: If we are not communicating using SSL, Abort!
    pthread_t ssl_thread;
    if (pthread_create(&ssl_thread, NULL, server_connection_handler_ssl, (void*)conn) < 0) {
      perror("Could not create thread");
    }
    pthread_join(ssl_thread, NULL);
  }
  free(((connection*)conn)->clisocket);
  return 0;
}

// Public functions
int server_listener(const char *host, const char *port) {
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
    conn.clisocket = malloc(1);
    *conn.clisocket = client_sock;
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

int client_connection(const char *host, const char *port) {
  sockets sock = communication_init(host, port);
  if (connect(sock.descriptor , (struct sockaddr*)&(sock.addr) , sizeof(sock.addr)) < 0) {
    perror("Connection error");
    return 1;
  }
  return sock.descriptor;
}

int client_handle(connection conn) {
  pthread_t thread;
  conn.clisocket = &(conn.socket);
  if (pthread_create(&thread, NULL, client_connection_handler, (void*)&conn) < 0) {
    perror("Could not create thread");
    return 1;
  }
  pthread_join(thread , NULL);
  return conn.socket;
}

//
// Initialize server
connection server_init(const char *host, const char *port, int type) {
  int socket_desc = server_listener(host, port);
  printf("\"[o.o]\" eating food...\n");
  connection c;
  c.socket = socket_desc;
  c.type = type;
  if (socket_desc >= 0) c.err = 0;
  else c.err = -1;
  return c;
}

//
// Initialize client
connection client_init(const char *host, const char *port, int type) {
  printf("\"[o.o]\" finding food...\n");
  int sck = client_connection(host, port);
  connection c;
  c.socket = sck;
  c.type = type;
  if (sck >= 0) c.err = 0;
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
  snd_cryptokey(sock, h, k);
}

//
// Receive key from client/server
void receive_cryptokey(connection c, head *h, cryptokey *k) {
  int sock = *((connection*)&c)->clisocket;
  cryptokey tmp;

  // This to ensure if we receive a private key we clear it
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
