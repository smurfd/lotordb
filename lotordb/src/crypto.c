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
// SSL server handler
static void *handler_ssl_server(void *sdesc) {
  // Switch to SSL
  // Decrypt the data
  u64 dat[BLOCK], cd[BLOCK];
  int sock = *(int*)sdesc;
  cryptokey k2 = *clear_cryptokey(&k2);
  head h = *set_header(&h, u64rnd(), u64rnd());
  receive_cryptodata(sock, &dat, &h, BLOCK - 1);
  for (u64 i = 0; i < 10; i++) handler_cryptography(dat[i], k2, &cd[i]);
  printf("ssl 0x%.16llx 0x%.16llx 0x%.16llx\n", dat[0], dat[1], dat[2]);

  kvsh k;
  key_recv(sock, &k);

  pthread_exit(NULL);
  return 0;
}

//
// Server handler
static void *handler_server(void *sdesc) {
  u64 g1 = u64rnd(), p1 = u64rnd();
  int sock = *(int*)sdesc;

  if (sock == -1) return (void*) - 1;
  head h = *set_header(&h, g1, p1);
  cryptokey k1 = generate_cryptokeys(&h), k2 = *clear_cryptokey(&k2);
  // Send and receive stuff
  if (h.len > BLOCK) return (void*) - 1;
  send_cryptokey(sock, &h, &k1);
  receive_cryptokey(sock, &h, &k2);
  generate_shared_cryptokey_server(&k1, &k2, &h);
  printf("share : 0x%.16llx\n", k2.shar);
  pthread_exit(NULL);
  return 0;
}

static void *handler_client(void *sock) {
  int s = *(int*)sock;
  u64 dat[BLOCK], cd[BLOCK];
  cryptokey k1, k2;
  head h;

  receive_cryptokey(s, &h, &k1);
  k2 = generate_cryptokeys(&h);
  send_cryptokey(s, &h, &k2);
  generate_shared_cryptokey_client(&k1, &k2, &h);
  printf("share : 0x%.16llx\n", k1.shar);
  for (u64 i = 0; i < 12; i++) {
    dat[i] = (u64)i;
    handler_cryptography(dat[i], k1, &cd[i]);
  }
  send_cryptodata(s, cd, &h, 11);
  pthread_exit(NULL);
  return 0;
}

static void *handler_client_ssl(void *sock) {
  int s = *(int*)sock;
  kvsh k;

  set_key_value_store(&k, "0002", "testvalue", "/tmp");
  key_write(&k);
  key_del(&k);
  key_send(s, &k);
  client_end(s);
  pthread_exit(NULL);
  return 0;
}

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


// Public functions

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
int server_init(const char *host, const char *port) {
  int sck = socket(AF_INET, SOCK_STREAM, 0);
  sock_in adr = communication_init(host, port);
  bind(sck, (sock*)&adr, sizeof(adr));
  printf("\"[o.o]\" eating food...\n");
  return sck;
}

//
// Initialize client
int client_init(const char *host, const char *port) {
  int sck = socket(AF_INET, SOCK_STREAM, 0);
  sock_in adr = communication_init(host, port);
  if (connect(sck, (sock*)&adr, sizeof(adr)) < 0) return -1;
  printf("\"[o.o]\" finding food...\n");
  return sck;
}

//
// Send data to client/server
void send_cryptodata(const int s, void* data, head *h, u64 len) {
  send(s, h, sizeof(head), 0);
  send(s, data, sizeof(u64)*len, 0);
}

//
// Receive data from client/server
void receive_cryptodata(const int s, void* data, head *h, u64 len) {
  recv(s, h, sizeof(head), 0);
  recv(s, data, sizeof(u64) * len, 0);
}

//
// Send key to client/server
void send_cryptokey(int s, head *h, cryptokey *k) {
  snd_cryptokey(s, h, k);
}

//
// Receive key from client/server
void receive_cryptokey(int s, head *h, cryptokey *k) {
  cryptokey tmp;

  // This to ensure if we receive a private key we clear it
  recv_cryptokey(s, h, &tmp);
  (*k).publ = tmp.publ; (*k).shar = tmp.shar; (*k).priv = 0;
}

//
// End connection
void client_end(int s) {
  close(s);
}

//
// End connection
void server_end(int s) {
  close(s);
}

//
// Server listener
int server_listen(const int s) {
  int c = 1, ns[sizeof(int)], len = sizeof(sock_in);
  sock *cli = NULL;

  listen(s, 10);
  while (c >= 1) {
    c = accept(s, (sock*)&cli, (socklen_t*)&len);
    pthread_t thrd;
    *ns = c;
    if (pthread_create(&thrd, NULL, handler_server, (void*)ns) < 0) return -1;
    pthread_join(thrd, NULL);
    // TODO: Only if handshake OK, we create SSL thread
    if (pthread_create(&thrd, NULL, handler_ssl_server, (void*)ns) < 0) return -1;
    pthread_join(thrd, NULL);
  }
  return c;
}

int client_connect(const int s) {
  pthread_t thrd;
  if (pthread_create(&thrd, NULL, handler_client, (void*)&s) < 0) return -1;
  pthread_join(thrd, NULL);
  // TODO: Only if handshake OK, we create SSL thread
  if (pthread_create(&thrd, NULL, handler_client_ssl, (void*)&s) < 0) return -1;
  pthread_join(thrd, NULL);
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

//
// Generate a keypair & shared key then print it (test / demo)
int generate_cryptokeys_local(void) {
  head h1 = *set_header(&h1, u64rnd(), u64rnd());
  head h2 = *set_header(&h2, u64rnd(), u64rnd());
  u64 c = 123456, d = 1, e = 1;
  cryptokey k1 = generate_cryptokeys(&h1), k2 = generate_cryptokeys(&h2);

  generate_shared_cryptokey_client(&k1, &k2, &h1);
  generate_shared_cryptokey_server(&k1, &k2, &h1);
  printf("Alice public & private key: 0x%.16llx 0x%.16llx\n", k1.publ, k1.priv);
  printf("Bobs public & private key: 0x%.16llx 0x%.16llx\n", k2.publ, k2.priv);
  printf("Alice & Bobs shared key: 0x%.16llx 0x%.16llx\n", k1.shar, k2.shar);
  handler_cryptography(c, k1, &d);
  handler_cryptography(d, k2, &e);
  printf("Before:  0x%.16llx\nEncrypt: 0x%.16llx\nDecrypt: 0x%.16llx\n",c,d,e);
  assert(c == e);
  return c == e;
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
// Random rotate
static u64 prng_rotate(u64 x, u64 k) {
  return (x << k) | (x >> (32 - k));
}

//
// Random next
static u64 prng_next(void) {
  u64 e = prng_ctx.a - prng_rotate(prng_ctx.b, 27);

  prng_ctx.a = prng_ctx.b ^ prng_rotate(prng_ctx.c, 17);
  prng_ctx.b = prng_ctx.c + prng_ctx.d;
  prng_ctx.c = prng_ctx.d + e; prng_ctx.d = e + prng_ctx.a;
  return prng_ctx.d;
}

//
// Random init
static void prng_init(u64 seed) {
  prng_ctx.a = 0xea7f00d1;

  prng_ctx.b = prng_ctx.c = prng_ctx.d = seed;
  for (u64 i = 0; i < 31; ++i) (void)prng_next();
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

//
// "Randomizer"
int lrand(uint8_t h[], u64 k[]) {
  prng_init((u64)(0xea1 ^ 0x31ee7 ^ 42) | 0xe1ee77ee | 31337);
  for (int i = 0; i < BYTES; ++i) {
    h[i] = (uint8_t)prng_next(); k[i] = prng_next();
  }
  return 1;
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
