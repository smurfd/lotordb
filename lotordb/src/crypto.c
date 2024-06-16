// Auth: smurfd, 2023 More reading & Borrow/Stolen parts read at the bottom of the file; 2 spacs indent; 120 width    //
#include <math.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "crypto.h"
#include "defs.h"

//
// Receive key (clears private key if we receive it for some reason)
static void recv_key(int s, head *h, key *k) {
  recv(s, h, sizeof(head), 0);
  recv(s, k, sizeof(key), 0);
  (*k).priv = 0;
}

//
// Send key
static void snd_key(int s, head *h, key *k) {
  // This to ensure not to send the private key
  key kk;

  kk.publ = (*k).publ;
  kk.shar = (*k).shar;
  kk.priv = 0;
  send(s, h, sizeof(head), 0);
  send(s, &kk, sizeof(key), 0);
}

//static void clear_key(key *k) {
static key *clear_key(key *k) {
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
  key k2 = *clear_key(&k2);
  head h = *set_header(&h, u64rnd(), u64rnd());
  receive_data(sock, &dat, &h, BLOCK - 1);
  for (u64 i = 0; i < 10; i++) cryption(dat[i], k2, &cd[i]);
  printf("ssl 0x%.16llx 0x%.16llx 0x%.16llx\n", dat[0], dat[1], dat[2]);
  pthread_exit(NULL);
  return 0;
}

//
// Server handler
static void *handler_server(void *sdesc) {
  u64 dat[BLOCK], cd[BLOCK], g1 = u64rnd(), p1 = u64rnd();
  int sock = *(int*)sdesc;

  if (sock == -1) return (void*) - 1;
  key k1 = generate_keys(g1, p1), k2 = *clear_key(&k2);
  head h = *set_header(&h, g1, p1);
  // Send and receive stuff
  if (h.len > BLOCK) return (void*) - 1;
  send_key(sock, &h, &k1);
  receive_key(sock, &h, &k2);
  generate_shared_key_server(&k1, &k2, h.p);
  printf("share : 0x%.16llx\n", k2.shar);
  pthread_exit(NULL);
  return 0;
}

u64 u64rnd() {
  int r[5], f = open("/dev/urandom", O_RDONLY);
  read(f, &r, sizeof r);
  close(f);
  return (r[0] & 0x7fffffffffffffff) << 48 ^ (r[1] & 0x7fffffffffffffff) << 35 ^\
         (r[2] & 0x7fffffffffffffff) << 22 ^ (r[3] & 0x7fffffffffffffff) << 9 ^ (r[4] & 0x7fffffffffffffff) >> 4;
}

//
// Encrypt and decrypt data with shared key
void cryption(u64 data, key k, u64 *enc) {
  (*enc) = data ^ k.shar;
}

//
// Communication init
sock_in communication_init(const char *host, const char *port) {
  sock_in adr;

  memset(&adr, '\0', sizeof(adr));
  adr.sin_family = AF_INET;
  adr.sin_port = atoi(port);
  adr.sin_addr.s_addr = inet_addr(host);
  return adr;
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

void send_data(const int s, void* data, head *h, u64 len) {
  send(s, h, sizeof(head), 0);
  send(s, data, sizeof(u64)*len, 0);
}

void receive_data(const int s, void* data, head *h, u64 len) {
  recv(s, h, sizeof(head), 0);
  recv(s, data, sizeof(u64) * len, 0);
}

void send_key(int s, head *h, key *k) {
  snd_key(s, h, k);
}

void receive_key(int s, head *h, key *k) {
  key tmp;

  // This to ensure if we receive a private key we clear it
  recv_key(s, h, &tmp);
  (*k).publ = tmp.publ; (*k).shar = tmp.shar; (*k).priv = 0;
}

//
// End connection
void crypto_end(int s) {close(s);}

//
// Server listener
int server_listen(const int s, sock *cli) {
  int c = 1, ns[sizeof(int)], len = sizeof(sock_in);

  listen(s, 3);
  while (c >= 1) {
    c = accept(s, (sock*)&cli, (socklen_t*)&len);
    pthread_t thrd;
    *ns = c;
    if (pthread_create(&thrd, NULL, handler_server, (void*)ns) < 0) return -1;
    pthread_join(thrd, NULL);
    // TODO: Only if handshake OK
    if (pthread_create(&thrd, NULL, handler_ssl_server, (void*)ns) < 0) return -1;
    pthread_join(thrd, NULL);
  }
  return c;
}

//
// Generate the server shared key
void generate_shared_key_server(key *k1, key *k2, u64 p) {
  (*k2).shar = p % (int64_t)pow((*k2).publ, (*k1).priv);
}

//
// Generate the client shared key
void generate_shared_key_client(key *k1, key *k2, u64 p) {
  (*k1).shar = p % (int64_t)pow((*k1).publ, (*k2).priv);
}

//
// Generate a public and private keypair
//key gen_keys(u64 g, u64 p) {
key generate_keys(u64 g, u64 p) {
  key k;

  k.priv = u64rnd();
  k.publ = (int64_t)pow(g, k.priv) % p;
  return k;
}

//
// Generate a keypair & shared key then print it (test / demo)
//int gen_keys_local(void) {
int generate_keys_local(void) {
  u64 g1 = u64rnd(), g2 = u64rnd(), p1 = u64rnd(), p2 = u64rnd(), c = 123456, d = 1, e = 1;
  key k1 = generate_keys(g1, p1), k2 = generate_keys(g2, p2);

  generate_shared_key_client(&k1, &k2, p1);
  generate_shared_key_server(&k1, &k2, p1);
  printf("Alice public & private key: 0x%.16llx 0x%.16llx\n", k1.publ, k1.priv);
  printf("Bobs public & private key: 0x%.16llx 0x%.16llx\n", k2.publ, k2.priv);
  printf("Alice & Bobs shared key: 0x%.16llx 0x%.16llx\n", k1.shar, k2.shar);
  cryption(c, k1, &d);
  cryption(d, k2, &e);
  printf("Before:  0x%.16llx\nEncrypt: 0x%.16llx\nDecrypt: 0x%.16llx\n",c,d,e);
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
