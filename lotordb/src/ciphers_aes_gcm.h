// Auth: smurfd 2024
#ifndef CIPHERS_AES_GCM_H
#define CIPHERS_AES_GCM_H 1
#include <inttypes.h>
#include <string.h>
#include <stdint.h>

#define ENCRYPT 1
#define DECRYPT 0
#define GCM_AUTH_FAILURE 0x55555555
#define U32 uint32_t

typedef uint8_t uchar;
typedef uint32_t uint;

typedef struct {
  int mode;           // 1 for Encryption, 0 for Decryption
  int rounds;         // keysize-based rounds count
  uint32_t *rk;       // pointer to current round key
  uint32_t buf[68];   // key expansion buffer
} aes_context;

typedef struct {
  int mode;               // cipher direction: encrypt/decrypt
  uint64_t len;           // cipher data length processed so far
  uint64_t add_len;       // total add data length
  uint64_t HL[16];        // precalculated lo-half HTable
  uint64_t HH[16];        // precalculated hi-half HTable
  uchar base_ectr[16];    // first counter-mode cipher output for tag
  uchar y[16];            // the current cipher-input IV|Counter value
  uchar buf[16];          // buf working value
  aes_context aes_ctx;    // cipher context used
} gcm_context;

typedef struct {
  uchar b[256]; // substitution box
  uint32_t T0[256], T1[256], T2[256], T3[256]; // key schedule assembly tables
} box;

static box fsb;
static box rsb;

static uint32_t RCON[10];   // AES round constants
static const uint64_t last4[16] = {0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0, 0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0};
#define GET_UINT32_LE(n,b,i) {(n) = ((uint32_t)(b)[(i)]) | ((uint32_t)(b)[(i) + 1] << 8) | ((uint32_t)(b)[(i) + 2] << 16) | ((uint32_t)(b)[(i) + 3] << 24);}
#define PUT_UINT32_LE(n,b,i) {(b)[(i)] = (uchar)((n)); (b)[(i) + 1] = (uchar)((n) >> 8); (b)[(i) + 2] = (uchar)((n) >> 16); (b)[(i) + 3] = (uchar)((n) >> 24);}
#define GET_UINT32_BE(n,b,i) {(n) = ((uint32_t)(b)[(i)] << 24) | ((uint32_t) (b)[(i) + 1] << 16) | ((uint32_t) (b)[(i) + 2] <<  8) | ((uint32_t)(b)[(i) + 3]);}
#define PUT_UINT32_BE(n,b,i) {(b)[(i)] = (uchar)((n) >> 24); (b)[(i) + 1] = (uchar)((n) >> 16); (b)[(i) + 2] = (uchar)((n) >> 8); (b)[(i) + 3] = (uchar)((n));}

#define AES_FROUND(X0,X1,X2,X3,Y0,Y1,Y2,Y3) { \
  X0 = *RK++ ^ fsb.T0[(Y0) & 0xFF] ^ fsb.T1[(Y1 >> 8) & 0xFF] ^ fsb.T2[(Y2 >> 16) & 0xFF] ^ fsb.T3[(Y3 >> 24) & 0xFF]; \
  X1 = *RK++ ^ fsb.T0[(Y1) & 0xFF] ^ fsb.T1[(Y2 >> 8) & 0xFF] ^ fsb.T2[(Y3 >> 16) & 0xFF] ^ fsb.T3[(Y0 >> 24) & 0xFF]; \
  X2 = *RK++ ^ fsb.T0[(Y2) & 0xFF] ^ fsb.T1[(Y3 >> 8) & 0xFF] ^ fsb.T2[(Y0 >> 16) & 0xFF] ^ fsb.T3[(Y1 >> 24) & 0xFF]; \
  X3 = *RK++ ^ fsb.T0[(Y3) & 0xFF] ^ fsb.T1[(Y0 >> 8) & 0xFF] ^ fsb.T2[(Y1 >> 16) & 0xFF] ^ fsb.T3[(Y2 >> 24) & 0xFF]; \
}

#define AES_RROUND(X0,X1,X2,X3,Y0,Y1,Y2,Y3) { \
  X0 = *RK++ ^ rsb.T0[(Y0) & 0xFF] ^ rsb.T1[(Y3 >> 8) & 0xFF] ^ rsb.T2[(Y2 >> 16) & 0xFF] ^ rsb.T3[(Y1 >> 24) & 0xFF]; \
  X1 = *RK++ ^ rsb.T0[(Y1) & 0xFF] ^ rsb.T1[(Y0 >> 8) & 0xFF] ^ rsb.T2[(Y3 >> 16) & 0xFF] ^ rsb.T3[(Y2 >> 24) & 0xFF]; \
  X2 = *RK++ ^ rsb.T0[(Y2) & 0xFF] ^ rsb.T1[(Y1 >> 8) & 0xFF] ^ rsb.T2[(Y0 >> 16) & 0xFF] ^ rsb.T3[(Y3 >> 24) & 0xFF]; \
  X3 = *RK++ ^ rsb.T0[(Y3) & 0xFF] ^ rsb.T1[(Y2 >> 8) & 0xFF] ^ rsb.T2[(Y1 >> 16) & 0xFF] ^ rsb.T3[(Y0 >> 24) & 0xFF]; \
}

#define ROTL8(x) ((x << 8) & 0xFFFFFFFF) | (x >> 24)
#define XTIME(x) ((x << 1) ^ ((x & 0x80) ? 0x1B : 0x00))
#define MUL(x,y) ((x && y) ? pow[(log[x]+log[y]) % 255] : 0)
#define MIX(x,y) {y = ((y << 1) | (y >> 7)) & 0xFF; x ^= y;}
#define CPY128(RK,SK) {*RK++ = *SK++; *RK++ = *SK++; *RK++ = *SK++; *RK++ = *SK++;}
#define ENCDECKEY(sb, RK, x) ({U32 r; r = (((U32)sb[(RK[x] >> 8) & 0xFF]) ^ ((U32)sb[(RK[x] >> 16) & 0xFF] << 8) ^ ((U32)sb[(RK[x] >> 24) & 0xFF] << 16) ^ ((U32)sb[(RK[x]) & 0xFF] << 24)); r;})
#define ENCDEC(S, A, B, C, D) ({U32 r; r = ((U32)S[A & 0xFF]) ^ ((U32)S[B >> 8 & 0xFF] << 8) ^ ((U32)S[C >> 16 & 0xFF] << 16) ^ ((U32)S[D >> 24 & 0xFF] << 24); r;})

// AES
void aes_init_keygen_tables(void);
int aes_setkey(aes_context *c, uint8_t mode, const uint8_t *key, uint8_t kz);
int aes_cipher(aes_context *ctx, const uchar input[16], uchar output[16]); // 128-bit in/out block

// GCM
int gcm_initialize(void);
int gcm_setkey(gcm_context *ctx, const uchar *key, const uint keysize); // keysize in bytes (must be 16, 24, 32 for 128, 192 or 256-bit keys)
int gcm_crypt_and_tag(gcm_context *ctx, int mode, const uchar *iv, size_t iv_len, const uchar *add, size_t add_len, const uchar *input, uchar *output, size_t length, uchar *tag, size_t tag_len);
int gcm_auth_decrypt(gcm_context *ctx, const uchar *iv, size_t iv_len, const uchar *add, size_t add_len, const uchar *input, uchar *output, size_t length, const uchar *tag, size_t tag_len);
int gcm_start(gcm_context *ctx, int mode, const uchar *iv, size_t iv_len, const uchar *add, size_t add_len);
int gcm_update(gcm_context *ctx, size_t length, const uchar *input, uchar *output);
int gcm_finish(gcm_context *ctx, uchar *tag, size_t tag_len);
void gcm_zero_ctx(gcm_context *ctx);

// AES GCM
int aes_gcm_encrypt(uchar* output, const uchar* input, int input_length, const uchar* key, const size_t key_len, const uchar * iv, const size_t iv_len);
int aes_gcm_decrypt(uchar* output, const uchar* input, int input_length, const uchar* key, const size_t key_len, const uchar * iv, const size_t iv_len);

// AES GCM Test functions
int verify_gcm(uchar *vd);
int load_file_into_ram(const char *filename, uchar **result);
#endif
