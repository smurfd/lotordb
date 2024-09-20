// Auth: smurfd 2024 https://github.com/mko-x/SharedAES-GCM // ----------------- taken from this, and massaged; 2 spacs indent; 150 width           //
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "ciphers_aes_gcm.h"

static box fsb;
static box rsb;
static uint32_t RCON[10]; // AES round constants

// AES
static uint8_t aes_set_encryption_key(aes_context *c, const uint8_t *key, uint8_t kz) {
  uint32_t *RK = c->rk, tmp;
  for (uint32_t i = 0; i < (kz >> 2); i++) GET_UINT32_LE(RK[i], key, i << 2);
  for(uint32_t i = 0; i < 7; i++, RK += 8) {
    ROUND(tmp, fsb.b, RK[7] >> 8, RK[7] >> 16, RK[7] >> 24, RK[7] >> 0, 0, 8, 16, 24);
    RK[8] = RK[0] ^ RCON[i] ^ tmp;
    RK[9]  = RK[1] ^ RK[8];
    RK[10] = RK[2] ^ RK[9];
    RK[11] = RK[3] ^ RK[10];
    ROUND(tmp, fsb.b, RK[11] >> 0, RK[11] >> 8, RK[11] >> 16, RK[11] >> 24, 0, 8, 16, 24);
    RK[12] = RK[4] ^ tmp;
    RK[13] = RK[5] ^ RK[12];
    RK[14] = RK[6] ^ RK[13];
    RK[15] = RK[7] ^ RK[14];
  }
  return 0;
}

static uint8_t aes_set_decryption_key(aes_context *c, const uint8_t *key, uint8_t keysize) {
  uint32_t *SK, *RK = c->rk, i, St;
  aes_context cc;
  cc.rounds = c->rounds;
  cc.rk = cc.buf;
  if (aes_set_encryption_key(&cc, key, keysize) != 0) return 1;
  SK = cc.rk + cc.rounds * 4;
  CPY128(RK, SK);
  for (i = c->rounds - 1, SK -= 8; i > 0; i--, SK -= 8) {
    St = *SK;
    *RK++ = rsb.T0[fsb.b[(St) & 0xFF]] ^ rsb.T1[fsb.b[(St >> 8) & 0xFF]] ^ rsb.T2[fsb.b[(St >> 16) & 0xFF]] ^ rsb.T3[fsb.b[(St >> 24) & 0xFF]]; St++;
    *RK++ = rsb.T0[fsb.b[(St) & 0xFF]] ^ rsb.T1[fsb.b[(St >> 8) & 0xFF]] ^ rsb.T2[fsb.b[(St >> 16) & 0xFF]] ^ rsb.T3[fsb.b[(St >> 24) & 0xFF]]; St++;
    *RK++ = rsb.T0[fsb.b[(St) & 0xFF]] ^ rsb.T1[fsb.b[(St >> 8) & 0xFF]] ^ rsb.T2[fsb.b[(St >> 16) & 0xFF]] ^ rsb.T3[fsb.b[(St >> 24) & 0xFF]]; St++;
    *RK++ = rsb.T0[fsb.b[(St) & 0xFF]] ^ rsb.T1[fsb.b[(St >> 8) & 0xFF]] ^ rsb.T2[fsb.b[(St >> 16) & 0xFF]] ^ rsb.T3[fsb.b[(St >> 24) & 0xFF]]; St++;
  }
  CPY128(RK, SK);
  memset(&cc, 0, sizeof(aes_context));
  return 0;
}

int aes_setkey(aes_context *c, uint8_t mode, const uint8_t *key, uint8_t keysize) {
  c->mode = mode;
  c->rk = c->buf;
  c->rounds = 14;
  if (mode == 0) return aes_set_decryption_key(c, key, keysize);
  else return aes_set_encryption_key(c, key, keysize);
}

int aes_cipher_encrypt(aes_context *c, const uint8_t in[16], uint8_t out[16]) {
  uint32_t *RK, X0, X1, X2, X3, Y0, Y1, Y2, Y3, tmp0, tmp1, tmp2, tmp3;
  RK = c->rk;
  GET_UINT32_LE(X0, in,  0); X0 ^= *RK++;
  GET_UINT32_LE(X1, in,  4); X1 ^= *RK++;
  GET_UINT32_LE(X2, in,  8); X2 ^= *RK++;
  GET_UINT32_LE(X3, in, 12); X3 ^= *RK++;
  for (int i = (c->rounds >> 1) - 1; i > 0; i--) {
    AES_FROUND(Y0, Y1, Y2, Y3, X0, X1, X2, X3);
    AES_FROUND(X0, X1, X2, X3, Y0, Y1, Y2, Y3);
  }
  AES_FROUND(Y0, Y1, Y2, Y3, X0, X1, X2, X3);
  ROUND(tmp0, fsb.b, Y0 >> 0, Y1 >> 8, Y2 >> 16, Y3 >> 24, 0, 8, 16, 24);
  ROUND(tmp1, fsb.b, Y1 >> 0, Y2 >> 8, Y3 >> 16, Y0 >> 24, 0, 8, 16, 24);
  ROUND(tmp2, fsb.b, Y2 >> 0, Y3 >> 8, Y0 >> 16, Y1 >> 24, 0, 8, 16, 24);
  ROUND(tmp3, fsb.b, Y3 >> 0, Y0 >> 8, Y1 >> 16, Y2 >> 24, 0, 8, 16, 24);
  PUT_UINT32_LE(*RK++ ^ tmp0, out,  0);
  PUT_UINT32_LE(*RK++ ^ tmp1, out,  4);
  PUT_UINT32_LE(*RK++ ^ tmp2, out,  8);
  PUT_UINT32_LE(*RK++ ^ tmp3, out, 12);
  return 0;
}

int aes_cipher_decrypt(aes_context *c, const uint8_t in[16], uint8_t out[16]) {
  uint32_t *RK, X0, X1, X2, X3, Y0, Y1, Y2, Y3, tmp0, tmp1, tmp2, tmp3;
  RK = c->rk;
  GET_UINT32_LE(X0, in,  0); X0 ^= *RK++;
  GET_UINT32_LE(X1, in,  4); X1 ^= *RK++;
  GET_UINT32_LE(X2, in,  8); X2 ^= *RK++;
  GET_UINT32_LE(X3, in, 12); X3 ^= *RK++;
  for (int i = (c->rounds >> 1) - 1; i > 0; i--) {
    AES_RROUND(Y0, Y1, Y2, Y3, X0, X1, X2, X3);
    AES_RROUND(X0, X1, X2, X3, Y0, Y1, Y2, Y3);
  }
  AES_RROUND(Y0, Y1, Y2, Y3, X0, X1, X2, X3);
  ROUND(tmp0, rsb.b, Y0 >> 0, Y3 >> 8, Y2 >> 16, Y1 >> 24, 0, 8, 16, 24);
  ROUND(tmp1, rsb.b, Y1 >> 0, Y0 >> 8, Y3 >> 16, Y2 >> 24, 0, 8, 16, 24);
  ROUND(tmp2, rsb.b, Y2 >> 0, Y1 >> 8, Y0 >> 16, Y3 >> 24, 0, 8, 16, 24);
  ROUND(tmp3, rsb.b, Y3 >> 0, Y2 >> 8, Y1 >> 16, Y0 >> 24, 0, 8, 16, 24);
  PUT_UINT32_LE(*RK++ ^ tmp0, out,  0);
  PUT_UINT32_LE(*RK++ ^ tmp1, out,  4);
  PUT_UINT32_LE(*RK++ ^ tmp2, out,  8);
  PUT_UINT32_LE(*RK++ ^ tmp3, out, 12);
  return 0;
}

// GCM
static void gcm_mult(gcm_context *ctx, const uint8_t x[16], uint8_t out[16]) {
  u64 zh = ctx->HH[(uint8_t)(x[15] & 0x0F)], zl = ctx->HL[(uint8_t)(x[15] & 0x0F)]; // lo, lo
  uint8_t r = (uint8_t)(zl & 0x0F);
  zl = (zh << 60) | (zl >> 4);
  zh = (zh >> 4);
  zh ^= (u64)last4[r] << 48;
  zh ^= ctx->HH[(uint8_t)(x[15] >> 4)]; // hi
  zl ^= ctx->HL[(uint8_t)(x[15] >> 4)]; // hi
  for (int i = 14; i >= 0; i--) {
    r = (uint8_t)(zl & 0x0F);
    zl = (zh << 60) | (zl >> 4);
    zh = (zh >> 4);
    zh ^= (u64)last4[r] << 48;
    zh ^= ctx->HH[(uint8_t)(x[i] & 0x0F)]; // lo
    zl ^= ctx->HL[(uint8_t)(x[i] & 0x0F)]; // lo

    r = (uint8_t)(zl & 0x0F);
    zl = (zh << 60) | (zl >> 4);
    zh = (zh >> 4);
    zh ^= (u64)last4[r] << 48;
    zh ^= ctx->HH[(uint8_t)(x[i] >> 4)]; // hi
    zl ^= ctx->HL[(uint8_t)(x[i] >> 4)]; // hi
  }
  PUT_UINT32_BE(zh >> 32, out, 0);
  PUT_UINT32_BE(zh, out, 4);
  PUT_UINT32_BE(zl >> 32, out, 8);
  PUT_UINT32_BE(zl, out, 12);
}

// keysize in bytes (must be 16, 24, 32 for 128, 192 or 256-bit keys respectively)
int gcm_setkey(gcm_context *ctx, const uint8_t *key, const uint32_t keysize) {
  u64 hi, lo;
  uint8_t h[16];
  memset(ctx, 0, sizeof(gcm_context));
  memset(h, 0, 16);
  if (aes_setkey(&ctx->aes_ctx, 1, key, keysize) != 0) return 1;
  if (aes_cipher_encrypt(&ctx->aes_ctx, h, h) != 0) return 1;
  GET_UINT32_BE(hi, h, 0); // pack h as two 64-bit ints, big-endian
  GET_UINT32_BE(lo, h, 4);
  u64 vh = (u64)hi << 32 | lo;
  GET_UINT32_BE(hi, h, 8);
  GET_UINT32_BE(lo, h, 12);
  u64 vl = (u64)hi << 32 | lo;
  ctx->HL[8] = vl; // 8 = 1000 corresponds to 1 in GF(2^128)
  ctx->HH[8] = vh;
  ctx->HH[0] = 0; // 0 corresponds to 0 in GF(2^128)
  ctx->HL[0] = 0;
  for(int i = 4; i > 0; i >>= 1) {
    uint32_t T = (uint32_t)(vl & 1) * 0xe1000000U;
    vl = (vh << 63) | (vl >> 1);
    vh = (vh >> 1) ^ ((u64)T << 32);
    ctx->HL[i] = vl;
    ctx->HH[i] = vh;
  }
  for (int i = 2; i < 16; i <<= 1) {
    u64 *HiL = ctx->HL + i, *HiH = ctx->HH + i;
    vh = *HiH;
    vl = *HiL;
    for(int j = 1; j < i; j++) {
      HiH[j] = vh ^ ctx->HH[j];
      HiL[j] = vl ^ ctx->HL[j];
    }
  }
  return 0;
}

int gcm_start(gcm_context *ctx, int mode, const uint8_t *iv, size_t iv_len, const uint8_t *add, size_t add_len) {
  uint8_t work_buf[16], ret;
  const uint8_t *p = iv;
  memset(ctx->y, 0, sizeof(ctx->y));
  memset(ctx->buf, 0, sizeof(ctx->buf));
  ctx->len = 0;
  ctx->add_len = 0;
  ctx->mode = mode;
  ctx->aes_ctx.mode = 1; // encrypt
  memset(work_buf, 0, 16);
  PUT_UINT32_BE(iv_len * 8, work_buf, 12); // place the IV into buffer
  XORARR(ctx->y, p, 16);
  gcm_mult(ctx, ctx->y, ctx->y);
  p += 16;
  XORARR(ctx->y, p, 16);
  gcm_mult(ctx, ctx->y, ctx->y);
  XORARR(ctx->y, work_buf, 16);
  gcm_mult(ctx, ctx->y, ctx->y);
  if ((ret = aes_cipher_encrypt(&ctx->aes_ctx, ctx->y, ctx->ectr)) != 0) return ret;
  ctx->add_len = add_len;
  p = add;
  return 0;
}

int gcm_update_encrypt(gcm_context *ctx, size_t length, const uint8_t *input, uint8_t *output) {
  uint8_t ectr[16], ret;
  size_t use_len = 16;
  ctx->len += length;
  while(length > 0) {
    for (size_t i = 16; i > 12; i--) if (++ctx->y[i - 1] != 0) break;
    if ((ret = aes_cipher_encrypt(&ctx->aes_ctx, ctx->y, ectr)) != 0) return ret;
    for (size_t i = 0; i < use_len; i++) {
      output[i] = (uint8_t)(ectr[i] ^ input[i]);
      ctx->buf[i] ^= output[i];
    }
    gcm_mult(ctx, ctx->buf, ctx->buf); // perform a GHASH operation
    length -= use_len; // drop the remaining byte count to process
    input  += use_len; // bump our input pointer forward
    output += use_len; // bump our output pointer forward
  }
  return 0;
}

int gcm_update_decrypt(gcm_context *ctx, size_t length, const uint8_t *input, uint8_t *output) {
  uint8_t ectr[16], ret;
  size_t use_len = 16;
  ctx->len += length;
  while(length > 0) {
    for (size_t i = 16; i > 12; i--) if (++ctx->y[i - 1] != 0) break;
    if ((ret = aes_cipher_decrypt(&ctx->aes_ctx, ctx->y, ectr)) != 0) return ret;
    for (size_t i = 0; i < use_len; i++) {
      ctx->buf[i] ^= input[i];
      output[i] = (uint8_t)(ectr[i] ^ input[i]);
    }
    gcm_mult(ctx, ctx->buf, ctx->buf); // perform a GHASH operation
    length -= use_len; // drop the remaining byte count to process
    input  += use_len; // bump our input pointer forward
    output += use_len; // bump our output pointer forward
  }
  return 0;
}

int gcm_crypt_and_tag(gcm_context *ctx, int mode, const uint8_t *iv, size_t iv_len, const uint8_t *add, size_t add_len, const uint8_t *input,
    uint8_t *output, size_t length, uint8_t *tag, size_t tag_len) {
  gcm_start(ctx, mode, iv, iv_len, add, add_len);
  if (mode == 0) gcm_update_decrypt(ctx, length, input, output);
  else if (mode == 1) gcm_update_encrypt(ctx, length, input, output);
  gcm_finish(ctx, tag, tag_len);
  return 0;
}

int gcm_finish(gcm_context *ctx, uint8_t *tag, size_t tag_len) {
  u64 orig_len = ctx->len * 8, orig_add_len = ctx->add_len * 8;
  uint8_t work_buf[16];
  if(tag_len != 0) memcpy(tag, ctx->ectr, tag_len);
  if(orig_len || orig_add_len) {
    memset(work_buf, 0, 16);
    PUT_UINT32_BE((orig_add_len >> 32), work_buf, 0);
    PUT_UINT32_BE((orig_add_len), work_buf, 4);
    PUT_UINT32_BE((orig_len >> 32), work_buf, 8);
    PUT_UINT32_BE((orig_len), work_buf, 12);
    for(size_t i = 0; i < 16; i++) ctx->buf[i] ^= work_buf[i];
    gcm_mult(ctx, ctx->buf, ctx->buf);
    for(size_t i = 0; i < tag_len; i++) tag[i] ^= ctx->buf[i];
  }
  return 0;
}

void gcm_zero_ctx(gcm_context *ctx) {
  memset(ctx, 0, sizeof(gcm_context));
}

// AES GCM
int aes_gcm_encrypt(uint8_t *out, const uint8_t *in, int in_len, const uint8_t *key, const size_t key_len, const uint8_t *iv, const size_t iv_len) {
  uint8_t tag_buf[16]; 
  size_t tl = 0;
  gcm_context c;
  gcm_setkey(&c, key, (const uint32_t)key_len);
  gcm_crypt_and_tag(&c, ENCRYPT, iv, iv_len, NULL, 0, in, out, in_len, tag_buf, tl);
  gcm_zero_ctx(&c);
  return 0;
}

int aes_gcm_decrypt(uint8_t *out, const uint8_t *in, int in_len, const uint8_t *key, const size_t key_len, const uint8_t *iv, const size_t iv_len) {
  uint8_t tag_buf[16]; 
  size_t tl = 0;
  gcm_context c;
  gcm_setkey(&c, key, (const uint32_t)key_len);
  gcm_crypt_and_tag(&c, DECRYPT, iv, iv_len, NULL, 0, in, out, in_len, tag_buf, tl);
  gcm_zero_ctx(&c);
  return 0;
}

// AES GCM
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
// https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
// http://csrc.nist.gov/groups/STM/cavp/documents/mac/gcmtestvectors.zip

// https://en.wikipedia.org/wiki/AES-GCM-SIV
// https://www.rfc-editor.org/rfc/rfc8452.html

// https://github.com/mko-x/SharedAES-GCM // ----------------- taken from this, and massaged
