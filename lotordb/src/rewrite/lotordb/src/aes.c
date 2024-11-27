#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "aes.h"

static inline unsigned long long to_bin(const char *s) {
  unsigned long long i = 0;
  while (*s) {
    i <<= 1;
    i += *s++ - '0';
  }
  return i;
}

/*
// https://www.rfc-editor.org/rfc/rfc8452.html
// pseudocode

   func derive_keys(key_generating_key, nonce) {
     message_authentication_key =
         AES(key = key_generating_key,
             block = little_endian_uint32(0) ++ nonce)[:8] ++
         AES(key = key_generating_key,
             block = little_endian_uint32(1) ++ nonce)[:8]
     message_encryption_key =
         AES(key = key_generating_key,
             block = little_endian_uint32(2) ++ nonce)[:8] ++
         AES(key = key_generating_key,
             block = little_endian_uint32(3) ++ nonce)[:8]

     if bytelen(key_generating_key) == 32 {
       message_encryption_key ++=
           AES(key = key_generating_key,
               block = little_endian_uint32(4) ++ nonce)[:8] ++
           AES(key = key_generating_key,
               block = little_endian_uint32(5) ++ nonce)[:8]
     }

     return message_authentication_key, message_encryption_key
   }

   func right_pad_to_multiple_of_16_bytes(input) {
     while (bytelen(input) % 16 != 0) {
       input = input ++ "\x00"
     }
     return input
   }

   func AES_CTR(key, initial_counter_block, in) {
     block = initial_counter_block

     output = ""
     while bytelen(in) > 0 {
       keystream_block = AES(key = key, block = block)
       block[0:4] = little_endian_uint32(
           read_little_endian_uint32(block[0:4]) + 1)

       todo = min(bytelen(in), bytelen(keystream_block)
       for j = 0; j < todo; j++ {
         output = output ++ (keystream_block[j] ^ in[j])
       }

       in = in[todo:]
     }

     return output
   }

   func encrypt(key_generating_key,
                nonce,
                plaintext,
                additional_data) {
     if bytelen(plaintext) > 2^36 {
       fail()
     }
     if bytelen(additional_data) > 2^36 {
       fail()
     }

     message_encryption_key, message_authentication_key =
         derive_keys(key_generating_key, nonce)


     length_block =
         little_endian_uint64(bytelen(additional_data) * 8) ++
         little_endian_uint64(bytelen(plaintext) * 8)
     padded_plaintext = right_pad_to_multiple_of_16_bytes(plaintext)
     padded_ad = right_pad_to_multiple_of_16_bytes(additional_data)
     S_s = POLYVAL(key = message_authentication_key,
                   input = padded_ad ++ padded_plaintext ++
                           length_block)
     for i = 0; i < 12; i++ {
       S_s[i] ^= nonce[i]
     }
     S_s[15] &= 0x7f
     tag = AES(key = message_encryption_key, block = S_s)

     counter_block = tag
     counter_block[15] |= 0x80
     return AES_CTR(key = message_encryption_key,
                    initial_counter_block = counter_block,
                    in = plaintext) ++
            tag
   }

   func decrypt(key_generating_key,
                nonce,
                ciphertext,
                additional_data) {
     if bytelen(ciphertext) < 16 || bytelen(ciphertext) > 2^36 + 16 {
       fail()
     }
     if bytelen(additional_data) > 2^36 {
       fail()
     }

     message_encryption_key, message_authentication_key =
         derive_keys(key_generating_key, nonce)

     tag = ciphertext[bytelen(ciphertext)-16:]

     counter_block = tag
     counter_block[15] |= 0x80
     plaintext = AES_CTR(key = message_encryption_key,
                         initial_counter_block = counter_block,
                         in = ciphertext[:bytelen(ciphertext)-16])

     length_block =
         little_endian_uint64(bytelen(additional_data) * 8) ++
         little_endian_uint64(bytelen(plaintext) * 8)
     padded_plaintext = right_pad_to_multiple_of_16_bytes(plaintext)
     padded_ad = right_pad_to_multiple_of_16_bytes(additional_data)
     S_s = POLYVAL(key = message_authentication_key,
                   input = padded_ad ++ padded_plaintext ++
                           length_block)
     for i = 0; i < 12; i++ {
       S_s[i] ^= nonce[i]
     }
     S_s[15] &= 0x7f
     expected_tag = AES(key = message_encryption_key, block = S_s)

     xor_sum = 0
     for i := 0; i < bytelen(expected_tag); i++ {
       xor_sum |= expected_tag[i] ^ tag[i]
     }

     if xor_sum != 0 {
       fail()
     }

     return plaintext
   }
*/

uint8_t *right_pad_to_multiple_of_16_bytes(uint8_t *input, int len) {
  while(len++ % 16 != 0) {
    input[len] = 0;
  }
  return input;
}

#define AES(x, y) 0 // TODO: fix : https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf // also return length
#define POLYVAL(x, y) 0 // TODO: fix

uint32_t little_endian_uint32(uint8_t x) {
  x = ((x << 8) & 0xFF00FF00) | ((x >> 8) & 0xFF00FF);
  return (x << 16) | (x >> 16);
}

u64 little_endian_uint64(u64 x) {
  x = ((x << 8) & 0xFF00FF00FF00FF00ULL) | ((x >> 8) & 0x00FF00FF00FF00FFULL);
  x = ((x << 16) & 0xFFFF0000FFFF0000ULL) | ((x >> 16) & 0x0000FFFF0000FFFFULL);
  return (x << 32) | (x >> 32);
}

uint32_t read_little_endian_uint32(uint8_t *x) {
  uint32_t result;
  memcpy(&result, x, sizeof(result));
  return result;
}

// return message_authentication_key, message_encryption_key
void derive_keys(uint8_t *key_generating_key, uint8_t *nonce, uint8_t **message_authentication_key, uint8_t **message_encryption_key) {
  message_authentication_key =
    AES(key_generating_key, little_endian_uint32(0) + nonce) +   // take first 8
    AES(key_generating_key, little_endian_uint32(1) + nonce);    // take first 8
  message_encryption_key =
    AES(key_generating_key, little_endian_uint32(2) + nonce) +   // take first 8
    AES(key_generating_key, little_endian_uint32(3) + nonce);    // take first 8

  //if bytelen(key_generating_key) == 32 {
  // always assume keylength == 32
  message_encryption_key +=
    AES(key_generating_key, little_endian_uint32(4) + nonce) + // take first 8
    AES(key_generating_key, little_endian_uint32(5) + nonce);  // take first 8
  //}
}

uint8_t *AES_CTR(uint8_t *key, uint8_t *initial_counter_block, uint8_t *in, u64 inlen) {
  //block = initial_counter_block;
  uint8_t *block = malloc(32);
  memcpy(block, initial_counter_block, 32);
  uint8_t *output = NULL;
  while (inlen > 0) {
    uint8_t *keystream_block = AES(key, block);
    block[0] = read_little_endian_uint32(&block[0]);
    block[1] = read_little_endian_uint32(&block[1]);
    block[2] = read_little_endian_uint32(&block[2]);
    block[3] = read_little_endian_uint32(&block[3]);

    block[0] = little_endian_uint32(*(&block[0]+1));
    block[1] = little_endian_uint32(*(&block[1]+1));
    block[2] = little_endian_uint32(*(&block[2]+1));
    block[3] = little_endian_uint32(*(&block[3]+1));

    u64 todo = inlen;//min(inlen, key_generating_key);//min(bytelen(in), bytelen(keystream_block));
    for (int j = 0; j < todo; j++) {
      output = output + (keystream_block[j] ^ in[j]);
    }
    memcpy(in, &in, todo);
  }
  free(block);
  return output;
}

uint8_t *encrypt(uint8_t *key_generating_key, uint8_t *nonce, uint8_t *plaintext, u64 plaintextlen, uint8_t *additional_data, u64 additional_datalen) {
  if (plaintextlen > 68719476736 || additional_datalen > 68719476736) { // 2 ^ 36 == 68719476736
    printf("Input text / data to long, exiting\n");
    exit(0);
  }
  uint8_t **message_authentication_key, **message_encryption_key;
  derive_keys(key_generating_key, nonce, &message_encryption_key, &message_authentication_key);
  u64 length_block = little_endian_uint64(additional_datalen * 8) + little_endian_uint64(plaintextlen * 8);
  uint8_t *padded_plaintext = right_pad_to_multiple_of_16_bytes(plaintext, plaintextlen);
  uint8_t *padded_ad = right_pad_to_multiple_of_16_bytes(additional_data, additional_datalen);
  u64 *S_s = POLYVAL(message_authentication_key, padded_ad + padded_plaintext + length_block);
  for (int i = 0; i < 12; i++) {
    S_s[i] ^= nonce[i];
  }
  S_s[15] &= 0x7f;
  uint8_t *tag, *counter_block;
  memcpy(tag, AES(message_encryption_key, S_s), 16); // TODO: fix correct length
  //ounter_block = tag;
  counter_block[15] |= 0x80;
  uint8_t *ret;
  memcpy(ret, AES_CTR(message_encryption_key, counter_block, plaintext, plaintextlen), 32); // TODO: fix correct length
  memcpy(ret + 32, tag, 16); // TODO: fix correct length
  return ret;
  //return AES_CTR(message_encryption_key, counter_block, plaintext, plaintextlen) + tag;
}

uint8_t *decrypt(uint8_t *key_generating_key,uint8_t *nonce, uint8_t *ciphertext, u64 ciphertextlen, uint8_t *additional_data, u64 additional_datalen) {
  if (ciphertextlen < 16 || ciphertextlen > (68719476736 + 16) || additional_datalen > 68719476736) { // 2 ^ 36 == 68719476736
    printf("Cipher text / data to long, exiting\n");
    exit(0);
  }
  uint8_t **message_authentication_key, **message_encryption_key;
  derive_keys(key_generating_key, nonce, &message_encryption_key, &message_authentication_key);
  //uint8_t *tag = ciphertext[bytelen(ciphertext)-16:];
  uint8_t *tag = NULL, *counter_block, *ct;
  memcpy(tag, ciphertext, ciphertextlen-16);
  //counter_block = tag;
  memcpy(counter_block, tag, sizeof(tag));
  counter_block[15] |= 0x80;
  memcpy(ct, ciphertext, ciphertextlen-16); // take end of ciphertext, from ciphertextlen - 16
  uint8_t *plaintext = AES_CTR(message_encryption_key, counter_block, ct, ciphertextlen - 16);//ciphertext[:bytelen(ciphertext)-16]);
  u64 plaintextlen = ciphertextlen; // TODO: incorrect
  u64 length_block = little_endian_uint64(additional_datalen * 8) + little_endian_uint64(plaintextlen * 8);
  uint8_t *padded_plaintext = right_pad_to_multiple_of_16_bytes(plaintext, plaintextlen);
  uint8_t *padded_ad = right_pad_to_multiple_of_16_bytes(additional_data, additional_datalen);
  u64 *S_s = POLYVAL(message_authentication_key, padded_ad + padded_plaintext + length_block);
  for (int i = 0; i < 12; i++) {
    S_s[i] ^= nonce[i];
  }
  S_s[15] &= 0x7f;
  uint8_t *expected_tag = AES(message_encryption_key, S_s);
  u64 expected_taglen = 32; // TOOD: fix
  u64 xor_sum = 0;
  for (int i = 0; i < expected_taglen; i++) {
    xor_sum |= expected_tag[i] ^ tag[i];
  }
  if (xor_sum != 0) {
    exit(0);
  }
  return plaintext;
}

//
// hmm where did i get these from? what paper?!?!
void multiply(u64 R[]) {
  R[25] = 0x06;
  for (int i = 7; i >= 0; --i) {
    for (int j = 3; j >= 0; --j) {
      if (R[16+j] == 1) {
        R[0] = R[0] + R[25];
        for (int k = 0; k < 4; ++k) {
          R[8+j+k] = R[8+j+k] ^ R[20+k];
        }
      } else {
        for (int k = 0; k < 4; ++k) {
          R[24] = R[24] ^ R[20+k];
        }
      }
    }
    for (int k = 15; k > 6; k--) {
      R[k] = R[k] << 1;
    }
  }
}

void modreduce(u64 K[]) {
  u64 A = (K[31] & BIN(1)) << 6, B = (K[31] & BIN(10)) << 5, C = (K[31] & BIN(1111111));
  K[16] = K[16] ^ ((A ^ B ^ C) << 1);
  K[8] = K[8] ^ K[24] ^ ((K[23] << 7) | K[24] >> 1) ^ ((K[23] << 6) | K[24] >> 2) ^ ((K[23] << 1) | K[24] >> 7);
  K[0] = K[0] ^ K[16] ^ (K[16] >> 2) ^ (K[16] >> 7);
  for (int i = 1; i < 8; ++i) {
    K[i+8] = K[i+8] ^ K[i+24] ^ ((K[i+23] << 7) | K[i+24] >> 1) ^ ((K[i+23] << 6) | K[i+24] >> 2) ^ ((K[i+23] << 1) | K[i+24] >> 7);
    K[i] = K[i] ^ K[i+16] ^ ((K[i+15] << 7) | K[i+16] >> 1) ^ ((K[i+15] << 6) | K[i+16] >> 2) ^ ((K[i+15] << 1) | K[i+16] >> 7);
  }
}

// translated from asm
void st(u64 Z) {
  u64 K0=0, K1=0, K2=0, K3=0, K4=0, K5=0, K6=0, K7=0; //
  u64 C4=0, C5=0, C6=0, C7=0; //

  // ROUND32 // 1
  u64 C0 = Z+0, C1 = Z+1, C2 = Z+2, C3 = Z+3; // 2-5
  C4 = C4 ^ C0; // 6
  C5 = C5 ^ C1; // 7
  C6 = C6 ^ C2; // 8
  C7 = C7 ^ C3; // 9

  C0 = K0; // 10
  C2 = K2; // 11
  C4 = K4; // 12
  C6 = K6; // 13

  // ROUND32 // 14
  C4 = Z + 12; // 15
  C5 = Z + 13; // 16
  C6 = Z + 14; // 17
  C7 = Z + 15; // 18

  C0 = C0 ^ K0; // 19
  C1 = C1 ^ K1; // 20
  C2 = C2 ^ K2; // 21
  C3 = C3 ^ K3; // 22

  C4 = C4 ^ C0; // 23
  C5 = C5 ^ C1; // 24
  C6 = C6 ^ C2; // 25
  C7 = C7 ^ C3; // 26

  C0 = C0 ^ K4; // 27
  C1 = C1 ^ K5; // 28
  C2 = C2 ^ K6; // 29
  C3 = C3 ^ K7; // 30

  // ROUND32 // 31
  K0 = K0 ^ C0; // 32
  K1 = K1 ^ C1; // 33
  K2 = K2 ^ C2; // 34
  K3 = K3 ^ C3; // 35

  K4 = K4 ^ C4; // 36
  K5 = K5 ^ C5; // 37
  K6 = K6 ^ C6; // 38
  K7 = K7 ^ C7; // 39

  C0 = Z + 4; // 40
  C1 = Z + 5; // 41
  C2 = Z + 6; // 42
  C3 = Z + 7; // 43
  C4 = Z + 8; // 44
  C5 = Z + 9; // 45
  C6 = Z + 10; // 46
  C7 = Z + 11; // 47
}
