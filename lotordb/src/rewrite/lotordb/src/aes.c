#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "aes.h"

// TODO: Figure out later how to generate these
static const uint8_t sbox[256] = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

static const uint8_t reverse_sbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};
uint8_t state[4][4] = {0};

// TODO: Fix always have 1st argument as return value if needed
static inline unsigned long long str_to_bin(const char *s) {
  unsigned long long i = 0;
  while (*s) {
    i <<= 1;
    i += *s++ - '0';
  }
  return i;
}

static inline void long_to_bin(u64 num, uint8_t *ret) {
  uint8_t i = 0;
  while (num != 0) {
    ret[i++] = num % 2;
    num /= 2;
  }
}

inline static u64 bin_to_long(uint8_t *bin) {
  uint8_t num[128] = {0};
  u64 dec = 0, base = 1;
  memcpy(num, bin, 128 * sizeof(uint8_t));
  for (int i = 127; i >= 0; i--) {
    if (num[i] == 1) dec += base;
    base = base * 2;
  }
  return dec;
}

/*
static inline void long_to_bin(unsigned long long num, uint8_t *ret) {
  uint8_t i = 0;
  while (num != 0) {
    ret[i++] = num % 2;
    num /= 2;
  }
}

inline static unsigned long long bin_to_long(uint8_t *bin) {
  uint8_t num[128] = {0};
  unsigned long long dec = 0, base = 1;
  memcpy(num, bin, 128 * sizeof(uint8_t));
  for (int i = 127; i >= 0; i--) {
    if (num[i] == 1) dec += base;
    base = base * 2;
  }
  return dec;
}

*/

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

/*
// good read:
//   https://engineering.purdue.edu/kak/compsec/NewLectures/Lecture8.pdf
//   https://www.cse.wustl.edu/~jain/cse571-11/ftp/l_05aes.pdf
//   https://ie.u-ryukyu.ac.jp/~wada/design04/spec_e.html
//   https://blog.0x7d0.dev/education/how-aes-is-implemented/


// AES Pseudocode https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
// 128, 192, 256 (Nk = 4, 6, 8)
func CIPHER(in, Nr, w) {
  state = in
  state = ADDROUNDKEY(state, w[0..3])
  for round from 1 to Nr - 1 do
    state = SUBBYTES(state)
    state = SHIFTROWS(state)
    state = MIXCOLUMNS(state)
    satet = ADDROUNDKEY(state, w[4*round..4*round+3])
  end for
  state = SUBBYTES(state)
  state = SHIFTROWS(state)
  state = ADDROUNDKEY(state, w[4*Nr..4*Nr+3])
  return state
}

func ADDROUNDKEY(state, key) {
  // memcpy to key so it contains right frame of key
  for i from 0 to 4 do
    for j from 0 to 4 do
      state[j][i] ^= key[(i * 4) + j] 
}

func SUBBYTES(state) {
  for i from 0 to 4 do
    for j from 0 to 4 do
      state[j][i] = SBOX[state[j][i]]
}

func INVSUBBYTES(state) {
  for i from 0 to 4 do
    for j from 0 to 4 do
      state[j][i] = SBOXINV[state[j][i]]
}

func SHIFTROWS(state) {
  // skip first row
  // rotate rows to left, number of steps = row
  temp = state[0][1]
  state[0][1] = state[1][1]
  state[1][1] = state[2][1]
  state[2][1] = state[3][1]
  state[3][1] = temp

  temp = state[0][2]
  state[0][2] = state[2][2]
  state[2][2] = temp
  temp = state[1][2]
  state[1][2] = state[3][2]
  state[3][2] = temp

  temp = state[0][3]
  state[0][3] = state[3][3]
  state[3][3] = state[2][3]
  state[2][3] = state[1][3]
  state[1][3] = temp
}

func INVSHIFTROWS(state) {
  // skip first row
  // rotate rows to right, number of steps = row
  temp = state[3][1]
  state[3][1] = state[2][1]
  state[2][1] = state[1][1]
  state[1][1] = state[0][1]
  state[0][1] = temp

  temp = state[0][2]
  state[0][2] = state[2][2]
  state[2][2] = temp
  temp = state[1][2]
  state[1][2] = state[3][2]
  state[3][2] = temp

  temp = state[0][3]
  state[0][3] = state[1][3]
  state[1][3] = state[2][3]
  state[2][3] = state[3][3]
  state[3][3] = temp
}

func times(x) {
  return ((x<<1) ^ (((x>>7) & 1) * 0x1b))
}

func MIXCOLUMNS(state) {
  for i from 0 to 4 do
    state0   = state[i][0];
    statecol = state[i][0] ^ state[i][1] ^ state[i][2] ^ state[i][3]
    statesav = times(state[i][0] ^ state[i][1])
    state[i][0] ^= statesav ^ statecol

    statesav = times(state[i][1] ^ state[i][2])
    state[i][1] ^= statesav ^ statecol

    statesav = times(state[i][2] ^ state[i][3])
    state[i][2] ^= statesav ^ statecol

    statesav = times(state[i][3] ^ state0)
    state[i][3] ^= statesav ^ statecol
}

func KEYEXPANSION(key) {
  i = 0
  while i <= Nk - 1 do
    w[i] = key[4*i..4*i+3]
    i += 1
  end while
  while i <= 4 * Nr + 3 do
    temp = w[i - 1]
    if i mod Nk == 0 {
      temp = SUBWORD(ROTWORD(temp)) ^ Rcon[i/Nk]
    } else if Nk > 6 and i mod Nk == 4 {
      temp = SUBWORD(temp)
    }
    w[i] = w[i - Nk] ^ temp
    i += 1
  end while
  return w
}

func INVCIPHER(in, Nr, w) {
  state = in
  state = ADDROUNDKEY(state, w[4*Nr..4*Nr+3])
  for round = Nr - 1 d >= 1 {
    state = INVSHIFTROWS(state)
    state = INVSUBBYTES(state)
    state = ADDROUNDKEY(state, w[4*round..4*round+3])
    state = INVMIXCOLUMNS(state)
  }
  state = INVSHIFTROWS(state)
  state = INVSUBBYTES(state)
  state = ADDROUNDKEY(state, w[0..3])
  return state
}

func EQINVCIPHER(in, Nr, dw) {
  state = in
  state = ADDROUNDKEY(state, dw[4*Nr..4*Nr+3])
  for round = Nr - 1 d >= 1 {
    state = INVSUBBYTES(state)
    state = INVSHIFTROWS(state)
    state = INVMIXCOLUMNS(state)
    state = ADDROUNDKEY(state, dw[4*round..4*round+3])
  }
  state = INVSUBBYTES(state)
  state = INVSHIFTROWS(state)
  state = ADDROUNDKEY(state, dw[0..3])
  return state
}

func KEYEXPANSIONEIC(key) {
  i = 0
  while i <= Nk - 1 do
    w[i] = key[4*i..4*i+3]
    dw[i] = w[i]
    i += 1
  end while
  while i <= 4 * Nr + 3 do
    temp = w[i - 1]
    if i mod Nk == 0 {
      temp = SUBWORD(ROTWORD(temp)) ^ Rcon[i/Nk]
    } else if Nk > 6 and i mod Nk == 4 {
      temp = SUBWORD(temp)
    }
    w[i] = w[i - Nk] ^ temp
    dw[i] = w[i]
    i += 1
  end while
  for round = 1 <= Nr - 1 {
    i = 4 * round
    dw[i..i+3] = INVMIXCOLUMNS(dw[i..i+3])
  }
  return dw
}

// https://github.com/m3y54m/aes-in-c?tab=readme-ov-file#the-rijndael-key-schedule
// https://en.wikipedia.org/wiki/Rijndael_S-box
#define ROTL8(x,shift) ((uint8_t) ((x) << (shift)) | ((x) >> (8 - (shift))))

void initialize_aes_sbox(uint8_t sbox[256]) {
  uint8_t p = 1, q = 1;
  
  // loop invariant: p * q == 1 in the Galois field
  do {
    // multiply p by 3
    p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0);

    // divide q by 3 (equals multiplication by 0xf6)
    q ^= q << 1;
    q ^= q << 2;
    q ^= q << 4;
    q ^= q & 0x80 ? 0x09 : 0;

    // compute the affine transformation
    uint8_t xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4);

    sbox[p] = xformed ^ 0x63;
  } while (p != 1);

  // 0 is a special case since it has no inverse
  sbox[0] = 0x63;
}


static void ShiftRows(AES_BYTE *b, int Nb, char *t)
{
  AES_BYTE *temp = alloca(AES_WS*Nb);
  int i, j;

  memcpy(temp, b, AES_WS*Nb);

  for (i = 0; i < AES_WS; i++) {
    for (j = 0; j < Nb; j++) {
      b[j*AES_WS + i] = temp[(j + t[i] + Nb) % Nb * AES_WS + i];
    }
  }
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
//#define POLYVAL() ByteReverse(GHASH(ByteReverse(H) * x, ByteReverse(X_1), ByteReverse(X_2), ...))
//  returns Its result is S_s, where S is defined by the iteration S_0 = 0; S_j = dot(S_{j-1} + X_j, H), for j = 1..s.
//  POLYVAL takes a field element, H, and a series of field elements X_1, ..., X_s.  Its result is S_s, where S is defined by the iteration S_0 = 0; S_j = dot(S_{j-1} + X_j, H), for j = 1..s.
// https://csrc.nist.gov/csrc/media/Events/2023/third-workshop-on-block-cipher-modes-of-operation/documents/accepted-papers/Galois%20Counter%20Mode%20with%20Secure%20Short%20Tags.pdf
// https://medium.com/codex/aes-how-the-most-advanced-encryption-actually-works-b6341c44edb9
// https://networkbuilders.intel.com/docs/networkbuilders/advanced-encryption-standard-galois-counter-mode-optimized-ghash-function-technology-guide-1693300747.pdf

// https://datatracker.ietf.org/doc/html/rfc8452#appendix-A

// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
// 6.3 multiply
uint8_t *mul(uint8_t *BITX, uint8_t *BITY) {
  uint8_t Z[128] = {0}, V[128], R[128] = {0}, BITV[128];//, BITX[128], BITY[128];
  u64 RDEC = 0;
  //LONG2BIN(X, BITX);
  //LONG2BIN(Y, BITY);
  R[0] = 1; R[1] = 1; R[2] = 1; R[7] = 1; // TODO: fix nicer
  //V[0] = Y;
  memcpy(V, BITY, 128);
  RDEC = BIN2LONG(R); // R = 11100001 || 0^120
  for (int i = 0; i < 128; i++) {
    if (BITX[i] == 0) Z[i+1] = Z[i];
    if (BITX[i] == 1) Z[i+1] = Z[i] ^ V[i];
    LONG2BIN(V[i], BITV); // Take LSB1 of V[i] below
    if (BITV[127] == 0) V[i+1] = V[i] >> 1;
    if (BITV[127] == 1) V[i+1] = (V[i] >> 1) ^ RDEC;
  }
  return Z;
}

void xorarr(uint8_t *X, uint8_t *Y, uint8_t *r) {
  for (int i = 1; i < 128; i++) {
    r[i] = X[i] ^ Y[i];
  }
}

// 6.4 for GHASH
// In effect, the GHASH function calculates: (X1*Hm) ^ (X2*Hm-1) ^ ... ^ (Xm-1*H2) ^ (Xm*H)
uint8_t **ghash(uint8_t **X, uint8_t **H, int m) { // X must be 128*m length
  uint8_t Y[128][128] = {0}, RET[128][128]; // TODO: we assume m=128
  for (int i = 1; i < m; i++) {
    // LONG2BIN(X[i])? LONG2BIN(H[m-(i-i)])?
    memcpy(&RET[i], mul(X[i], H[m-(i-1)]), 128);
  }
  for (int i = 1; i < m; i++) {
    xorarr(RET[i-1], RET[i], &Y[i]);
  }
  return Y;
}

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
  uint8_t *tmp1, *tmp2, AESSIZE = 8;
  memcpy(tmp1, AES(key_generating_key, little_endian_uint32(0) + nonce), 8 * AESSIZE);
  memcpy(tmp2, AES(key_generating_key, little_endian_uint32(1) + nonce), 8 * AESSIZE);
  memcpy(message_authentication_key + (0 * AESSIZE), tmp1, 8 * AESSIZE);
  memcpy(message_authentication_key + (8 * AESSIZE), tmp2, 8 * AESSIZE);

  memcpy(tmp1, AES(key_generating_key, little_endian_uint32(2) + nonce), 8 * AESSIZE);
  memcpy(tmp2, AES(key_generating_key, little_endian_uint32(3) + nonce), 8 * AESSIZE);
  memcpy(message_encryption_key + (0 * AESSIZE), tmp1, 8 * AESSIZE);
  memcpy(message_encryption_key + (8 * AESSIZE), tmp2, 8 * AESSIZE);

  // always assume keylength == 32, if not, check length of key_generating_key == 32
  memcpy(tmp1, AES(key_generating_key, little_endian_uint32(4) + nonce), 8 * AESSIZE);
  memcpy(tmp2, AES(key_generating_key, little_endian_uint32(5) + nonce), 8 * AESSIZE);
  memcpy(message_encryption_key + (16 * AESSIZE), tmp1, 8 * AESSIZE);
  memcpy(message_encryption_key + (24 * AESSIZE), tmp2, 8 * AESSIZE);
}

uint8_t *AES_CTR(uint8_t *key, uint8_t *initial_counter_block, uint8_t *in, u64 inlen) {
  //block = initial_counter_block;
  uint8_t todo, *block = malloc(32);
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

    u64 keystream_blocklen = 16; // TODO: fix correct length
    if (inlen < keystream_blocklen) todo = inlen;
    else todo = keystream_blocklen;//min(inlen, key_generating_key);//min(bytelen(in), bytelen(keystream_block));
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
