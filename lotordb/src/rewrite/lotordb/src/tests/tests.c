#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../hash.h"
#include "../aes.h"

void printing(char str[], u64 r[]) {
  printf("%s ", str);
  for (int i = 0; i < 32; i++) printf("%llu ", r[i]);
  printf("\n");
}

void printing_1matrix(char var[], int start, int end, u64 r[]) {
  printf("%s: ", var);
  for (int i = start; i >= end; i--) printf("%llu ", r[i]);
  printf("\n");
}

int main(void) {
  u64 r[32];
  char hash[256];
  clock_t t = clock();
  hash_new(hash, (uint8_t*)"some string to hash");
  printf("hash: %s\n", hash);
  for (int i = 0; i < 32; i++) r[i] = i;
  printing_1matrix("A", 19, 16, r);
  printing_1matrix("B", 23, 20, r);
  printing("before multiply: ", r);
  multiply(r);
  printing("after multiply: ", r);
  printing_1matrix("C", 15, 9, r);
  modreduce(r);
  printing("after modreduce: ", r);
  for (int i = 0; i < 32; i++) st(r[i]);
  printing("after st: ", r);
  double time_taken = ((double)clock() - t) / CLOCKS_PER_SEC; // in seconds
  printf("took %f seconds to execute\n\n", time_taken);
  printf("OK\n");
}