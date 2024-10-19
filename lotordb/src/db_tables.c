#include <sys/socket.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "db_tables.h"
#include "ciphers.h"
// TODO: add check that f is not NULL == couldnt open file
// TODO: this feels stupid. read the index file several times.
//       is worse to have whole indexfile in memory(probably, especially when it scales)

// TODO: Randomize these to file for program to use
static uint8_t iv1[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,\
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, key1[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b\
  , 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

int static table_check_unique_index(char path[256], char unique_id[256]) {
  FILE *f = fopen(path, "r");
  size_t len = 512;
  char *line = NULL;
  ssize_t read;
  if (f == NULL) {printf("ROHRO %s\n", path);return 1;}
  while((read = getline(&line, &len, f)) >= 0) {
    char **ap, *argv[4];
    for (ap = argv; (*ap = strsep(&line, "|")) != NULL;) {
      if (++ap >= &argv[4]) break;
    }
    printf("arg %s %s\n", argv[1], unique_id);
    if (strcmp(argv[1], unique_id) == 0) {
      printf("Not unique\n");
      fclose(f);
      return -1;
    }
  }
  fclose(f);
  return 0;
}

// TODO: write and read one line per entry that is encrypted with separators. Both index and data
void table_read_index(tbls *t, char path[256], char unique_id[256]) {
  FILE *f = fopen(path, "r");
  size_t len = 512;
  char *line = NULL;
  ssize_t read;
  while((read = getline(&line, &len, f)) != -1) {
    char **ap, *argv[4];
    for (ap = argv; (*ap = strsep(&line, "|")) != NULL;) {
      if (++ap >= &argv[4]) break;
    }
    if (strcmp(argv[1], unique_id) == 0) {
      printf("Not unique\n");
    } else {
      set_table_index(t, (u64)atoi(argv[0]), argv[1], (u64)atoi(argv[2]), argv[3]);
      printf("SEP index %s %s %s %s", argv[0], argv[1], argv[2], argv[3]);
    }
  }
  fclose(f);
}

int table_read_data(tbls *t) {
  FILE *f = fopen((*t).i.path, "r");
  size_t len = 512;
  char *line = NULL;
  ssize_t read;
  if (f == NULL) {printf("No data file\n"); return 1;}
  while((read = getline(&line, &len, f)) != -1) {
    printf("Line: %s\n", line);
    if (strstr(line, (*t).i.unique_id) != NULL) {
      char **ap, *argv[2];
      for (ap = argv; (*ap = strsep(&line, "|")) != NULL;) {
        if (++ap >= &argv[2]) break;
      }
    }
  }
  fclose(f);
  return 0;
}

int table_write_index(tbls *t, char path[256]) {
  if (table_check_unique_index(path, (*t).i.unique_id) >= 0) {
    FILE *f = fopen(path, "a");
    printf("writing index: %llu %s %llu %s\n", (*t).i.index, (*t).i.unique_id, (*t).i.length, (*t).i.path);
    fprintf(f, "%llu|%s|%llu|%s\n", (*t).i.index, (*t).i.unique_id, (*t).i.length, (*t).i.path);
    fclose(f);
  } else {
    printf("unique_id is not unique, will not write to index file\n");
    return -1;
  }
  return 0;
}

int table_write_data(tbls *t) {
  FILE *f = fopen((*t).i.path, "a");
  fprintf(f, "%s|%s\n", (*t).d.unique_id, (*t).d.data);
  fclose(f);
  return 0;
}

void set_table_data(tbls *t, char unique_id[256], char data[4096]) {
  strncpy((*t).d.unique_id, unique_id, 255);
  strncpy((*t).d.data, data, 4095);
}

void set_table_index(tbls *t, u64 index, char unique_id[256], u64 length, char path[256]) {
  strncpy((*t).i.unique_id, unique_id, 255);
  strncpy((*t).i.path, path, 255);
  (*t).i.index = index;
  (*t).i.length = length;
}

void table_send(const int s, tbls *t) {
  send(s, t, sizeof(struct tbls), 0);
}

void table_recv(const int s, tbls *t) {
  recv(s, t, sizeof(struct tbls), 0);
}

void table_decrypt_indexfile(tbls *t) {
  FILE *f = fopen((*t).i.path, "r");
  u64 length = fseek(f, 0, SEEK_END);
  fseek(f, 0, SEEK_SET);
  uint8_t *index;
  fread(&index, sizeof(uint8_t), length, f);
  fclose(f);
  uint8_t outdec[256];
  aes_gcm_decrypt(outdec, index, sizeof(index), key1, 32, iv1, 32);
}

void table_encrypt_indexfile(tbls *t, uint8_t *index) {
  FILE *f = fopen((*t).i.path, "w");
  uint8_t outenc[256];
  aes_gcm_encrypt(outenc, index, 32, key1, 32, iv1, 32);
  fwrite(outenc, sizeof(uint8_t), sizeof(outenc), f);
  fclose(f);
}

void table_decrypt_datafile(tbls *t) {
  FILE *f = fopen((*t).i.path, "r");
  u64 length = fseek(f, 0, SEEK_END);
  fseek(f, 0, SEEK_SET);
  uint8_t *data;
  fread(&data, sizeof(uint8_t), length, f);
  fclose(f);
  uint8_t outdec[256];
  aes_gcm_decrypt(outdec, data, length, key1, 32, iv1, 32);
}

void table_encrypt_datafile(tbls *t, uint8_t *data) {
  FILE *f = fopen((*t).i.path, "w");
  uint8_t outenc[256];
  aes_gcm_encrypt(outenc, data, 32, key1, 32, iv1, 32);
  fwrite(outenc, sizeof(uint8_t), sizeof(outenc), f);
  fclose(f);
}

static void getperson(struct Person *person, struct Data *datatmp) {
  memcpy(&person->packedheader, datatmp->encrypted, sizeof(u64));
  memcpy(&person->name, datatmp->encrypted + sizeof(u64), 20 * sizeof(char));
  memcpy(&person->age, datatmp->encrypted + sizeof(u64) + 20 * sizeof(char), sizeof(u64));
  memcpy(&person->height, datatmp->encrypted + sizeof(u64) + 20 * sizeof(char) + sizeof(u64), sizeof(float));
}

static void getheaders(u64 *header, struct Data *data) {
  for (u64 i = 0; i < DBLENGTH; i++) {
    memcpy(&header[i], data[i].encrypted, sizeof(u64));
  }
}

int table_tmp(void) {
  struct Data *datatmp = malloc(sizeof (struct Data)), *dataall = malloc(sizeof(struct Data) * DBLENGTH);
  u64 *header = malloc(sizeof(u64) * DBLENGTH);
  char fn[] = {".build/cbin.b"};
  FILE *ptr, *write_ptr = fopen(fn, "ab");
  struct Person person;
  bool found = false;
  for (u64 i = 0; i < DBLENGTH; i++) {
    strncpy(person.name, "John", 20);
    person.packedheader = 1234567890 + i;
    person.age = 32 + i;
    person.height = 6.0;
    // "convert" Person to "binary" data
    memset(datatmp->encrypted, (uint8_t)' ', 512); // "PAD" the data
    memcpy(datatmp->encrypted, (uint8_t*)&person, sizeof(struct Person));
    aes_gcm_encrypt(datatmp->encrypted, datatmp->encrypted, 512, key1, 32, iv1, 32);
    fwrite(datatmp->encrypted, sizeof(struct Data), 1, write_ptr);
  }
  fclose(write_ptr);
  // find size of file
  ptr = fopen(fn, "rb");
  fseek(ptr, 0, SEEK_END);
  u64 size = ftell(ptr), chunk = size / sizeof(struct Data);
  printf("size of the file: %llu and number of chunks: %llu\n", size, chunk);
  for (u64 j = 0; j < (size / sizeof(struct Data)) / DBLENGTH; j++) {
    fseek(ptr, j * (DBLENGTH * sizeof(struct Data) + 1), SEEK_SET);
    fread(dataall, sizeof(struct Data) * DBLENGTH, 1, ptr);
    printf("searching for age 666: ");
    for (u64 i = 0; i < DBLENGTH; i++) {
      memcpy(datatmp, dataall + i, sizeof(struct Data));
      aes_gcm_decrypt(datatmp->encrypted, datatmp->encrypted, 512, key1, 32, iv1, 32);
      getheaders(header, dataall + i);
      getperson(&person, datatmp);
      if (person.age == 666) {
        printf("found\n");
        found = true;
        break;
      }
    }
    if (found) break;
  }
  fclose(ptr);
  if (datatmp != NULL) free(datatmp);
  if (dataall != NULL) free(dataall);
  if (header != NULL) free(header);
  if (found) return 1;
  return 0;
}

// Write binary data to file
// Read specific "struct" from file
// TODO: For now, assume same size of data for each entry in the database
//       Dont use packed header at first, that might store number of segments of data later, and size of data to be read.
/*
# Python
import struct, os
with open('bin.b', 'ab') as f:
  for i in range(20):
    packedheader = 123456789  # len = 27
    name = 'John'.ljust(20)[:20]  # len = 20
    age = 32 + i  # len = 6
    height = 6.0  # len = 8
    data = packedheader.to_bytes(packedheader.bit_length() + 7 // 8) + name.encode() + age.to_bytes(age.bit_length() + 7 // 8) + bytes(struct.pack('d', height)) + b' ' * (512-(27+6+8+20))
    # TODO: encrypt data before write, data = 512 bytes
    f.write(data)

with open('bin.b', 'rb') as f:
  len = 512  # 27+6+8+20
  fs = os.path.getsize('bin.b')
  chunk = fs // len
  print(f'size of the file: {fs} and number of chunks: {fs // len}')
  f.seek(len * 10, 0)
  data = f.read(len)
  # Decrypt data
  pkh, name, age, h = data[0:27], data[27:47], data[47:53], data[53:61]
  print(f'11th entry: {name} {int.from_bytes(age, 'big')} {struct.unpack('d', h)[0]} {int.from_bytes(pkh, 'big')}')
  print('Searching for age 42: ', end='')
  f.seek(0, 0)
  for i in range(fs // len):
    data = f.read(len)
    pkh, name, age, h = data[0:27], data[27:47], data[47:53], data[53:61]
    if int.from_bytes(age, 'big') == 42:
      print('found')
      exit()
*/
