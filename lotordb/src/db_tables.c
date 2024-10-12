#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "db_tables.h"
#include "ciphers.h"
// TODO: add check that f is not NULL == couldnt open file
// TODO: this feels stupid. read the index file several times.
//       is worse to have whole indexfile in memory(probably, especially when it scales)
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
      // printf("SEP data %s %s", argv[0], argv[1]);
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
  uint8_t iv1[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  uint8_t key1[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
  aes_gcm_decrypt(outdec, index, sizeof(index), key1, 32, iv1, 32);
}

void table_encrypt_indexfile(tbls *t, uint8_t *index) {
  FILE *f = fopen((*t).i.path, "w");
  uint8_t outenc[256];
  uint8_t iv1[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  uint8_t key1[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
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
  uint8_t iv1[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  uint8_t key1[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
  aes_gcm_decrypt(outdec, data, length, key1, 32, iv1, 32);
}

void table_encrypt_datafile(tbls *t, uint8_t *data) {
  FILE *f = fopen((*t).i.path, "w");
  uint8_t outenc[256];
  uint8_t iv1[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  uint8_t key1[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
  aes_gcm_encrypt(outenc, data, 32, key1, 32, iv1, 32);
  fwrite(outenc, sizeof(uint8_t), sizeof(outenc), f);
  fclose(f);
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

/*
// C
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

struct Data {
  uint8_t encrypted[512];
};

struct Person {
  long long int packedheader;
  char name[20];
  int age;
  float height;
};

void getperson(struct Person *p2, struct Data *dd) {
  // TODO: decrypt binary data
  memcpy(&p2->packedheader, dd->encrypted, sizeof(long long int));
  memcpy(&p2->name, dd->encrypted + sizeof(long long int), 20 * sizeof(char));
  memcpy(&p2->age, dd->encrypted + sizeof(long long int) + 20 * sizeof(char), sizeof(int));
  memcpy(&p2->height, dd->encrypted + sizeof(long long int) + 20 * sizeof(char) + sizeof(int), sizeof(float));
}

int main(void) {
  struct Data *dd = malloc(sizeof (struct Data)), d, d2;
  struct Person person, p2;
  FILE *ptr, *write_ptr;
  write_ptr = fopen("cbin.b", "ab");
  for (int i = 0; i < 20; i++) {
    strncpy(person.name, "John", 20);
    person.packedheader = 1234567890;
    person.age = 32 + i;
    person.height = 6.0;
    // "convert" Person to "binary" data
    memcpy(d.encrypted, (uint8_t*)&person, sizeof(struct Person));
    // TODO: encrypt binary data
    // write encrypted binary data to file
    fwrite(&d, sizeof(struct Data), 1, write_ptr);
  }
  fclose(write_ptr);
  // find size of file
  ptr = fopen("cbin.b", "rb");
  fseek(ptr, 0, SEEK_END);
  int size = ftell(ptr);
  int chunk = size / sizeof(struct Data);
  printf("size of the file: %d and number of chunks: %d\n", size, chunk);
  // read 11th entry
  fseek(ptr, 0, SEEK_SET);
  fseek(ptr, 0, sizeof(struct Data) * 10);
  fread(dd, sizeof(struct Data), 1, ptr);
  getperson(&p2, dd);
  printf("Person 11: %llu %s %d %f\n", p2.packedheader, p2.name, p2.age, p2.height);
  // TODO: only get headers in the future
  fseek(ptr, 0, SEEK_SET);
  printf("searching for age 42: ");
  for (int i = 0; i < (size / sizeof(struct Data)); i++) {
    fread(dd, sizeof(struct Data), 1, ptr);
    getperson(&p2, dd);
    if (p2.age == 42) {
      printf("found\n");
      break;
    }
  }
  fclose(ptr);
}
*/
