CC:=gcc -O3 -Wall -pedantic -std=c99
BUILD:=../.build

all: tests

tests:
	${CC} -o ${BUILD}/tests tests.c ${BUILD}/hash.o ${BUILD}/aes.o
	${BUILD}/tests
#${BUILD}/keys_client.o ${BUILD}/tables_client.o \
${BUILD}/crypto_client.o ${BUILD}/tables_server.o ${BUILD}/keys_server.o ${BUILD}/crypto_server.o ${BUILD}/db_keystore.o \
${BUILD}/hash.o ${BUILD}/hash_tooling.o ${BUILD}/db_tables.o ${BUILD}/ciphers.o ${BUILD}/keys.o -lpthread -lm
