CL:=gcc -O3 -Wall -pedantic -std=c99
CC:=gcc -O3 -Wall -pedantic -std=c99
BUILD:=../.build

all: tests

tests:
	${CL} -o ${BUILD}/tests tests.c ${BUILD}/crypto.o ${BUILD}/crypto_client.o ${BUILD}/crypto_server.o \
${BUILD}/db_keystore.o ${BUILD}/hash.o ${BUILD}/hash_tooling.o ${BUILD}/db_tables.o \
${BUILD}/ciphers.o ${BUILD}/keys.o -lpthread -lm
