CL:=gcc -O3 -Wall -pedantic
CC:=gcc -O3 -Wall -pedantic
BUILD:=../.build

all: tests

tests:
	${CL} -o ${BUILD}/tests tests.c ${BUILD}/crypto.o ${BUILD}/crypto_client.o ${BUILD}/crypto_server.o\
	  ${BUILD}/db_keystore.o ${BUILD}/hash.o ${BUILD}/hash_tooling.o ${BUILD}/db_tables.o ${BUILD}/ciphers.o\
	  ${BUILD}/ciphers_aes_gcm.o ${BUILD}/keys.o -lpthread -lm
