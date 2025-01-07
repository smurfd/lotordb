CC := gcc -O3 -Wall -pedantic -std=c99
BUILD := ../.build

all: build runner
local: build runner_local

build:
	${CC} -o ${BUILD}/tests tests.c ${BUILD}/hash.o ${BUILD}/ecc.o ${BUILD}/crypto.o \
	${BUILD}/keys_client.o ${BUILD}/tables_client.o ${BUILD}/crypto_client.o ${BUILD}/tables_server.o ${BUILD}/keys_server.o ${BUILD}/crypto_server.o \
  ${BUILD}/db_keystore.o ${BUILD}/db_tables.o -lpthread -lm

runner:
	${BUILD}/tests

runner_local:
	${BUILD}/tests local
