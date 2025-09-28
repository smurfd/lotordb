CC := gcc -O3 -ffast-math -Wall -Wextra -pedantic -std=c99 -march=native
BUILD := ../.build
all: build runner
local: build runner_local

build:
	${CC} -o ${BUILD}/tests tests.c ${BUILD}/crypto.o ${BUILD}/keys_client.o ${BUILD}/tables_client.o \
${BUILD}/crypto_client.o ${BUILD}/tables_server.o ${BUILD}/keys_server.o ${BUILD}/crypto_server.o ${BUILD}/db_keystore.o \
${BUILD}/hash.o ${BUILD}/tooling.o ${BUILD}/db_tables.o ${BUILD}/ciph.o ${BUILD}/lotormath.o ${BUILD}/bmec.o -lpthread -lm

runner:
	${BUILD}/tests

runner_local:
	${BUILD}/tests local
