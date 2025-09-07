CC := gcc -O3 -ffast-math -Wall -pedantic -std=c99
BUILD:=.build
SUBMODULES := lotorssl

all: mkbuilddir checksubmodules hash aes keys ssl tooling db_keystore db_tables crypto crypto_server crypto_client test
local: mkbuilddir checksubmodules hash aes keys ssl tooling db_keystore db_tables crypto crypto_server crypto_client test_local

mkbuilddir:
	mkdir -p ${BUILD}

checksubmodules:
	for s in ${SUBMODULES} ; do \
		if [ -d $$s ]; then \
			echo "Deleting $$s ..."; \
			rm -rf $$s; \
		fi; \
		git submodule add --force https://github.com/smurfd/$$s; \
		git submodule init; \
		git submodule update; \
	done

crypto:
	${CC} -c crypto.c -o ${BUILD}/crypto.o

crypto_server:
	${CC} -c examples/tables_example_server.c -o ${BUILD}/tables_server.o
	${CC} -c examples/keys_example_server.c -o ${BUILD}/keys_server.o
	${CC} -c crypto_server.c -o ${BUILD}/crypto_server.o

crypto_client:
	${CC} -c examples/tables_example_client.c -o ${BUILD}/tables_client.o
	${CC} -c examples/keys_example_client.c -o ${BUILD}/keys_client.o
	${CC} -c crypto_client.c -o ${BUILD}/crypto_client.o

db_keystore:
	${CC} -c db_keystore.c -o ${BUILD}/db_keystore.o

hash:
	${CC} -c hash.c -o ${BUILD}/hash.o

tooling:
	${CC} -c tooling.c -o ${BUILD}/tooling.o

db_tables:
	${CC} -c db_tables.c -o ${BUILD}/db_tables.o

keys:
	${CC} -c keys.c -o ${BUILD}/keys.o

aes:
	${CC} -c aes.c -o .build/aes.o

ssl:
	echo "compiling ssl"
	make -Clotorssl/src

test:
	make -Ctests

test_local:
	make -Ctests local

clean:
	rm ${BUILD}/crypto.o ${BUILD}/keys_client.o ${BUILD}/tables_client.o ${BUILD}/tests ${BUILD}/ciphers_aes_gcm.o \
${BUILD}/crypto_client.o ${BUILD}/tables_server.o ${BUILD}/keys_server.o ${BUILD}/crypto_server.o ${BUILD}/db_keystore.o \
${BUILD}/hash.o ${BUILD}/tooling.o ${BUILD}/db_tables.o ${BUILD}/keys.o ${BUILD}/aes.o ${BUILD}/*bin.b
