CC := gcc -O3 -ffast-math -Wall -pedantic -std=c99
BUILD:=.build
SUBMODULES := lotorssl

all: mkbuilddir checksubmodules keys ssl tooling db_keystore db_tables crypto crypto_server crypto_client test
local: mkbuilddir checksubmodules keys ssl tooling db_keystore db_tables crypto crypto_server crypto_client test_local


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

tooling:
	${CC} -c tooling.c -o ${BUILD}/tooling.o

db_tables:
	${CC} -c db_tables.c -o ${BUILD}/db_tables.o

keys:
	${CC} -c keys.c -o ${BUILD}/keys.o

ssl:
	make -Clotorssl/src  # to pull down lotormath
	${CC} -c lotorssl/src/lotormath/src/lotormath.c -o ${BUILD}/lotormath.o
	${CC} -c lotorssl/src/bmec.c -o ${BUILD}/bmec.o
	${CC} -c lotorssl/src/hash.c -o ${BUILD}/hash.o
	${CC} -c lotorssl/src/ciph.c -o ${BUILD}/ciph.o

test:
	make -Ctests

test_local:
	make -Ctests local

clean:
	rm ${BUILD}/*.o ${BUILD}/tests ${BUILD}/*bin.b
