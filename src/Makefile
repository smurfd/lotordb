CC := gcc -O3 -ffast-math -Wall -Wextra -pedantic -std=c99 -march=native
BUILD := .build
MODULES := mkbuilddir checksubmodules ssl db_keystore db_tables
SUBMODULES := lotorssl
all: ${MODULES} test
local: ${MODULES} test_local

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

db_keystore:
	${CC} -c db_keystore.c -o ${BUILD}/db_keystore.o

db_tables:
	${CC} -c db_tables.c -o ${BUILD}/db_tables.o

ssl:
	${MAKE} -Clotorssl/src build  # to pull down lotormath
	${CC} -c lotorssl/src/lotormath/src/lotormath.c -o ${BUILD}/lotormath.o
	${CC} -c lotorssl/src/tooling.c -o ${BUILD}/tooling.o
	${CC} -c lotorssl/src/bmec.c -o ${BUILD}/bmec.o
	${CC} -c lotorssl/src/hash.c -o ${BUILD}/hash.o
	${CC} -c lotorssl/src/ciph.c -o ${BUILD}/ciph.o
	${CC} -c lotorssl/src/crpt.c -o ${BUILD}/crpt.o
	${CC} -c lotorssl/src/crpt_cli.c -o ${BUILD}/crpt_cli.o
	${CC} -c lotorssl/src/crpt_srv.c -o ${BUILD}/crpt_srv.o

test:
	${MAKE} -Ctests

test_local:
	${MAKE} -Ctests local

clean:
	rm ${BUILD}/*.o ${BUILD}/tests ${BUILD}/*bin.b
