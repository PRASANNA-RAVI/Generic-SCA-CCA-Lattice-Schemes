CC = /usr/bin/gcc -g
LDFLAGS = -lcrypto

SOURCES = kem.c cpapke.c fips202.c ntt.c poly.c precomp.c reduce.c rng.c verify.c PQCgenKAT_kem.c
HEADERS = api.h cpapke.h fips202.h ntt.h params.h poly.h reduce.h rng.h verify.h

# SOURCES = PQCgenKAT_kem.c
# HEADERS = api.h params.h

PQCgenKAT_kem: $(SOURCES) $(HEADERS)
	$(CC) $(SOURCES) -o $@ $(LDFLAGS)

.PHONY: clean

clean:
	-rm PQCgenKAT_kem
