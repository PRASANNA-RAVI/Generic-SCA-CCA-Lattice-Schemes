CC = /usr/bin/gcc -g
LDFLAGS =

SOURCES = PQCgenKAT_kem.c
HEADERS = api.h params.h

get_chosen_ct: $(SOURCES) $(HEADERS)
	$(CC) $(SOURCES) -o $@ $(LDFLAGS)

.PHONY: clean

clean:
	-rm get_chosen_ct
