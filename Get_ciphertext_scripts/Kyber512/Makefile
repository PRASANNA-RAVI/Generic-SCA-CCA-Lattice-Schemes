CC=/usr/bin/gcc
LDFLAGS=

SOURCES= test.c reduce.c
HEADERS= api.h params.h reduce.h

get_chosen_ct: $(HEADERS) $(SOURCES)
	$(CC) -o $@ $(SOURCES) $(LDFLAGS)

.PHONY: clean

clean:
	-rm get_chosen_ct
