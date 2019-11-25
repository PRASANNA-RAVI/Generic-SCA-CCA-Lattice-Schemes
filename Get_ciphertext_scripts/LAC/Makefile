objects = main.o
cflags = -O3 -Wall -DNDEBUG

get_chosen_ct : $(objects)
	gcc -o get_chosen_ct $(objects)  -lcrypto -lz

main.o: main.c api.h lac_param.h
	gcc -c main.c $(cflags)

clean:
	rm -f get_chosen_ct get_chosen_ct.exemak $(objects)
