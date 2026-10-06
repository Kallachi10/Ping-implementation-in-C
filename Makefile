CFLAGS = -Wall -Wextra -g

ping : ping.o
	gcc -o ping ping.o

ping.o : ping.c ping.h
	gcc $(CFLAGS) -c ping.c

clean:
	rm -f ping.o