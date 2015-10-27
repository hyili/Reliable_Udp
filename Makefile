CC = gcc
CFLAG = -g -Wall -DDEBUG

all: rudp.o server.o client.o
	$(CC) $(CFLAG) rudp.o server.o -o s
	$(CC) $(CFLAG) rudp.o client.o -o c
	rm -f rudp.o server.o client.o
rudp.o:
	gcc -c rudp.c -o rudp.o
server.o:
	gcc -c testrecv.c -o server.o
client.o:
	gcc -c test.c -o client.o
clean:
	rm -f server.o client.o s c
