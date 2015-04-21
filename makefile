.PHONY : all
all : server client
	rm *.o
server : server.o
	cc -pthread -o server server.o -lgmp
client : client.o
	cc -o client client.o -lgmp
server.o : server.c
	cc -c server.c -lgmp
client.o : client.c
	cc -c client.c -lgmp

clean :
	rm server client
