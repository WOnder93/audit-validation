CFLAGS=-g -W -Wall -Wundef -D_GNU_SOURCE
LIBS=-lauparse -laudit
CC=gcc
all:
	$(CC) $(CFLAGS) audit-validate.c service.c audit-llist.c -o audit-validate $(LIBS)

clean:
	rm -f audit-validate *.o audit.log
