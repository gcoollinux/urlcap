CC:=gcc
#CFLAGS:=-g -DDEBUG
CFLAGS:=
LDFLAGS:=-lpthread -lpcap -lcurl
bins=urlcap

all:$(bins)

config.o:config.c
	$(CC) $(CFLAGS)  -c $^
list.o:list.c
	$(CC) $(CFLAGS) -c  $^
urlcap.o:urlcap.c
	$(CC) $(CFLAGS) -c  $^
urlcap:urlcap.o list.o config.o
	$(CC) $(LDFLAGS) $^ -o $@

clean:
	rm -rf  $(bins)  *.o
