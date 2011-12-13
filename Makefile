CC = clang
CFLAGS = -O0 -g3 -Wall
LIBS = 

CFLAGS += `pkg-config --cflags fuse glib-2.0 sqlite3`
LIBS += `pkg-config --libs fuse glib-2.0 sqlite3`

all: insecure.c
	$(CC) -o insecure insecure.c $(CFLAGS) $(LIBS)
	
