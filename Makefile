CC = gcc
LIBEVENT_DIR=/usr
LIBEVENT_LIB_DIR=$(LIBEVENT_DIR)/lib
LIBEVENT_INC_DIR=$(LIBEVENT_DIR)/include
CFLAGS = -g -O2 -DSOCKS -I$(LIBEVENT_INC_DIR)

OBJ = transocks_ev.o

all: transocks_ev

clean:
	rm -f *.o transocks_ev

transocks_ev: $(OBJ)
	$(CC) -o transocks_ev $(OBJ) -L$(LIBEVENT_LIB_DIR) -Wl,--rpath -Wl,$(LIBEVENT_LIB_DIR) -levent

.c.o:
	$(CC) -c $(CFLAGS) $<
