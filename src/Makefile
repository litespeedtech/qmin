CFLAGS=-Wall -g $(EXTRA_CFLAGS) -fPIC

SRCS=qmin_id_list.c qmin_internal.c qmin_enc.c qmin_dec.c
OBJS=${SRCS:.c=.o}

all: test-enc libqmin.so

test-enc: test-enc.o ${OBJS}
	$(CC) $(CFLAGS) -o $@ ${OBJS} $<

libqmin.so: ${OBJS}
	ld -shared -fPIC -o libqmin.so ${OBJS}

clean:
	rm -vf ${OBJS} test-enc test-enc.o
