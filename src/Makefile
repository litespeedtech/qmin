CFLAGS=-Wall -g $(EXTRA_CFLAGS)

SRCS=qmin_id_list.c qmin_internal.c qmin_enc.c qmin_dec.c
OBJS=${SRCS:.c=.o}

all: test-enc

test-enc: test-enc.o ${OBJS}
	$(CC) $(CFLAGS) -o $@ ${OBJS} $<

clean:
	rm -vf ${OBJS} test-enc test-enc.o
