/* Copyright (c) 2017 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * test-enc.c -- Small program to test drive the encoder and the decoder
 */

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <unistd.h>

#include "qmin_common.h"
#include "qmin_dec.h"
#include "qmin_enc.h"

struct header
{
    STAILQ_ENTRY(header)  h_next;
    unsigned              h_name_len;
    unsigned              h_val_len;
    char                  h_buf[0];
};

#define H_NAME(h) ((h)->h_buf)
#define H_VALUE(h) (&(h)->h_buf[(h)->h_name_len])

/* Each stream has an ID and a bunch of header fields.  We create streams,
 * encode them, and then pass them to the decoder in random order.  The
 * decoded list of header fields is compared with the original.
 */
struct stream
{
    TAILQ_ENTRY(stream)     sm_next;
    unsigned                sm_id;
    STAILQ_HEAD(, header)   sm_headers;
    unsigned char          *sm_headbuf;     /* Encoded headers */
    size_t                  sm_bufsz;       /* Size of sm_headbuf */
};


static struct stream *
stream_new (unsigned stream_id)
{
    struct stream *stream;

    stream = calloc(1, sizeof(*stream));
    stream->sm_id = stream_id;
    STAILQ_INIT(&stream->sm_headers);

    return stream;
}


static void
stream_add_header (struct stream *stream, const char *name, const char *value)
{
    struct header *header;
    size_t name_len, val_len;

    name_len = strlen(name);
    val_len = strlen(value);

    header = malloc(sizeof(*header) + name_len + val_len);
    header->h_name_len = name_len;
    header->h_val_len = val_len;
    memcpy(H_NAME(header), name, name_len);
    memcpy(H_VALUE(header), value, val_len);

    STAILQ_INSERT_TAIL(&stream->sm_headers, header, h_next);
}


static void
stream_encode_headers (struct stream *stream, struct qmin_enc *enc)
{
    const struct header *header;
    enum qmin_encode_status st;
    size_t n_written;
    unsigned off;
    unsigned char buf[0x1000];

    off = 0;
    STAILQ_FOREACH(header, &stream->sm_headers, h_next)
    {
        st = qmin_enc_encode(enc, stream->sm_id, H_NAME(header),
                    header->h_name_len, H_VALUE(header), header->h_val_len,
                    QIT_YES, buf + off, sizeof(buf) - off, &n_written);
        assert(st == QES_OK);
        off += n_written;
    }

    assert(off > 0);    /* Assume at least one header */
    stream->sm_headbuf = malloc(off);
    memcpy(stream->sm_headbuf, buf, off);
    stream->sm_bufsz = off;
}


static void
stream_destroy (struct stream *stream)
{
    struct header *header;

    while ((header = STAILQ_FIRST(&stream->sm_headers)))
    {
        STAILQ_REMOVE_HEAD(&stream->sm_headers, h_next);
        free(header);
    }
    free(stream->sm_headbuf);
    free(stream);
}


/* Some HTTP header values: */
static const char *const calvary[] =
{
"And then the pew-opener had stolen up unobserved, and had taken it so for",
"granted that she would like to be shown round, and had seemed so pleased",
"and eager, that she had not the heart to repel her.  A curious little old",
"party with a smooth, peach-like complexion and white soft hair that the",
"fading twilight, stealing through the yellow glass, turned to gold.  So",
"that at first sight Joan took her for a child.  The voice, too, was so",
"absurdly childish--appealing, and yet confident.  Not until they were",
"crossing the aisle, where the clearer light streamed in through the open",
"doors, did Joan see that she was very old and feeble, with about her",
"figure that curious patient droop that comes to the work-worn.  She",
"proved to be most interesting and full of helpful information.  Mary",
"Stopperton was her name.  She had lived in the neighbourhood all her",
"life; had as a girl worked for the Leigh Hunts and had \"assisted\" Mrs.",
"Carlyle.  She had been very frightened of the great man himself, and had",
"always hidden herself behind doors or squeezed herself into corners and",
"stopped breathing whenever there had been any fear of meeting him upon",
"the stairs.  Until one day having darted into a cupboard to escape from",
"him and drawn the door to after her, it turned out to be the cupboard in",
"which Carlyle was used to keep his boots.  So that there was quite a",
"struggle between them; she holding grimly on to the door inside and",
"Carlyle equally determined to open it and get his boots.  It had ended in",
"her exposure, with trembling knees and scarlet face, and Carlyle had",
"addressed her as \"woman,\" and had insisted on knowing what she was doing",
"there.  And after that she had lost all terror of him.  And he had even",
"allowed her with a grim smile to enter occasionally the sacred study with",
"her broom and pan.  It had evidently made a lasting impression upon her,",
"that privilege.",
"It was all so sweet and restful.  Religion had never appealed to her",
"before.  The business-like service in the bare cold chapel where she had",
"sat swinging her feet and yawning as a child had only repelled her.  She",
"could recall her father, aloof and awe-inspiring in his Sunday black,",
"passing round the bag.  Her mother, always veiled, sitting beside her, a",
"thin, tall woman with passionate eyes and ever restless hands; the women",
"mostly overdressed, and the sleek, prosperous men trying to look meek.  At",
"school and at Girton, chapel, which she had attended no oftener than she",
"was obliged, had had about it the same atmosphere of chill compulsion.",
"But here was poetry.  She wondered if, after all, religion might not have",
"its place in the world--in company with the other arts.  It would be a",
"pity for it to die out.  There seemed nothing to take its place.  All",
"these lovely cathedrals, these dear little old churches, that for",
"centuries had been the focus of men's thoughts and aspirations.  The",
"harbour lights, illumining the troubled waters of their lives.  What",
"could be done with them?  They could hardly be maintained out of the",
"public funds as mere mementoes of the past.  Besides, there were too many",
"of them.  The tax-payer would naturally grumble.  As Town Halls, Assembly",
"Rooms?  The idea was unthinkable.  It would be like a performance of",
"Barnum's Circus in the Coliseum at Rome.  Yes, they would disappear.",
"Though not, she was glad to think, in her time.  In towns, the space",
"would be required for other buildings.  Here and there some gradually",
"decaying specimen would be allowed to survive, taking its place with the",
"feudal castles and walled cities of the Continent: the joy of the",
"American tourist, the text-book of the antiquary.  A pity!  Yes, but then",
"from the aesthetic point of view it was a pity that the groves of ancient",
"Greece had ever been cut down and replanted with currant bushes, their",
"altars scattered; that the stones of the temples of Isis should have come",
"to be the shelter of the fisher of the Nile; and the corn wave in the",
"wind above the buried shrines of Mexico.  All these dead truths that from",
"time to time had encumbered the living world.  Each in its turn had had",
"to be cleared away.",
};


/* This structure is used as one direction of the control channel: */
struct ctl_out {
    size_t          write_off,
                    read_off;
    unsigned char   buf[0x10000];
};

static struct ctl_out g_enc_ctl_out, g_dec_ctl_out;

static void
write_to_ctl (void *ctx, const void *buf, size_t count)
{
    struct ctl_out *const ctl_out = ctx;

    assert(count <= sizeof(ctl_out->buf) - ctl_out->write_off);   /* Sanity check */

    memcpy(ctl_out->buf + ctl_out->write_off, buf, count);
    ctl_out->write_off += count;

    /*
    printf("sent %zd bytes on %s control channel\n", count,
           ctl_out == &g_enc_ctl_out ? "enc-dec" : "dec-enc");
    */
}

#define PAIR(x) x, (sizeof(x) - 1)

static void
maybe_cmds_to_decoder (struct qmin_dec *dec)
{
    ssize_t s;

    if (g_enc_ctl_out.read_off < g_enc_ctl_out.write_off)
    {
        s = qmin_dec_cmds_in(dec,
                    g_enc_ctl_out.buf + g_enc_ctl_out.read_off,
                    g_enc_ctl_out.write_off - g_enc_ctl_out.read_off);
        assert(s > 0);
        g_enc_ctl_out.read_off += s;
        assert(g_enc_ctl_out.write_off == g_enc_ctl_out.read_off);
    }
}


static void
maybe_cmds_to_encoder (struct qmin_enc *enc)
{
    ssize_t s;

    if (g_dec_ctl_out.read_off < g_dec_ctl_out.write_off)
    {
        s = qmin_enc_cmds_in(enc,
                    g_dec_ctl_out.buf + g_dec_ctl_out.read_off,
                    g_dec_ctl_out.write_off - g_dec_ctl_out.read_off);
        assert(s > 0);
        g_dec_ctl_out.read_off += s;
        assert(g_dec_ctl_out.write_off == g_dec_ctl_out.read_off);
    }
}


/* Active streams */
static struct {
    TAILQ_HEAD(, stream)    list;
    unsigned                count;
    unsigned                next_id;
} streams = { TAILQ_HEAD_INITIALIZER(streams.list), 0, 1, };


static struct stream *
open_stream (void)
{
    struct stream *stream = stream_new(streams.next_id);
    streams.next_id += 2;
    return stream;
}


static int s_random_stream;
static unsigned s_stream_seed;


static void
maybe_finish_some_streams (struct qmin_enc *enc, struct qmin_dec *dec)
{
    struct header *header;
    struct stream *stream;
    unsigned name_len, val_len;
    unsigned off;
    ssize_t sz;
    int s;
    char out[0x1000];

    if (streams.count < 20)     /* TODO: make this limit adjustable */
        return;

    if (s_random_stream)
    {
        unsigned pos = rand_r(&s_stream_seed) % streams.count;
        TAILQ_FOREACH(stream, &streams.list, sm_next)
            if (!pos--)
                break;
    }
    else
        stream = TAILQ_FIRST(&streams.list);

    TAILQ_REMOVE(&streams.list, stream, sm_next);
    --streams.count;

    off = 0;
    STAILQ_FOREACH(header, &stream->sm_headers, h_next)
    {
        sz = qmin_dec_decode(dec, stream->sm_headbuf + off,
                             stream->sm_bufsz - off, out, sizeof(out),
                             &name_len, &val_len);
        assert(sz > 0);
        assert(name_len == header->h_name_len);
        assert(val_len == header->h_val_len);
        assert(0 == memcmp(H_NAME(header), out, name_len));
        assert(0 == memcmp(H_VALUE(header), out + name_len, val_len));
        off += sz;
    }

    assert(off == stream->sm_bufsz);

    s = qmin_enc_stream_done(enc, stream->sm_id);
    assert(s == 0);

    stream_destroy(stream);
}


/* Or send "request".  This may trigger some streams to be reported as done. */
static void
send_stream (struct qmin_enc *enc, struct qmin_dec *dec, struct stream *stream)
{
    TAILQ_INSERT_TAIL(&streams.list, stream, sm_next);
    streams.count++;
    stream_encode_headers(stream, enc);
    qmin_enc_end_stream_headers(enc);
    maybe_finish_some_streams(enc, dec);
}


int
main (int argc, char **argv)
{
    int dump_state = 0;

#define DUMP_STATE() do {                                   \
    if (!dump_state) break;                                 \
    char *state = qmin_enc_to_str(enc, &size);              \
    if (state)                                              \
    {                                                       \
        fwrite(state, 1, size, stdout);                     \
        free(state);                                        \
    }                                                       \
    else                                                    \
        perror("qmin_enc_to_str");                          \
    state = qmin_dec_to_str(dec, &size);                    \
    if (state)                                              \
    {                                                       \
        fwrite(state, 1, size, stdout);                     \
        free(state);                                        \
    }                                                       \
    else                                                    \
        perror("qmin_dec_to_str");                          \
} while (0)

#define RUN_CTL_STREAM() do {                               \
    maybe_cmds_to_decoder(dec);                             \
    maybe_cmds_to_encoder(enc);                             \
} while (0)

    struct qmin_enc *enc;
    struct qmin_dec *dec;
    struct qmin_ctl_out enc_ctl_out = { write_to_ctl, &g_enc_ctl_out, };
    struct qmin_ctl_out dec_ctl_out = { write_to_ctl, &g_dec_ctl_out, };
    unsigned max_capacity = QMIN_DYNAMIC_TABLE_SIZE;
    size_t size;
    struct stream *stream;
    int opt;

    while (-1 != (opt = getopt(argc, argv, "c:shtr:")))
    {
        switch (opt)
        {
        case 'c':
            max_capacity = atoi(optarg);
            break;
        case 's':
            dump_state = 1;
            break;
        case 'D':
            setenv("QMIN_DEC_TRACE", "1", 1);
            break;
        case 'E':
            setenv("QMIN_ENC_TRACE", "1", 1);
            break;
        case 'r':
            s_random_stream = 1;
            s_stream_seed = atoi(optarg);
            break;
        case 'h':
            fprintf(stderr,
"Usage: %s [options]\n"
"\n"
"Options:\n"
"   -c VAL      Capacity.  Defaults to %u\n"
"   -s          Dump encoder and decoder states once in a while\n"
"   -E          Trace encoder calls\n"
"   -D          Trace decoder calls\n"
"   -r SEED     Finish random stream instead of always the last one.  SEED\n"
"                 argument specifies the seed for repeatable run.\n"
                , argv[0], max_capacity);
            exit(EXIT_SUCCESS);
        case '?':
            exit(EXIT_FAILURE);
        }
    }

    enc = qmin_enc_new(QSIDE_CLIENT, max_capacity, &enc_ctl_out);
    dec = qmin_dec_new(QSIDE_SERVER, max_capacity, &dec_ctl_out);

    stream = open_stream();
    stream_add_header(stream, "some-header", "some-value");

    RUN_CTL_STREAM();

    stream_add_header(stream, "some-header", "some-value");
    stream_add_header(stream, "server", "LiteStream");

    DUMP_STATE();

    send_stream(enc, dec, stream);
    stream = open_stream();

    DUMP_STATE();

    stream_add_header(stream, "some-other-header", "another-value");
    stream_add_header(stream, "some-header", "some-OTHER-value");
    stream_add_header(stream, "server", "LiteStream");
    DUMP_STATE();

    send_stream(enc, dec, stream);
    stream = open_stream();

    stream_add_header(stream, "yet-another-header", "another-value");
    stream_add_header(stream, "some-other-header", "another-value");
    stream_add_header(stream, "server", "LiteStream");

    send_stream(enc, dec, stream);
    DUMP_STATE();
    RUN_CTL_STREAM();
    DUMP_STATE();

    stream = open_stream();
    stream_add_header(stream, "some-header", "some-value");
    stream_add_header(stream, "some-header", "some-OTHER-value");
    DUMP_STATE();
    send_stream(enc, dec, stream);

    RUN_CTL_STREAM();

    DUMP_STATE();

    int i;
    for (i = 0; i < 10000; ++i)
    {
        stream = open_stream();
        int j;
        for (j = 0; j < (1 + (i & 0x7)); ++j)
        {
            int idx = i++ % (sizeof(calvary) / sizeof(calvary[0]));
            stream_add_header(stream, "some-header", calvary[idx]);
        }
        send_stream(enc, dec, stream);
        RUN_CTL_STREAM();
        DUMP_STATE();
    }

    qmin_enc_destroy(enc);
    qmin_dec_destroy(dec);

    while ((stream = TAILQ_FIRST(&streams.list)))
    {
        TAILQ_REMOVE(&streams.list, stream, sm_next);
        stream_destroy(stream);
    }

    return 0;
}
