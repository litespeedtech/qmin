/* Copyright (c) 2017 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * qmin_enc.c - QMIN encoder
 */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "qmin_common.h"
#include "qmin_id_list.h"
#include "qmin_internal.h"
#include "qmin_enc.h"

enum enc_checkpoint_state
{
    ECS_NEW,
    ECS_PENDING,
    ECS_LIVE,
    ECS_DEAD,
};


struct enc_checkpoint
{
    TAILQ_ENTRY(enc_checkpoint)     ecp_next;

    /* IDs of entries added the the dynamic table when this enc_checkpoint
     * was in ECS_NEW state and those referenced when the checkpoint is in
     * ECS_LIVE state:
     */
    struct id_list                  ecp_entry_ids;

    /* IDs of streams that triggered entry addition to the dynamic
     * table when the checkpoit was in ECS_NEW state.
     *
     * When the state is ECS_LIVE or ECS_DEAD, this list also keeps a record
     * of stream IDs that have taken out dynamic entry references from
     * this enc_checkpoint.
     */
    struct id_list                  ecp_stream_ids[2];

    enum enc_checkpoint_state       ecp_state;
};


static struct enc_checkpoint *
enc_ckpoint_new (unsigned min_stream_id_server, unsigned min_stream_id_client)
{
    struct enc_checkpoint *ckpoint;

    ckpoint = calloc(1, sizeof(*ckpoint));
    if (!ckpoint)
        return NULL;

    id_list_init(&ckpoint->ecp_entry_ids, QMIN_STATIC_TABLE_N_ENTRIES + 1);
    id_list_init(&ckpoint->ecp_stream_ids[0], min_stream_id_server);
    id_list_init(&ckpoint->ecp_stream_ids[1], min_stream_id_client);
    ckpoint->ecp_state = ECS_NEW;

    return ckpoint;
}


static void
enc_ckpoint_destroy (struct enc_checkpoint *ckpoint)
{
    id_list_cleanup(&ckpoint->ecp_entry_ids);
    id_list_cleanup(&ckpoint->ecp_stream_ids[0]);
    id_list_cleanup(&ckpoint->ecp_stream_ids[1]);
    free(ckpoint);
}


static size_t
enc_ckpoint_mem_used (const struct enc_checkpoint *ckpoint)
{
    return sizeof(*ckpoint)
         - sizeof(ckpoint->ecp_entry_ids)
         + id_list_mem_used(&ckpoint->ecp_entry_ids)
         - sizeof(ckpoint->ecp_stream_ids[0])
         + id_list_mem_used(&ckpoint->ecp_stream_ids[0])
         - sizeof(ckpoint->ecp_stream_ids[1])
         + id_list_mem_used(&ckpoint->ecp_stream_ids[1]);
}

#define ENC_HIST_MAX_ELEMS 1024

struct enc_hist
{
    unsigned    ehe_hashes[ENC_HIST_MAX_ELEMS];
    unsigned    ehe_hist_next;
    bool        ehe_wrapped;
};


enum enc_hist_add_st { EHA_ADDED, EHA_EXISTS, };


static enum enc_hist_add_st
enc_hist_add (struct enc_hist *hist, unsigned nameval_hash)
{
    unsigned max, n;

    max = hist->ehe_wrapped ? ENC_HIST_MAX_ELEMS : hist->ehe_hist_next;

    for (n = 0; n < max; ++n)
        if (hist->ehe_hashes[n] == nameval_hash)
            return EHA_EXISTS;

    if (!hist->ehe_wrapped && n == ENC_HIST_MAX_ELEMS)
        hist->ehe_wrapped = true;

    n = hist->ehe_hist_next++ % ENC_HIST_MAX_ELEMS;
    hist->ehe_hashes[n] = nameval_hash;
    return EHA_ADDED;
}

struct enc_table_entry;

TAILQ_HEAD(enc_head, enc_table_entry);
struct double_enc_head;

TAILQ_HEAD(checkpoint_head , enc_checkpoint);

struct qmin_enc
{
    enum {
        QME_TRACE = (1 << 0),
    }                           qme_flags;

    enum qmin_side              qme_side;

    /* List of all the dynamic entry IDs */
    struct id_list              qme_entry_ids;

    struct {
        struct id_list  list;
        /* All stream IDs at and below this value have been closed: */
        unsigned        low;
    }                           qme_closed_stream_ids[2];

    unsigned                    qme_max_opened_stream_id;
    unsigned                    qme_streams_since_last_flush;

    /* Dynamic table entries (struct enc_table_entry) live in two hash
     * tables: name/value hash table and name hash table.  These tables
     * are the same size.
     */
    struct double_enc_head     *qme_buckets;
    unsigned                    qme_nelem;
    unsigned                    qme_nbits;

    struct checkpoint_head      qme_checkpoints;

    /*
     * In addition, the dynamic table entries are in array.
     */
    struct {
        struct enc_table_entry    **arr;
        unsigned                    count;
    }                           qme_entries;

    const struct qmin_ctl_out  *qme_ctl_out;

    const char                 *qme_idstr;

    unsigned                    qme_max_capacity;

    size_t                      qme_bytes_out,
                                qme_bytes_in;

    struct enc_hist             qme_enc_hist;
};

#define TRACE(args...) do {                                     \
    if (enc->qme_flags & QME_TRACE) {                           \
        fprintf(stderr, "ENC TRACE(%s): ", enc->qme_idstr);     \
        fprintf(stderr, args);                                  \
        fflush(stderr);                                         \
    }                                                           \
} while (0)

struct double_enc_head
{
    struct enc_head by_name;
    struct enc_head by_nameval;
};

struct enc_table_entry
{
    /* An entry always lives on both lists */
    TAILQ_ENTRY(enc_table_entry)    ete_next_nameval,
                                    ete_next_name;
    unsigned                        ete_id;
    unsigned                        ete_live_refcnt;
    unsigned                        ete_total_refcnt;
    unsigned                        ete_nameval_hash;
    unsigned                        ete_name_hash;
    unsigned                        ete_name_len;
    unsigned                        ete_val_len;
    char                            ete_buf[0];
};

#define ETE_NAME(ete) ((ete)->ete_buf)
#define ETE_VALUE(ete) (&(ete)->ete_buf[(ete)->ete_name_len])


#define N_BUCKETS(n_bits) (1U << (n_bits))
#define BUCKNO(n_bits, hash) ((hash) & (N_BUCKETS(n_bits) - 1))

struct qmin_enc *
qmin_enc_new (enum qmin_side side, unsigned max_capacity,
              const struct qmin_ctl_out *ctl_out, const char *idstr)
{
    struct qmin_enc *enc;
    struct enc_checkpoint *enc_checkpoint;
    struct double_enc_head *buckets;
    const char *s;
    unsigned nbits = 2;
    unsigned i;

    if (max_capacity < QMIN_CKPOINT_OVERHEAD)
    {
        errno = EINVAL;
        return NULL;
    }

    enc = malloc(sizeof(*enc));
    if (!enc)
        return NULL;

    enc_checkpoint = enc_ckpoint_new(0, 0);
    if (!enc_checkpoint)
    {
        free(enc);
        return NULL;
    }

    buckets = malloc(sizeof(buckets[0]) * N_BUCKETS(nbits));
    if (!buckets)
    {
        free(enc_checkpoint);
        free(enc);
        return NULL;
    }

    for (i = 0; i < N_BUCKETS(nbits); ++i)
    {
        TAILQ_INIT(&buckets[i].by_name);
        TAILQ_INIT(&buckets[i].by_nameval);
    }

    memset(enc, 0, sizeof(*enc));
    enc->qme_idstr        = idstr ? idstr : "";
    enc->qme_side         = side;
    enc->qme_ctl_out      = ctl_out;
    enc->qme_max_capacity = max_capacity;
    enc->qme_buckets      = buckets;
    enc->qme_nbits        = nbits;
    enc->qme_nelem        = 0;
    enc->qme_entries.arr  = NULL;
    enc->qme_entries.count= 0;
    id_list_init(&enc->qme_closed_stream_ids[0].list, 0);
    id_list_init(&enc->qme_closed_stream_ids[1].list, 0);
    id_list_init(&enc->qme_entry_ids, QMIN_STATIC_TABLE_N_ENTRIES + 1);
    TAILQ_INIT(&enc->qme_checkpoints);
    TAILQ_INSERT_HEAD(&enc->qme_checkpoints, enc_checkpoint, ecp_next);

    s = getenv("QMIN_ENC_TRACE");
    if (s && atoi(s))
        enc->qme_flags |= QME_TRACE;

    return enc;
}


void
qmin_enc_destroy (struct qmin_enc *enc)
{
    struct enc_checkpoint *enc_checkpoint;
    unsigned n;

    while ((enc_checkpoint = TAILQ_FIRST(&enc->qme_checkpoints)))
    {
        TAILQ_REMOVE(&enc->qme_checkpoints, enc_checkpoint, ecp_next);
        enc_ckpoint_destroy(enc_checkpoint);
    }

    for (n = 0; n < enc->qme_entries.count; ++n)
        if (enc->qme_entries.arr[n])
            free(enc->qme_entries.arr[n]);

    id_list_cleanup(&enc->qme_closed_stream_ids[0].list);
    id_list_cleanup(&enc->qme_closed_stream_ids[1].list);
    id_list_cleanup(&enc->qme_entry_ids);
    free(enc->qme_entries.arr);
    free(enc->qme_buckets);
    free(enc);
}


//not find return 0, otherwise return the index
static unsigned
qmin_enc_get_stx_tab_id (const char *name, unsigned name_len,
                    const char *val, unsigned val_len, bool *val_matched)
{
    if (name_len < 3)
        return 0;

    *val_matched = false;

    //check value first
    int i = -1;
    switch (*val)
    {
        case 'G':
            i = 1;
            break;
        case 'P':
            i = 2;
            break;
        case '/':
            if (val_len == 1)
                i = 3;
            else if (val_len == 11)
                i = 4;
            break;
        case 'h':
            if (val_len == 4)
                i = 5;
            else if (val_len == 5)
                i = 6;
            break;
        case '2':
            if (val_len == 3)
            {
                switch (*(val + 2))
                {
                    case '0':
                        i = 7;
                        break;
                    case '4':
                        i = 8;
                        break;
                    case '6':
                        i = 9;
                        break;
                    default:
                        break;
                }
            }
            break;
        case '3':
            i = 10;
            break;
        case '4':
            if (val_len == 3)
            {
                switch (*(val + 2))
                {
                    case '0':
                        i = 11;
                        break;
                    case '4':
                        i = 12;
                    default:
                        break;
                }
            }
            break;
        case '5':
            i = 13;
            break;
        case 'g':
            i = 15;
            break;
        default:
            break;
    }

    if (i > 0 && qmin_stx_tab[i].val_len == val_len
            && qmin_stx_tab[i].name_len == name_len
            && memcmp(val, qmin_stx_tab[i].val, val_len) == 0
            && memcmp(name, qmin_stx_tab[i].name, name_len) == 0)
    {
        *val_matched = true;
        return i + 1;
    }

    //macth name only checking
    i = -1;
    switch (*name)
    {
        case ':':
            switch (*(name + 1))
            {
                case 'a':
                    i = 0;
                    break;
                case 'm':
                    i = 1;
                    break;
                case 'p':
                    i = 3;
                    break;
                case 's':
                    if (*(name + 2) == 'c') //:scheme
                        i = 5;
                    else
                        i = 7;
                    break;
                default:
                    break;
            }
            break;
        case 'a':
            switch (name_len)
            {
                case 3:
                    i = 20; //age
                    break;
                case 5:
                    i = 21; //allow
                    break;
                case 6:
                    i = 18; //accept
                    break;
                case 13:
                    if (*(name + 1) == 'u')
                        i = 22; //authorization
                    else
                        i = 17; //accept-ranges
                    break;
                case 14:
                    i  = 14; //accept-charset
                    break;
                case 15:
                    if (*(name + 7) == 'l')
                        i = 16; //accept-language,
                    else
                        i = 15;// accept-encoding
                    break;
                case 27:
                    i = 19;//access-control-allow-origin
                    break;
                default:
                    break;
            }
            break;
        case 'c':
            switch (name_len)
            {
                case 6:
                    i = 31; //cookie
                    break;
                case 12:
                    i = 30; //content-type
                    break;
                case 13:
                    if (*(name + 1) == 'a')
                        i = 23; //cache-control
                    else
                        i = 29; //content-range
                    break;
                case 14:
                    i = 27; //content-length
                    break;
                case 16:
                    switch (*(name + 9))
                    {
                        case 'n':
                            i = 25 ;//content-encoding
                            break;
                        case 'a':
                            i = 26; //content-language
                            break;
                        case 'o':
                            i = 28; //content-location
                        default:
                            break;
                    }
                    break;
                case 19:
                    i = 24; //content-disposition
                    break;
            }
            break;
        case 'd':
            i = 32 ;//date
            break;
        case 'e':
            switch (name_len)
            {
                case 4:
                    i = 33; //etag
                    break;
                case 6:
                    i = 34;
                    break;
                case 7:
                    i = 35;
                    break;
                default:
                    break;
            }
            break;
        case 'f':
            i = 36; //from
            break;
        case 'h':
            i = 37; //host
            break;
        case 'i':
            switch (name_len)
            {
                case 8:
                    if (*(name + 3) == 'm')
                        i = 38; //if-match
                    else
                        i = 41; //if-range
                    break;
                case 13:
                    i = 40; //if-none-match
                    break;
                case 17:
                    i = 39; //if-modified-since
                    break;
                case 19:
                    i = 42; //if-unmodified-since
                    break;
                default:
                    break;
            }
            break;
        case 'l':
            switch (name_len)
            {
                case 4:
                    i = 44; //link
                    break;
                case 8:
                    i = 45; //location
                    break;
                case 13:
                    i = 43; //last-modified
                    break;
                default:
                    break;
            }
            break;
        case 'm':
            i = 46; //max-forwards
            break;
        case 'p':
            if (name_len == 18)
                i = 47; //proxy-authenticate
            else
                i = 48; //proxy-authorization
            break;
        case 'r':
            if (name_len >= 5)
            {
                switch (*(name + 4))
                {
                    case 'e':
                        if (name_len == 5)
                            i = 49; //range
                        else
                            i = 51; //refresh
                        break;
                    case 'r':
                        i = 50; //referer
                        break;
                    case 'y':
                        i = 52; //retry-after
                        break;
                    default:
                        break;
                }
            }
            break;
        case 's':
            switch (name_len)
            {
                case 6:
                    i = 53; //server
                    break;
                case 10:
                    i = 54; //set-cookie
                    break;
                case 25:
                    i = 55; //strict-transport-security
                    break;
                default:
                    break;
            }
            break;
        case 't':
            i = 56;//transfer-encoding
            break;
        case 'u':
            i = 57; //user-agent
            break;
        case 'v':
            if (name_len == 4)
                i = 58;
            else
                i = 59;
            break;
        case 'w':
            i = 60;
            break;
        default:
            break;
    }

    if (i >= 0
            && qmin_stx_tab[i].name_len == name_len
            && memcmp(name, qmin_stx_tab[i].name, name_len) == 0)
        return i + 1;

    return 0;
}


#define DJB2_INIT 5381

/* There are better hashes, but this is good enough for this proof-of-concept.
 * And it is five lines of code.
 */
static unsigned
djb2 (unsigned hash, const void *data, size_t sz)
{
    const unsigned char *c = data;
    const unsigned char *const end = c + sz;
    for (; c < end; ++c)
	hash = ((hash << 5) + hash) + *c;
    return hash;
}


enum
{
    FIBIT_LIVE,
    FIBIT_PENDING,
    FIBIT_NEW,
};


enum found_in
{
    FI_LIVE     = 1 << FIBIT_LIVE,
    FI_PENDING  = 1 << FIBIT_PENDING,
    FI_NEW      = 1 << FIBIT_NEW,
};


struct entry_search_result {
    unsigned    esr_entry_id;       /* If 0, entry is not found */
    unsigned    esr_name_hash,
                esr_nameval_hash;
    bool        esr_val_matched;
    enum found_in
                esr_found_in;
};


static struct entry_search_result
qmin_enc_find_entry (struct qmin_enc *enc, const char *name,
                     unsigned name_len, const char *value, unsigned value_len)
{
    struct enc_checkpoint *const new_ckpoint = TAILQ_FIRST(&enc->qme_checkpoints);
    struct enc_checkpoint *pend_ckpoint;
    struct enc_table_entry *entry;
    struct entry_search_result r;
    unsigned buckno;

    pend_ckpoint = TAILQ_NEXT(new_ckpoint, ecp_next);
    if (pend_ckpoint && pend_ckpoint->ecp_state != ECS_PENDING)
        pend_ckpoint = NULL;

    memset(&r, 0, sizeof(r));

    /* First, look for a match in the static table: */
    r.esr_entry_id = qmin_enc_get_stx_tab_id(name, name_len, value,
                                             value_len, &r.esr_val_matched);
    if (r.esr_entry_id > 0 && r.esr_val_matched)
    {
        r.esr_found_in = FI_LIVE;
        return r;
    }

    /* Search by name and value: */
    r.esr_name_hash = djb2(DJB2_INIT, &name_len, sizeof(name_len));
    r.esr_name_hash = djb2(r.esr_name_hash, name, name_len);
    r.esr_nameval_hash = djb2(r.esr_name_hash, &value_len, sizeof(value_len));
    r.esr_nameval_hash = djb2(r.esr_nameval_hash, value, value_len);
    buckno = BUCKNO(enc->qme_nbits, r.esr_nameval_hash);
    TAILQ_FOREACH(entry, &enc->qme_buckets[buckno].by_nameval, ete_next_nameval)
        if (r.esr_nameval_hash == entry->ete_nameval_hash
            && name_len == entry->ete_name_len
            && value_len == entry->ete_val_len
            && 0 == memcmp(name, ETE_NAME(entry), name_len)
            && 0 == memcmp(value, ETE_VALUE(entry), value_len)
            && (entry->ete_live_refcnt > 0
                || (pend_ckpoint &&
                    id_list_exists(&pend_ckpoint->ecp_entry_ids, entry->ete_id))
                || id_list_exists(&new_ckpoint->ecp_entry_ids, entry->ete_id)))
        {
            r.esr_entry_id    = entry->ete_id;
            r.esr_val_matched = true;
            r.esr_found_in =
                ((entry->ete_live_refcnt > 0) << FIBIT_LIVE)
                |
                ((pend_ckpoint &&
                    id_list_exists(&pend_ckpoint->ecp_entry_ids, entry->ete_id)) << FIBIT_PENDING)
                |
                (id_list_exists(&new_ckpoint->ecp_entry_ids, entry->ete_id) << FIBIT_NEW);
            return r;
        }

    /* Name/value match is not found, but if the caller found a matching
     * static table entry, no need to continue to search:
     */
    if (r.esr_entry_id > 0)
    {
        r.esr_found_in = FI_LIVE;
        return r;
    }

    /* Search by name only: */
    buckno = BUCKNO(enc->qme_nbits, r.esr_name_hash);
    TAILQ_FOREACH(entry, &enc->qme_buckets[buckno].by_name, ete_next_name)
        if (r.esr_name_hash == entry->ete_name_hash
            && name_len == entry->ete_name_len
            && 0 == memcmp(name, ETE_NAME(entry), name_len)
            && (entry->ete_live_refcnt > 0
                || (pend_ckpoint &&
                    id_list_exists(&pend_ckpoint->ecp_entry_ids, entry->ete_id))
                || id_list_exists(&new_ckpoint->ecp_entry_ids, entry->ete_id)))
        {
            r.esr_entry_id    = entry->ete_id;
            r.esr_val_matched = false;
            r.esr_found_in =
                ((entry->ete_live_refcnt > 0) << FIBIT_LIVE)
                |
                ((pend_ckpoint &&
                    id_list_exists(&pend_ckpoint->ecp_entry_ids, entry->ete_id)) << FIBIT_PENDING)
                |
                (id_list_exists(&new_ckpoint->ecp_entry_ids, entry->ete_id) << FIBIT_NEW);
            return r;
        }

    r.esr_entry_id = 0;
    return r;
}


static int
qmin_huffman_enc (const unsigned char *src, const unsigned char *const src_end,
                                            unsigned char *dst, int dst_len)
{
    const unsigned char *p_src = src;
    unsigned char *p_dst = dst;
    unsigned char *dst_end = p_dst + dst_len;
    uint64_t bits = 0;
    int bits_left = 40;
    struct qmin_huff_encode cur_enc_code;

    assert(dst_len > 0);

    while (p_src != src_end)
    {
        cur_enc_code = qmin_huff_encode_tables[(int) *p_src++];
        assert(bits_left >= cur_enc_code.bits); //  (possible negative shift, undefined behavior)
        bits |= (uint64_t)cur_enc_code.code << (bits_left - cur_enc_code.bits);
        bits_left -= cur_enc_code.bits;
        while (bits_left <= 32)
        {
            *p_dst++ = bits >> 32;
            bits <<= 8;
            bits_left += 8;
            if (p_dst == dst_end)
                return -1;  //dst does not have enough space
        }
    }

    if (bits_left != 40)
    {
        assert(bits_left < 40 && bits_left > 0);
        bits |= ((uint64_t)1 << bits_left) - 1;
        *p_dst++ = bits >> 32;
    }

    return p_dst - dst;
}


static int
qmin_enc_enc_str (unsigned char *const dst, size_t dst_len,
                            const unsigned char *str, unsigned str_len)
{
    unsigned char size_buf[4];
    unsigned char *p;
    unsigned size_len;
    int rc;

    if (dst_len > 1)
        /* We guess that the string size fits into a single byte -- meaning
         * compressed string of size 126 and smaller -- which is the normal
         * case.  Thus, we immediately write compressed string to the output
         * buffer.  If our guess is not correct, we fix it later.
         */
        rc = qmin_huffman_enc(str, str + str_len, dst + 1, dst_len - 1);
    else if (dst_len == 1)
        /* Here, the call can only succeed if the string to encode is empty. */
        rc = 0;
    else
        return -1;

    /*
     * Check if need huffman encoding or not
     * Comment: (size_t)rc <= str_len   = means if same length, still use Huffman
     *                     ^
     */
    if (rc > 0 && (size_t)rc <= str_len)
    {
        if (rc < 127)
        {
            *dst = 0x80 | rc;
            return 1 + rc;
        }
        size_buf[0] = 0x80;
        str_len = rc;
        str = dst + 1;
    }
    else if (str_len <= dst_len - 1)
    {
        if (str_len < 127)
        {
            *dst = str_len;
            memcpy(dst + 1, str, str_len);
            return 1 + str_len;
        }
        size_buf[0] = 0x00;
    }
    else
        return -1;

    /* The guess of one-byte size was incorrect.  Perform necessary
     * adjustments.
     */
    p = qmin_encode_int(size_buf, size_buf + sizeof(size_buf), str_len, 7);
    if (p == size_buf)
        return -1;

    size_len = p - size_buf;
    assert(size_len > 1);

    /* Check if there is enough room in the output buffer for both
     * encoded size and the string.
     */
    if (size_len + str_len > dst_len)
        return -1;

    memmove(dst + size_len, str, str_len);
    memcpy(dst, size_buf, size_len);
    return size_len + str_len;
}


static int
qmin_enc_grow_tables (struct qmin_enc *enc)
{
    struct double_enc_head *new_buckets, *new[2];
    struct enc_table_entry *entry;
    unsigned n, old_nbits;
    int idx;

    old_nbits = enc->qme_nbits;
    new_buckets = malloc(sizeof(enc->qme_buckets[0])
                                                * N_BUCKETS(old_nbits + 1));
    if (!new_buckets)
        return -1;

    for (n = 0; n < N_BUCKETS(old_nbits); ++n)
    {
        new[0] = &new_buckets[n];
        new[1] = &new_buckets[n + N_BUCKETS(old_nbits)];
        TAILQ_INIT(&new[0]->by_name);
        TAILQ_INIT(&new[1]->by_name);
        TAILQ_INIT(&new[0]->by_nameval);
        TAILQ_INIT(&new[1]->by_nameval);
        while ((entry = TAILQ_FIRST(&enc->qme_buckets[n].by_name)))
        {
            TAILQ_REMOVE(&enc->qme_buckets[n].by_name, entry, ete_next_name);
            idx = (BUCKNO(old_nbits + 1, entry->ete_name_hash) >> old_nbits) & 1;
            TAILQ_INSERT_TAIL(&new[idx]->by_name, entry, ete_next_name);
        }
        while ((entry = TAILQ_FIRST(&enc->qme_buckets[n].by_nameval)))
        {
            TAILQ_REMOVE(&enc->qme_buckets[n].by_nameval, entry, ete_next_nameval);
            idx = (BUCKNO(old_nbits + 1, entry->ete_nameval_hash) >> old_nbits) & 1;
            TAILQ_INSERT_TAIL(&new[idx]->by_nameval, entry, ete_next_nameval);
        }
    }

    free(enc->qme_buckets);
    enc->qme_nbits   = old_nbits + 1;
    enc->qme_buckets = new_buckets;
    return 0;
}


static const struct enc_table_entry *
qmin_enc_push_entry (struct qmin_enc *enc, unsigned stream_id, const char *name,
                     unsigned name_len, const char *value, unsigned value_len)
{
    struct enc_checkpoint *const new_ckpoint = TAILQ_FIRST(&enc->qme_checkpoints);
    unsigned name_hash, nameval_hash, buckno, new_entry_id, arr_idx;
    struct enc_table_entry *entry;
    enum id_list_add_st add_st;
    size_t size;

    assert(new_ckpoint->ecp_state == ECS_NEW);
    add_st = id_list_add(&new_ckpoint->ecp_stream_ids[ stream_id & 1 ],
                         stream_id >> 1);
    if (add_st == ILA_ERROR)
        return NULL;

    /* See SPEC, Section 4.1.1 */
    new_entry_id = id_list_min_unused(&enc->qme_entry_ids);
    assert(new_entry_id >= QMIN_STATIC_TABLE_N_ENTRIES + 1);
    arr_idx = new_entry_id - QMIN_STATIC_TABLE_N_ENTRIES - 1;
    if (arr_idx >= enc->qme_entries.count)
    {
        struct enc_table_entry **new_entries;
        unsigned count;
        if (enc->qme_entries.count)
            count = enc->qme_entries.count * 2;
        else
            count = 8;
        new_entries = realloc(enc->qme_entries.arr,
                                    sizeof(enc->qme_entries.arr[0]) * count);
        if (!new_entries)
            return NULL;
        memset(new_entries + enc->qme_entries.count, 0,
                sizeof(new_entries[0]) * (count - enc->qme_entries.count));
        enc->qme_entries.arr = new_entries;
        enc->qme_entries.count = count;
    }

    if (enc->qme_nelem >= N_BUCKETS(enc->qme_nbits) / 2
        && 0 != qmin_enc_grow_tables(enc))
    {
        return NULL;
    }

    size = sizeof(*entry) + name_len + value_len;
    entry = malloc(size);
    if (!entry)
        return NULL;

    assert(!enc->qme_entries.arr[arr_idx]);
    enc->qme_entries.arr[arr_idx] = entry;
    add_st = id_list_add(&enc->qme_entry_ids, new_entry_id);
    assert(add_st != ILA_EXISTS);
    if (add_st != ILA_ADDED)
    {
        free(entry);
        return NULL;
    }

    add_st = id_list_add(&new_ckpoint->ecp_entry_ids, new_entry_id);
    if (add_st == ILA_ERROR)
        return NULL;

    name_hash = djb2(DJB2_INIT, &name_len, sizeof(name_len));
    name_hash = djb2(name_hash, name, name_len);
    nameval_hash = djb2(name_hash, &value_len, sizeof(value_len));
    nameval_hash = djb2(nameval_hash, value, value_len);

    entry->ete_name_hash = name_hash;
    entry->ete_nameval_hash = nameval_hash;
    entry->ete_name_len = name_len;
    entry->ete_val_len = value_len;
    entry->ete_id = new_entry_id;
    entry->ete_live_refcnt = 0;
    entry->ete_total_refcnt = 1;
    memcpy(ETE_NAME(entry), name, name_len);
    memcpy(ETE_VALUE(entry), value, value_len);

    buckno = BUCKNO(enc->qme_nbits, nameval_hash);
    TAILQ_INSERT_TAIL(&enc->qme_buckets[buckno].by_nameval, entry,
                      ete_next_nameval);
    buckno = BUCKNO(enc->qme_nbits, name_hash);
    TAILQ_INSERT_TAIL(&enc->qme_buckets[buckno].by_name, entry, ete_next_name);

    ++enc->qme_nelem;

    return entry;
}


/* Used to send HPACK binary-equivalent messages QMM_DUPLICATE and
 * QMM_INSERT.
 */
static void
send_control_message (struct qmin_enc *enc, const void *buf, size_t bufsz)
{
    enc->qme_ctl_out->qco_write(enc->qme_ctl_out->qco_ctx, buf, bufsz);
    enc->qme_bytes_out += bufsz;
}


static void
send_duplicate_cmd (struct qmin_enc *enc, unsigned entry_id)
{
    unsigned char *end, cmd_buf[10];

    cmd_buf[0] = QMM_DUPLICATE;
    end = qmin_encode_int(cmd_buf, cmd_buf + sizeof(cmd_buf), entry_id, 7);
    send_control_message(enc, cmd_buf, end - cmd_buf);
}


static size_t
checkpoint_size (const struct qmin_enc *enc)
{
    return QMIN_CKPOINT_OVERHEAD
        + (id_list_max(&enc->qme_entry_ids)
                                - QMIN_STATIC_TABLE_N_ENTRIES - 1) / 8;
}


static size_t
qmin_enc_size (const struct qmin_enc *enc)
{
    const struct enc_checkpoint *ckpoint;
    size_t size;
    size_t ckpoint_size;
    unsigned n;

    size = 0;
    for (n = 0; n < enc->qme_entries.count; ++n)
        if (enc->qme_entries.arr[n])
            size += QMIN_DYNAMIC_ENTRY_OVERHEAD
                 + enc->qme_entries.arr[n]->ete_name_len
                 + enc->qme_entries.arr[n]->ete_val_len;

    ckpoint_size = checkpoint_size(enc);
    TAILQ_FOREACH(ckpoint, &enc->qme_checkpoints, ecp_next)
        size += ckpoint_size;

    return size;
}


static int
flush (struct qmin_enc *enc)
{
    struct enc_checkpoint *ckpoint;
    const char flush_cmd[1] = { QMM_FLUSH_CHKPOINT, };

    ckpoint = enc_ckpoint_new(0, 0);
    if (!ckpoint)
        return -1;

    TRACE("performing flush...\n");
    enc->qme_streams_since_last_flush = 0;

    TAILQ_FIRST(&enc->qme_checkpoints)->ecp_state = ECS_PENDING;
    TAILQ_INSERT_HEAD(&enc->qme_checkpoints, ckpoint, ecp_next);

    send_control_message(enc, flush_cmd, sizeof(flush_cmd));
    return 0;
}


static int
maybe_flush (struct qmin_enc *enc)
{
    const struct enc_checkpoint *new_ckpoint;
    size_t table_size;

    new_ckpoint = TAILQ_FIRST(&enc->qme_checkpoints);
    if (TAILQ_NEXT(new_ckpoint, ecp_next) &&
        TAILQ_NEXT(new_ckpoint, ecp_next)->ecp_state == ECS_PENDING)
    {
        return 0;   /* Not flushable */
    }

    if (0 == id_list_count(&new_ckpoint->ecp_entry_ids))
        return 0;   /* Nothing to flush */

    table_size = qmin_enc_size(enc);
    if (table_size + checkpoint_size(enc) > enc->qme_max_capacity)
        return 0;   /* Not flushable */

    if (enc->qme_streams_since_last_flush > 0
        && table_size < enc->qme_max_capacity / 2)
    {
        return flush(enc);
    }

    if (enc->qme_streams_since_last_flush >= 10)
        return flush(enc);

    return 0;
}


static int
add_stream_ref_to_live_ckpoint (struct qmin_enc *enc, unsigned entry_id,
                                unsigned stream_id)
{
    struct enc_checkpoint *ckpoint;
    unsigned idx;

    idx = stream_id & 1;
    stream_id >>= 1;

    TAILQ_FOREACH(ckpoint, &enc->qme_checkpoints, ecp_next)
        if (ckpoint->ecp_state == ECS_LIVE
            && id_list_exists(&ckpoint->ecp_entry_ids, entry_id))
        {
            switch (id_list_add(&ckpoint->ecp_stream_ids[idx], stream_id))
            {
            case ILA_EXISTS:
            case ILA_ADDED:
                return 0;
            default:
                assert(0);
            case ILA_ERROR:
                return -1;
            }
        }

    assert(0);
    return -1;
}


enum enc_action
{
    EA_INSERT_ENTRY        = (1 << 0),
    EA_DUPLICATE_ENTRY     = (1 << 1),
    EA_LINK_HEADER_NEW_CK  = (1 << 2),
    EA_UPDATE_LIVE_CK      = (1 << 3),
    EA_USE_FOUND_ENTRY     = (1 << 4),
    EA_NOOP                = (1 << 5),
};


enum entry_status
{
    ES_ENTRY_NOT_FOUND,
    ES_ENTRY_FOUND_LIVE_ONLY,
    ES_ENTRY_FOUND_NEW_ONLY,
    ES_ENTRY_FOUND_PEND_ONLY,
    ES_ENTRY_FOUND_LIVE_AND_NEW,
    ES_ENTRY_FOUND_LIVE_AND_PEND,
};


/* Even though there are eight possibilities, the actions are fewer than that: */
static const enum entry_status fi2es[] =
{
    [   0           | 0             | 0         ] = ES_ENTRY_NOT_FOUND,
    [   0           | 0             | FI_NEW    ] = ES_ENTRY_FOUND_NEW_ONLY,
    [   0           | FI_PENDING    | 0         ] = ES_ENTRY_FOUND_PEND_ONLY,
    [   0           | FI_PENDING    | FI_NEW    ] = ES_ENTRY_FOUND_NEW_ONLY,
    [   FI_LIVE     | 0             | 0         ] = ES_ENTRY_FOUND_LIVE_ONLY,
    [   FI_LIVE     | 0             | FI_NEW    ] = ES_ENTRY_FOUND_LIVE_AND_NEW,
    [   FI_LIVE     | FI_PENDING    | 0         ] = ES_ENTRY_FOUND_LIVE_AND_PEND,
    [   FI_LIVE     | FI_PENDING    | FI_NEW    ] = ES_ENTRY_FOUND_LIVE_AND_NEW,
};


/*
 * Assuming ix_type is QIT_YES:
 *
 *                                     ,---------- Header field seen before
 *                                     |   ,------ Entry found in
 *                                     |  |  ,---- Header value matched
 *                                     |  |  |  ,- Found static entry
 *                                     |  |  |  |
 *                                     |  |  |  |                             */
static const enum enc_action g_actions[2][6][2][2] = {
/*   ,---------- Header field seen before
 *   |   ,------ Entry found in
 *   |  |                             ,---- Header value matched
 *   |  |                             |  ,- Found static entry
 *   |  |                             |  |
 *   |  |                             |  |                             */
    [0][ES_ENTRY_NOT_FOUND ]         [0][0] = EA_NOOP,
    [0][ES_ENTRY_NOT_FOUND ]         [0][1] = 0,
    [0][ES_ENTRY_NOT_FOUND ]         [1][0] = 0,
    [0][ES_ENTRY_NOT_FOUND ]         [1][1] = 0,
    [0][ES_ENTRY_FOUND_LIVE_ONLY]    [0][0] = EA_USE_FOUND_ENTRY | EA_DUPLICATE_ENTRY | EA_LINK_HEADER_NEW_CK | EA_UPDATE_LIVE_CK,
    [0][ES_ENTRY_FOUND_LIVE_ONLY]    [0][1] = EA_USE_FOUND_ENTRY,
    [0][ES_ENTRY_FOUND_LIVE_ONLY]    [1][0] = EA_USE_FOUND_ENTRY | EA_DUPLICATE_ENTRY | EA_LINK_HEADER_NEW_CK | EA_UPDATE_LIVE_CK,
    [0][ES_ENTRY_FOUND_LIVE_ONLY]    [1][1] = EA_USE_FOUND_ENTRY,
    [0][ES_ENTRY_FOUND_PEND_ONLY ]   [0][0] = EA_NOOP,
    [0][ES_ENTRY_FOUND_PEND_ONLY ]   [0][1] = 0, /* Static entries do not exist in pending checkpoints */
    [0][ES_ENTRY_FOUND_PEND_ONLY ]   [1][0] = 0, /* If haven't seen, how can it be found? */  /* XXX */
    [0][ES_ENTRY_FOUND_PEND_ONLY ]   [1][1] = 0, /* Static entries do not exist in pending checkpoints */
    [0][ES_ENTRY_FOUND_NEW_ONLY ]    [0][0] = EA_NOOP,
    [0][ES_ENTRY_FOUND_NEW_ONLY ]    [0][1] = 0, /* Static entries do not exist in new checkpoints */
    [0][ES_ENTRY_FOUND_NEW_ONLY ]    [1][0] = 0, /* If haven't seen, how can it be found? */  /* XXX */
    [0][ES_ENTRY_FOUND_NEW_ONLY ]    [1][1] = 0, /* Static entries do not exist in new checkpoints */
    [0][ES_ENTRY_FOUND_LIVE_AND_PEND][0][0] = EA_USE_FOUND_ENTRY | EA_UPDATE_LIVE_CK | EA_LINK_HEADER_NEW_CK | EA_DUPLICATE_ENTRY,
    [0][ES_ENTRY_FOUND_LIVE_AND_PEND][0][1] = 0, /* Static entries do not exist in pending checkpoints */
    [0][ES_ENTRY_FOUND_LIVE_AND_PEND][1][0] = 0, /* If haven't seen, how can it be found? */
    [0][ES_ENTRY_FOUND_LIVE_AND_PEND][1][1] = 0, /* Static entries do not exist in pending checkpoints */
    [0][ES_ENTRY_FOUND_LIVE_AND_NEW] [0][0] = EA_USE_FOUND_ENTRY | EA_UPDATE_LIVE_CK | EA_LINK_HEADER_NEW_CK,
    [0][ES_ENTRY_FOUND_LIVE_AND_NEW] [0][1] = 0, /* Static entries do not exist in new checkpoints */
    [0][ES_ENTRY_FOUND_LIVE_AND_NEW] [1][0] = 0, /* If haven't seen, how can it be found? */
    [0][ES_ENTRY_FOUND_LIVE_AND_NEW] [1][1] = 0, /* Static entries do not exist in new checkpoints */
/*   ,---------- Header field seen before
 *   |   ,------ Entry found in
 *   |  |                             ,---- Header value matched
 *   |  |                             |  ,- Found static entry
 *   |  |                             |  |
 *   |  |                             |  |                             */
    [1][ES_ENTRY_NOT_FOUND ]         [0][0] = EA_INSERT_ENTRY | EA_LINK_HEADER_NEW_CK,
    [1][ES_ENTRY_NOT_FOUND ]         [0][1] = 0,
    [1][ES_ENTRY_NOT_FOUND ]         [1][0] = 0,
    [1][ES_ENTRY_NOT_FOUND ]         [1][1] = 0,
    [1][ES_ENTRY_FOUND_LIVE_ONLY]    [0][0] = EA_USE_FOUND_ENTRY | EA_INSERT_ENTRY | EA_DUPLICATE_ENTRY | EA_UPDATE_LIVE_CK | EA_LINK_HEADER_NEW_CK,
    [1][ES_ENTRY_FOUND_LIVE_ONLY]    [0][1] = EA_USE_FOUND_ENTRY | EA_INSERT_ENTRY | EA_LINK_HEADER_NEW_CK,
    [1][ES_ENTRY_FOUND_LIVE_ONLY]    [1][0] = EA_USE_FOUND_ENTRY | EA_DUPLICATE_ENTRY | EA_UPDATE_LIVE_CK | EA_LINK_HEADER_NEW_CK,
    [1][ES_ENTRY_FOUND_LIVE_ONLY]    [1][1] = EA_USE_FOUND_ENTRY,
    [1][ES_ENTRY_FOUND_NEW_ONLY ]    [0][0] = EA_LINK_HEADER_NEW_CK,
    [1][ES_ENTRY_FOUND_NEW_ONLY ]    [0][1] = 0, /* Static entries do not exist in new checkpoints */
    [1][ES_ENTRY_FOUND_NEW_ONLY ]    [1][0] = EA_LINK_HEADER_NEW_CK,
    [1][ES_ENTRY_FOUND_NEW_ONLY ]    [1][1] = 0, /* Static entries do not exist in new checkpoints */
    [1][ES_ENTRY_FOUND_PEND_ONLY ]   [0][0] = EA_LINK_HEADER_NEW_CK | EA_DUPLICATE_ENTRY | EA_INSERT_ENTRY,
    [1][ES_ENTRY_FOUND_PEND_ONLY ]   [0][1] = 0, /* Static entries do not exist in pending checkpoints */
    [1][ES_ENTRY_FOUND_PEND_ONLY ]   [1][0] = EA_LINK_HEADER_NEW_CK | EA_DUPLICATE_ENTRY,
    [1][ES_ENTRY_FOUND_PEND_ONLY ]   [1][1] = 0, /* Static entries do not exist in pending checkpoints */
    [1][ES_ENTRY_FOUND_LIVE_AND_NEW] [0][0] = EA_USE_FOUND_ENTRY | EA_INSERT_ENTRY | EA_UPDATE_LIVE_CK,
    [1][ES_ENTRY_FOUND_LIVE_AND_NEW] [0][1] = 0, /* Static entries do not exist in new checkpoints */
    [1][ES_ENTRY_FOUND_LIVE_AND_NEW] [1][0] = EA_USE_FOUND_ENTRY | EA_UPDATE_LIVE_CK,
    [1][ES_ENTRY_FOUND_LIVE_AND_NEW] [1][1] = 0, /* Static entries do not exist in new checkpoints */
    [1][ES_ENTRY_FOUND_LIVE_AND_PEND][0][0] = EA_USE_FOUND_ENTRY | EA_INSERT_ENTRY | EA_UPDATE_LIVE_CK | EA_DUPLICATE_ENTRY | EA_LINK_HEADER_NEW_CK,
    [1][ES_ENTRY_FOUND_LIVE_AND_PEND][0][1] = 0, /* Static entries do not exist in new checkpoints */
    [1][ES_ENTRY_FOUND_LIVE_AND_PEND][1][0] = EA_USE_FOUND_ENTRY | EA_UPDATE_LIVE_CK | EA_LINK_HEADER_NEW_CK | EA_DUPLICATE_ENTRY,
    [1][ES_ENTRY_FOUND_LIVE_AND_PEND][1][1] = 0, /* Static entries do not exist in new checkpoints */
};


static int
maybe_update_checkpoints (struct qmin_enc *enc, enum enc_action actions,
           unsigned stream_id, unsigned live_entry_id, unsigned new_entry_id)
{
    struct enc_checkpoint *const new_ckpoint = TAILQ_FIRST(&enc->qme_checkpoints);
    enum id_list_add_st add_st;

    if (actions & EA_UPDATE_LIVE_CK)
    {
        assert(live_entry_id);
        if (0 != add_stream_ref_to_live_ckpoint(enc, live_entry_id, stream_id))
            return -1;
    }

    if (actions & EA_LINK_HEADER_NEW_CK)
    {
        add_st = id_list_add(&new_ckpoint->ecp_stream_ids[ stream_id & 1],
                             stream_id >> 1);
        if (add_st == ILA_ERROR)
            return -1;
        add_st = id_list_add(&new_ckpoint->ecp_entry_ids, new_entry_id);
        if (add_st == ILA_ERROR)
            return -1;
        if (add_st == ILA_ADDED)
            ++enc->qme_entries.arr[
                new_entry_id - QMIN_STATIC_TABLE_N_ENTRIES - 1
                    ]->ete_total_refcnt;
    }

    if (actions & EA_DUPLICATE_ENTRY)
    {
        add_st = id_list_add(&new_ckpoint->ecp_entry_ids, live_entry_id);
        if (add_st == ILA_ERROR)
            return -1;
        if (add_st == ILA_ADDED)
            ++enc->qme_entries.arr[
                live_entry_id - QMIN_STATIC_TABLE_N_ENTRIES - 1
                    ]->ete_total_refcnt;
    }

    return 0;
}


/* Returns true if push is allowed.  Calling this function may trigger a
 * flush instead.  (See SPEC, Section 7.4).
 */
static bool
check_table_size_before_push (struct qmin_enc *enc, unsigned name_len,
                              unsigned val_len)
{
    size_t table_size, entry_size;

    table_size = qmin_enc_size(enc);
    entry_size = QMIN_DYNAMIC_ENTRY_OVERHEAD + name_len + val_len;

    if (table_size + entry_size > enc->qme_max_capacity)
        return false;

    if (table_size + entry_size + checkpoint_size(enc) > enc->qme_max_capacity)
    {
        maybe_flush(enc);
        return false;
    }

    return true;
}


enum qmin_encode_status
qmin_enc_encode (struct qmin_enc *enc, unsigned stream_id, const char *name,
    unsigned name_len,
    const char *value, unsigned value_len, enum qmin_index_type ix_type,
    unsigned char *dst, size_t dst_sz, size_t *n_written)
{
    static const char indexed_prefix_number[] = {0x40, 0x00, 0x10};
    unsigned char *const dst_orig = dst;
    unsigned char *const dst_end = dst + dst_sz;
    struct entry_search_result esr;
    enum enc_action actions;
    int rc;

    TRACE("called %s(stream_id: %u, ix_type: %u, %.*s: %.*s)\n", __func__,
            stream_id, ix_type, name_len, name, value_len, value);

    if (stream_id > enc->qme_max_opened_stream_id)
        enc->qme_max_opened_stream_id = stream_id;

    if (enc->qme_side == QSIDE_CLIENT && ((stream_id & 1) != QSIDE_CLIENT))
        return QES_ERR;

    if (dst_end <= dst)
        return QES_NOBUFS;

    rc = maybe_flush(enc);
    if (rc != 0)
        return QES_ERR;

    enc->qme_bytes_in += name_len + value_len;

    esr = qmin_enc_find_entry(enc, name, name_len, value, value_len);

    if (ix_type == QIT_YES)
    {
        enum entry_status est;
        enum enc_hist_add_st eha_st;

        eha_st = enc_hist_add(&enc->qme_enc_hist, esr.esr_nameval_hash);

        est = fi2es[ esr.esr_found_in ];

        actions = g_actions
            [eha_st == EHA_EXISTS]
            [est]
            [esr.esr_val_matched]
            [esr.esr_entry_id >= 1
                        && esr.esr_entry_id <= QMIN_STATIC_TABLE_N_ENTRIES];

        if (!actions)
        {
            assert(0);
            return QES_ERR;
        }

        if ((actions & EA_INSERT_ENTRY)
            && !check_table_size_before_push(enc, name_len, value_len))
        {
            /* Pretend we did not find anything.  This is a bit hacky and
             * may indicate suboptimal code (or spec).
             */
            TRACE("up to memory limit: cannot push entry\n");
            actions = EA_NOOP;
        }
    }
    else if (esr.esr_entry_id > 0)
        actions = EA_USE_FOUND_ENTRY;
    else
        actions = EA_NOOP;

    if (actions & EA_USE_FOUND_ENTRY)
    {
        assert(esr.esr_entry_id > 0);

        if (actions & EA_DUPLICATE_ENTRY)
        {
            struct enc_checkpoint *ckpoint = TAILQ_FIRST(&enc->qme_checkpoints);
            assert(!id_list_exists(&ckpoint->ecp_entry_ids, esr.esr_entry_id));
            send_duplicate_cmd(enc, esr.esr_entry_id);
            TRACE("duplicate entry %u\n", esr.esr_entry_id);
        }

        if (esr.esr_val_matched)
        {
            *dst = 0x80;
            dst = qmin_encode_int(dst, dst_end, esr.esr_entry_id, 7);
            if (dst == dst_orig)
                return QES_NOBUFS;
            if (0 != maybe_update_checkpoints(enc, actions, stream_id,
                                         esr.esr_entry_id, esr.esr_entry_id))
                return -1;
            *n_written = dst - dst_orig;
            enc->qme_bytes_out += dst - dst_orig;
            return QES_OK;
        }
        else
        {
            *dst = indexed_prefix_number[ix_type];
            dst = qmin_encode_int(dst, dst_end, esr.esr_entry_id,
                               ix_type == QIT_YES ? 6 : 4);
            if (dst == dst_orig)
                return QES_NOBUFS;
        }
    }
    else
    {
        *dst++ = indexed_prefix_number[ix_type];
        rc = qmin_enc_enc_str(dst, dst_end - dst,
                              (const unsigned char *) name, name_len);
        if (rc < 0)
            return QES_ERR;
        dst += rc;
    }

    rc = qmin_enc_enc_str(dst, dst_end - dst, (const unsigned char *)value, value_len);
    if (rc < 0)
        return QES_ERR;
    dst += rc;

    if (actions & EA_INSERT_ENTRY)
    {
        const struct enc_table_entry *new_entry;
        new_entry = qmin_enc_push_entry(enc, stream_id, name, name_len, value,
                                        value_len);
        if (!new_entry)
            return QES_ERR;
        if (0 != maybe_update_checkpoints(enc, actions, stream_id,
                                          esr.esr_entry_id, new_entry->ete_id))
            return QES_ERR;
        send_control_message(enc, dst_orig, dst - dst_orig);
        TRACE("insert entry %u\n", new_entry->ete_id);
    }
    else if (0 != maybe_update_checkpoints(enc, actions, stream_id,
                                           esr.esr_entry_id, esr.esr_entry_id))
            return QES_ERR;

    *n_written = dst - dst_orig;
    enc->qme_bytes_out += dst - dst_orig;
    return QES_OK;
}


size_t
qmin_enc_mem_used (const struct qmin_enc *enc)
{
    const struct enc_checkpoint *ckpoint;
    size_t size;
    unsigned n;

    size = sizeof(*enc);

    for (n = 0; n < enc->qme_entries.count; ++n)
        if (enc->qme_entries.arr[n])
            size += sizeof(*enc->qme_entries.arr[n])
                  + enc->qme_entries.arr[n]->ete_name_len
                  + enc->qme_entries.arr[n]->ete_val_len;

    size += sizeof(enc->qme_entries.arr[n]) * enc->qme_entries.count;

    size += id_list_mem_used(&enc->qme_closed_stream_ids[0].list);
    size += id_list_mem_used(&enc->qme_closed_stream_ids[1].list);

    TAILQ_FOREACH(ckpoint, &enc->qme_checkpoints, ecp_next)
        size += enc_ckpoint_mem_used(ckpoint);

    return size;
}


static int
issue_drop_ckpoint_cmd (struct qmin_enc *enc, unsigned position)
{
    unsigned char *end, cmd_buf[10];

    cmd_buf[0] = QMM_DROP_CHKPOINT;
    end = qmin_encode_int(cmd_buf, cmd_buf + sizeof(cmd_buf), position, 2);
    if (end <= cmd_buf)
        return -1;

    send_control_message(enc, cmd_buf, end - cmd_buf);
    return 0;
}


static void
drop_unreferenced_entries (struct qmin_enc *enc, struct enc_checkpoint *ckpoint)
{
    struct enc_table_entry *entry;
    unsigned buckno, entry_id, idx;

    id_list_reset_iter(&ckpoint->ecp_entry_ids);
    while ((entry_id = id_list_next(&ckpoint->ecp_entry_ids)) != INVALID_ID)
    {
        idx = entry_id - QMIN_STATIC_TABLE_N_ENTRIES - 1;
        entry = enc->qme_entries.arr[idx];
        assert(entry->ete_total_refcnt > 0);
        --entry->ete_total_refcnt;
        if (0 == entry->ete_total_refcnt)
        {
            assert(entry->ete_live_refcnt == 0);
            enc->qme_entries.arr[idx] = NULL;
            id_list_del(&enc->qme_entry_ids, entry_id);
            buckno = BUCKNO(enc->qme_nbits, entry->ete_name_hash);
            TAILQ_REMOVE(&enc->qme_buckets[buckno].by_name, entry,
                                                        ete_next_name);
            buckno = BUCKNO(enc->qme_nbits, entry->ete_nameval_hash);
            TAILQ_REMOVE(&enc->qme_buckets[buckno].by_nameval, entry,
                                                        ete_next_nameval);
            --enc->qme_nelem;
            free(entry);
        }
    }
}


static int
maybe_drop_checkpoints (struct qmin_enc *enc)
{
    struct enc_checkpoint *ckpoint, *prev;
    unsigned position;

    position = 0;
    for (ckpoint = TAILQ_LAST(&enc->qme_checkpoints, checkpoint_head);
                                                        ckpoint; ckpoint = prev)
    {
        prev = TAILQ_PREV(ckpoint, checkpoint_head, ecp_next);
        if (ckpoint->ecp_state == ECS_DEAD
            && 0 == id_list_count(&ckpoint->ecp_stream_ids[0])
            && 0 == id_list_count(&ckpoint->ecp_stream_ids[1]))
        {
            TAILQ_REMOVE(&enc->qme_checkpoints, ckpoint, ecp_next);
            drop_unreferenced_entries(enc, ckpoint);
            enc_ckpoint_destroy(ckpoint);
            if (0 != issue_drop_ckpoint_cmd(enc, position))
                return -1;
            TRACE("dropped checkpoint #%u\n", position);
        }
        else
            ++position;
    }

    return 0;
}


static void
decref_live_ckpoint_entries (struct qmin_enc *enc, struct enc_checkpoint *ckpoint)
{
    unsigned entry_id, idx;

    id_list_reset_iter(&ckpoint->ecp_entry_ids);
    while ((entry_id = id_list_next(&ckpoint->ecp_entry_ids)) != INVALID_ID)
    {
        assert(entry_id > QMIN_STATIC_TABLE_N_ENTRIES);
        idx = entry_id - QMIN_STATIC_TABLE_N_ENTRIES - 1;
        assert(idx < enc->qme_entries.count);
        assert(enc->qme_entries.arr[idx]);
        assert(enc->qme_entries.arr[idx]->ete_live_refcnt > 0);
        --enc->qme_entries.arr[ idx ]->ete_live_refcnt;
    }
}


static void
declare_one_checkpoint_dead (struct qmin_enc *enc)
{
    struct enc_checkpoint *ckpoint, *victim;
    unsigned min_count, count;

    min_count = ~0;
    victim = NULL;

    /* Pick oldest LIVE enc_checkpoint with minumum number of entries: */
    TAILQ_FOREACH(ckpoint, &enc->qme_checkpoints, ecp_next)
    {
        /* For the PoC implementation, one dead enc_checkpoint is enough: */
        if (ckpoint->ecp_state == ECS_DEAD)
            return;

        if (ckpoint->ecp_state == ECS_LIVE)
        {
            count = id_list_count(&ckpoint->ecp_stream_ids[0])
                  + id_list_count(&ckpoint->ecp_stream_ids[1]);
            if (count <= min_count)
            {
                min_count = count;
                victim = ckpoint;
            }
        }
    }

    if (victim)
    {
        decref_live_ckpoint_entries(enc, victim);
        victim->ecp_state = ECS_DEAD;
    }
}


static size_t
low_mem_threshold (const struct qmin_enc *enc)
{
    return enc->qme_max_capacity * 3 / 4;
}


static size_t
high_mem_threshold (const struct qmin_enc *enc)
{
    return enc->qme_max_capacity * 15 / 16;
}


static unsigned
n_dead_checkpoints (const struct qmin_enc *enc)
{
    const struct enc_checkpoint *ckpoint;
    unsigned count;

    count = 0;
    TAILQ_FOREACH(ckpoint, &enc->qme_checkpoints, ecp_next)
        count += ckpoint->ecp_state == ECS_DEAD;

    return count;
}


static void
maybe_declare_dead_checkpoints (struct qmin_enc *enc)
{
    size_t size;

    size = qmin_enc_size(enc);

    if (size > high_mem_threshold(enc)
        || (size > low_mem_threshold(enc) && n_dead_checkpoints(enc) == 0))
    {
        declare_one_checkpoint_dead(enc);
    }
}


static int
process_newly_closed_stream (struct qmin_enc *enc, unsigned stream_id)
{
    struct enc_checkpoint *ckpoint;
    unsigned idx;

    idx = stream_id & 1;
    stream_id >>= 1;

    TAILQ_FOREACH(ckpoint, &enc->qme_checkpoints, ecp_next)
        if (0 != id_list_del(&ckpoint->ecp_stream_ids[idx], stream_id))
            return -1;

    maybe_declare_dead_checkpoints(enc);

    if (0 != maybe_drop_checkpoints(enc))
        return -1;

    return 0;
}


int
qmin_enc_stream_done (struct qmin_enc *enc, unsigned stream_id)
{
    TRACE("called %s(%u)\n", __func__, stream_id);

    if (stream_id > enc->qme_max_opened_stream_id)
        return -1;

    switch (id_list_add(&enc->qme_closed_stream_ids[ stream_id & 1 ].list,
                        stream_id >> 1))
    {
    case ILA_ADDED:
        /* TODO: At this point we should try to reduce memory usage of
         * the stream ID list by dropping as many initial consecutive
         * full sets as possible.  This is because stream IDs are not
         * reused.
         */
        return process_newly_closed_stream(enc, stream_id);
    case ILA_EXISTS:
        return 0;
    default:
        assert(0);
    case ILA_ERROR:
        return -1;
    }
}


static void
move_checkpoint_to_live (struct qmin_enc *enc, struct enc_checkpoint *ckpoint)
{
    unsigned entry_id, idx;

    id_list_reset_iter(&ckpoint->ecp_entry_ids);
    while ((entry_id = id_list_next(&ckpoint->ecp_entry_ids)) != INVALID_ID)
    {
        assert(entry_id > QMIN_STATIC_TABLE_N_ENTRIES);
        idx = entry_id - QMIN_STATIC_TABLE_N_ENTRIES - 1;
        assert(idx < enc->qme_entries.count);
        assert(enc->qme_entries.arr[idx]);
        ++enc->qme_entries.arr[ idx ]->ete_live_refcnt;
    }

    ckpoint->ecp_state = ECS_LIVE;
}


int
qmin_enc_flush_acked (struct qmin_enc *enc)
{
    struct enc_checkpoint *ckpoint;

    TRACE("called %s()\n", __func__);

    TAILQ_FOREACH(ckpoint, &enc->qme_checkpoints, ecp_next)
        if (ckpoint->ecp_state == ECS_PENDING)
        {
            move_checkpoint_to_live(enc, ckpoint);
            return maybe_flush(enc);
        }

    assert(0);
    return -1;
}


static void
dump_checkpoint_state (struct enc_checkpoint *ckpoint, FILE *out)
{
    unsigned id;

    fprintf(out, "  CHECKPOINT: %s\n",
                              ckpoint->ecp_state == ECS_NEW     ? "NEW" :
                              ckpoint->ecp_state == ECS_PENDING ? "PENDING" :
                              ckpoint->ecp_state == ECS_LIVE    ? "LIVE" :
                              ckpoint->ecp_state == ECS_DEAD    ? "DEAD" :
                                                                "UNKNOWN");

    fprintf(out, "   HEADER IDS:");
    id_list_reset_iter(&ckpoint->ecp_entry_ids);
    while ((id = id_list_next(&ckpoint->ecp_entry_ids)) != INVALID_ID)
        fprintf(out, " %u", id);
    fprintf(out, "\n");

    fprintf(out, "   STREAM IDS:");
    id_list_reset_iter(&ckpoint->ecp_stream_ids[0]);
    while ((id = id_list_next(&ckpoint->ecp_stream_ids[0])) != INVALID_ID)
        fprintf(out, " %u", id << 1);
    id_list_reset_iter(&ckpoint->ecp_stream_ids[1]);
    while ((id = id_list_next(&ckpoint->ecp_stream_ids[1])) != INVALID_ID)
        fprintf(out, " %u", 1 + (id << 1));
    fprintf(out, "\n");
}


static float
compression_ratio (const struct qmin_enc *enc)
{
    return (double) enc->qme_bytes_in / (double) enc->qme_bytes_out;
}


char *
qmin_enc_to_str (struct qmin_enc *enc, size_t *size)
{
    struct enc_checkpoint *ckpoint;
    unsigned n;
    FILE *out;
    char *buf;

    out = open_memstream(&buf, size);
    if (!out)
        return NULL;

    fprintf(out, "\n QMIN ENCODER STATE\n");
    fprintf(out, "  MEM: %zd out of %u (real size: %zd)\n", qmin_enc_size(enc),
                                enc->qme_max_capacity, qmin_enc_mem_used(enc));
    fprintf(out, "  COMPRESSION: Bytes in/out: %zd/%zd; ratio: %.2f\n",
        enc->qme_bytes_in, enc->qme_bytes_out, compression_ratio(enc));

    for (n = 0; n < enc->qme_entries.count; ++n)
        if (enc->qme_entries.arr[n])
            fprintf(out, "  ENTRY % 3d: (l:%u;t:%u) %.*s: %.*s\n",
                n + 1 + QMIN_STATIC_TABLE_N_ENTRIES,
                enc->qme_entries.arr[n]->ete_live_refcnt,
                enc->qme_entries.arr[n]->ete_total_refcnt,
                enc->qme_entries.arr[n]->ete_name_len, ETE_NAME(enc->qme_entries.arr[n]),
                enc->qme_entries.arr[n]->ete_val_len, ETE_VALUE(enc->qme_entries.arr[n]));

    TAILQ_FOREACH(ckpoint, &enc->qme_checkpoints, ecp_next)
        dump_checkpoint_state(ckpoint, out);

    fprintf(out, "\n");
    fflush(out);

    return buf;
}


int
qmin_enc_end_stream_headers (struct qmin_enc *enc)
{
    TRACE("called %s()\n", __func__);
    ++enc->qme_streams_since_last_flush;
    return maybe_flush(enc);
}


static enum dec_st
qmin_enc_msg_ack_flush (struct qmin_enc *enc, const unsigned char **cur_p,
                        const unsigned char *const end)
{
    if (0 == qmin_enc_flush_acked(enc))
    {
        ++*cur_p;
        return DEC_ST_OK;
    }
    else
        return DEC_ST_ERR;
}


static enum dec_st
qmin_enc_msg_stream_done (struct qmin_enc *enc, const unsigned char **cur_p,
                          const unsigned char *const end)
{
    const unsigned char *p = *cur_p;
    unsigned stream_id;
    enum dec_st st;

    st = qmin_decode_int(&p, end, 4, &stream_id);
    if (st == DEC_ST_OK)
    {
        if (0 == qmin_enc_stream_done(enc, stream_id))
            *cur_p = p;
        else
            st = DEC_ST_ERR;
    }

    return st;
}


ssize_t
qmin_enc_cmds_in (struct qmin_enc *enc, const void *buf, size_t bufsz)
{
    const unsigned char *p = buf;
    const unsigned char *const end = p + bufsz;
    enum dec_st cmd_st;

    while (p < end)
    {
        switch (qmin_char_to_qmm(*p))
        {
        case QMM_ACK_FLUSH:
            cmd_st = qmin_enc_msg_ack_flush(enc, &p, end);
            break;
        case QMM_STREAM_DONE:
            cmd_st = qmin_enc_msg_stream_done(enc, &p, end);
            break;
        default:
            return -1;
        }

        switch (cmd_st)
        {
        case DEC_ST_OK:
            break;
        case DEC_ST_NOBUF_SRC:
            goto end;
        default:
            assert(0);
        case DEC_ST_ERR:
            return -1;
        }
    }

  end:
    return p - (unsigned char *) buf;
}
