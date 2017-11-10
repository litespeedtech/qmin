/* Copyright (c) 2017 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * qmin_dec.c - QMIN decoder
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
#include "qmin_dec.h"

enum dec_checkpoint_state
{
    DCS_NEW,
    DCS_LIVE,
};


struct dec_checkpoint
{
    TAILQ_ENTRY(dec_checkpoint)     dcp_next;

    /* IDs of entries added the the dynamic table when this dec_checkpoint
     * was in DCS_NEW state and those referenced when the checkpoint is in
     * DCS_LIVE state:
     */
    struct id_list                  dcp_entry_ids;

    enum dec_checkpoint_state       dcp_state;
};


static struct dec_checkpoint *
dec_ckpoint_new (void)
{
    struct dec_checkpoint *ckpoint;

    ckpoint = calloc(1, sizeof(*ckpoint));
    if (!ckpoint)
        return NULL;

    id_list_init(&ckpoint->dcp_entry_ids, QMIN_STATIC_TABLE_N_ENTRIES + 1);
    ckpoint->dcp_state = DCS_NEW;

    return ckpoint;
}


static void
dec_ckpoint_destroy (struct dec_checkpoint *ckpoint)
{
    id_list_cleanup(&ckpoint->dcp_entry_ids);
    free(ckpoint);
}


static size_t
dec_ckpoint_size (const struct dec_checkpoint *ckpoint)
{
    return sizeof(*ckpoint) - sizeof(ckpoint->dcp_entry_ids)
         + id_list_mem_used(&ckpoint->dcp_entry_ids);
}


struct dec_table_entry
{
    unsigned    dte_live_refcnt;
    unsigned    dte_total_refcnt;
    unsigned    dte_name_len;
    unsigned    dte_val_len;
    char        dte_buf[0];
};

#define DTE_NAME(dte) ((dte)->dte_buf)
#define DTE_VALUE(dte) (&(dte)->dte_buf[(dte)->dte_name_len])

TAILQ_HEAD(dec_ckpoint_head, dec_checkpoint);

struct qmin_dec
{
    enum {
        QMD_TRACE = (1 << 0),
    }                               qmd_flags;

    enum qmin_side                  qmd_side;

    struct dec_ckpoint_head         qmd_checkpoints;

    struct dec_table_entry        **qmd_entries;

    /* Number of elements in qmd_entries array.  NULL pointers are
     * allowed.
     */
    unsigned                        qmd_count;

    unsigned                        qmd_max_capacity;

    const struct qmin_ctl_out      *qmd_ctl_out;
};


#define TRACE(args...) do {                         \
    if (dec->qmd_flags & QMD_TRACE)                 \
        printf("DEC TRACE: " args), fflush(stdout); \
} while (0)


struct qmin_dec *
qmin_dec_new (enum qmin_side side, unsigned max_capacity,
              const struct qmin_ctl_out *ctl_out)
{
    struct qmin_dec *dec;
    struct dec_checkpoint *ckpoint;
    const char *s;

    if (max_capacity < QMIN_CKPOINT_OVERHEAD)
    {
        errno = EINVAL;
        return NULL;
    }

    ckpoint = dec_ckpoint_new();
    if (!ckpoint)
        return NULL;

    dec = calloc(1, sizeof(*dec));
    if (!dec)
    {
        dec_ckpoint_destroy(ckpoint);
        return NULL;
    }

    dec->qmd_side           = side;
    dec->qmd_max_capacity   = max_capacity;
    dec->qmd_ctl_out        = ctl_out;

    TAILQ_INIT(&dec->qmd_checkpoints);
    TAILQ_INSERT_HEAD(&dec->qmd_checkpoints, ckpoint, dcp_next);

    s = getenv("QMIN_DEC_TRACE");
    if (s && atoi(s))
        dec->qmd_flags |= QMD_TRACE;

    return dec;
}


static void
drop_unreferenced_entries (struct qmin_dec *dec, struct dec_checkpoint *ckpoint)
{
    struct dec_table_entry *entry;
    unsigned entry_id, idx;

    id_list_reset_iter(&ckpoint->dcp_entry_ids);
    while ((entry_id = id_list_next(&ckpoint->dcp_entry_ids)) != INVALID_ID)
    {
        idx = entry_id - QMIN_STATIC_TABLE_N_ENTRIES - 1;
        entry = dec->qmd_entries[idx];
        assert(entry);
        assert(entry->dte_total_refcnt > 0);
        --entry->dte_total_refcnt;
        entry->dte_live_refcnt -= ckpoint->dcp_state == DCS_LIVE;
        if (0 == entry->dte_total_refcnt)
        {
            TRACE("drop entry %u\n", entry_id);
            assert(entry->dte_live_refcnt == 0);
            dec->qmd_entries[idx] = NULL;
            free(entry);
        }
    }
}


void
qmin_dec_destroy (struct qmin_dec *dec)
{
    struct dec_checkpoint *ckpoint;
    unsigned n;

    while ((ckpoint = TAILQ_FIRST(&dec->qmd_checkpoints)))
    {
        TAILQ_REMOVE(&dec->qmd_checkpoints, ckpoint, dcp_next);
#ifndef NDEBUG
        drop_unreferenced_entries(dec, ckpoint);
#endif
        dec_ckpoint_destroy(ckpoint);
    }

    for (n = 0; n < dec->qmd_count; ++n)
        if (dec->qmd_entries[n])
        {
            assert(0);  /* refcount is wrong? */
            free(dec->qmd_entries[n]);
        }

    free(dec->qmd_entries);
    free(dec);
}


/* XXX This is inefficient.  I intend to change the way checkpoint size is
 * calculated, because once a checkpoint goes from NEW to LIVE, its size
 * does not change.  This would make calculations simpler, not to mention
 * more correct.
 */
static unsigned
dec_max_entry_id (const struct qmin_dec *dec)
{
    unsigned n, max;

    max = 0;
    for (n = 0; n < dec->qmd_count; ++n)
        if (dec->qmd_entries[n])
            max = n;

    return max + QMIN_STATIC_TABLE_N_ENTRIES + 1;
}


static size_t
dec_checkpoint_size (const struct qmin_dec *dec)
{
    return QMIN_CKPOINT_OVERHEAD
        + (dec_max_entry_id(dec) - QMIN_STATIC_TABLE_N_ENTRIES - 1) / 8;
}


static size_t
qmin_dec_size (const struct qmin_dec *dec)
{
    const struct dec_checkpoint *ckpoint;
    size_t size;
    size_t ckpoint_size;
    unsigned n;

    size = 0;
    for (n = 0; n < dec->qmd_count; ++n)
        if (dec->qmd_entries[n])
            size += QMIN_DYNAMIC_ENTRY_OVERHEAD
                 + dec->qmd_entries[n]->dte_name_len
                 + dec->qmd_entries[n]->dte_val_len;

    ckpoint_size = dec_checkpoint_size(dec);
    TAILQ_FOREACH(ckpoint, &dec->qmd_checkpoints, dcp_next)
        size += ckpoint_size;

    return size;
}


size_t
qmin_dec_mem_used (const struct qmin_dec *dec)
{
    const struct dec_checkpoint *ckpoint;
    size_t size;
    unsigned n;

    size = sizeof(*dec);

    for (n = 0; n < dec->qmd_count; ++n)
        if (dec->qmd_entries[n])
            size += sizeof(*dec->qmd_entries[n])
                  + dec->qmd_entries[n]->dte_name_len
                  + dec->qmd_entries[n]->dte_val_len;

    size += sizeof(dec->qmd_entries[n]) * dec->qmd_count;

    TAILQ_FOREACH(ckpoint, &dec->qmd_checkpoints, dcp_next)
        size += dec_ckpoint_size(ckpoint);

    return size;
}


static int
qmin_dec_drop_checkpoint (struct qmin_dec *dec, unsigned target_position)
{
    struct dec_checkpoint *ckpoint;
    unsigned cur_position;

    cur_position = 0;
    TAILQ_FOREACH_REVERSE(ckpoint, &dec->qmd_checkpoints, dec_ckpoint_head,
                          dcp_next)
    {
        if (cur_position == target_position)
        {
            if (ckpoint->dcp_state != DCS_LIVE)
                return -1;
            TAILQ_REMOVE(&dec->qmd_checkpoints, ckpoint, dcp_next);
            drop_unreferenced_entries(dec, ckpoint);
            dec_ckpoint_destroy(ckpoint);
            return 0;
        }
        ++cur_position;
    }

    return -1;
}


static int
qmin_dec_flush (struct qmin_dec *dec)
{
    struct dec_checkpoint *ckpoint;
    unsigned entry_id, idx;

    TRACE("called %s()\n", __func__);

    /* TODO: check memory */

    ckpoint = TAILQ_FIRST(&dec->qmd_checkpoints);
    assert(DCS_NEW == ckpoint->dcp_state);

    id_list_reset_iter(&ckpoint->dcp_entry_ids);
    while ((entry_id = id_list_next(&ckpoint->dcp_entry_ids)) != INVALID_ID)
    {
        assert(entry_id > QMIN_STATIC_TABLE_N_ENTRIES);
        idx = entry_id - QMIN_STATIC_TABLE_N_ENTRIES - 1;
        if (0 == dec->qmd_entries[ idx ]->dte_live_refcnt)
            TRACE("entry %u is now live\n", entry_id);
        ++dec->qmd_entries[ idx ]->dte_live_refcnt;
    }

    ckpoint->dcp_state = DCS_LIVE;

    ckpoint = dec_ckpoint_new();
    if (!ckpoint)
        return -1;

    TAILQ_INSERT_HEAD(&dec->qmd_checkpoints, ckpoint, dcp_next);

    const unsigned char ack_flush[1] = { QMM_ACK_FLUSH, };
    dec->qmd_ctl_out->qco_write(dec->qmd_ctl_out->qco_ctx, ack_flush,
                                sizeof(ack_flush));

    return 0;
}


static void
dump_checkpoint_state (struct dec_checkpoint *ckpoint, FILE *out)
{
    unsigned id;

    fprintf(out, "  CHECKPOINT: %s\n",
                              ckpoint->dcp_state == DCS_NEW     ? "NEW" :
                              ckpoint->dcp_state == DCS_LIVE    ? "LIVE" :
                                                      (assert(0), "UNKNOWN"));

    fprintf(out, "   HEADER IDS:");
    id_list_reset_iter(&ckpoint->dcp_entry_ids);
    while ((id = id_list_next(&ckpoint->dcp_entry_ids)) != INVALID_ID)
        fprintf(out, " %u", id);

    fprintf(out, "\n");
}


char *
qmin_dec_to_str (struct qmin_dec *dec, size_t *size)
{
    struct dec_checkpoint *ckpoint;
    unsigned n;
    FILE *out;
    char *buf;

    out = open_memstream(&buf, size);
    if (!out)
        return NULL;

    fprintf(out, "\n QMIN DECODER STATE\n");
    fprintf(out, "  MEM: %zd out of %u (real size: %zd)\n", qmin_dec_size(dec),
                                dec->qmd_max_capacity, qmin_dec_mem_used(dec));

    for (n = 0; n < dec->qmd_count; ++n)
        if (dec->qmd_entries[n])
            fprintf(out, "  ENTRY % 3d: (l:%u;t:%u) %.*s: %.*s\n",
                n + 1 + QMIN_STATIC_TABLE_N_ENTRIES,
                dec->qmd_entries[n]->dte_live_refcnt,
                dec->qmd_entries[n]->dte_total_refcnt,
                dec->qmd_entries[n]->dte_name_len, DTE_NAME(dec->qmd_entries[n]),
                dec->qmd_entries[n]->dte_val_len, DTE_VALUE(dec->qmd_entries[n]));

    TAILQ_FOREACH(ckpoint, &dec->qmd_checkpoints, dcp_next)
        dump_checkpoint_state(ckpoint, out);

    fprintf(out, "\n");
    fflush(out);

    return buf;
}


static struct dec_table_entry *
qmin_dec_get_live_entry (struct qmin_dec *dec, unsigned entry_id)
{
    unsigned idx;

    if (!(entry_id > QMIN_STATIC_TABLE_N_ENTRIES))
        return NULL;

    idx = entry_id - QMIN_STATIC_TABLE_N_ENTRIES - 1;
    if (idx >= dec->qmd_count)
        return NULL;

    if (!(dec->qmd_entries[idx]
          && dec->qmd_entries[idx]->dte_live_refcnt > 0))
        return NULL;

    return dec->qmd_entries[idx];
}


static int
qmin_dec_duplicate (struct qmin_dec *dec, unsigned entry_id)
{
    struct dec_checkpoint *ckpoint;
    struct dec_table_entry *entry;

    entry = qmin_dec_get_live_entry(dec, entry_id);
    if (!entry)         /* See SPEC, Section 4.1.2 */
        return -1;

    ckpoint = TAILQ_FIRST(&dec->qmd_checkpoints);
    switch (id_list_add(&ckpoint->dcp_entry_ids, entry_id))
    {
    case ILA_ADDED:
        ++entry->dte_total_refcnt;
        return 0;
    case ILA_EXISTS:    /* See SPEC, Section 4.1.2 */
        return -1;
    default:
        assert(0);
    case ILA_ERROR:
        return -1;
    }
}


enum
{
    QMIN_HUFFMAN_FLAG_ACCEPTED = 0x01,
    QMIN_HUFFMAN_FLAG_SYM = 0x02,
    QMIN_HUFFMAN_FLAG_FAIL = 0x04,
};


struct qmin_huff_decode_status
{
    uint8_t state;
    uint8_t eos;
};


static unsigned char *
qmin_dec_huff_dec4bits (uint8_t src_4bits, unsigned char *dst,
               struct qmin_huff_decode_status *status)
{
    const struct qmin_huff_decode cur_dec_code =
        qmin_huff_decode_tables[status->state][src_4bits];
    if (cur_dec_code.flags & QMIN_HUFFMAN_FLAG_FAIL) {
        return NULL; //failed
    }
    if (cur_dec_code.flags & QMIN_HUFFMAN_FLAG_SYM)
    {
        *dst = cur_dec_code.sym;
        dst++;
    }

    status->state = cur_dec_code.state;
    status->eos = ((cur_dec_code.flags & QMIN_HUFFMAN_FLAG_ACCEPTED) != 0);
    return dst;
}


static int
qmin_dec_huff_decode (const unsigned char *src, int src_len,
                                            unsigned char *dst, int dst_len)
{
    const unsigned char *p_src = src;
    const unsigned char *src_end = src + src_len;
    unsigned char *p_dst = dst;
    unsigned char *dst_end = dst + dst_len;
    struct qmin_huff_decode_status status = { 0, 1 };

    while (p_src != src_end)
    {
        if (p_dst == dst_end)
            return -2;
        if ((p_dst = qmin_dec_huff_dec4bits(*p_src >> 4, p_dst, &status))
                == NULL)
            return -1;
        if (p_dst == dst_end)
            return -2;
        if ((p_dst = qmin_dec_huff_dec4bits(*p_src & 0xf, p_dst, &status))
                == NULL)
            return -1;
        ++p_src;
    }

    if (!status.eos)
        return -1;

    return p_dst - dst;
}


static enum dec_st
qmin_dec_decode_str (char *dst, size_t dst_len, unsigned *dst_len_out,
                     const unsigned char **src, const unsigned char *src_end)
{
    int ret, is_huffman;
    enum dec_st st;
    unsigned len;

    if ((*src) == src_end)
        return DEC_ST_OK;

    is_huffman = (*(*src) & 0x80);
    st = qmin_decode_int(src, src_end, 7, &len);
    if (st != DEC_ST_OK)
        return st;

    if ((unsigned)(src_end - (*src)) < len)
        return DEC_ST_NOBUF_SRC;

    if (is_huffman)
    {
        ret = qmin_dec_huff_decode(*src, len, (unsigned char *) dst, dst_len);
        if (ret > 0)
        {
            *src += len;
            *dst_len_out = ret;
            return DEC_ST_OK;
        }
        else if (ret == -2)
            return DEC_ST_NOBUF_DST;
        else
        {
            assert(ret == -1);
            return DEC_ST_ERR;
        }
    }
    else
    {
        if (dst_len >= (size_t)(src_end - (*src)))
        {
            memcpy(dst, (*src), len);
            (*src) += len;
            *dst_len_out = len;
            return DEC_ST_OK;
        }
        else
            return DEC_ST_NOBUF_DST;
    }
}


static unsigned
qmin_dec_next_avail_id (const struct qmin_dec *dec)
{
    unsigned n;

    /* See SPEC, Section 4.1.1 */
    for (n = 0; n < dec->qmd_count; ++n)
        if (!dec->qmd_entries[n])
            break;

    return n + QMIN_STATIC_TABLE_N_ENTRIES + 1;
}


static int
qmin_dec_maybe_realloc_array (struct qmin_dec *dec, unsigned entry_id)
{
    struct dec_table_entry **new_entries;
    unsigned idx, new_count;

    idx = entry_id - QMIN_STATIC_TABLE_N_ENTRIES - 1;

    if (idx >= dec->qmd_count)
    {
        if (dec->qmd_count)
            new_count = dec->qmd_count * 2;
        else
            new_count = 8;
        assert(idx < new_count);
        new_entries = realloc(dec->qmd_entries,
                              sizeof(dec->qmd_entries[0]) * new_count);
        if (!new_entries)
            return -1;
        memset(new_entries + dec->qmd_count, 0,
               sizeof(dec->qmd_entries[0]) * (new_count - dec->qmd_count));
        dec->qmd_entries = new_entries;
        dec->qmd_count   = new_count;
    }

    return 0;
}


static enum dec_st
qmin_dec_cmd_duplicate (struct qmin_dec *dec, const unsigned char **cur_p,
                        const unsigned char *const end)
{
    const unsigned char *p = *cur_p;
    unsigned entry_id;
    enum dec_st st;

    st = qmin_decode_int(&p, end, 7, &entry_id);
    if (st == DEC_ST_OK)
    {
        if (0 == qmin_dec_duplicate(dec, entry_id))
        {
            TRACE("duplicated entry %u\n", entry_id);
            *cur_p = p;
        }
        else
            st = DEC_ST_ERR;
    }

    return st;
}


static enum dec_st
qmin_dec_cmd_insert (struct qmin_dec *dec, const unsigned char **cur_p,
                     const unsigned char *const end)
{
    unsigned name_entry_id, new_entry_id, name_len, val_len, dec_off, idx;
    struct dec_checkpoint *const new_ckpoint
                                    = TAILQ_FIRST(&dec->qmd_checkpoints);
    const struct dec_table_entry *name_entry;
    const struct qmin_hdr_tbl *static_entry;
    struct dec_table_entry *new_entry;
    const unsigned char *p = *cur_p;
    const char *name, *val;
    enum dec_st st;
    char decoded_buf[0x1000];

    st = qmin_decode_int(&p, end, 6, &name_entry_id);
    if (st != DEC_ST_OK)
        return st;

    if (name_entry_id)
    {
        if (name_entry_id > QMIN_STATIC_TABLE_N_ENTRIES)
        {
            /* See SPEC, Section 4.1.1 */
            name_entry = qmin_dec_get_live_entry(dec, name_entry_id);
            if (!name_entry)
                return DEC_ST_ERR;
            if (name_entry->dte_total_refcnt == name_entry->dte_live_refcnt)
                return DEC_ST_ERR;  /* This means no DUPLICATE command was
                                     * issued for this entry: it must already
                                     * exist in the NEW checkpoint before it
                                     * can be used.  (SPEC, Section 4.1.1).
                                     */
            name = DTE_NAME(name_entry);
            name_len = name_entry->dte_name_len;
        }
        else
        {
            static_entry = &qmin_stx_tab[ name_entry_id - 1 ];
            name = static_entry->name;
            name_len = static_entry->name_len;
        }
        dec_off = 0;
    }
    else
    {
        st = qmin_dec_decode_str(decoded_buf, sizeof(decoded_buf), &name_len,
                                 &p, end);
        if (st == DEC_ST_NOBUF_DST)
            return DEC_ST_ERR;          /* XXX We don't handle this yet */
        if (st != DEC_ST_OK)
            return st;
        name = decoded_buf;
        dec_off = name_len;
    }

    st = qmin_dec_decode_str(decoded_buf + dec_off,
                             sizeof(decoded_buf) - dec_off, &val_len, &p, end);
    if (st == DEC_ST_NOBUF_DST)
        return DEC_ST_ERR;          /* XXX We don't handle this yet */
    if (st != DEC_ST_OK)
        return st;
    val = decoded_buf + dec_off;

    new_entry_id = qmin_dec_next_avail_id(dec);
    if (0 != qmin_dec_maybe_realloc_array(dec, new_entry_id))
        return DEC_ST_ERR;

    if (ILA_ADDED != id_list_add(&new_ckpoint->dcp_entry_ids, new_entry_id))
        return DEC_ST_ERR;

    new_entry = malloc(sizeof(*new_entry) + name_len + val_len);
    if (!new_entry)
        return DEC_ST_ERR;

    new_entry->dte_total_refcnt  =  1;
    new_entry->dte_live_refcnt   =  0;
    new_entry->dte_name_len      =  name_len;
    new_entry->dte_val_len       =  val_len;
    memcpy(DTE_NAME(new_entry), name, name_len);
    memcpy(DTE_VALUE(new_entry), val, val_len);

    idx = new_entry_id - QMIN_STATIC_TABLE_N_ENTRIES - 1;
    dec->qmd_entries[idx] = new_entry;

    TRACE("inserted entry %u\n", new_entry_id);

    *cur_p = p;
    return DEC_ST_OK;
}


static enum dec_st
qmin_dec_cmd_drop_ckpoint (struct qmin_dec *dec, const unsigned char **cur_p,
                           const unsigned char *const end)
{
    const unsigned char *p = *cur_p;
    unsigned position;
    enum dec_st st;

    st = qmin_decode_int(&p, end, 2, &position);
    if (st == DEC_ST_OK)
    {
        if (0 == qmin_dec_drop_checkpoint(dec, position))
        {
            TRACE("dropped checkpoint #%u\n", position);
            *cur_p = p;
        }
        else
            st = DEC_ST_ERR;
    }

    return st;
}



static enum dec_st
qmin_dec_cmd_flush_ckpoint (struct qmin_dec *dec,
                const unsigned char **cur_p, const unsigned char *const end)
{
    if (0 == qmin_dec_flush(dec))
    {
        TRACE("flushed checkpoint\n");
        ++*cur_p;
        return DEC_ST_OK;
    }
    else
        return DEC_ST_ERR;
}


ssize_t
qmin_dec_cmds_in (struct qmin_dec *dec, const void *buf, size_t bufsz)
{
    const unsigned char *p = buf;
    const unsigned char *const end = p + bufsz;
    enum dec_st cmd_st;

    while (p < end)
    {
        switch (qmin_char_to_qmm(*p))
        {
        case QMM_DUPLICATE:
            cmd_st = qmin_dec_cmd_duplicate(dec, &p, end);
            break;
        case QMM_INSERT:
            cmd_st = qmin_dec_cmd_insert(dec, &p, end);
            break;
        case QMM_DROP_CHKPOINT:
            cmd_st = qmin_dec_cmd_drop_ckpoint(dec, &p, end);
            break;
        case QMM_FLUSH_CHKPOINT:
            cmd_st = qmin_dec_cmd_flush_ckpoint(dec, &p, end);
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


/* XXX If we run out of input or output buffer, we treat it as an error.
 *     There is enough information, however, to distinguish between all
 *     of these conditions.
 */
ssize_t
qmin_dec_decode (struct qmin_dec *dec, const void *void_src, size_t src_sz,
            char *dst, size_t dst_sz, unsigned *name_len, unsigned *val_len)
{
    const unsigned char *src = void_src;
    const unsigned char *const src_end = src + src_sz;
    const char *const dst_end = dst + dst_sz;
    struct dec_table_entry *entry;
    uint32_t index;
    int indexed_type;

    if (src == src_end)
        return 0;

    /* qmin_decode_int() sets `index' and advances `src'.  If we do not call
     * it, we set `index' and advance `src' ourselves:
     */
    if (*src & 0x80) //1 xxxxxxx
    {
        if (DEC_ST_OK != qmin_decode_int(&src, src_end, 7, &index))
            return -1;

        indexed_type = 3; //need to parse value
    }
    else if (*src > 0x40) //01 xxxxxx
    {
        if (DEC_ST_OK != qmin_decode_int(&src, src_end, 6, &index))
            return -1;

        indexed_type = 0;
    }
    else if (*src == 0x40) //custmized //0100 0000
    {
        indexed_type = 0;
        index = 0;
        ++src;
    }
    else if (*src & 0x20)
    {
        /* See SPEC, Section 8 */
        return -1;
    }

    //Never indexed
    else if (*src == 0x10)  //00010000
    {
        indexed_type = 2;
        index = 0;
        ++src;
    }
    else if ((*src & 0xf0) == 0x10)  //0001 xxxx
    {
        if (DEC_ST_OK != qmin_decode_int(&src, src_end, 4, &index))
            return -1;

        indexed_type = 2;
    }

    //without indexed
    else if (*src == 0x00)  //0000 0000
    {
        indexed_type = 1;
        index = 0;
        ++src;
    }
    else // 0000 xxxx
    {
        if (DEC_ST_OK != qmin_decode_int(&src, src_end, 4, &index))
            return -1;

        indexed_type = 1;
    }

    char *const name = dst;
    if (index > 0)
    {
        if (index <= QMIN_STATIC_TABLE_N_ENTRIES) //static table
        {
            if (qmin_stx_tab[index - 1].name_len > dst_end - dst)
                return -1;
            *name_len = qmin_stx_tab[index - 1].name_len;
            memcpy(name, qmin_stx_tab[index - 1].name, *name_len);
            if (indexed_type == 3)
            {
                if (qmin_stx_tab[index - 1].name_len +
                    qmin_stx_tab[index - 1].val_len > dst_end - dst)
                    return -1;
                *val_len = qmin_stx_tab[index - 1].val_len;
                memcpy(name + *name_len, qmin_stx_tab[index - 1].val, *val_len);
                return 1;
            }
        }
        else
        {
            entry = qmin_dec_get_live_entry(dec, index);
            if (entry == NULL)
                return -1;
            if (entry->dte_name_len > dst_end - dst)
                return -1;

            *name_len = entry->dte_name_len;
            memcpy(name, DTE_NAME(entry), *name_len);
            if (indexed_type == 3)
            {
                if (entry->dte_name_len + entry->dte_val_len > dst_end - dst)
                    return -1;
                *val_len = entry->dte_val_len;
                memcpy(name + *name_len, DTE_VALUE(entry), *val_len);
                return 1;
            }
        }
    }
    else
    {
        if (DEC_ST_OK != qmin_dec_decode_str(name, dst_end - dst,
                                             name_len, &src, src_end))
            return -1;
    }

    if (DEC_ST_OK != qmin_dec_decode_str(name + *name_len,
                            dst_end - dst - *name_len, val_len, &src, src_end))
        return -1;

    return src - (unsigned char *) void_src;
}
