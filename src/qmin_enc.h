/* Copyright (c) 2017 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * qmin_enc.h -- QMIN encoder
 */

#ifndef QMIN_ENC_H
#define QMIN_ENC_H 1


struct qmin_enc;
struct qmin_ctl_out;

struct qmin_enc *
qmin_enc_new (enum qmin_side, unsigned capacity, const struct qmin_ctl_out *);

void
qmin_enc_destroy (struct qmin_enc *);

enum qmin_index_type { QIT_YES, QIT_NO, QIT_NEVER, };

enum qmin_encode_status { QES_OK, QES_NOBUFS, QES_ERR, };

enum qmin_encode_status
qmin_enc_encode (struct qmin_enc *enc, unsigned stream_id, const char *name,
    unsigned name_len, const char *value, unsigned value_len,
    enum qmin_index_type, unsigned char *dst, size_t dst_sz, size_t *n_written);

int
qmin_enc_stream_done (struct qmin_enc *, unsigned stream_id);

size_t
qmin_enc_mem_used (const struct qmin_enc *);

char *
qmin_enc_to_str (struct qmin_enc *, size_t *);

int
qmin_enc_maybe_flush (struct qmin_enc *);

int
qmin_enc_flush_acked (struct qmin_enc *);

int
qmin_enc_end_stream_headers (struct qmin_enc *);

/* Pass control channel messages directly to the encoder.  Returns number
 * of bytes processed or -1 on error.
 */
ssize_t
qmin_enc_cmds_in (struct qmin_enc *, const void *, size_t);

#endif
