/* Copyright (c) 2017 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef QMIN_DEC_H
#define QMIN_DEC_H 1

#ifdef __cplusplus
extern "C" {
#endif

struct qmin_dec;
struct qmin_ctl_out;

struct qmin_dec *
qmin_dec_new (enum qmin_side, unsigned capacity,
                const struct qmin_ctl_out *, const char *);

void
qmin_dec_destroy (struct qmin_dec *);

/* Pass control channel commands directly to the encoder.  Returns number
 * of bytes processed or -1 on error.
 */
ssize_t
qmin_dec_cmds_in (struct qmin_dec *, const void *, size_t);

/* Decoded header field is placed into buffer pointed to by `dst'.  Header
 * name and value are not NUL-terminated.
 *
 * Return number of bytes processed or -1 on error.
 */
ssize_t
qmin_dec_decode (struct qmin_dec *, const void *src, size_t src_sz,
    char *dst, size_t dst_sz, unsigned *name_len, unsigned *val_len);

char *
qmin_dec_to_str (struct qmin_dec *, size_t *size);

/* Helper function to put the stream-done message onto the control stream. */
int
qmin_dec_stream_done (struct qmin_dec *, unsigned stream_id);

#ifdef __cplusplus
}
#endif

#endif
