/* Copyright (c) 2017 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef QMIN_COMMON_H
#define QMIN_COMMON_H 1

enum qmin_side {
    /* Ordering is important: the values match the low bit in QUIC stream ID */
    QSIDE_SERVER,
    QSIDE_CLIENT,
};

/* These are the messages sent on the control channel: */
enum qmin_message
{
    /* DUPLICATE is an encoder-to-decoder command.  It instructs the decoder
     * to duplicate the specified dynamic table entry.  This command is
     * binary-equivalent to HPACK Indexed Header Field representation
     * (RFC 7541, Section 6.1).
     */
    QMM_DUPLICATE       = 0x80,

    /* INSERT is an encoder-to-decoder command.  It instructs the decoder to
     * create a new dynamic table entry.  This command is binary-equivalent
     * to HPACK Literal Header Field representation (RFC 7541, Sections 6.2.1
     * and 6.2.2).
     */
    QMM_INSERT          = 0x40,

    /* FLUSH_CHKPOINT is an encoder-to-decoder command.  It instructs the
     * decoder to make all dynamic entries duplicated or inserted since the
     * last checkpoint available for decoding incoming HEADER blocks.
     */
    QMM_FLUSH_CHKPOINT  = 0x02,

    /* DROP_CHKPOINT is an encoder-to-decoder command.  It instructs the
     * decoder to drop the checkpoint with the specified ID and decrement
     * reference count of dynamic table entries it refers to, potentially
     * evicting them.
     *
     * The ID of the checkpoint is its position in the checkpoint list when
     * they are ordered by age.  The oldest checkpoint has ID 0, the second-
     * oldest has ID 1, and so on.
     */
    QMM_DROP_CHKPOINT   = 0x04,

    /* ACK_FLUSH is a decoder-to-encoder command.  The decoder acknowledges
     * the receipt and application of FLUSH_CHKPOINT command.  The encoder
     * makes all dynamic entries duplicated or inserted since the last
     * checkpoint available for encoding outgoing HEADER blocks.
     */
    QMM_ACK_FLUSH       = 0x03,

    /* STREAM_DONE message instructs the encoder that the peer is done
     * decoding all HEADER blocks associated with identified stream.  The
     * encoder uses this information to determine when to create new
     * checkpoints.
     */
    QMM_STREAM_DONE     = 0x10,
};


struct qmin_ctl_out
{
    /* void function: if the caller cannot write to the control stream,
     * it is its problem.  It should probably clean up and abort.
     */
    void    (*qco_write)(void *qco_ctx, const void *, size_t);
    void     *qco_ctx;
};


#define QMIN_STATIC_TABLE_N_ENTRIES   61
#define QMIN_DYNAMIC_TABLE_SIZE  (64 * 1024)

#define QMIN_DYNAMIC_ENTRY_OVERHEAD 36

#define QMIN_CKPOINT_OVERHEAD 128

#endif
