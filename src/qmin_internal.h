/* Copyright (c) 2017 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef QMIN_INTERNAL_H
#define QMIN_INTERNAL_H

struct qmin_hdr_tbl
{
    const char *name;
    unsigned name_len;
    const char *val;
    unsigned val_len;
};

struct qmin_huff_encode
{
    uint32_t code;
    int      bits;
};

struct qmin_huff_decode
{
    uint8_t state;
    uint8_t flags;
    uint8_t sym;
};


extern const struct qmin_huff_decode qmin_huff_decode_tables[256][16];
extern const struct qmin_huff_encode qmin_huff_encode_tables[257];
extern const struct qmin_hdr_tbl     qmin_stx_tab[QMIN_STATIC_TABLE_N_ENTRIES];

enum qmin_message
qmin_char_to_qmm (unsigned char c);

enum dec_st { DEC_ST_OK, DEC_ST_NOBUF_SRC, DEC_ST_NOBUF_DST, DEC_ST_ERR, };

enum dec_st
qmin_decode_int (const unsigned char **src, const unsigned char *src_end,
                 unsigned prefix_bits, unsigned *value);

#endif
