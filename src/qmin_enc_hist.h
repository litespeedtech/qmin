/* Copyright (c) 2017 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef QMIN_ENC_HIST_H
#define QMIN_ENC_HIST_H 1

int
enc_hist_init (struct enc_hist *);

void
enc_hist_cleanup (struct enc_hist *);

enum enc_hist_add_st { EHA_ADDED, EHA_EXISTS, EHA_ERROR, };

enum enc_hist_add_st
enc_hist_add (struct enc_hist *, unsigned nameval_hash);

#endif
