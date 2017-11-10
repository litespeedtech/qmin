/* Copyright (c) 2017 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef QMIN_ID_LIST_H
#define QMIN_ID_LIST_H 1

/* Keep dynamic entry IDs in a list that does not take up a lot of memory
 * and is fast to scan.
 */

struct id_list
{
    unsigned    il_min;
    unsigned    il_nsets;
    uint64_t   *il_sets;
    struct      {
        unsigned        set_idx,
                        next_bit;
    }           il_iter;
};

#define INVALID_ID (~0U)

void
id_list_init (struct id_list *, unsigned min);

void
id_list_cleanup (struct id_list *);

unsigned
id_list_min_unused (const struct id_list *);

enum id_list_add_st { ILA_ADDED, ILA_EXISTS, ILA_ERROR, };

enum id_list_add_st
id_list_add (struct id_list *, unsigned id);

int
id_list_del (struct id_list *, unsigned id);

void
id_list_reset_iter (struct id_list *);

unsigned
id_list_next (struct id_list *);

unsigned
id_list_count (const struct id_list *list);

unsigned
id_list_count_cons (const struct id_list *list);

int
id_list_exists (const struct id_list *list, unsigned id);

void
id_list_del_all (struct id_list *list);

unsigned
id_list_max (const struct id_list *list);

size_t
id_list_mem_used (const struct id_list *);

#endif
