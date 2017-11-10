/* Copyright (c) 2017 LiteSpeed Technologies Inc.  See LICENSE. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "qmin_id_list.h"

void
id_list_init (struct id_list *list, unsigned min)
{
    memset(list, 0, sizeof(*list));
    list->il_min = min;
}

void
id_list_cleanup (struct id_list *list)
{
    free(list->il_sets);
    memset(list, 0, sizeof(*list));
}

void
id_list_del_all (struct id_list *list)
{
    free(list->il_sets);
    list->il_sets = NULL;
    list->il_nsets = 0;
}

static unsigned
find_smallest_unused (const struct id_list *list)
{
    unsigned i;

    for (i = 0; list->il_sets[i] == UINT64_MAX; ++i)
        ;

    if (i < list->il_nsets && list->il_sets[i] != 0)
        return i * 64 + __builtin_ctzll(~list->il_sets[i]);
    else
        return i * 64;
}


unsigned
id_list_min_unused (const struct id_list *list)
{
    if (list->il_nsets)
        return list->il_min + find_smallest_unused(list);
    else
        return list->il_min;
}


enum id_list_add_st
id_list_add (struct id_list *list, unsigned id)
{
    uint64_t *new_sets;
    unsigned set_idx, n_sets;

    if (id < list->il_min)
        return ILA_ERROR;

    id -= list->il_min;
    set_idx = id / 64;

    if (set_idx >= list->il_nsets)
    {
        if (list->il_nsets == 0)
            n_sets = 4;
        else
            n_sets = list->il_nsets * 2;
        if (set_idx >= n_sets)
            n_sets = set_idx + 1;
        new_sets = realloc(list->il_sets, sizeof(list->il_sets[0]) * n_sets);
        if (!new_sets)
            return ILA_ERROR;
        memset(new_sets + list->il_nsets, 0,
                        (n_sets - list->il_nsets) * sizeof(list->il_sets[0]));
        list->il_sets = new_sets;
        list->il_nsets = n_sets;
    }

    if (list->il_sets[set_idx] & (1ULL << (id % 64)))
        return ILA_EXISTS;

    list->il_sets[set_idx] |= (1ULL << (id % 64));
    return ILA_ADDED;
}


int
id_list_del (struct id_list *list, unsigned id)
{
    unsigned set_idx;

    if (id < list->il_min)
        return -1;

    id -= list->il_min;
    set_idx = id / 64;

    if (set_idx < list->il_nsets)
        list->il_sets[set_idx] &= ~(1ULL << (id % 64));

    return 0;
}


void
id_list_reset_iter (struct id_list *list)
{
    list->il_iter.set_idx = 0;
    list->il_iter.next_bit = 0;
}


unsigned
id_list_next (struct id_list *list)
{
    for ( ; list->il_iter.set_idx < list->il_nsets; ++list->il_iter.set_idx)
    {
        for ( ; list->il_iter.next_bit < 64; ++list->il_iter.next_bit)
        {
            if (list->il_sets[ list->il_iter.set_idx ]
                                        & (1ULL << list->il_iter.next_bit))
                return list->il_min
                     + 64 * list->il_iter.set_idx
                     + list->il_iter.next_bit++
                     ;
        }
        list->il_iter.next_bit = 0;
    }

    return INVALID_ID;
}


unsigned
id_list_count (const struct id_list *list)
{
    unsigned n, count;

    count = 0;
    for (n = 0; n < list->il_nsets; ++n)
        count += __builtin_popcountll(list->il_sets[n]);

    return count;
}


#if 0
unsigned
id_list_count_cons (const struct id_list *list)
{
    unsigned n, count;

    if (list->il_nsets == 0)
        return 0;

    count = 0;
    for (n = 0; list->il_sets[n] == UINT64_MAX; ++n)
        count += 64;

    if (list->il_sets[n])
        count += __builtin_ctzll(~list->il_sets[n]);

    return count;
}
#endif


int
id_list_exists (const struct id_list *list, unsigned id)
{
    unsigned set_idx;

    if (id < list->il_min)
        return -1;

    id -= list->il_min;
    set_idx = id / 64;

    if (set_idx >= list->il_nsets)
        return 0;
    return !!(list->il_sets[set_idx] & (1ULL << (id % 64)));
}


unsigned
id_list_max (const struct id_list *list)
{
    unsigned n, max;

    max = 0;
    for (n = 0; n < list->il_nsets; ++n)
        if (list->il_sets[n])
            max = n * 64 + __builtin_ctzll(~list->il_sets[n]);

    return max + list->il_min;
}


size_t
id_list_mem_used (const struct id_list *list)
{
    return sizeof(*list) + sizeof(list->il_sets[0]) * list->il_nsets;
}
