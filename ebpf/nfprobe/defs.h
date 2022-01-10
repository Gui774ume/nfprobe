/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2022
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _DEFS_H_
#define _DEFS_H_

union ___skb_pkt_type {
    __u8 value;
    struct {
        __u8			__pkt_type_offset[0];
        __u8			pkt_type:3;
        __u8			pfmemalloc:1;
        __u8			ignore_df:1;

        __u8			nf_trace:1;
        __u8			ip_summed:2;
    };
};

struct nf_event_t {
    u8 hook;
    u8 pf;
    u8 pkt_type;
    u8 padding1;
    u32 netns;
    u32 in_dev_ifindex;
    u32 out_dev_ifindex;
    u32 pkt_csum;
    u32 ret;
    u64 pkt_addr;
    u64 timestamp;
    char in_dev_name[IFNAMSIZ];
    char out_dev_name[IFNAMSIZ];
    char table_name[XT_TABLE_MAXNAMELEN];
};

struct bpf_map_def SEC("maps/events") events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = 0,
    .value_size = 0,
    .max_entries = 0,
    .pinning = PIN_NONE,
    .namespace = "",
};

struct ip_do_table_cache_t {
    struct sk_buff *skb;
    struct nf_hook_state *state;
    struct xt_table *table;
};

struct bpf_map_def SEC("maps/ip_do_table_cache") ip_do_table_cache = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct ip_do_table_cache_t),
    .max_entries = 1,
    .pinning = 0,
    .namespace = "",
};

__attribute__((always_inline)) struct ip_do_table_cache_t* get_cache() {
    u32 key = 0;
    struct ip_do_table_cache_t *entry = bpf_map_lookup_elem(&ip_do_table_cache, &key);
    return entry;
}

__attribute__((always_inline)) struct ip_do_table_cache_t* pop_cache() {
    struct ip_do_table_cache_t *entry = get_cache();
    u32 key = 0;
    bpf_map_delete_elem(&ip_do_table_cache, &key);
    return entry;
}

__attribute__((always_inline)) struct ip_do_table_cache_t* reset_cache() {
    u32 key = 0;
    struct ip_do_table_cache_t entry = {};
    bpf_map_update_elem(&ip_do_table_cache, &key, &entry, BPF_ANY);
    return get_cache();
}

#endif
