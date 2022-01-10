/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2022
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _CONST_H_
#define _CONST_H_

#define LOAD_CONSTANT(param, var) asm("%0 = " param " ll" : "=r"(var))

__attribute__((always_inline)) static u64 load_hook_filter() {
    u64 hook_filter = 0;
    LOAD_CONSTANT("hook_filter", hook_filter);
    return hook_filter;
}

__attribute__((always_inline)) static u64 load_proto_filter() {
    u64 proto_filter = 0;
    LOAD_CONSTANT("proto_filter", proto_filter);
    return proto_filter;
}

__attribute__((always_inline)) static u64 load_packet_type_filter() {
    u64 packet_type_filter = 0;
    LOAD_CONSTANT("packet_type_filter", packet_type_filter);
    return packet_type_filter;
}

__attribute__((always_inline)) static u64 load_verdict_filter() {
    u64 verdict_filter = 0;
    LOAD_CONSTANT("verdict_filter", verdict_filter);
    return verdict_filter;
}

__attribute__((always_inline)) static u64 load_netns_filter() {
    u64 netns_filter = 0;
    LOAD_CONSTANT("netns_filter", netns_filter);
    return netns_filter;
}

__attribute__((always_inline)) static u64 load_table_filter() {
    u64 table_filter = 0;
    LOAD_CONSTANT("table_filter", table_filter);
    return table_filter;
}

__attribute__((always_inline)) static u64 load_in_name_filter() {
    u64 in_name_filter = 0;
    LOAD_CONSTANT("in_name_filter", in_name_filter);
    return in_name_filter;
}

__attribute__((always_inline)) static u64 load_in_ifindex_filter() {
    u64 in_ifindex_filter = 0;
    LOAD_CONSTANT("in_ifindex_filter", in_ifindex_filter);
    return in_ifindex_filter;
}

__attribute__((always_inline)) static u64 load_out_name_filter() {
    u64 out_name_filter = 0;
    LOAD_CONSTANT("out_name_filter", out_name_filter);
    return out_name_filter;
}

__attribute__((always_inline)) static u64 load_out_ifindex_filter() {
    u64 out_ifindex_filter = 0;
    LOAD_CONSTANT("out_ifindex_filter", out_ifindex_filter);
    return out_ifindex_filter;
}

__attribute__((always_inline)) static u64 load_debug() {
    u64 debug = 0;
    LOAD_CONSTANT("debug", debug);
    return debug;
}

#endif
