/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2022
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _MAPS_H_
#define _MAPS_H_

#define TABLE_NAME_MAX XT_TABLE_MAXNAMELEN
#define DEVICE_NAME_MAX IFNAMSIZ
#define MAX_FILTER_COUNT 100

struct bpf_map_def SEC("maps/hook_filters") hook_filters = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u8),
    .value_size = sizeof(u8),
    .max_entries = MAX_FILTER_COUNT,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/proto_filters") proto_filters = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u8),
    .value_size = sizeof(u8),
    .max_entries = MAX_FILTER_COUNT,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/packet_type_filters") packet_type_filters = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u8),
    .value_size = sizeof(u8),
    .max_entries = MAX_FILTER_COUNT,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/verdict_filters") verdict_filters = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u8),
    .max_entries = MAX_FILTER_COUNT,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/netns_filters") netns_filters = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u8),
    .max_entries = MAX_FILTER_COUNT,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/table_filters") table_filters = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = TABLE_NAME_MAX,
    .value_size = sizeof(u8),
    .max_entries = MAX_FILTER_COUNT,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/in_ifindex_filters") in_ifindex_filters = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u8),
    .max_entries = MAX_FILTER_COUNT,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/in_name_filters") in_name_filters = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = DEVICE_NAME_MAX,
    .value_size = sizeof(u8),
    .max_entries = MAX_FILTER_COUNT,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/out_ifindex_filters") out_ifindex_filters = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u8),
    .max_entries = MAX_FILTER_COUNT,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/out_name_filters") out_name_filters = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = DEVICE_NAME_MAX,
    .value_size = sizeof(u8),
    .max_entries = MAX_FILTER_COUNT,
    .pinning = 0,
    .namespace = "",
};

#endif
