/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2022
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _NFPROBE_H_
#define _NFPROBE_H_

__attribute__((always_inline)) int trace_ip_do_table(struct pt_regs *ctx) {
    struct ip_do_table_cache_t *entry = reset_cache();
    if (entry == NULL) {
        return 0;
    }

    entry->skb = (struct sk_buff*) PT_REGS_PARM1(ctx);
    entry->state = (struct nf_hook_state*) PT_REGS_PARM2(ctx);
    entry->table = (struct xt_table*) PT_REGS_PARM3(ctx);
    return 0;
}

SEC("kprobe/ipt_do_table")
int kprobe_ipt_do_table(struct pt_regs *ctx) {
    return trace_ip_do_table(ctx);
};

SEC("kprobe/ip6t_do_table")
int kprobe_ip6t_do_table(struct pt_regs *ctx) {
    return trace_ip_do_table(ctx);
};

__attribute__((always_inline)) int trace_ip_do_table_ret(struct pt_regs *ctx) {
    struct ip_do_table_cache_t *entry = pop_cache();
    if (entry == NULL) {
        return 0;
    }

    struct nf_event_t event = {
        .ret = (u32) PT_REGS_RC(ctx),
        .timestamp = bpf_ktime_get_ns(),
        .pkt_addr = (u64)(void*)entry->skb,
    };
    u8 *filtered = NULL;

    // filter verdict
    if (load_verdict_filter()) {
        filtered = bpf_map_lookup_elem(&verdict_filters, &event.ret);
        if (!filtered || (filtered && *filtered != 1)) {
            return 0;
        }
    }

    bpf_probe_read(&event.hook, sizeof(event.hook), &entry->state->hook);
    // filter hook
    if (load_hook_filter()) {
        filtered = bpf_map_lookup_elem(&hook_filters, &event.hook);
        if (!filtered || (filtered && *filtered != 1)) {
            return 0;
        }
    }

    bpf_probe_read(&event.pf, sizeof(event.pf), &entry->state->pf);
    // filter proto
    if (load_proto_filter()) {
        filtered = bpf_map_lookup_elem(&proto_filters, &event.pf);
        if (!filtered || (filtered && *filtered != 1)) {
            return 0;
        }
    }

    union ___skb_pkt_type type = {};
    bpf_probe_read(&type.value, 1, ((char*)entry->skb) + offsetof(struct sk_buff, __pkt_type_offset));
    event.pkt_type = type.pkt_type;
    // filter packet_type
    if (load_packet_type_filter()) {
        filtered = bpf_map_lookup_elem(&packet_type_filters, &event.pkt_type);
        if (!filtered || (filtered && *filtered != 1)) {
            return 0;
        }
    }

    bpf_probe_read(&event.table_name, sizeof(event.table_name), &entry->table->name);
    // filter table name
    if (load_table_filter()) {
        filtered = bpf_map_lookup_elem(&table_filters, &event.table_name);
        if (!filtered || (filtered && *filtered != 1)) {
            return 0;
        }
    }

    struct net_device *in = NULL;
    struct net_device *out = NULL;
    bpf_probe_read(&in, sizeof(in), &entry->state->in);
    if (in != NULL) {
        bpf_probe_read(&event.in_dev_ifindex, sizeof(event.in_dev_ifindex), &in->ifindex);
        // filter in_ifindex
        if (load_in_ifindex_filter()) {
            filtered = bpf_map_lookup_elem(&in_ifindex_filters, &event.in_dev_ifindex);
            if (!filtered || (filtered && *filtered != 1)) {
                return 0;
            }
        }
        bpf_probe_read_str(&event.in_dev_name, sizeof(event.in_dev_name), &in->name);
        // filter in_name
        if (load_in_name_filter()) {
            filtered = bpf_map_lookup_elem(&in_name_filters, &event.in_dev_name);
            if (!filtered || (filtered && *filtered != 1)) {
                return 0;
            }
        }
    } else if (load_in_ifindex_filter() || load_in_name_filter()) {
        return 0;
    }
    bpf_probe_read(&out, sizeof(out), &entry->state->out);
    if (out != NULL) {
        bpf_probe_read(&event.out_dev_ifindex, sizeof(event.out_dev_ifindex), &out->ifindex);
        // filter out_ifindex
        if (load_out_ifindex_filter()) {
            filtered = bpf_map_lookup_elem(&out_ifindex_filters, &event.out_dev_ifindex);
            if (!filtered || (filtered && *filtered != 1)) {
                return 0;
            }
        }
        bpf_probe_read_str(&event.out_dev_name, sizeof(event.out_dev_name), &out->name);
        // filter out_name
        if (load_out_name_filter()) {
            filtered = bpf_map_lookup_elem(&out_name_filters, &event.out_dev_name);
            if (!filtered || (filtered && *filtered != 1)) {
                return 0;
            }
        }
    } else if (load_out_name_filter() || load_out_ifindex_filter()) {
        return 0;
    }

    struct net *net = NULL;
    bpf_probe_read(&net, sizeof(net), &entry->state->net);
    struct ns_common ns;
    bpf_probe_read(&ns, sizeof(ns), &net->ns);
    event.netns = ns.inum;
    // filter netns
    if (load_netns_filter()) {
        filtered = bpf_map_lookup_elem(&netns_filters, &event.netns);
        if (!filtered || (filtered && *filtered != 1)) {
            return 0;
        }
    }

    bpf_probe_read(&event.pkt_csum, sizeof(event.pkt_csum), &entry->skb->csum);

    if (load_debug()) {
        bpf_printk("hook:%d proto:%d verdict:%d\n", event.hook, event.pf, event.ret);
        bpf_printk("      skb_addr:0x%lx skb_csum:0x%x netns:%u\n", event.pkt_addr, event.pkt_csum, event.netns);
        bpf_printk("      in_ifindex:%d out_ifindex:%d table:%s\n", event.in_dev_ifindex, event.out_dev_ifindex, event.table_name);
    }

    u32 cpu = bpf_get_smp_processor_id();
    bpf_perf_event_output(ctx, &events, cpu, &event, sizeof(event));
    return 0;
}

SEC("kretprobe/ipt_do_table")
int kretprobe_ipt_do_table(struct pt_regs *ctx) {
    return trace_ip_do_table_ret(ctx);
}

SEC("kretprobe/ip6t_do_table")
int kretprobe_ip6t_do_table(struct pt_regs *ctx) {
    return trace_ip_do_table_ret(ctx);
}

#endif
