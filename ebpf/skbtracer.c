#include "skbtracer.h"

/**
 * Common tracepoint handler. Detect IPv4/IPv6 and
 * emit event with address, interface and namespace.
 */
static __inline bool
do_trace_skb(struct event_t *event,
    struct pt_regs *ctx,
    struct sk_buff *skb)
{
    unsigned char *l3_header;
    u8 ip_version, l4_proto;

    event->flags |= SKBTRACER_EVENT_IF;
    set_event_info(skb, event);
    set_pkt_info(skb, &event->pkt_info);
    set_ether_info(skb, &event->l2_info);

    l3_header = get_l3_header(skb);
    ip_version = get_ip_version(l3_header);
    if (ip_version == 4) {
        event->l2_info.l3_proto = ETH_P_IP;
        set_ipv4_info(skb, &event->l3_info);
    } else if (ip_version == 6) {
        event->l2_info.l3_proto = ETH_P_IPV6;
        set_ipv6_info(skb, &event->l3_info);
    } else {
        return false;
    }

    l4_proto = event->l3_info.l4_proto;
    if (l4_proto == IPPROTO_TCP) {
        set_tcp_info(skb, &event->l4_info);
    } else if (l4_proto == IPPROTO_UDP) {
        set_udp_info(skb, &event->l4_info);
    } else if (l4_proto == IPPROTO_ICMP || l4_proto == IPPROTO_ICMPV6) {
        set_icmp_info(skb, &event->icmp_info);
    } else {
        return false;
    }

    return true;
}

static __noinline int
__ipt_do_table_in(struct pt_regs *ctx,
    struct sk_buff *skb,
    const struct nf_hook_state *state,
    struct xt_table *table)
{
    u64 pid_tgid;
    pid_tgid = bpf_get_current_pid_tgid();

    if (filter_pid(pid_tgid>>32) || filter_netns(skb) || filter_l3_and_l4_info(skb))
        return false;

    struct ipt_do_table_args args = {
        .skb = skb,
        .state = state,
        .table = table,
    };

    args.start_ns = bpf_ktime_get_ns();
    bpf_map_update_elem(&skbtracer_ipt, &pid_tgid, &args, BPF_ANY);

    return BPF_OK;
};

static __noinline int
__ipt_do_table_out(struct pt_regs *ctx, uint verdict)
{
    u64 pid_tgid;
    u64 ipt_delay;
    struct ipt_do_table_args *args;

    pid_tgid = bpf_get_current_pid_tgid();
    args = bpf_map_lookup_elem(&skbtracer_ipt, &pid_tgid);
    if (args == NULL)
        return BPF_OK;

    bpf_map_delete_elem(&skbtracer_ipt, &pid_tgid);

    struct event_t *event = GET_EVENT_BUF();
    if (!event)
        return BPF_OK;

    if (!do_trace_skb(event, ctx, args->skb))
        return BPF_OK;

    event->flags |= SKBTRACER_EVENT_IPTABLE;

    ipt_delay = bpf_ktime_get_ns() - args->start_ns;
    set_iptables_info(args->table, args->state, (u32)verdict, ipt_delay, &event->ipt_info);

    bpf_perf_event_output(ctx, &skbtracer_event, BPF_F_CURRENT_CPU, event,
        sizeof(struct event_t));

    return BPF_OK;
}

// >= 5.16

SEC("kprobe/ipt_do_table")
int BPF_KPROBE(k_ipt_do_table, struct xt_table *table,
    struct sk_buff *skb,
    const struct nf_hook_state *state)
{
    return __ipt_do_table_in(ctx, skb, state, table);
};

// < 5.16

SEC("kprobe/ipt_do_table")
int BPF_KPROBE(ipt_do_table_old, struct sk_buff *skb,
    const struct nf_hook_state *state,
    struct xt_table *table)
{
    return __ipt_do_table_in(ctx, skb, state, table);
}

SEC("kretprobe/ipt_do_table")
int BPF_KRETPROBE(kr_ipt_do_table, uint ret)
{
    return __ipt_do_table_out(ctx, ret);
}

// SEC("kprobe/ip6t_do_table")
// int BPF_KPROBE(k_ip6t_do_table, void *priv, struct sk_buff *skb,
//     const struct nf_hook_state *state)
// {
//     struct xt_table *table = (struct xt_table *)priv;
//     return __ipt_do_table_in(ctx, skb, state, table);
// };

// SEC("kretprobe/ip6t_do_table")
// int BPF_KRETPROBE(kr_ip6t_do_table, uint ret)
// {
//     return __ipt_do_table_out(ctx, ret);
// }
