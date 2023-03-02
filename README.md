# skbtracer-iptables

`skbtracer-iptables` is an eBPF-based
[skbtracer](https://github.com/Asphaltt/skbtracer) focused on iptables.

## kernel

`skbtracer-iptables` requires >= 5.2 kernel with **CONFIG_DEBUG_INFO_BTF=y**.

## kprobes

- `ipt_do_tables`: attach eBPF program on kprobe and kretprobe of this function
  for IPv4.
- `ip6t_do_tables`: attach eBPF program on kprobe and kretprobe of this function
  for IPv6.

But, at kernel 5.16, the declarations of `ipt_do_tables` and `ip6t_do_tables`
changed.

```C
// from

extern unsigned int ipt_do_table(struct sk_buff *skb,
         const struct nf_hook_state *state,
         struct xt_table *table);

// to

extern unsigned int ipt_do_table(void *priv,
         struct sk_buff *skb,
         const struct nf_hook_state *state);

// ---

// from

extern unsigned int ip6t_do_table(struct sk_buff *skb,
          const struct nf_hook_state *state,
          struct xt_table *table);

// to

extern unsigned int ip6t_do_table(void *priv, struct sk_buff *skb,
          const struct nf_hook_state *state);

```

As a result, `skbtracer-iptables` has to prepare two versions of eBPF program
for kprobe on them.

```C
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
```

Note: confirm that you can kprobe the two functions:

```bash
# bpftrace -l 'k:ip*t_do_table'
kprobe:ip6t_do_table
kprobe:ipt_do_table
```

## Build and run

Building requires clang and llvm.

```bash
# git clone https://github.com/Asphaltt/skbtracer-iptables.git
# cd skbtracer-iptables
# go generate
# go build
# ./skbtracer-iptables --proto icmp
2023/02/27 13:35:07 Attached kprobe(ipt_do_table)
2023/02/27 13:35:07 Attached kretprobe(ipt_do_table)
2023/02/27 13:35:07 Attached kprobe(ip6t_do_table)
2023/02/27 13:35:07 Attached kretprobe(ip6t_do_table)
TIME       SKB                  NETWORK_NS   PID      CPU    INTERFACE          DEST_MAC           IP_LEN PKT_INFO                                               IPTABLES_INFO
[00:00:56] [0xffff95398a31a200] [4026531840] 2347     0      nil                61:6e:37:38:78:78  84     I_request:10.0.2.15->8.8.8.8                           pkt_type=HOST iptables=[pf=PF_INET, table=nat hook=OUTPUT verdict=ACCEPT]
[00:00:56] [0xffff95398a31a200] [4026531840] 2347     0      nil                61:6e:37:38:78:78  84     I_request:10.0.2.15->8.8.8.8                           pkt_type=HOST iptables=[pf=PF_INET, table=filter hook=OUTPUT verdict=ACCEPT]
[00:00:56] [0xffff95398a31a200] [4026531840] 2347     0      enp0s3             61:6e:37:38:78:78  84     I_request:10.0.2.15->8.8.8.8                           pkt_type=HOST iptables=[pf=PF_INET, table=nat hook=POSTROUTING verdict=ACCEPT]
[00:00:56] [0xffff953990ac5500] [4026531840] 0        3      enp0s3             08:00:27:ff:1e:ab  84     I_reply:8.8.8.8->10.0.2.15                             pkt_type=HOST iptables=[pf=PF_INET, table=filter hook=INPUT verdict=ACCEPT]
[00:00:57] [0xffff95398a31ac00] [4026531840] 2347     0      nil                00:00:00:00:00:00  84     I_request:10.0.2.15->8.8.8.8                           pkt_type=HOST iptables=[pf=PF_INET, table=filter hook=OUTPUT verdict=ACCEPT]
[00:00:57] [0xffff953990ac5100] [4026531840] 0        3      enp0s3             08:00:27:ff:1e:ab  84     I_reply:8.8.8.8->10.0.2.15                             pkt_type=HOST iptables=[pf=PF_INET, table=filter hook=INPUT verdict=ACCEPT]
^C2023/02/27 13:35:19 Received signal, exiting program...
```

## License

Apache License 2.0
