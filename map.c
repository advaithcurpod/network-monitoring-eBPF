#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/if_packet.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <arpa/inet.h>

// #include <uapi/linux/bpf.h>
// #include <uapi/linux/if_ether.h>
// #include <uapi/linux/if_packet.h>
// #include <uapi/linux/if_vlan.h>
// #include <uapi/linux/ip.h>
// #include <uapi/linux/in.h>
// #include <uapi/linux/tcp.h>
#include "bpf_helpers.h"


// Define the map type and key/value size
#define BPF_MAP_TYPE_HASH 1
#define BPF_ANY 0
#define IP4_KEY_SIZE 4
#define IP4_VALUE_SIZE 4
#define IP6_KEY_SIZE 16
#define IP6_VALUE_SIZE 4

// Define a helper macro to access the map
// #define bpf_map_lookup_elem(map, key) \
// ({ \
//     void *ret; \
//     asm volatile ("call %c[map]" \
//         : "=a"(ret) \
//         : "0"(BPF_ANY), "D"(map), "S"(key) \
//         : "memory", "cc"); \
//     ret; \
// })

// Define the map structure and initialize it with some attributes
struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
};

// Define two maps, one for IPv4 and one for IPv6 addresses
// struct bpf_map_def SEC("maps") ip4_map = {
//     .type = BPF_MAP_TYPE_HASH,
//     .key_size = IP4_KEY_SIZE,
//     .value_size = IP4_VALUE_SIZE,
//     .max_entries = 1024,
// };

// struct bpf_map_def SEC("maps") ip6_map = {
//     .type = BPF_MAP_TYPE_HASH,
//     .key_size = IP6_KEY_SIZE,
//     .value_size = IP6_VALUE_SIZE,
//     .max_entries = 1024,
// };

struct ipv6kv {
    __u8 kv[16];
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, unsigned int);
    __type(value, unsigned int);
    // __type(key, struct _5tuple);
    // __type(value, struct pdm_flow_details);
    __uint(max_entries, 1024);
    // __uint(pinning, 1);
} ip4_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct ipv6key);
    __type(value, struct ipv6key);
    // __type(key, struct _5tuple);
    // __type(value, struct pdm_flow_details);
    __uint(max_entries, 1024);
    // __uint(pinning, 1);
} ip6_map SEC(".maps");

// Define the xdp program function
SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    // Get the packet data and length
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse the ethernet header and check if it is IPv4 or IPv6
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;
    
    if (eth->h_proto == htons(ETH_P_IP)) {
        // Parse the IPv4 header and get the source IP address
        struct iphdr *iph = data + sizeof(*eth);
        if (data + sizeof(*eth) + sizeof(*iph) > data_end)
            return XDP_PASS;
        __u32 src_ip = iph->saddr;

        // Lookup the source IP address in the IPv4 map
        // use the macro defined above in program
        // __u32 *value = 
        __u32 *value = bpf_map_lookup_elem(&ip4_map, &src_ip);
        if (value) {
            // If the IP address is found in the map, drop the packet
            return XDP_DROP;
        }
    } else if (eth->h_proto == htons(ETH_P_IPV6)) {
        // Parse the IPv6 header and get the source IP address
        struct ipv6hdr *ip6h = data + sizeof(*eth);
        if (data + sizeof(*eth) + sizeof(*ip6h) > data_end)
            return XDP_PASS;
        __u8 src_ip[16];
        memcpy(src_ip, ip6h->saddr.s6_addr, 16);

        // Lookup the source IP address in the IPv6 map
        __u32 *value = bpf_map_lookup_elem(&ip6_map, &src_ip);
        if (value) {
            // If the IP address is found in the map, drop the packet
            return XDP_DROP;
        }
    }

    // Return XDP_PASS to allow the packet to continue
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";