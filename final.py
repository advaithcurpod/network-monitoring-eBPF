#!/usr/bin/env python3

# Import the bcc module
from bcc import BPF
import socket
import struct
import ctypes


program = r"""
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bcc/proto.h>

// Define the xdp program function
BPF_HASH(ip4_map, u64);
// BPF_HASH(ip6_map, u8[16]);

// SEC("xdp");
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
        
        // define the source ip address of packet
        u64 src_ip = iph->saddr;

        // Lookup the source IP address in the IPv4 map
        u64 *value = ip4_map.lookup(&src_ip);

        if (value) {
            // If the IP address is found in the map, drop the packet
            return XDP_DROP;
        }
    }
    /*
    else if (eth->h_proto == htons(ETH_P_IPV6)) {
        // Parse the IPv6 header and get the source IP address
        struct ipv6hdr *ip6h = data + sizeof(*eth);
        if (data + sizeof(*eth) + sizeof(*ip6h) > data_end)
            return XDP_PASS;

        // define the source ip address of packet
        u8 src_ip6[16];
        memcpy(src_ip6, ip6h->saddr.s6_addr, 16);

        // Lookup the source IP address in the IPv6 map
        u64 *value = ip6_map.lookup(&src_ip6);
        if (value) {
            // If the IP address is found in the map, drop the packet
            return XDP_DROP;
        }
    } */

    // Return XDP_PASS to allow the packet to continue
    return XDP_PASS;
}

// char _license[] SEC("license") = "GPL";
"""


b = BPF(text=program)
fn = b.load_func("xdp_prog", BPF.XDP)

# Attach the XDP program to the interface
device = "wlp5s0"
b.attach_xdp(device, fn)

# get a reference to the map
ip4_map = b["ip4_map"]

# Add an ip address to the ip4 map
dos_ip = "10.53.114.168"
ip_hex = struct.unpack("!I", socket.inet_aton(dos_ip))[0]

# convert it into a ctypes instance
ip_hex_ctypes = ctypes.c_uint32(ip_hex)

# look up the map
value = ip4_map.get(ip_hex_ctypes)
print(dir(ip4_map))
if(value):
    print("ip present in map")
    ip4_map.update(ip_hex_ctypes, value+1)

else:
    ip4_map.update(ip_hex_ctypes, 1)