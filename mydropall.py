from bcc import BPF 
from time import sleep
import os

prog = """
#define SEC(NAME) __attribute__((section(NAME), used))
SEC("prog")
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>


int dropall(struct xdp_md *ctx) 
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_PASS;
    }

    struct ethhdr *eth = data;
    if (eth + 1 > (struct ethhdr *)data_end) {
        return XDP_PASS;
    }

    return XDP_DROP;

}

"""

device = "eth0"

b =BPF(text=prog)
fn = b.load_func("dropall",BPF.XDP)
b.attach_xdp(device,fn)


while True:
    sleep(1.5)
    try:
        b.trace_print()
    except KeyboardInterrupt:
        b.remove_xdp(device)
        exit()




